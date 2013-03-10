#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE
#undef LINUX
#define LINUX

#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/prefetch.h>
#include "gao_mmio_resource.h"


static struct gao_resources resources;

inline struct gao_resources*	gao_get_resources(void) {
	return &resources;
}
EXPORT_SYMBOL(gao_get_resources);

/**
 * Get an interface pointer from a kernel ifindex.
 * @param ifindex The kernel netdev ifindex
 * @return The pointer to that interface if registered, NULL otherwise.
 */
inline struct gao_port* gao_get_port_from_ifindex(int ifindex) {
	if(unlikely((unsigned int)ifindex >= GAO_MAX_IFINDEX)) return NULL;
	else return resources.ifindex_to_port_lut[ifindex];
}
EXPORT_SYMBOL(gao_get_port_from_ifindex);


static int gao_open(struct inode *inode, struct file *filep) {
	int ret = 0;
	struct gao_file_private	*gao_file = NULL;

	log_debug("Open file for filep %p", filep);


	gao_file = kmalloc(sizeof(struct gao_file_private), GFP_KERNEL);
	if(!gao_file) gao_error_val(-ENOMEM, "Failed to open device, out of memory.");
	memset(gao_file, 0, sizeof(struct gao_file_private));

	sema_init(&gao_file->lock, 1);

	gao_file->filep = filep;
	gao_file->state = GAO_RESOURCE_STATE_REGISTERED;
	gao_file->grid = NULL;

	filep->private_data = gao_file;
	return 0;
	err:
	return ret;
}

static int gao_release(struct inode *inode, struct file *filep) {
	struct gao_file_private* gao_file = filep->private_data;
	log_debug("Release file for filep %p", filep);

	if(gao_file->grid) gao_grid_return(&resources.grid_allocator, gao_file->grid);
	//If we were bound to anything, remove the binding. If the queue was deleting,
	//and we were the last reference, delete the queue.
	kfree(filep->private_data);



	return 0;
}


/**
 * Map either the descriptor queue or the buffer space to userspace.
 * If the fd has a bound queue, map the queue, otherwise map the bufferspace.
 * This algorithm is super slow, but only needs to be done once on initialization.
 * @param filep
 * @param vma
 * @return
 */
int gao_mmap(struct file* filep, struct vm_area_struct* vma) {
	uint64_t 	requested_length = vma->vm_end - vma->vm_start;
	struct gao_file_private	*gao_file = filep->private_data;
	//struct gao_rx_queue 		*queue = NULL;
	unsigned long vm_addr, pfn, buffer_offset, buffer_addr, base_addr;
	void*					grid_addr = NULL;
	uint64_t				page_index, i;

	//uint64_t 	buffer_length = ((uint64_t)GAO_BUFFER_GROUP_SIZE*(uint64_t)GAO_MAX_BUFFER_GROUPS);
	int ret, index; //XXX: These should probably be int64_t ...

	gao_lock_file(gao_file);


	if(requested_length == (sizeof(struct gao_grid)*GAO_GRIDS)) {
		log_debug("Request for gridspace mapping.");

		vm_addr = vma->vm_start;

		for(i = 0; i < GAO_GRIDS; i++) {
			grid_addr = resources.grid_allocator.grids[i];

			//The grids are always evenly divisible by the pagesize
			for(page_index = 0; page_index < (sizeof(struct gao_grid)/GAO_SMALLPAGE_SIZE); page_index++) {
				pfn = vmalloc_to_pfn(grid_addr);
				ret = vm_insert_page(vma, vm_addr, pfn_to_page(pfn));
				grid_addr += GAO_SMALLPAGE_SIZE;
				vm_addr += GAO_SMALLPAGE_SIZE;
			}
		}

	} else {
		log_debug("mmap: buffer request for length %llu base addr %lx", requested_length, vma->vm_start);

		if(requested_length != resources.buffer_space_frame) {
			gao_error_val(-EINVAL,  "Userspace requested invalid mmap size: %lu, can only map: %lu",
					(unsigned long)requested_length, resources.buffer_space_frame);
		}

		//Walk the space frame, and map allocated buffer groups, if unallocated map the dummy frame
		for(buffer_offset = 0; buffer_offset < (resources.buffer_space_frame); buffer_offset += GAO_BUFFER_SIZE) {
			//log_debug("Lookup: base_offset=%lx", group_offset);

			//Is that a valid buffer group? This really kills performance, but it only needs to be done once.
			for(buffer_addr = 0, index = 0; index < GAO_BUFFERS; index++) {
				base_addr = (virt_to_phys(resources.buffers[index]) - resources.buffer_start_phys);
				if(base_addr == buffer_offset) {
					buffer_addr = virt_to_phys(resources.buffers[index]);
					//log_debug("Found buffer group at index %d, phys=%lx, base=%lx", index, (unsigned long)virt_to_phys(resources.buffer_groups[index]), base_addr);
					break;
				}
			}

			//Nope, map the dummy group
			if(!buffer_addr) {
				buffer_addr = virt_to_phys(resources.dummy_buffer);
			}

			vm_addr = vma->vm_start + (buffer_offset);
			pfn = buffer_addr >> PAGE_SHIFT;

//			if (buffer_addr!=virt_to_phys(resources.dummy_buffer)) {
//			log_debug("Mapping: phys=%016lx pfn=%016lx -> vm=%016lx (%s)",
//					buffer_addr, buffer_addr >> PAGE_SHIFT, vm_addr, (buffer_addr==virt_to_phys(resources.dummy_buffer) ? "dummy":"buffer"));
//			}
//			ret = remap_pfn_range(vma, vm_addr, pfn, GAO_BUFFER_GROUP_SIZE, vma->vm_page_prot);
			//The below call is required instead of the above, otherwise the NVIDIA driver flips its shit when remapping it into GPU space.
			for(page_index = 0; page_index < GAO_PAGE_PER_BUFFER; page_index++) {
				ret = vm_insert_page(vma, vm_addr + (page_index*GAO_SMALLPAGE_SIZE), pfn_to_page(pfn+page_index));
			}

			if(ret) gao_error("Failed to MMAP buffer page to userspace: %d (offset %lx)", ret, buffer_offset);
		}



	}

	log_debug("MMAP Successful.");
	gao_unlock_file(gao_file);
	return 0;
	err:
	gao_unlock_file(gao_file);
	return ret;
}





long gao_ioctl_handle_port(struct file * filep, unsigned long request_ptr) {
	long ret = 0;
	struct gao_request_port	*request = NULL;
	struct gao_request_port_list *list = NULL;
	struct gao_request_port_info *info = NULL;

	request = kmalloc(sizeof(struct gao_request_port), GFP_KERNEL);
	check_ptr(request);

	ret = copy_from_user(request, (void*) request_ptr, sizeof(struct gao_request_port));
	if(ret) gao_error("Copy from user failed.");


	switch(request->request_code) {

	case GAO_REQUEST_PORT_ENABLE:
		ret = gao_enable_gao_port(gao_get_resources(), request->gao_ifindex);

		if(ret) request->response_code = GAO_RESPONSE_PORT_NOK;
		else request->response_code = GAO_RESPONSE_PORT_OK;

		ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_port));
		if(ret) gao_error("Copy to user failed.");

		break;
	case GAO_REQUEST_PORT_DISABLE:
		ret = gao_disable_gao_port(gao_get_resources(), request->gao_ifindex);

		if(ret) request->response_code = GAO_RESPONSE_PORT_NOK;
		else request->response_code = GAO_RESPONSE_PORT_OK;

		ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_port));
		if(ret) gao_error("Copy to user failed.");

		break;

	case GAO_REQUEST_PORT_LIST:
		if(!request->data) gao_error_val(-EINVAL, "Null port list buffer given for port list request.");

		list = gao_get_port_list(gao_get_resources());
		check_ptr(list);

		request->response_code = GAO_RESPONSE_PORT_OK;
		ret = copy_to_user((void*)request->data, (void*)list, sizeof(struct gao_request_port_list));
		gao_free_port_list(list);
		if(ret) gao_error("Copy to user failed.");

		break;
	case GAO_REQUEST_PORT_GET_INFO:
		if(!request->data) gao_error_val(-EINVAL, "Null port list buffer given for port list request.");

		info = gao_get_port_info(gao_get_resources(), request->gao_ifindex);
		check_ptr(info);

		request->response_code = GAO_RESPONSE_PORT_OK;
		ret = copy_to_user((void*)request->data, (void*)info, sizeof(struct gao_request_port_info));
		gao_free_port_info(info);
		if(ret) gao_error("Copy to user failed.");

		break;

	default:
		ret = -EINVAL;
		break;
	}



	err:
	if(request) kfree_null(request);
	return ret;
}


static int64_t	gao_ioctl_handle_mmap(struct file *filep, unsigned long request_ptr) {
	long ret = 0;
	struct gao_request_mmap	*request = NULL;

	request = kmalloc(sizeof(struct gao_request_mmap), GFP_KERNEL);
	if(!request) gao_error_val(-ENOMEM, "IOCTL failed, no memory!");

	request->bufferspace_size = resources.buffer_space_frame;
	request->gridspace_size = sizeof(struct gao_grid)*GAO_GRIDS;
	request->offset = resources.buffer_start_phys;
	log_debug("IOCTL: Get MMAP request returns bufferspace_size=%lx gridspace_size=%lx offset=%lx",
			request->bufferspace_size, request->gridspace_size, request->offset);

	ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_mmap));
	if(ret) gao_error("Copy to user failed.");

	err:
	return ret;
}




void	gao_fabric_task(unsigned long data) {
	log_debug("Entering fabric tasklet");



	log_debug("Exiting fabric tasklet");
}


static int32_t	gao_rx_into_ring(struct gao_rx_queue* rxq) {
	int32_t	ret = 0, num_read, num_cleaned;

	log_debug("start recv: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);
	//Recv from clean to use
	num_read = resources.ports[rxq->port_id].port_ops->gao_recv(&rxq->ring, (rxq->ring.use - rxq->ring.clean), rxq->hw_private);
	if(num_read < 0) gao_error_val(-EIO, "recv failed");

	rxq->ring.clean += num_read;
	log_debug("done recv: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	//Refill from avail to forward. Unless we're an interrupt. That would be bad.
	if( !in_interrupt() && ((rxq->ring.avail - rxq->ring.forward) < rxq->ring.capacity )) {
		//XXX: Mode intr check to refill descriptors, and trylock? We will need to bh spinlock, anyways
		gao_refill_descriptors(&resources.descriptor_allocator, &rxq->ring);
		log_debug("done refill: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);
	}

	//Clean from use to avail
	num_cleaned = resources.ports[rxq->port_id].port_ops->gao_clean(&rxq->ring, (rxq->ring.avail - rxq->ring.use), rxq->hw_private);
	if(num_cleaned < 0) gao_error_val(-EIO, "clean failed");

	rxq->ring.use += num_cleaned;
	log_debug("done clean: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	return (rxq->ring.clean - rxq->ring.forward);
	err:
	return ret;
}


static int32_t 	gao_rx_into_grid(struct gao_rx_queue* rxq, struct gao_grid* grid) {
	int32_t ret = 0, num_to_forward, i;


	log_dp("Reading rxq port/q (%u/%u) into grid %hhu", rxq->port_id, rxq->id, grid->header.id);
	spin_lock(&rxq->lock);

	num_to_forward = gao_rx_into_ring(rxq);
	log_debug("Rx ring returned %d to fwd", num_to_forward);
	if(num_to_forward < 1) gao_error_val(-EIO, "rx into ring failed");



	for(i = 0; i < num_to_forward; i++) {
		grid->desc[i] = rxq->ring.desc[rxq->ring.forward & rxq->ring.mask];
		rxq->ring.forward++;
	}
	log_debug("done fwd: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	grid->header.gao_ifindex = rxq->port_id;
	grid->header.queue_idx = rxq->id;
	grid->header.count = num_to_forward;
	ret = 0;
	log_debug("grid ready: id=%hhu count=%u port=%u qid=%u", grid->header.id, grid->header.count, grid->header.gao_ifindex, grid->header.queue_idx);

	err:
	spin_unlock(&rxq->lock);
	resources.ports[rxq->port_id].port_ops->gao_enable_rx_interrupts(rxq);
	return ret;
}





long gao_ioctl_read_grid(struct file *filep) {
	unsigned long irq_flags;
	int32_t ret = 0;
	struct gao_grid* grid = NULL;
	struct gao_rx_queue* rxq = NULL;
	struct gao_file_private* gao_file = filep->private_data;

	if(unlikely(gao_file->grid)) {
		log_error("Already own a grid");
		return -EBUSY;
	}

	read_again:
	log_debug("Polling for grids...");

	spin_lock_irqsave(&resources.waitlist.lock, irq_flags);

	if(resources.waitlist.rxq_cnt) {
		grid = gao_grid_get(&resources.grid_allocator);
		if(unlikely(!grid)) gao_error("No grids left!");

		log_debug("Got grid %hu", grid->header.id);
		rxq = gao_ll_remove(resources.waitlist.rxq_list);
		resources.waitlist.rxq_cnt--;

		if(unlikely(!rxq)) {
			log_bug("Got a null rxq!");
			gao_grid_return(&resources.grid_allocator, grid);
			spin_unlock_irqrestore(&resources.waitlist.lock, irq_flags);
			goto read_again;
		}

		log_debug("Got rxq port/q (%u/%u) (rxq_cnt=%u)", rxq->port_id, rxq->id, resources.waitlist.rxq_cnt);
		ret = gao_rx_into_grid(rxq, grid);


		//Reading into the grid failed, try another one
		if(ret) {
			gao_grid_return(&resources.grid_allocator, grid);
			spin_unlock_irqrestore(&resources.waitlist.lock, irq_flags);
			goto read_again;
		}


	} else {
		//If there are no outstanding queues, go into waiting
		spin_unlock_irqrestore(&resources.waitlist.lock, irq_flags);
		if(wait_event_interruptible(resources.waitlist.rxq_wait, resources.waitlist.rxq_cnt)) {
			goto interrupted;
		} else {
			goto read_again;
		}
	}


	spin_unlock_irqrestore(&resources.waitlist.lock, irq_flags);
	log_debug("Got grid id %u", grid->header.id);
	gao_file->grid = grid;
	return grid->header.id;

	err:
	spin_unlock_irqrestore(&resources.waitlist.lock, irq_flags);
	return -1;

	interrupted:
	return -EINTR;
}

void	gao_rx_interrupt_threshold_handle(int ifindex, uint32_t qid) {
	struct gao_rx_queue *rxq = NULL;

	log_dp("Handling rx threshold interrupt for if/q (%d/%u)", ifindex, qid);

	//Bounds check the indicies. The memory is statically allocated.
	if(unlikely( (((uint32_t)ifindex) > GAO_MAX_IFINDEX) || (qid > GAO_MAX_PORT_HWQUEUE) )) return;

	rxq = resources.ifindex_to_port_lut[((uint32_t)ifindex)]->rx_queues[qid];
	if(unlikely(!rxq)) return;
	if(unlikely(rxq->state != GAO_RESOURCE_STATE_ACTIVE)) return;

	if(spin_trylock(&rxq->lock)) {
		log_dp("Threshold interrupt locked ring");
		gao_rx_into_ring(rxq);
		spin_unlock(&rxq->lock);
	} else {
		log_dp("Threshold interrupt could not lock ring");
	}
}
EXPORT_SYMBOL(gao_rx_interrupt_threshold_handle);

/**
 * Post the rx queue as pending receive
 * @warning Can only be called from HW interrupt context
 * @param ifindex Linux kernel ifindex of the port
 * @param qid The hw queue id of the port
 */
void	gao_rx_interrupt_handle(int ifindex, uint32_t qid) {
	struct gao_rx_queue *rxq = NULL;

	log_dp("Handling rx interrupt for if/q (%d/%u)", ifindex, qid);

	//Bounds check the indicies. The memory is statically allocated.
	if(unlikely( (((uint32_t)ifindex) > GAO_MAX_IFINDEX) || (qid > GAO_MAX_PORT_HWQUEUE) )) return;

	rxq = resources.ifindex_to_port_lut[((uint32_t)ifindex)]->rx_queues[qid];
	if(unlikely(!rxq)) return;
	if(unlikely(rxq->state != GAO_RESOURCE_STATE_ACTIVE)) return;

	spin_lock(&resources.waitlist.lock);

	if(unlikely(gao_ll_push(resources.waitlist.rxq_list, rxq))) {
		log_bug("Overflowed rx waitlist");
	} else {
		resources.waitlist.rxq_cnt++;
		log_dp("Waitlist count is now %u", resources.waitlist.rxq_cnt);
	}

	//There was nothing in the list before, signal any waiters
	if(resources.waitlist.rxq_cnt == 1)
		wake_up_interruptible(&resources.waitlist.rxq_wait);

	resources.ifindex_to_port_lut[((uint32_t)ifindex)]->port_ops->gao_disable_rx_interrupts(rxq);

	spin_unlock(&resources.waitlist.lock);
	return;
}
EXPORT_SYMBOL(gao_rx_interrupt_handle);





/**
 *
 * Command:
 *	GAO_IOCTL_COMMAND_GET_MMAP_SIZE:
 *		Return the size of the mmap area.
 *		Arg: Null
 *		Ret: Size of MMAP area in bytes, negative on error.
 * 	GAO_IOCTL_COMMAND_CREATE_QUEUE:
 * 		Create a queue for userspace.
 * 		Arg: Size of queue in descriptor blocks.
 * 		Ret: Positive or zero index of queue, or negative error code.
 * 	GAO_IOCTL_COMMAND_DELETE_QUEUE:
 * 		Delete a queue at the specified index.
 * 		Arg: Index of queue to delete.
 * 		Ret: 0 on success, negative on error.
 * 	GAO_IOCTL_COMMAND_DUMP_DESCRIPTORS:
 * 		Force the module to dump the descriptor group status to the kernel log.
 * 		Arg: Null
 * 		Ret: 0
 * @param filep
 * @param command
 * @param argument
 */
long gao_ioctl (struct file *filep, unsigned int command, unsigned long argument_ptr) {
	long ret = 0;

	gao_lock_file(filep->private_data);
	log_dp("IOCTL: Got an ioctl with %u command and %lx arg", command, argument_ptr);

	switch(command) {
	case GAO_IOCTL_READ_GRID:
		ret = gao_ioctl_read_grid(filep);
		break;
	case GAO_IOCTL_COMMAND_GET_MMAP_SIZE:
		ret = gao_ioctl_handle_mmap(filep, argument_ptr);
		break;

	case GAO_IOCTL_COMMAND_PORT:
		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
		ret = gao_ioctl_handle_port(filep, argument_ptr);
		break;

	default:
		gao_error_val(-EINVAL, "IOCTL: Unsupported IOCTL command: %u", command);
		break;
	}

	err:
	gao_unlock_file(filep->private_data);
	return ret;
}


static struct file_operations gao_fops = {
	.owner	 = THIS_MODULE,
	.mmap	 = gao_mmap,
	.open	 = gao_open,
	.release = gao_release,
	.unlocked_ioctl = gao_ioctl,
};



static struct miscdevice gao_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "gaommio",
	.fops	= &gao_fops,
};




static void __exit gao_mmio_exit(void)
{
	gao_free_resources(&resources);
	misc_deregister(&gao_miscdev);

	log_info("Removing GAOMMIO.");
    return;
}


static int __init gao_mmio_init(void) {
	int64_t ret = 0;
	log_info("Starting GAOMMIO.");


	ret = misc_register(&gao_miscdev);
	if(ret) gao_error("Failed to register device.");


	ret = gao_init_resources(&resources);

	if(ret) log_error("Failed to initialize gaommio.");

    log_debug("GAOMMIO registered to Major: 10 Minor: %i Name: /dev/%s.", gao_miscdev.minor, gao_miscdev.name);

    return 0;
    err:
    return -1;
}

module_init(gao_mmio_init);
module_exit(gao_mmio_exit);
MODULE_LICENSE("GPL");
