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


	filep->private_data = gao_file;
	return 0;
	err:
	return ret;
}

static int gao_release(struct inode *inode, struct file *filep) {
	log_debug("Release file for filep %p", filep);

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
				ret = vm_insert_page(vma, vm_addr + (page_index*GAO_SMALLPAGE_SIZE), pfn_to_page(pfn));
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

			if(ret) gao_error("Failed to MMAP queue page to userspace: %d (offset %lx)", ret, buffer_offset);
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



/**
 * Kick off scheduling on all ports in the bitmap. If scheduling is already in progress,
 * the port will be skipped. The port queues are chosen to be scheduled wrt the sport/queue.
 * @param ports_to_schedule A bitmap of ports to schedule. The LSB is port index 1.
 * @param sport The originating source port that is starting the scheduling.
 * @param squeue
 */
//static void	gao_schedule_ports(uint64_t ports_to_schedule, uint64_t sport, uint64_t squeue) {
//	uint64_t	next_port = GAO_FFSL(ports_to_schedule);
//	for(;next_port;next_port = GAO_FFSL(ports_to_schedule)){
//		if(unlikely(resources.ports[next_port].state == GAO_RESOURCE_STATE_UNUSED)) continue;
//		resources.ports[next_port].port_scheduler(resources.ports[next_port].tx_queues[squeue]);
//	}
//
//}


//static void	gao_forward_frames(struct gao_rx_queue* queue) {
//	//struct gao_descriptor_ring	*dest_queue = NULL;
//	struct gao_descriptor 	descriptor;
//	struct gao_action 		*action = NULL;
//	struct gao_descriptor_subring *dest_queue = NULL;
//	uint32_t	i, num_to_forward = queue->full_descriptors.count;
//	uint64_t	ports_forwarded_to = 0;
//
//
//	log_dp("start fwd: left=%u", num_to_forward);
//
//	//Main action apply loop
//	for(i = 0; i < num_to_forward; i++) {
//
//		action = &queue->actions[i];
//		descriptor = queue->full_descriptors.descriptors[i];
//
//
//
//		switch(action->action_id) {
//
//		case GAO_ACTION_DROP:
//			log_dp("fwd drop: action_id is drop, refill empty to size=%u", queue->empty_descriptors.count);
//			goto drop;
//
//		case GAO_ACTION_FWD:
//			dest_queue = queue->queue_map.port[action->fwd.dport].ring[action->fwd.dqueue];
//
//			if(unlikely(!dest_queue)) {
//				log_dp("fwd drop: null dest queue, refill empty to size=%u", queue->empty_descriptors.count);
//				goto drop;
//			}
//
//			gao_lock_subqueue(dest_queue);
//
//
//			if(!gao_ring_slots_left(dest_queue)) {
//				log_error("fwd drop: no slots left");
//				gao_unlock_subqueue(dest_queue);
//				goto drop;
//			}
//
//			queue->full_descriptors.descriptors[i].offset = action->new_offset;
//			queue->full_descriptors.descriptors[i].len = action->new_len;
//
//			//swap_descriptors(&descriptors[index], &dest_queue->descriptors[dest_queue->header.tail]);
//			dest_queue->descriptors[dest_queue->header.tail] = queue->full_descriptors.descriptors[i];
//			dest_queue->header.tail = (dest_queue->header.tail+1) & (dest_queue->header.capacity-1);
//
//			//Wake the endpoint
//			set_bit(action->fwd.dqueue, (unsigned long*)dest_queue->control.tail_wake_condition_ref);
//			//Ports start at index 1, the bitfield is 1-indexed.
//			ports_forwarded_to |= (1 << (action->fwd.dport-1));
//
//			log_dp("fwd: index=%u port=%hhu queue=%hhu desc_index=%u new dest_tail=%llu",
//					i, action->fwd.dport, action->fwd.dqueue, queue->full_descriptors.descriptors[i].index, dest_queue->header.tail);
//
//			gao_unlock_subqueue(dest_queue);
//			break;
//
//		default:
//			log_bug("fwd drop: invalid action=%#04hhx, refill empty to size=%u", action->action_id, queue->empty_descriptors.count);
//			goto drop;
//
//		continue;
//		drop:
//		//Put the descriptor back in the empty list
//		queue->empty_descriptors.descriptors[queue->empty_descriptors.count++] = descriptor;
//		}
//	}
//
//	gao_schedule_ports(ports_forwarded_to, queue->binding.port->gao_ifindex, queue->index);
//
//	queue->full_descriptors.count = 0;
//}

//long	gao_sync_queue_old(struct file *filep) {
//	ssize_t 				ret = 0;
//	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
//	struct gao_queue 		*queue = NULL;
//	struct gao_descriptor 	*descriptors = NULL;
//	uint64_t				size, num_to_forward , last_head, new_head;
//
//	rcu_read_lock();
//
//	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//	queue = file_private->bound_queue;
//
//	if(unlikely(!queue))
//		gao_error_val(-EIO, "Reading null queue");
//
//	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//
//
//	num_to_forward = gao_ring_slots_left(queue->ring);
//	gao_forward_frames(queue, num_to_forward);
//	file_private->port_ops->gao_clean(queue, num_to_forward);
//
//
//	read_again:
//
//	//We will save the current head -- if packets are read the new head will be the end of the read packets.
//	last_head = queue->ring->header.head;
//	size = queue->ring->header.capacity;
//	descriptors = (struct gao_descriptor*)&queue->ring->descriptors;
//	ret = file_private->port_ops->gao_recv(queue, size);
//
//
//
//	if(unlikely(ret < 0)) gao_error("Error while reading fd %p", filep);
//	//Got something
//	if(ret > 0) {
//
//		new_head = queue->ring->header.head;
//		log_dp("Got %ld descriptors, copying to userspace. last_head=%lu new_head=%lu",
//						ret, (	unsigned long)last_head, (unsigned long)new_head);
//
//		//Copy the ring descriptors to the linear buffer in the right order
//		if( new_head >= last_head) {
//			memcpy( ((void*)queue->descriptor_pipeline), (void*)&descriptors[last_head], (new_head - last_head)*sizeof(struct gao_descriptor) );
//		}else{
//			memcpy( ((void*)queue->descriptor_pipeline), (void*)&descriptors[last_head], (size - last_head)*sizeof(struct gao_descriptor));
//			memcpy( ((void*)queue->descriptor_pipeline) + ((size - last_head)*sizeof(struct gao_descriptor)) , (void*)&descriptors[0], new_head*sizeof(struct gao_descriptor));
//		}
//
//	}else{ //Didn't read anything, block
//		rcu_read_unlock();
//		atomic_long_set(queue->ring->control.head_wake_condition_ref, 0);
//		file_private->port_ops->gao_enable_rx_interrupts(queue);
//		if(wait_event_interruptible(queue->ring->control.head_wait_queue, atomic_long_read(&queue->ring->control.head_wake_condition) )) {
//			ret = -EINTR;
//			log_debug("Read on %p interrupted", filep);
//			goto interrupted;
//		}
//
//		rcu_read_lock();
//		//Check the states again to make sure the queue is still valid.
//		if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
//			gao_error_val(-EIO, "Cannot read from inactive queue");
//
//		if(unlikely(!queue))
//			gao_error_val(-EIO, "Reading null queue");
//
//		if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
//			gao_error_val(-EIO, "Cannot read from inactive queue");
//
//		file_private->port_ops->gao_disable_rx_interrupts(queue);
//		goto read_again;
//	}
//
//
//
//	err:
//	rcu_read_unlock();
//	interrupted:
//	return ret;
//}


//long	gao_sync_queue(struct file *filep) {
//	int64_t 				ret = 0;
//	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
//	struct gao_rx_queue 	*queue = NULL;
//	int32_t					total_rx;
//
//	rcu_read_lock();
//
//	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//	queue = rcu_dereference(file_private->bound_queue);
//
//	if(unlikely(!queue))
//		gao_error_val(-EIO, "Reading null queue");
//
//	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//
//	prefetch(((void*)&resources.descriptor_ring) + (64*0));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*0));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*1));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*2));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*3));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*4));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*5));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*6));
//	prefetch(((void*)queue->empty_descriptors.descriptors) + (64*7));
//	prefetch(((void*)queue->full_descriptors.descriptors) + (64*0));
//	prefetch(((void*)queue->full_descriptors.descriptors) + (64*1));
//	prefetch(((void*)queue->full_descriptors.descriptors) + (64*2));
//	prefetch(((void*)queue->full_descriptors.descriptors) + (64*3));
//	prefetch(((void*)queue->full_descriptors.descriptors) + (64*0));
//	prefetch(((void*)queue->actions) + (64*0));
//	prefetch(((void*)queue->actions) + (64*1));
//	prefetch(((void*)queue->actions) + (64*2));
//	prefetch(((void*)queue->actions) + (64*3));
//	prefetch(((void*)queue->shadow_ring) + (64*0));
//	prefetch(((void*)queue->shadow_ring) + (64*1));
//	prefetch(((void*)queue->shadow_ring) + (64*2));
//	prefetch(((void*)queue->shadow_ring) + (64*3));
//	prefetch(((void*)&resources.descriptor_ring.descriptors[resources.descriptor_ring.head]) + (64*0));
//	prefetch(((void*)&resources.descriptor_ring.descriptors[resources.descriptor_ring.head]) + (64*1));
//	prefetch(((void*)&resources.descriptor_ring.descriptors[resources.descriptor_ring.head]) + (64*2));
//	prefetch(((void*)&resources.descriptor_ring.descriptors[resources.descriptor_ring.head]) + (64*3));
//
//	gao_forward_frames(queue);
//	//file_private->port_ops->gao_clean(queue, num_to_forward);
//
//
//	read_again:
//	//Rx
//	log_dp("rx recv: descriptors full size=%u capacity=%u", queue->full_descriptors.count, queue->full_descriptors.capacity);
//	total_rx = file_private->port_ops->gao_recv(&queue->full_descriptors, queue->shadow_ring, queue->full_descriptors.capacity - queue->full_descriptors.count, queue->hw_private);
//	if(unlikely(total_rx < 0)) gao_error_val(-EIO, "Error while reading fd %p", filep);
//
//
//	//Clean
//	if(queue->empty_descriptors.count < queue->descriptors) {
//		log_dp("rx clean: refill descriptors empty size=%u capacity=%u", queue->empty_descriptors.count, queue->empty_descriptors.capacity);
//		gao_refill_descriptors(&resources.descriptor_ring, &queue->empty_descriptors);
//		log_dp("rx clean: refilled descriptors empty size=%u capacity=%u", queue->empty_descriptors.count, queue->empty_descriptors.capacity);
//	}
//
//
//	if(queue->empty_descriptors.count > 0) {
//		file_private->port_ops->gao_clean(&queue->empty_descriptors, queue->shadow_ring, queue->empty_descriptors.count, queue->hw_private);
//	}
//
//
//
//	if(queue->full_descriptors.count > 0) {
//		//If we have outstanding descriptors, return the amount
//		log_dp("rx done: descriptors full size=%u capacity=%u", queue->full_descriptors.count, queue->full_descriptors.capacity);
//		rcu_read_unlock();
//		return queue->full_descriptors.count;
//	}
//	else if(queue->empty_descriptors.count > 0) {
//		//If there are no rx'd frames, but we have descriptors block on rx interrupt
//		atomic_long_set(&queue->wake_cond, 0);
//		file_private->port_ops->gao_enable_rx_interrupts(queue);
//		if( wait_event_interruptible(queue->wait_queue, atomic_long_read(&queue->wake_cond) )) {
//			ret = -EINTR;
//			log_debug("Read on %p interrupted", filep);
//			goto interrupted;
//		}
//
//	}
//	else {
//		//We are starving -- no descriptors left to receive! Block on the descriptor ring.
//	}
//
//
//	rcu_read_lock();
//	//Check the states again to make sure the queue is still valid.
//	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//	if(unlikely(!queue))
//		gao_error_val(-EIO, "Reading null queue");
//
//	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
//		gao_error_val(-EIO, "Cannot read from inactive queue");
//
//	file_private->port_ops->gao_disable_rx_interrupts(queue);
//	goto read_again;
//
//
//
//
//
//
//	err:
//	rcu_read_unlock();
//	interrupted:
//	return ret;
//}
















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
//	.read	 = gao_read,
//	.write	 = gao_write,
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
