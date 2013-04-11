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
#include <net/ip_fib.h>
#include "gao_mmio_resource.h"


struct gao_resources gao_global_resources;
EXPORT_SYMBOL(gao_global_resources);





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
			grid_addr = gao_global_resources.grid_allocator.grids[i];

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

		if(requested_length != gao_global_resources.buffer_space_frame) {
			gao_error_val(-EINVAL,  "Userspace requested invalid mmap size: %lu, can only map: %lu",
					(unsigned long)requested_length, gao_global_resources.buffer_space_frame);
		}

		//Walk the space frame, and map allocated buffer groups, if unallocated map the dummy frame
		for(buffer_offset = 0; buffer_offset < (gao_global_resources.buffer_space_frame); buffer_offset += GAO_BUFFER_SIZE) {
			//log_debug("Lookup: base_offset=%lx", group_offset);

			//Is that a valid buffer group? This really kills performance, but it only needs to be done once.
			for(buffer_addr = 0, index = 0; index < GAO_BUFFERS; index++) {
				base_addr = (virt_to_phys(gao_global_resources.buffers[index]) - gao_global_resources.buffer_start_phys);
				if(base_addr == buffer_offset) {
					buffer_addr = virt_to_phys(gao_global_resources.buffers[index]);
					//log_debug("Found buffer group at index %d, phys=%lx, base=%lx", index, (unsigned long)virt_to_phys(resources.buffer_groups[index]), base_addr);
					break;
				}
			}

			//Nope, map the dummy group
			if(!buffer_addr) {
				buffer_addr = virt_to_phys(gao_global_resources.dummy_buffer);
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

	request->bufferspace_size = gao_global_resources.buffer_space_frame;
	request->gridspace_size = sizeof(struct gao_grid)*GAO_GRIDS;
	request->offset = gao_global_resources.buffer_start_phys;
	log_debug("IOCTL: Get MMAP request returns bufferspace_size=%lx gridspace_size=%lx offset=%lx",
			request->bufferspace_size, request->gridspace_size, request->offset);

	ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_mmap));
	if(ret) gao_error("Copy to user failed.");

	err:
	return ret;
}

void gao_tx_interrupt_handle(int ifindex) {
	struct gao_tx_queue *txq = NULL;
	struct gao_port *port = NULL;
	uint32_t num_to_xmit;

	log_dp("Handling tx interrupt for if/q (%d/%u)", ifindex, 0);

	rcu_read_lock();

	txq = gao_rcu_get_txq_ifindex(ifindex, 0);
	if(unlikely(!txq)) goto done;

	port = gao_ifindex_to_port(ifindex);
	if(unlikely(!port)) goto done;

	if(spin_trylock(&txq->lock)) {

		num_to_xmit = (txq->ring.avail - txq->ring.use);
		port->port_ops->gao_xmit(&txq->ring, num_to_xmit, txq->hw_private);

		spin_unlock(&txq->lock);
	}

	done:
	rcu_read_unlock();
}
EXPORT_SYMBOL(gao_tx_interrupt_handle);

static void gao_schedule_port(uint8_t port_id) {
	struct gao_tx_queue* txq = NULL;
	uint32_t	num_to_xmit;

	txq = gao_global_resources.ports[port_id].tx_queues[0];
	if(!txq) gao_error("Null sched port!");


	if( (txq->ring.clean - txq->ring.forward) > (txq->ring.capacity/2) )
		gao_return_descriptors(&gao_global_resources.descriptor_allocator, &txq->ring);


	spin_lock(&txq->lock);
	num_to_xmit = (txq->ring.avail - txq->ring.use);
	gao_global_resources.ports[port_id].port_ops->gao_xmit(&txq->ring, num_to_xmit, txq->hw_private);
	spin_unlock(&txq->lock);


	err:
	return;
}

static inline struct gao_grid* gao_fabric_get_grid(struct gao_fabric *fabric) {
	struct gao_grid* grid = NULL;
	spin_lock_bh(&fabric->lock);
	//If there are any left, get the next grid
	if((fabric->avail != fabric->use)) {
		grid = fabric->grids[fabric->use & (GAO_GRIDS-1)];
		fabric->use++;
	}
	spin_unlock_bh(&fabric->lock);
	return grid;
}

void	gao_fabric_task(unsigned long data) {
	struct gao_fabric *fabric = (struct gao_fabric*)data;
	struct gao_grid	  *grid;
	struct gao_action action;
	struct gao_descriptor_ring *ring = fabric->free_desc;
	struct gao_tx_queue *txq = NULL;
	uint32_t	i, drops, fwds;
	uint64_t	ports_to_sched = 0, next_port;
	log_debug("Entering fabric tasklet");


	while((grid = gao_fabric_get_grid(fabric))) {
		drops = 0, fwds = 0;

		log_debug("fabric [%hhu]: start grid processing", grid->header.id);

		//just empty it for now
		for(i = 0; i < grid->header.count; i++) {
			action = grid->actions[i];

			switch(action.action_id) {
			case GAO_ACTION_FWD:

				if((unlikely(action.fwd.dport > GAO_MAX_PORTS))) break;
				txq = gao_global_resources.ports[action.fwd.dport].tx_queues[0];
				if(unlikely(!txq)) break;

				//no room left
				if( (txq->ring.avail - txq->ring.forward) >= txq->ring.capacity ) break;

				txq->ring.desc[txq->ring.avail & txq->ring.mask] = grid->desc[i];
				log_dp("fabric [%hhu/%u]: fwd idx %u to dport %hhu (avail=%u forward=%u)", grid->header.id, i,
						grid->desc[i].index, action.fwd.dport, txq->ring.avail, txq->ring.forward);
				txq->ring.avail++;

				ports_to_sched |= (((unsigned long)1) << action.fwd.dport);

				continue;
			case GAO_ACTION_DROP:
			default:
				break;
			}

			log_dp("fabric [%hhu/%u]: drop", grid->header.id, i);
			drops++;
			ring->desc[ring->avail & ring->mask] = grid->desc[i];
			ring->avail++;
		}


		if(drops) {
			log_debug("Returning %u drops", drops);
			gao_empty_descriptors(&gao_global_resources.descriptor_allocator, ring);
		}

		grid->header.count = 0;
		gao_grid_return(&gao_global_resources.grid_allocator, grid);
	}

	log_debug("fabric: need to sched portmap: %016llx", ports_to_sched);
	for(next_port = GAO_FFSL(ports_to_sched); next_port; next_port = GAO_FFSL(ports_to_sched)) {
		next_port--; //Rewind it by 1 to get the 0-index
		log_debug("fabric: schedule port id %llu", next_port);

		gao_schedule_port(next_port);

		ports_to_sched &= ~(((unsigned long)1) << next_port);
	}



	log_debug("Exiting fabric tasklet");
}


/**
 * Send a grid to the fabric for forwarding
 * @warning Transfers ownership of grid to the fabric
 * @param fabric
 * @param grid
 */
static inline void	gao_forward_grid(struct gao_fabric *fabric, struct gao_grid *grid) {
	log_debug("Forwarding grid %hu", grid->header.id);

	spin_lock_bh(&fabric->lock);

	fabric->grids[fabric->avail & (GAO_GRIDS-1)] = grid;
	//Kick off a forwarding cycle if there was nothing in the queue.
	if(fabric->avail == fabric->use) tasklet_schedule(&fabric->task);
	fabric->avail++;

	spin_unlock_bh(&fabric->lock);
}

/**
 * Drop all descriptors in the grid.
 * @warning Transfers ownership of grid to the fabric
 * @param fabric
 * @param grid
 */
static inline void gao_drop_grid(struct gao_grid *grid) {
	uint32_t i;
	log_debug("dropping grid %hu", grid->header.id);

	for(i = 0; i < grid->header.count; i++) {
		grid->actions[i].action_id = GAO_ACTION_DROP;
	}

	gao_forward_grid(&gao_global_resources.fabric, grid);
}



//static inline void gao_add_pending_rx_queue(struct gao_rx_queue* rxq) {
//	unsigned long	flags = 0;
//
//	spin_lock_irqsave(&gao_global_resources.waitlist.lock, flags);
//
//	if(!rxq->pending_read) {
//		rxq->pending_read = 1;
//		if(unlikely(gao_ll_push(gao_global_resources.waitlist.rxq_list, rxq))) {
//			log_bug("Overflowed rx waitlist");
//		} else {
//			if(gao_global_resources.waitlist.is_blocking) {
//				gao_global_resources.waitlist.is_blocking = 0;
//				wake_up_interruptible(&gao_global_resources.waitlist.rxq_wait);
//				log_dp("Woke the rx wakelist");
//			}
//		}
//	}
//
//	spin_unlock_irqrestore(&gao_global_resources.waitlist.lock, flags);
//}



/**
 *
 * @param rxq
 * @return The number of frames in the queue's grid
 */
static inline int32_t gao_rx_clean_ring(struct gao_rx_queue* rxq) {
	int32_t	num_read, num_cleaned;
	struct gao_grid *grid = rxq->grid;

	log_debug("start recv: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);
	//Recv from clean to use
	num_read = gao_global_resources.ports[rxq->port_id].port_ops->gao_recv(&rxq->ring, (rxq->ring.use - rxq->ring.clean), rxq->hw_private);
	if(num_read > 0) rxq->ring.clean += num_read;
	log_debug("done recv: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	//Clean from use to avail
	num_cleaned = gao_global_resources.ports[rxq->port_id].port_ops->gao_clean(&rxq->ring, (rxq->ring.avail - rxq->ring.use), rxq->hw_private);
	if(num_cleaned > 0) rxq->ring.use += num_cleaned;

	log_debug("done clean: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	//Put the descriptors into the grid
	while((rxq->ring.forward < rxq->ring.clean) && (grid->header.count < GAO_GRID_SIZE)) {
		grid->desc[grid->header.count] = rxq->ring.desc[rxq->ring.forward & rxq->ring.mask];
		grid->header.count++, rxq->ring.forward++;
	}
	log_debug("done rx to grid: fwd=%u clean=%u use=%u avail=%u grid_count=%hu", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail, grid->header.count);

	if(rxq->ring.capacity - (rxq->ring.avail - rxq->ring.forward))
		gao_refill_descriptors(&gao_global_resources.descriptor_allocator, &rxq->ring);

	log_debug("done refill: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, rxq->ring.clean, rxq->ring.use, rxq->ring.avail);

	return grid->header.count;
}

/**
 * Receive new descriptors from the NIC and refill empty descriptor slots.
 * @warning Called from interrupt context
 * @warning HW owns clean and use, SW owns avail and forward
 * @param rxq
 * @return Negative on error,
 *
 */
static inline int32_t	gao_rx_into_ring(struct gao_rx_queue* rxq) {
	int32_t	num_read, num_cleaned;
	uint32_t forward = ACCESS_ONCE(rxq->ring.forward), avail = ACCESS_ONCE(rxq->ring.avail);

	log_debug("start recv: fwd=%u clean=%u use=%u avail=%u", forward, rxq->ring.clean, rxq->ring.use, avail);
	//Recv from clean to use
	num_read = gao_global_resources.ports[rxq->port_id].port_ops->gao_recv(&rxq->ring, (rxq->ring.use - rxq->ring.clean), rxq->hw_private);
	if(num_read > 0) rxq->ring.clean += num_read;
	log_debug("done recv: fwd=%u clean=%u use=%u avail=%u", forward, rxq->ring.clean, rxq->ring.use, avail);

	//Clean from use to avail
	num_cleaned = gao_global_resources.ports[rxq->port_id].port_ops->gao_clean(&rxq->ring, (avail - rxq->ring.use), rxq->hw_private);
	if(num_cleaned > 0) rxq->ring.use += num_cleaned;


	if(unlikely((avail - rxq->ring.use) == 0)) {
		log_warn("rxq is starving!");
		atomic_set(&rxq->starving, 1);
	} else {
		gao_global_resources.ports[rxq->port_id].port_ops->gao_enable_rx_intr(rxq);
	}

	log_debug("done clean: fwd=%u clean=%u use=%u avail=%u", forward, rxq->ring.clean, rxq->ring.use, avail);




	return 0;
}

/**
 * @warning Called from user context
 * @warning HW owns clean and use, SW owns avail and forward
 * @param rxq
 * @param grid
 * @return
 */
static inline int32_t 	gao_rx_into_grid(struct gao_rx_queue *rxq, struct gao_grid **grid) {
	struct gao_grid *tmp_grid = *grid;

	spin_lock_bh(&rxq->lock);

	*grid = rxq->grid;
	rxq->grid = tmp_grid;

	spin_unlock_bh(&rxq->lock);

	return 0;
}
//static inline int32_t 	gao_rx_into_grid(struct gao_rx_queue* rxq, struct gao_grid* grid) {
//	int32_t ret = 0, num_to_forward, i;
//	uint32_t use = ACCESS_ONCE(rxq->ring.use), clean = ACCESS_ONCE(rxq->ring.clean);
//
//	log_dp("rx to grid start: port/q (%u/%u) into grid %hhu", rxq->port_id, rxq->id, grid->header.id);
//	//spin_lock(&rxq->lock);
//
//	num_to_forward = (clean - rxq->ring.forward);
//
//	log_debug("rx to grid: fwd=%u clean=%u use=%u avail=%u num_to_forward=%u",
//			rxq->ring.forward, clean, use, rxq->ring.avail, num_to_forward);
//
//	if(!num_to_forward) {
//		return -EAGAIN;
//		//gao_bug_val(-EAGAIN, "rx into grid got no pkts");
//	}
//
//
//	//Put the descriptors into the grid
//	for(i = 0; i < num_to_forward; i++) {
//		grid->desc[i] = rxq->ring.desc[rxq->ring.forward & rxq->ring.mask];
//		rxq->ring.forward++;
//	}
//	log_debug("rx to grid: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, clean, use, rxq->ring.avail);
//
//	//Refill the ring's descriptors for rxq cleaning
//	if((rxq->ring.avail - rxq->ring.forward) < rxq->ring.capacity) {
//		if(unlikely(!gao_refill_descriptors(&gao_global_resources.descriptor_allocator, &rxq->ring))) {
//			log_bug("DESCRIPTOR GOOF: Ran out of descriptors globally");
//			gao_dump_resources();
//		}
//		log_debug("done refill: fwd=%u clean=%u use=%u avail=%u", rxq->ring.forward, clean, use, rxq->ring.avail);
//	}
//
//	//Make sure that any modifications to the queue are seen before checking for starvation
//	barrier();
//	if(atomic_read(&rxq->starving)) {
//		//If the queue previously had no resources, then it has stopped. Give it a jump start.
//		//XXX: If the spinlock is to be removed, there must be a guarantee that the interrupt cannot occur.
//		gao_rx_into_ring(rxq);
//		gao_global_resources.ports[rxq->port_id].port_ops->gao_enable_rx_intr(rxq);
//		atomic_set(&rxq->starving, 0);
//		//FIXME: If we were completely out of descriptors, the queue is still stalled
//		log_warn("rx into grid saved starving queue");
//	}
//
//
//	grid->header.gao_ifindex = rxq->port_id;
//	grid->header.queue_idx = rxq->id;
//	grid->header.count = num_to_forward;
//	log_debug("rx to grid done: id=%hhu count=%u port=%u qid=%u", grid->header.id, grid->header.count, grid->header.gao_ifindex, grid->header.queue_idx);
//
//	return 0;
//}



long gao_ioctl_send_grid(struct file *filep) {
	struct gao_file_private* gao_file = filep->private_data;

	if(unlikely(!gao_file->grid)) {
		log_error("Don't have a grid");
		return -EINVAL;
	}

	gao_forward_grid(&gao_global_resources.fabric, gao_file->grid);
	gao_file->grid = NULL;

	return 0;
}



long gao_ioctl_recv_grid(struct file *filep) {
	int32_t ret = 0;
	struct gao_grid* grid = NULL;
	struct gao_rx_queue* rxq = NULL;
	struct gao_hw_queue hwq;
	struct gao_file_private* gao_file = filep->private_data;

	if(unlikely(gao_file->grid)) gao_error_val(-EBUSY, "recv grid: already own a grid");

	grid = gao_grid_get(&gao_global_resources.grid_allocator);
	if(unlikely(!grid)) gao_error_val(-ENOMEM,"recv grid: no grids left!");


	read_again:
	log_debug("recv grid: polling for rx queue...");

	ret = gao_queue_set_get(&gao_global_resources.rx_waitlist, &hwq);

	if(unlikely(ret)) {
		gao_grid_return(&gao_global_resources.grid_allocator, grid);
		gao_error_val(-EINTR, "read interrupted or failed");
	}

	rcu_read_lock();
	rxq = gao_rcu_get_rxq(hwq.port_id, hwq.id);

	if(!rxq) {
		rcu_read_unlock();
		log_bug("got null queue on read");
		goto read_again;
	}

	log_debug("Got rxq port/q (%u/%u)", rxq->port_id, rxq->id);
	ret = gao_rx_into_grid(rxq, &grid);
	rcu_read_unlock();

	if(ret) {
		log_debug("reading into grid failed: ret=%d", ret);
		goto read_again;
	}
	log_debug("recv grid: %u pkts into grid id %u", grid->header.count, grid->header.id);


	gao_file->grid = grid;
	return grid->header.id;
	err:
	return ret;
}




void	gao_rx_clean(int ifindex, uint32_t qid) {
	struct gao_rx_queue *rxq = NULL;

	log_dp("Handling rx clean for if/q (%d/%u)", ifindex, qid);

	rcu_read_lock();
	rxq = gao_rcu_get_rxq_ifindex(ifindex, qid);

	if(unlikely(!rxq)) {
		rcu_read_unlock();
		log_debug("rx clean found null queue");
		return;
	}

	if(gao_rx_clean_ring(rxq))
		gao_queue_set_add(&gao_global_resources.rx_waitlist, rxq->port_id, rxq->id);

	rcu_read_unlock();
	return;
}
EXPORT_SYMBOL(gao_rx_clean);

/**
 * Post the rx queue as pending receive
 * @warning Can only be called from HW interrupt context
 * @param ifindex Linux kernel ifindex of the port
 * @param qid The hw queue id of the port
 */
void	gao_rx_interrupt_handle(int ifindex, uint32_t qid) {
	struct gao_rx_queue *rxq = NULL;

	log_dp("Handling rx interrupt for if/q (%d/%u)", ifindex, qid);

	rcu_read_lock();
	rxq = gao_rcu_get_rxq_ifindex(ifindex, qid);

	if(!rxq) {
		rcu_read_unlock();
		log_debug("intr found null queue");
		return;
	}

	gao_global_resources.ports[rxq->port_id].port_ops->gao_disable_rx_intr(rxq);

//	if(spin_trylock(&rxq->lock)) {
//		gao_rx_into_ring(rxq);
//		spin_unlock(&rxq->lock);
//	}

	if(!atomic_read(&rxq->starving)) {
		gao_rx_into_ring(rxq);
	} else {
		log_bug("rx intr during starvation");
	}

	gao_queue_set_add(&gao_global_resources.rx_waitlist, rxq->port_id, rxq->id);

	rcu_read_unlock();

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
	case GAO_IOCTL_RECV_GRID:
		ret = gao_ioctl_recv_grid(filep);
		break;
	case GAO_IOCTL_SEND_GRID:
		ret = gao_ioctl_send_grid(filep);
		break;
	case GAO_IOCTL_EXCH_GRID:
		gao_ioctl_send_grid(filep);
		ret = gao_ioctl_recv_grid(filep);
		break;
	case GAO_IOCTL_COMMAND_GET_MMAP_SIZE:
		ret = gao_ioctl_handle_mmap(filep, argument_ptr);
		break;

	case GAO_IOCTL_COMMAND_PORT:
		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
		ret = gao_ioctl_handle_port(filep, argument_ptr);
		break;

	case GAO_IOCTL_DUMP_RESC:
		gao_dump_resources();
		break;

	default:
		gao_error_val(-EINVAL, "IOCTL: Unsupported IOCTL command: %u", command);
		break;
	}

	err:
	gao_unlock_file(filep->private_data);
	return ret;
}

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

	if(gao_file->grid) {
		gao_drop_grid(gao_file->grid);
	}

	//If we were bound to anything, remove the binding. If the queue was deleting,
	//and we were the last reference, delete the queue.
	kfree(filep->private_data);

	return 0;
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
	gao_free_resources(&gao_global_resources);
	misc_deregister(&gao_miscdev);

	log_info("Removing GAOMMIO.");
    return;
}


static int __init gao_mmio_init(void) {
	int64_t ret = 0;
	log_info("Starting GAOMMIO.");


	ret = misc_register(&gao_miscdev);
	if(ret) gao_error("Failed to register device.");


	ret = gao_init_resources(&gao_global_resources);
	if(ret) log_error("Failed to initialize gaommio.");
	gao_dump_resources();

    log_debug("GAOMMIO registered to Major: 10 Minor: %i Name: /dev/%s.", gao_miscdev.minor, gao_miscdev.name);

    return 0;
    err:
    return -1;
}

module_init(gao_mmio_init);
module_exit(gao_mmio_exit);
MODULE_LICENSE("GPL");
