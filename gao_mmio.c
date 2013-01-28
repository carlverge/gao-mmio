#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE
#undef LINUX
#define LINUX

#include "gao_mmio.h"


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

inline unsigned long descriptor_to_phys_addr(uint64_t descriptor) {
	return GAO_DESC_TO_PHYS(descriptor);
}
EXPORT_SYMBOL(descriptor_to_phys_addr);

inline void* descriptor_to_virt_addr(uint64_t descriptor) {
	return GAO_DESC_TO_VIRT(descriptor);
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


	filep->private_data = gao_file;
	return 0;
	err:
	return ret;
}

static int gao_release(struct inode *inode, struct file *filep) {
	log_debug("Release file for filep %p", filep);

	//If we were bound to anything, remove the binding. If the queue was deleting,
	//and we were the last reference, delete the queue.
	gao_unbind_queue(filep);

	kfree(filep->private_data);



	return 0;
}



int gao_mmap(struct file* filep, struct vm_area_struct* vma) {
	uint64_t 	requested_length = vma->vm_end - vma->vm_start;
	struct gao_file_private	*gao_file = filep->private_data;
	struct gao_queue 		*queue = NULL;
	unsigned long vm_addr, pfn, group_offset, group_addr, base_addr;
	void*					queue_vm_addr;

	//uint64_t 	buffer_length = ((uint64_t)GAO_BUFFER_GROUP_SIZE*(uint64_t)GAO_MAX_BUFFER_GROUPS);
	int ret, index; //XXX: These should probably be int64_t ...

	if(gao_file->bound_queue) {

		log_debug("mmap: queue request for length %llu", requested_length);
		queue = gao_file->bound_queue;

		if(requested_length != (queue->descriptor_pipeline_size + queue->action_pipeline_size)) {
			gao_error_val(-EINVAL,  "Userspace requested invalid mmap size: %llu, can only map: %llu",
								requested_length, (queue->descriptor_pipeline_size + queue->action_pipeline_size));
		}

		vm_addr = vma->vm_start;

		log_debug("Mapping descriptor pipeline.");
		queue_vm_addr = queue->descriptor_pipeline;
		while(queue_vm_addr < (((void*)queue->descriptor_pipeline) + queue->descriptor_pipeline_size)) {
			pfn = vmalloc_to_pfn(queue_vm_addr);
			ret = remap_pfn_range(vma, vm_addr, pfn, PAGE_SIZE, vma->vm_page_prot);
			if(ret) gao_error("Failed to MMAP queue page to userspace: %d (addr %p)", ret, queue_vm_addr);

			queue_vm_addr += PAGE_SIZE;
			vm_addr += PAGE_SIZE;
		}

		log_debug("Mapping action pipeline.");
		queue_vm_addr = queue->action_pipeline;
		while(queue_vm_addr < (((void*)queue->action_pipeline) + queue->action_pipeline_size)) {
			pfn = vmalloc_to_pfn(queue_vm_addr);
			ret = remap_pfn_range(vma, vm_addr, pfn, PAGE_SIZE, vma->vm_page_prot);
			if(ret) gao_error("Failed to MMAP queue page to userspace: %d (addr %p)", ret, queue_vm_addr);

			queue_vm_addr += PAGE_SIZE;
			vm_addr += PAGE_SIZE;
		}


	} else {

		log_debug("mmap: buffer request for length %llu base addr %lx", requested_length, vma->vm_start);

		if(requested_length != resources.buffer_space_frame) {
			gao_error_val(-EINVAL,  "Userspace requested invalid mmap size: %lu, can only map: %lu",
					(unsigned long)requested_length, resources.buffer_space_frame);
		}

		//Walk the space frame, and map allocated buffer groups, if unallocated map the dummy frame
		for(group_offset = 0; group_offset < (resources.buffer_space_frame); group_offset += GAO_BUFFER_GROUP_SIZE) {
			//log_debug("Lookup: base_offset=%lx", group_offset);

			//Is that a valid buffer group?
			for(group_addr = 0, index = 0; index < GAO_BUFFER_GROUPS; index++) {
				base_addr = (virt_to_phys(resources.buffer_groups[index]) - resources.buffer_start_phys);
				if( base_addr == group_offset) {
					group_addr = virt_to_phys(resources.buffer_groups[index]);
					//log_debug("Found buffer group at index %d, phys=%lx, base=%lx", index, (unsigned long)virt_to_phys(resources.buffer_groups[index]), base_addr);
					break;
				}
			}

			//Nope, map the dummy group
			if(!group_addr) {
				group_addr = virt_to_phys(resources.dummy_group);
			}

			vm_addr = vma->vm_start + (group_offset);
			pfn = group_addr >> PAGE_SHIFT;

			log_debug("Mapping: phys=%016lx pfn=%016lx -> vm=%016lx (%s)",
					group_addr, group_addr >> PAGE_SHIFT, vm_addr, (group_addr==virt_to_phys(resources.dummy_group) ? "dummy":"buffer"));
			ret = remap_pfn_range(vma, vm_addr, pfn, GAO_BUFFER_GROUP_SIZE, vma->vm_page_prot);
			if(ret) gao_error("Failed to MMAP queue page to userspace: %d (offset %lx)", ret, group_offset);
		}



	}

	log_debug("MMAP Successful.");

	return 0;
	err:
	return ret;
}

static void gao_ioctl_dump(struct file *filep, gao_request_dump_t type) {
	switch(type) {
	case GAO_REQUEST_DUMP_BUFFERS:
		gao_dump_buffers(&resources);
		break;
	case GAO_REQUEST_DUMP_DESCRIPTORS:
		gao_dump_descriptors(&resources);
		break;
	case GAO_REQUEST_DUMP_PORTS:
		gao_dump_ports(&resources);
		break;
	case GAO_REQUEST_DUMP_PORTS_NESTED:
		gao_dump_ports_nested(&resources);
		break;
	case GAO_REQUEST_DUMP_FILE:
		gao_dump_file(filep);
		break;
	default:
		log_debug("Unknown dump type.");
		break;
	}

}

long gao_ioctl_handle_queue(struct file * filep, unsigned long request_ptr) {
	long ret = 0;
	struct gao_request_queue	*request = NULL;

	request = kmalloc(sizeof(struct gao_request_queue), GFP_KERNEL);
	check_ptr(request);

	ret = copy_from_user(request, (void*) request_ptr, sizeof(struct gao_request_queue));
	if(ret) gao_error("Copy from user failed.");

	switch(request->request_code) {

//	case GAO_REQUEST_QUEUE_CREATE:
//		ret = gao_enable_gao_port(gao_get_resources(), request->gao_ifindex);
//
//		if(ret) request->response_code = GAO_RESPONSE_INTERFACE_NOK;
//		else request->response_code = GAO_RESPONSE_INTERFACE_OK;
//
//		copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_interface));
//		break;
//
//
//	case GAO_REQUEST_QUEUE_DELETE:
//		break;

	case GAO_REQUEST_QUEUE_BIND:
		ret = gao_bind_queue(filep, request);

		if(ret) request->response_code = GAO_RESPONSE_QUEUE_NOK;
		else request->response_code = GAO_RESPONSE_QUEUE_OK;

		ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_queue));
		if(ret) gao_error("Copy to user failed.");

		break;

	case GAO_REQUEST_QUEUE_UNBIND:
		gao_unbind_queue(filep);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	err:
	if(request) kfree_null(request);
	return ret;
}





long gao_ioctl_handle_port(struct file * filep, unsigned long request_ptr) {
	long ret = 0;
	struct gao_request_port	*request = NULL;
	struct gao_request_port_list *list = NULL;

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
		if(!request->port_list) gao_error_val(-EINVAL, "Null port list buffer given for port list request.");

		list = gao_get_port_list(gao_get_resources());
		check_ptr(list);

		request->response_code = GAO_RESPONSE_PORT_OK;
		ret = copy_to_user((void*)request->port_list, (void*)list, sizeof(struct gao_request_port_list));
		gao_free_port_list(list);
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

	request->size = resources.buffer_space_frame;
	request->offset = resources.buffer_start_phys;
	log_debug("IOCTL: Get MMAP request returns size=%lx offset=%lx", request->size, request->offset);
	ret = copy_to_user((void*)request_ptr, request, sizeof(struct gao_request_mmap));
	if(ret) gao_error("Copy to user failed.");

	err:
	return ret;
}



/**
 * Assumptions allowed:
 * 	Queue pointer and HW pointer are valid
 * 	Queue is not being deleted
 * 	It is safe to read the queue until we release RCU lock
 */
ssize_t gao_read_old(struct file *filep, char __user *descriptor_buf, size_t num_to_read, loff_t *offset) {
	ssize_t ret = 0;
	uint64_t last_head, new_head, size;
	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
	struct gao_queue *queue = NULL;
	struct gao_descriptor *descriptors = NULL;

	read_again:

	rcu_read_lock();

	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	queue = file_private->bound_queue;

	if(unlikely(!queue))
		gao_error_val(-EIO, "Reading null queue");

	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	last_head = queue->ring->header.head;
	size = queue->ring->header.capacity;
	descriptors = (struct gao_descriptor*)&queue->ring->descriptors;


	ret = file_private->port_ops->gao_recv(queue, num_to_read);


	//Got something
	if(unlikely(ret < 0)) gao_error("Error while reading fd %p", filep);

	if(ret > 0) {

		new_head = queue->ring->header.head;
		log_dp("Got %ld descriptors, copying to userspace. last_head=%lu new_head=%lu",
						ret, (unsigned long)last_head, (unsigned long)new_head);

		//Copy the ring descriptors to the linear buffer in the right order
		if( new_head >= last_head) {
			copy_to_user( descriptor_buf, &descriptors[last_head], (new_head - last_head)*sizeof(struct gao_descriptor) );
		}else{
			copy_to_user( descriptor_buf, &descriptors[last_head], (size - last_head)*sizeof(struct gao_descriptor));
			copy_to_user( descriptor_buf + ((size - last_head)*sizeof(struct gao_descriptor)) , &descriptors[0], new_head*sizeof(struct gao_descriptor));
		}

	}else{ //Didn't read anything, block
		rcu_read_unlock();
		atomic_long_set(queue->ring->control.head_wake_condition_ref, 0);
		file_private->port_ops->gao_enable_rx_interrupts(queue);
		if(wait_event_interruptible(queue->ring->control.head_wait_queue, atomic_long_read(&queue->ring->control.head_wake_condition) )) {
			ret = -EINTR;
			log_debug("Read on %p interrupted", filep);
			goto interrupted;
		}

		//The queue can't be deleted while there is a file bound to it. If the port is removed,
		//the queue will be cleaned up on fd close (or unbind).
		//But if the port device mod is unloaded then this function pointer becomes invalid...
		if(queue->state == GAO_RESOURCE_STATE_ACTIVE)
			file_private->port_ops->gao_disable_rx_interrupts(queue);

		goto read_again;


	}



	err:
	rcu_read_unlock();
	interrupted:
	return ret;
}

inline static void gao_lock_subqueue(struct gao_descriptor_ring *ring) {
	log_dp("Spinlocking ring");
	spin_lock(&ring->control.tail_lock);
	log_dp("Locked ring");
}

inline static void gao_unlock_subqueue(struct gao_descriptor_ring *ring) {
	log_dp("Unlocking ring");
	spin_unlock(&ring->control.tail_lock);
}



//static log_
//inline static int64_t gao_queue_descriptor()
/**
 * TODO: Marked for deletion
 */
ssize_t gao_write_old(struct file *filep, const char __user *action_buf, size_t num_frames, loff_t *offset) {
	ssize_t ret = 0;
	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
	struct gao_queue *queue = NULL;
	struct gao_descriptor_ring	*dest_queue = NULL;
	struct gao_descriptor (*descriptors)[] = NULL;
	struct gao_action *action = NULL;
	uint64_t	previous_wake_condition;
	uint64_t	frames_to_forward, hwqueue_index, hwqueue_capacity, action_index, frames_same_action = 0;
	uint64_t	round_index = 0, round_max;
	uint64_t	dest_tail, dest_head, dest_capacity, dest_remaining;


	rcu_read_lock();

	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	queue = file_private->bound_queue;

	if(unlikely(!queue))
		gao_error_val(-EIO, "Reading null queue");

	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	descriptors = &queue->ring->descriptors;

	//Find the max number of frames outstanding to forward
	hwqueue_index = CIRC_NEXT(queue->ring->header.tail, queue->ring->header.capacity);
	hwqueue_capacity = queue->ring->header.capacity;
	if (num_frames > CIRC_DIFF64(queue->ring->header.head, hwqueue_index, hwqueue_capacity )) {
		frames_to_forward = CIRC_DIFF64(queue->ring->header.head, hwqueue_index, hwqueue_capacity);
	}else{
		frames_to_forward = num_frames;
	}

	//Get the actions from userspace
	ret = copy_from_user(queue->action_map, action_buf, sizeof(struct gao_action)*frames_to_forward);
	if(ret) gao_error("Copy from user failed.");

	log_dp("Starting write with %lu frames to forward.", (unsigned long)frames_to_forward);


	//The in


	//Main action apply loop
	for(action_index = 0; action_index < frames_to_forward; action_index += frames_same_action) {

		log_dp("Forwarding: index=%lu", (unsigned long)action_index);
		action = &queue->action_map[action_index];
		gao_dump_action(action);

		//How many frames have the same action? Apply them in batch.
		frames_same_action = 0;
		while(action->action == queue->action_map[action_index+frames_same_action].action) {
			if((action_index+frames_same_action) > frames_to_forward) break;
			frames_same_action++;
		}

		log_dp("Frames with same action this round: %lu", (unsigned long)frames_same_action);

		if(unlikely(action->action & GAO_INVALID_ACTION_MASK)) {
			log_dp("Drop: Invalid action=%#08x", action->action);
			hwqueue_index = CIRC_ADD(hwqueue_index, frames_same_action, hwqueue_capacity);
			continue;
		}


		switch(action->action_id) {

		case GAO_ACTION_DROP:
			//Forward the hwqueue index over the dropped frames
			hwqueue_index = CIRC_ADD(hwqueue_index, frames_same_action, hwqueue_capacity);
			log_dp("Drop: Action id is DROP");
			break;

		case GAO_ACTION_FORWARD:


			dest_queue = queue->queue_map.port[action->port_id].ring[action->queue_id];

			if(unlikely(!dest_queue)) {
				log_dp("Drop: Null dest queue");
				hwqueue_index = CIRC_ADD(hwqueue_index, frames_same_action, hwqueue_capacity);
				break;
			}

			gao_lock_subqueue(dest_queue);

			dest_head = dest_queue->header.head;
			dest_tail = dest_queue->header.tail;
			dest_capacity = dest_queue->header.capacity;
			dest_remaining = CIRC_DIFF64(dest_tail, dest_head, dest_capacity);
			round_max = (frames_same_action > dest_remaining) ? dest_remaining : frames_same_action;

			log_dp("dest_remaining=%lu round_max=%lu", (unsigned long)dest_remaining, (unsigned long)round_max);

			//Swap the descriptors
			for(round_index = 0; round_index < round_max; round_index++) {
				log_dp("Queuing desc [action %lu]: hwqueue_index=%lu dest_head=%lu hw_desc=%lx dest_desc=%lx",
						(unsigned long)(action_index + round_index), (unsigned long)hwqueue_index,
						(unsigned long)dest_head, (unsigned long)(*descriptors)[hwqueue_index].descriptor,
						(unsigned long)dest_queue->descriptors[dest_head].descriptor);
				swap_descriptors(&(*descriptors)[hwqueue_index], &dest_queue->descriptors[dest_head]);
				dest_head = CIRC_NEXT(dest_head, dest_capacity);
				hwqueue_index = CIRC_NEXT(hwqueue_index, hwqueue_capacity);
			}

			hwqueue_index = CIRC_ADD(hwqueue_index, (frames_same_action - round_max), hwqueue_capacity);
			log_dp("Left/dropped: %lu", (unsigned long)(frames_same_action - round_max));
			log_dp("Done action round, dest_head=%lu", (unsigned long)dest_head);

			dest_queue->header.head = dest_head;


			//Wake the endpoint
			previous_wake_condition = test_and_set_bit(action->queue_id, (unsigned long*)dest_queue->control.tail_wake_condition_ref);
			log_dp("Prev wake condition = %lx", (unsigned long)previous_wake_condition);
			if(!(previous_wake_condition & ~(1 << action->queue_id))) {
				log_debug("Need to wake queue.");
				wake_up_interruptible(dest_queue->control.tail_wait_queue_ref);
			}


			gao_unlock_subqueue(dest_queue);
			break;

		default:
			//Forward the hwqueue index over the dropped frames
			hwqueue_index = CIRC_ADD(hwqueue_index, frames_same_action, hwqueue_capacity);
			log_dp("Drop: Action id is Unsupported");
			break;

		}


	}


	ret = file_private->port_ops->gao_write(file_private, frames_to_forward);

//
//	forward_index = CIRC_NEXT(queue->ring->header.tail, queue->ring->header.capacity);
//	//Find the max number of frames outstanding to forward
//	if (num_frames > CIRC_DIFF64(queue->ring->header.head, forward_index, queue->ring->header.capacity)) {
//		frames_to_forward = CIRC_DIFF64(queue->ring->header.head, forward_index, queue->ring->header.capacity);
//	}else{
//		frames_to_forward = num_frames;
//	}
//
//	//Get the actions from userspace
//	copy_from_user(queue->action_map, action_buf, sizeof(struct gao_action)*frames_to_forward);
//
//	log_debug("Send this shit to p0/q0!");
//
//	dest_queue = queue->queue_map.port[0].ring[0];
//	if(!dest_queue) {
//		log_bug("nvm, destq was null, lol!");
//		goto err;
//	}
//
//	previous_wake_condition = test_and_set_bit(0, (unsigned long*)dest_queue->control.tail_wake_condition_ref);
//	log_debug("Prev wake condition = %lx", (unsigned long)previous_wake_condition);
//	//if(!(previous_wake_condition & ~1)) {
//		log_debug("Need to wake queue.");
//		wake_up_interruptible(dest_queue->control.tail_wait_queue_ref);
//	//}
//
////	for(action_index = 0, frames_left = frames_to_forward; frames_left > 0; frames_left--, forward_index++, action_index++) {
////
////		log_dp("Forwarding %lu: index=%lu", (unsigned long)forward_index, (unsigned long)action_index);
////		action = &(*queue->action_map)[action_index];
////		gao_dump_action(action);
////
////		if(!action->action_id) {
////			log_dp("Drop: Action id is DROP");
////			continue;
////		}
////
////		dest_queue = queue->queue_map.port[action->port_id].ring[action->queue_id];
////		if(unlikely(!dest_queue)) {
////			log_dp("Drop: Null dest queue id");
////			continue;
////		}
////
////		log_dp("Would forward");
////
////	}
//
//	ret = 1;//file_private->port_ops->gao_write(file_private, (frames_to_forward - frames_left));


	err:
	rcu_read_unlock();
	return ret;
}



static void	gao_forward_frames(struct gao_queue* queue, uint64_t num_to_forward) {
	struct gao_descriptor_ring	*dest_queue = NULL;
	struct gao_descriptor 	*descriptors = NULL;
	struct gao_action 		*action = NULL;
	uint64_t				action_index, index, size, previous_wake_condition;

	//Initialize ring variables
	size = queue->ring->header.capacity;
	index = CIRC_NEXT(queue->ring->header.tail, size);
	descriptors = (struct gao_descriptor*)&queue->ring->descriptors;

	log_dp("start fwd: index/next_to_clean=%llu left=%llu", index, num_to_forward);

//	for(prefetch_index = 0; prefetch_index < 4; prefetch_index++) {
//		prefetch(queue->action_pipeline + (prefetch_index*16));
//		prefetch(descriptors + (prefetch_index*8));
//	}

	//Main action apply loop
	for(action_index = 0; action_index < num_to_forward; action_index++, index = CIRC_NEXT(index, size)) {

		action = &queue->action_pipeline[action_index];

		if(unlikely(action->action & GAO_INVALID_ACTION_MASK)) {
			log_bug("fwd drop: invalid action=%#08x", action->action);
			continue;
		}


		switch(action->action_id) {

		case GAO_ACTION_DROP:
			log_error("fwd drop: action_id is drop");
			continue;

		case GAO_ACTION_FORWARD:
			dest_queue = queue->queue_map.port[action->port_id].ring[action->queue_id];

			if(unlikely(!dest_queue)) {
				log_error("fwd drop: null dest queue");
				continue;
			}

			gao_lock_subqueue(dest_queue);


			if(!gao_ring_slots_left(dest_queue)) {
				log_error("fwd drop: no slots left");
				gao_unlock_subqueue(dest_queue);
				continue;
			}


			swap_descriptors(&descriptors[index], &dest_queue->descriptors[dest_queue->header.tail]);
			dest_queue->header.tail = CIRC_NEXT(dest_queue->header.tail, dest_queue->header.capacity);

			//Wake the endpoint
			previous_wake_condition = test_and_set_bit(action->queue_id, (unsigned long*)dest_queue->control.tail_wake_condition_ref);

			log_dp("fwd: action_index=%llu port=%hhu queue=%hhu index=%llu new dest_tail=%llu prev_wake_cond=%llx",
					action_index, action->port_id, action->queue_id, index, dest_queue->header.tail, previous_wake_condition);

			if(!(previous_wake_condition & ~(1 << action->queue_id))) {
				wake_up_interruptible(dest_queue->control.tail_wait_queue_ref);
			}


			gao_unlock_subqueue(dest_queue);
			break;

		default:
			break;

		}
	}

//	for(prefetch_index = 0; prefetch_index < 4; prefetch_index++) {
//		prefetch(queue->descriptor_pipeline + (prefetch_index*8));
//		prefetch(descriptors + (prefetch_index*8));
//	}

}

long	gao_sync_queue(struct file *filep) {
	ssize_t 				ret = 0;
	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
	struct gao_queue 		*queue = NULL;
	struct gao_descriptor 	*descriptors = NULL;
	uint64_t				size, num_to_forward , last_head, new_head;

	rcu_read_lock();

	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	queue = file_private->bound_queue;

	if(unlikely(!queue))
		gao_error_val(-EIO, "Reading null queue");

	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");



	num_to_forward = gao_ring_slots_left(queue->ring);
	gao_forward_frames(queue, num_to_forward);
	file_private->port_ops->gao_clean(queue, num_to_forward);


	read_again:

	//We will save the current head -- if packets are read the new head will be the end of the read packets.
	last_head = queue->ring->header.head;
	size = queue->ring->header.capacity;
	descriptors = (struct gao_descriptor*)&queue->ring->descriptors;
	ret = file_private->port_ops->gao_recv(queue, size);



	if(unlikely(ret < 0)) gao_error("Error while reading fd %p", filep);
	//Got something
	if(ret > 0) {

		new_head = queue->ring->header.head;
		log_dp("Got %ld descriptors, copying to userspace. last_head=%lu new_head=%lu",
						ret, (unsigned long)last_head, (unsigned long)new_head);

		//Copy the ring descriptors to the linear buffer in the right order
		if( new_head >= last_head) {
			memcpy( ((void*)queue->descriptor_pipeline), (void*)&descriptors[last_head], (new_head - last_head)*sizeof(struct gao_descriptor) );
		}else{
			memcpy( ((void*)queue->descriptor_pipeline), (void*)&descriptors[last_head], (size - last_head)*sizeof(struct gao_descriptor));
			memcpy( ((void*)queue->descriptor_pipeline) + ((size - last_head)*sizeof(struct gao_descriptor)) , (void*)&descriptors[0], new_head*sizeof(struct gao_descriptor));
		}

	}else{ //Didn't read anything, block
		rcu_read_unlock();
		atomic_long_set(queue->ring->control.head_wake_condition_ref, 0);
		file_private->port_ops->gao_enable_rx_interrupts(queue);
		if(wait_event_interruptible(queue->ring->control.head_wait_queue, atomic_long_read(&queue->ring->control.head_wake_condition) )) {
			ret = -EINTR;
			log_debug("Read on %p interrupted", filep);
			goto interrupted;
		}

		rcu_read_lock();
		//Check the states again to make sure the queue is still valid.
		if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
			gao_error_val(-EIO, "Cannot read from inactive queue");

		if(unlikely(!queue))
			gao_error_val(-EIO, "Reading null queue");

		if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
			gao_error_val(-EIO, "Cannot read from inactive queue");

		file_private->port_ops->gao_disable_rx_interrupts(queue);
		goto read_again;
	}



	err:
	rcu_read_unlock();
	interrupted:
	return ret;
}

/**
 * XXX: This is a hack, replace this if time permits.
 * Perform a "write" to a descriptor in the controller port Rx queue to give
 * userspace a descriptor with a certain length and offset to write to.
 * Right now only works on the controller port
 * @param frame_size The length to set the descriptor to.
 * @param offset The offset for the descriptor
 */
ssize_t gao_write(struct file *filep, const char __user *action_buf, size_t num_frames, loff_t *offset) {
	ssize_t 				ret = 0;
	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
	struct gao_queue 		*queue = NULL;
	struct gao_descriptor_ring_header	*header = NULL;
	struct gao_descriptor 	*ring_descriptors = NULL, *mmap_descriptors = NULL;
	uint64_t				index, size;


	rcu_read_lock();

	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	//We can only write to the controller port
	if(unlikely(file_private->bound_gao_ifindex != GAO_CONTROLLER_PORT_ID))
		gao_error_val(-EIO, "Cannot write to non-controller queue.");

	queue = file_private->bound_queue;

	if(unlikely(!queue))
		gao_error_val(-EIO, "Reading null queue");

	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	header = queue->hw_private;
	if(unlikely(!header))
		gao_bug_val(-EIO, "Queue had a null hw_private pointer.");


	//Initialize ring variables
	size = queue->ring->header.capacity;
	index = header->head;
	ring_descriptors = (struct gao_descriptor*)&queue->ring->descriptors;
	mmap_descriptors = queue->descriptor_pipeline;
	//Cap the number of injected frames to the ring capacity
	num_frames = ((uint64_t)num_frames > (size - 1)) ? (size - 1) : num_frames;

	for(index = 0; index < num_frames; index++) {
		ring_descriptors[index].len = mmap_descriptors[index].len;
	}

	queue->ring->header.tail = size - 1;
	queue->ring->header.head = num_frames;

	log_dp("write: num_frames=%ld", num_frames);
	ret = num_frames;

	err:
	rcu_read_unlock();
	return ret;
}


/**
 * Assumptions allowed:
 * 	Queue pointer and HW pointer are valid
 * 	Queue is not being deleted
 * 	It is safe to read the queue until we release RCU lock
 */
ssize_t gao_read(struct file *filep, char __user *packet_buf, size_t packet_size, loff_t *offset) {
	ssize_t ret = 0;
	uint64_t size, packet_length;
	struct gao_file_private *file_private = (struct gao_file_private*)filep->private_data;
	struct gao_queue *queue = NULL;
	struct gao_descriptor *descriptors = NULL;
	struct gao_descriptor_ring_header	*header = NULL;

	read_again:

	rcu_read_lock();

	if(unlikely(file_private->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	//We can only write to the controller port
	if(unlikely(file_private->bound_gao_ifindex != GAO_CONTROLLER_PORT_ID))
		gao_error_val(-EIO, "Cannot write to non-controller queue.");

	//FIXME: I think I just gave my code cancer
	queue = gao_get_resources()->ports[GAO_CONTROLLER_PORT_ID].tx_queues[0];

	if(unlikely(!queue))
		gao_error_val(-EIO, "Reading null queue");

	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE))
		gao_error_val(-EIO, "Cannot read from inactive queue");

	header = queue->hw_private;
	if(unlikely(!header))
		gao_bug_val(-EIO, "Queue had a null hw_private pointer.");


	descriptors = (struct gao_descriptor*)&queue->ring->descriptors;
	header = queue->hw_private;
	size = queue->ring->header.capacity;


	log_dp("start controller xmit/read: index/tail=%llu left=%ld", header->tail, atomic_long_read(queue->ring->control.head_wake_condition_ref));

	//The condition acts like a semaphore in this case, if there are no packets wait for some
	rcu_read_unlock(); //We can't be deleted while we're bound anyways, unlock before the wait and copy to user
	if(!atomic_long_read(queue->ring->control.head_wake_condition_ref)) {
		if(wait_event_interruptible( queue->ring->control.head_wait_queue, atomic_long_read(&queue->ring->control.head_wake_condition) )) {
			ret = -EINTR;
			log_debug("Read on %p interrupted", filep);
			goto interrupted;
		}
		goto read_again;
	}



	//There are packets waiting
	packet_length = descriptors[header->tail].len;
	ret = copy_to_user( (void*)packet_buf, descriptor_to_virt_addr(descriptors[header->tail].descriptor), packet_length );

	header->tail = CIRC_NEXT(header->tail, size);

	//If there are no more packets left, wake xmit
	if(atomic_long_dec_and_test(queue->ring->control.head_wake_condition_ref)) {
		wake_up_interruptible(queue->ring->control.head_wait_queue_ref);
	}


	if(ret) {
		ret = -EIO;
	} else {
		ret = packet_length;
	}

	return ret;

	err:
	rcu_read_unlock();
	interrupted:
	return ret;
}


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
	long ret;
	gao_request_dump_t request_dump;

	log_dp("IOCTL: Got an ioctl with %u command and %lx arg", command, argument_ptr);

	switch(command) {

	case GAO_IOCTL_SYNC_QUEUE:
		return gao_sync_queue(filep);

	case GAO_IOCTL_COMMAND_GET_MMAP_SIZE:

		ret = gao_ioctl_handle_mmap(filep, argument_ptr);


		//log_debug("IOCTL: Returning MMAP area size: %ld bytes.", resources.buffer_space_frame);
		return ret;
		break;

	case GAO_IOCTL_COMMAND_PORT:
		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
		ret = gao_ioctl_handle_port(filep, argument_ptr);

		break;
	case GAO_IOCTL_COMMAND_QUEUE:
		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
		ret = gao_ioctl_handle_queue(filep, argument_ptr);
		break;

//	case GAO_IOCTL_COMMAND_CREATE_QUEUE:
//		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
//		copy_from_user(&argument, (void*) argument_ptr, sizeof(argument));
//
//		log_debug("IOCTL: Create a queue of size %lu", argument);
//
//		ret = gao_create_queue_user(&gao_mmio_dev.queue_manager, &gao_mmio_dev.descriptor_manager, argument, filep);
//		if(ret < 0) gao_error("IOCTL: Create queue failed to create queue, errno %ld", ret);
//
//		return ret;
//		break;

//	case GAO_IOCTL_COMMAND_DELETE_QUEUE:
//		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
//		copy_from_user(&argument, (void*) argument_ptr, sizeof(argument));
//
//		log_debug("IOCTL: Deleting a queue with index %lu", argument);
//
//		ret = gao_delete_queue(&gao_mmio_dev.queue_manager, &gao_mmio_dev.descriptor_manager, argument);
//		if(ret < 0) gao_error("IOCTL: Delete queue failed to delete queue index %lu, errno %ld", argument, ret);
//
//		return ret;
//		break;
//
	case GAO_IOCTL_COMMAND_DUMP:
		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
		ret = copy_from_user(&request_dump, (void*) argument_ptr, sizeof(request_dump));
		if(ret) gao_error("Copy from user failed.");

		gao_ioctl_dump(filep, request_dump);

		break;

//	case GAO_IOCTL_COMMAND_BIND_QUEUE:
//		if(!argument_ptr) gao_error_val(-EFAULT, "IOCTL: Null argument pointer.");
//		copy_from_user(&bind_queue_req, (void*) argument_ptr, sizeof(struct gao_ioctl_bind_queue));
//
//		log_debug("IOCTL: Binding to ifindex %lu queue %lu direction %u",
//				(unsigned long)bind_queue_req.if_index,(unsigned long)bind_queue_req.queue_index,
//				bind_queue_req.direction);
//		ret = gao_bind_queue(&bind_queue_req, filep);
//
//		return ret;
//		break;
//
//
//	case GAO_IOCTL_COMMAND_DETACH_QUEUE:
//		log_debug("IOCTL: Detach Interface");
//		gao_detach_queue(filep);
//		return 0;
//
//		break;

	default:
		gao_error_val(-EFAULT, "IOCTL: Unsupported IOCTL command: %u", command);
		break;
	}


	return 0;
	err:
	return ret;
}


static struct file_operations gao_fops = {
	.owner	 = THIS_MODULE,
	.mmap	 = gao_mmap,
	.read	 = gao_read,
	.write	 = gao_write,
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
//
    log_debug("GAOMMIO registered to Major: 10 Minor: %i Name: /dev/%s.", gao_miscdev.minor, gao_miscdev.name);

    err:
    return ret;
}

module_init(gao_mmio_init);
module_exit(gao_mmio_exit);
MODULE_LICENSE("GPL");
