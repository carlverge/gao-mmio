#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#ifndef LINUX
#define LINUX
#endif

#include "gao_mmio_resource.h"


const static char *gao_resource_state_str[] = {"Unused", "Registered", "Active", "Configuring", "Deleting", "Error", "Invalid State"};

const char*	gao_resource_state_string(gao_resource_state_t state) {
	if(state >= GAO_RESOURCE_STATE_FINAL) return gao_resource_state_str[GAO_RESOURCE_STATE_FINAL];
	else return gao_resource_state_str[state];
}

const static char *gao_owner_str[] = {"None", "Userspace", "Interface"};
const static char *gao_direction_str[] = {"NA", "RX", "TX"};


void	gao_dump_buffers(struct gao_resources *resources) {
	uint64_t index;
	log_debug("Dump Buffer Groups: start=%lu end=%lu frame=%lu",
			resources->buffer_start_phys, resources->buffer_end_phys, resources->buffer_space_frame);
	for(index = 0; index < GAO_BUFFER_GROUPS; index++) {
		log_debug("Index:%8lu virtaddr=%p",
				(unsigned long)index, resources->buffer_groups[index]);
	}
}

void	gao_dump_descriptor(struct	gao_descriptor *desc) {
	log_debug("Desc: %016lx GFN=%04hx BufIdx=%04hx Len=%04hx Offset=%04hx",
			(unsigned long)desc->descriptor, desc->gfn, desc->index, desc->len, desc->offset);
}

void	gao_dump_descriptors(struct gao_resources *resources) {
	uint64_t index;
	log_debug("Dump Descriptors %p: head=%lu tail=%lu left=%lu",
			resources->descriptor_ring.descriptors,
			(unsigned long)resources->descriptor_ring.head,
			(unsigned long)resources->descriptor_ring.tail,
			(unsigned long)resources->descriptor_ring.left);

	for(index = 0; index < GAO_DESCRIPTORS; index++) {
			gao_dump_descriptor(&(*resources->descriptor_ring.descriptors)[index]);
	}

}

void	gao_dump_descriptor_ring(struct gao_descriptor_ring *ring) {
	uint64_t index;
	if(!ring) {
		log_debug("Dump Descriptor Ring: %p", ring);
		return;
	}
	log_debug("Dump Descriptor Ring: (dump %lu descriptors)", (unsigned long)ring->header.capacity);
	log_debug("head=%10u tail=%10u size=%10u capacity=%10u",
			(unsigned)ring->header.head, (unsigned)ring->header.tail,
			(unsigned)ring->header.size, (unsigned)ring->header.capacity);
	for(index = 0; index < ring->header.capacity; index++) {
		gao_dump_descriptor(&ring->descriptors[index]);
	}

}

void	gao_dump_descriptor_ring_nested(struct gao_descriptor_ring *ring) {
	uint64_t index;
	gao_dump_descriptor_ring(ring);
	if(!ring) return;
	for(index = 0; index < ring->header.capacity; index++) {
		gao_dump_descriptor(&ring->descriptors[index]);
	}

}

void	gao_dump_action(struct gao_action *action) {
	log_debug("Action: id=%hhu port=%hhu queue=%hhu", action->action_id, action->port_id, action->queue_id);
}

void	gao_dump_resources(struct gao_resources *resources) {
	log_debug("Resources:");
}

void	gao_dump_ingress_queue_map(struct gao_ingress_queue_map *map) {
	uint64_t port_index, subqueue_index, has_queues;
	log_debug("Dumping Ingress Queue Map:");
	for(port_index = 0; port_index < GAO_MAX_PORTS; port_index++) {
		//Only dump if the port actually has queues
		for(subqueue_index = 0, has_queues = 0; subqueue_index < GAO_MAX_PORT_SUBQUEUE; subqueue_index++) {
			if(map->port[port_index].ring[subqueue_index]) has_queues++;
		}
		if(!has_queues) continue;

		log_debug("Port %lu map:", (unsigned long)port_index);

		for(subqueue_index = 0; subqueue_index < GAO_MAX_PORT_SUBQUEUE; subqueue_index++) {
			log_debug("	[%lu]->%p", (unsigned long)subqueue_index,map->port[port_index].ring[subqueue_index]);
		}
	}
}

void	gao_dump_queue_binding(struct gao_queue_binding *binding) {
	log_debug("Queue Binding:");
	log_debug("Owner Type:%10s filep=%p IfIndex/Queue/Direction=%lu/%lu/%2s",
			gao_owner_str[binding->owner_type], binding->gao_file,
			(unsigned long)binding->gao_ifindex, (unsigned long)binding->queue_index,
			gao_direction_str[binding->direction_txrx]);
}

void	gao_dump_queue(struct gao_queue *queue) {
	uint64_t index;
	log_debug("Dump Queue: index=%lu state=%s flags=%lx descriptors=%lu ring=%p",
			(unsigned long)queue->index, gao_resource_state_str[queue->state],
			(unsigned long)queue->flags, (unsigned long)queue->descriptors, queue->ring);

	gao_dump_queue_binding(&queue->binding);

	for(index = 0; index < GAO_MAX_PORT_SUBQUEUE; index++) {
		log_debug("Subqueue Ring[%lu]: %p", (unsigned long)index, queue->subqueues[index].ring);
	}

	gao_dump_ingress_queue_map(&queue->queue_map);
}


void	gao_dump_queue_nested(struct gao_queue *queue) {
	gao_dump_queue(queue);

	if(queue->ring) gao_dump_descriptor_ring(queue->ring);
}

void	gao_dump_port(struct gao_port* port) {
	log_debug("Dumping Port %lu: name=%s ifindex=%lu state=%s",
			(unsigned long)port->gao_ifindex, port->name, (unsigned long)port->ifindex, gao_resource_state_string(port->state));
	log_debug("netdev=%p port_ops=%p", port->netdev, port->port_ops);
	log_debug("Num Queues/Descriptors: rx=%u/%u tx=%u/%u",
			(unsigned)port->num_rx_queues, (unsigned)port->num_rx_desc, (unsigned)port->num_tx_queues, (unsigned)port->num_tx_desc);
}

void gao_dump_port_nested(struct gao_port* port) {
	uint64_t index;
	gao_dump_port(port);
	log_debug("RX Queues:");
	for(index = 0; index < port->num_rx_queues; index++) {
		if(!port->rx_queues[index]) continue;
		gao_dump_queue(port->rx_queues[index]);
	}

	for(index = 0; index < port->num_tx_queues; index++) {
		if(!port->tx_queues[index]) continue;
		gao_dump_queue(port->tx_queues[index]);
	}

}

void gao_dump_ports(struct gao_resources *resources) {
	uint64_t index;
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		if(resources->ports[index].state == GAO_RESOURCE_STATE_UNUSED) continue;
		gao_dump_port(&resources->ports[index]);
	}
}

void gao_dump_ports_nested(struct gao_resources *resources) {
	uint64_t index;
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		if(resources->ports[index].state == GAO_RESOURCE_STATE_UNUSED) continue;
		gao_dump_port_nested(&resources->ports[index]);
	}
}

//void	gao_dump_queues(struct gao_resources *resources) {
//	uint64_t index;
//	log_debug("Dump Queues:");
//	for(index = 0; index < GAO_MAX_QUEUES; index++) {
//		gao_dump_queue(&resources->queues[index]);
//	}
//}

void	gao_dump_file(struct file *filep) {
	struct gao_file_private *file_private = (struct gao_file_private*) filep->private_data;
	log_debug("Dump File: state=%s filep=%p bind if/q/dir %lu/%lu/%d queue=%p",
			gao_resource_state_string(file_private->state), filep,
			(unsigned long)file_private->bound_gao_ifindex, (unsigned long)file_private->bound_queue_index,
			file_private->bound_direction, file_private->bound_queue);
}


inline void swap_descriptors(struct gao_descriptor *desc1, struct gao_descriptor *desc2) {
	uint64_t desc_tmp = desc1->descriptor;
	desc1->descriptor = desc2->descriptor;
	desc2->descriptor = desc_tmp;
}

/**
 * This "validates" the buffers by checking if we kernel panic when we
 * write into them. Writes a unique string into each buffer we can check
 * in the descriptor and userspace validation later on. Can only be done on
 * module init, and the module will not come up if this fails (neither will the machine...)
 * @param resources
 * @return Void on success, a machine in need of reboot on failure.
 */
static void		gao_validate_buffer_groups(struct gao_resources *resources) {
	uint64_t 	index, buffer_index;
	uint16_t 	gfn, bufnum;
	void		*buffer_group, *buffer;
	char		strbuf[GAO_BUFFER_TEST_STR_LEN];
	log_info("Validating buffer groups.");

	for(index = 0; index < GAO_BUFFER_GROUPS; index++) {
		buffer_group = resources->buffer_groups[index];
//		log_debug("Validate buffer group %p:", buffer_group);
		//Put a unique string in each buffer, and fill the rest with dead cows.
		for(buffer_index = 0; buffer_index < GAO_BUFFER_GROUP_SIZE; buffer_index += GAO_BUFFER_SIZE) {
			buffer = (buffer_group + buffer_index);
			gfn = (uint16_t)GAO_VIRT_TO_GFN(buffer_group);
			bufnum = (uint16_t)((unsigned long)(buffer_index/GAO_BUFFER_SIZE));

			snprintf((char*)&strbuf, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, gfn, bufnum);

//			log_debug("Write to %p: %s. Fill with cows for %d",
//					buffer, (char*)&strbuf, (GAO_BUFFER_SIZE-GAO_BUFFER_TEST_STR_LEN));

			snprintf((char*)buffer, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, gfn, bufnum);
			memset((buffer + GAO_BUFFER_TEST_STR_LEN), GAO_BUFFER_FILL_VAL, (GAO_BUFFER_SIZE-GAO_BUFFER_TEST_STR_LEN));
		}

	}

	log_info("Buffer validation successful. Start=%lx End=%lx Size=%lx (%lu MB)",
			resources->buffer_start_phys, resources->buffer_end_phys, resources->buffer_space_frame, resources->buffer_space_frame >> 20);

	return;
}

static void		gao_free_buffer_group(void	*buffer_group) {
	int64_t page_index;

	if(!buffer_group) gao_bug("Cannot free null buffer group.");

//	log_debug("Freeing a buffer group: Virt=%p Phys=%lx GFN=%lx", buffer_group,
//				(unsigned long)virt_to_phys(buffer_group),
//				GAO_VIRT_TO_GFN(buffer_group));

	for(page_index = 0; page_index < (GAO_BUFFER_GROUP_SIZE); page_index += GAO_SMALLPAGE_SIZE) {
		ClearPageReserved( virt_to_page( (((unsigned long)buffer_group) + page_index) ));
	}

	kfree_null(buffer_group);

	err:
	return;
}

/**
 * Free and unlock all buffer groups allocated to GAO.
 * @param resources
 */
static void		gao_free_buffer_groups(struct gao_resources *resources) {
	uint64_t index;
	log_info("Free buffer groups.");

	gao_free_buffer_group(resources->dummy_group);

	for(index = 0; index < GAO_BUFFER_GROUPS; index++) {
		gao_free_buffer_group(resources->buffer_groups[index]);
	}

}

static void* 	gao_alloc_buffer_group(void) {
	int64_t page_index;
	void* buffer_group = NULL;

	buffer_group = kmalloc((GAO_BUFFER_GROUP_SIZE), GFP_KERNEL);

	if(!buffer_group) gao_error("Failed to allocate a buffer group.");

	if( (((unsigned long)buffer_group) & ~GAO_GFN_MASK) != ((unsigned long)buffer_group) )
		gao_error("A buffer group not aligned to GFN boundary.");

	for(page_index = 0; page_index < (GAO_BUFFER_GROUP_SIZE); page_index += GAO_SMALLPAGE_SIZE) {
		SetPageReserved(virt_to_page( (((unsigned long)buffer_group) + page_index) ));
	}

//	log_debug("Allocated a buffer group: Virt=%p Phys=%lx GFN=%lx", buffer_group,
//			(unsigned long)virt_to_phys(buffer_group),
//			GAO_VIRT_TO_GFN(buffer_group));

	return buffer_group;
	err:
	return NULL;
}

/**
 * Allocate the memory for the buffer groups. Each buffer group is physically
 * contiguous and page-locked in memory.
 * @param resources
 * @return 0 on success, -ENOMEM on failure.
 */
static int64_t gao_init_buffer_groups(struct gao_resources *resources) {
	int64_t ret = 0;
	uint64_t index;
	void*	buffer_group = NULL;
	unsigned long buffer_min = -1, buffer_max = 0, phys_addr;


	log_info("Allocating buffer groups.");


	resources->dummy_group = gao_alloc_buffer_group();
	if(!resources->dummy_group) gao_error_val(-ENOMEM, "Failed to allocate dummy buffer group.");

	for(index = 0; index < GAO_BUFFER_GROUPS; index++) {
		buffer_group = gao_alloc_buffer_group();
		if(!buffer_group) gao_error_val(-ENOMEM, "Failed to allocate buffer at index %lu.", (unsigned long)index);
		resources->buffer_groups[index] = buffer_group;
		//Set min and max range values
		phys_addr = ((unsigned long)virt_to_phys(buffer_group));
		if( phys_addr < buffer_min ) buffer_min = phys_addr;
		if( phys_addr > buffer_max ) buffer_max = phys_addr;
	}

	resources->buffer_start_phys = buffer_min;
	resources->buffer_end_phys = (buffer_max + GAO_BUFFER_GROUP_SIZE);
	resources->buffer_space_frame = (resources->buffer_end_phys - resources->buffer_start_phys);


	gao_validate_buffer_groups(resources);

	log_info("Successfully allocated %lu buffer groups (%luMB). [Start=%lx End=%lx Frame=%lx (%lu MB) Gaps=%lu]",
			(unsigned long)GAO_BUFFER_GROUPS, (unsigned long)(GAO_BUFFER_SPACE_SIZE >> 20),
			(unsigned long)resources->buffer_start_phys, (unsigned long)resources->buffer_end_phys,
			(unsigned long)resources->buffer_space_frame,
			(unsigned long)resources->buffer_space_frame >> 20,
			(unsigned long)((resources->buffer_space_frame/GAO_BUFFER_GROUP_SIZE) - GAO_BUFFER_GROUPS));

	return 0;
	err:
	gao_free_buffer_groups(resources);
	return ret;
}

/**
 * Read the values written by the buffer validation by de-referencing each
 * descriptor. Can only be done on module init, and module will not start if
 * this does not succeed.
 * @param resources
 * @return
 */
static int64_t	gao_validate_descriptor_allocator_ring(struct gao_resources *resources) {
	int64_t 	ret = 0;
	uint64_t 	index;
	uint16_t	gfn, bufnum;
	char		descriptor_str[GAO_BUFFER_TEST_STR_LEN], buffer_str[GAO_BUFFER_TEST_STR_LEN];
	uint32_t	*dead_cows;
	struct gao_descriptor descriptor;
	struct gao_descriptor (*descriptors)[GAO_DESCRIPTORS] = resources->descriptor_ring.descriptors;

	log_info("Validating descriptors.");

	dead_cows = vmalloc(GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN);
	if(!dead_cows) gao_error_val(-ENOMEM, "No moooomery for cows.");
	memset(dead_cows, GAO_BUFFER_FILL_VAL, (GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN));


	for(index = 0; index < GAO_DESCRIPTORS; index++) {
		descriptor.descriptor = (*descriptors)[index].descriptor;
//		log_debug("Desc=%016lx Phys=%016lx Virt=%p",
//				(unsigned long)descriptor.descriptor,
//				GAO_DESC_TO_PHYS(descriptor.descriptor),
//				GAO_DESC_TO_VIRT(descriptor.descriptor));

		gfn = descriptor.gfn;
		bufnum = descriptor.index;

		snprintf((char*)&descriptor_str, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, gfn, bufnum);
		strncpy((char*)&buffer_str, (char*)GAO_DESC_TO_VIRT(descriptor.descriptor), GAO_BUFFER_TEST_STR_LEN);
		ret = strncmp((char*)&descriptor_str, (char*)&buffer_str, GAO_BUFFER_TEST_STR_LEN);

		if(ret) {
			gao_bug_val(-EINVAL, "Error while validating descriptors, strings unequal: Buffer=%s Descriptor=%s Equal=%ld",
					(char*)&buffer_str, (char*)&descriptor_str, (long)ret);
			log_bug("Buffer=%s Descriptor=%s Memcmp=%ld", (char*)&buffer_str, (char*)&descriptor_str, (long)ret);
		}

		ret = memcmp(dead_cows, GAO_DESC_TO_VIRT(descriptor.descriptor) + GAO_BUFFER_TEST_STR_LEN,  (GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN));

		if(ret) {
			gao_bug_val(-EINVAL, "Error while validating descriptors, memory fill unequal at %ld.", (long)ret);
			log_bug("Buffer=%s Descriptor=%s Memcmp=%ld", (char*)&buffer_str, (char*)&descriptor_str, (long)ret);
		}

//		log_debug("Buffer=%s Descriptor=%s Memcmp=%ld", (char*)&buffer_str, (char*)&descriptor_str, (long)ret);
	}

	vfree(dead_cows);

	log_info("Descriptor validation successful.");

	return 0;
	err:
	if(dead_cows) vfree(dead_cows);
	return ret;
}

/**
 * Dealloc the descriptor ring.
 * @param resources
 */
static void	gao_free_descriptor_allocator_ring(struct gao_resources *resources) {
	log_info("Free descriptor groups.");

	if(resources->descriptor_ring.descriptors)
		vfree(resources->descriptor_ring.descriptors);

	return;
}

/**
 * Initialize the descriptor ring. Creates a descriptor for each buffer.
 * @param resources
 * @return 0 on success, -ENOMEM on failure.
 */
static int64_t	gao_init_descriptor_allocator_ring(struct gao_resources *resources) {
	int64_t		ret = 0;
	uint64_t 	index, buffer_index, descriptor_index = 0;
	uint16_t 	gfn, bufnum;
	void		*buffer_group, *buffer;

	struct gao_descriptor (*descriptors)[GAO_DESCRIPTORS] = NULL;
	struct gao_descriptor descriptor;


	log_info("Initializing descriptors.");

	descriptors = vmalloc(GAO_DESCRIPTORS*sizeof(struct gao_descriptor));
	if(!descriptors) gao_error_val(-ENOMEM, "Failed to allocate descriptor ring.");

	for(index = 0; index < GAO_BUFFER_GROUPS; index++) {
		buffer_group = resources->buffer_groups[index];
		gfn = (uint16_t)(GAO_VIRT_TO_GFN(buffer_group));
		//Fill each descriptor slot with information on every buffer
		for(buffer_index = 0; buffer_index < GAO_BUFFER_GROUP_SIZE; buffer_index += GAO_BUFFER_SIZE) {
			buffer = (buffer_group + buffer_index);
			bufnum = (uint16_t)((unsigned long)(buffer_index/GAO_BUFFER_SIZE));

			descriptor.len = 0;
			descriptor.gfn = gfn;
			descriptor.index = bufnum;

			(*descriptors)[descriptor_index].descriptor = descriptor.descriptor;

			descriptor_index++;
		}
	}

	log_info("Created %lu descriptors (Max=%lu).",
			(unsigned long)descriptor_index, (unsigned long)GAO_DESCRIPTORS);

	resources->descriptor_ring.descriptors = descriptors;
	resources->descriptor_ring.head = 0;
	resources->descriptor_ring.tail = 0;
	resources->descriptor_ring.left = descriptor_index;
	spin_lock_init(&resources->descriptor_ring.lock);

	if(descriptor_index != GAO_DESCRIPTORS)
		gao_bug_val(-EINVAL, "Mismatch between number of descriptors and buffers!");


	gao_validate_descriptor_allocator_ring(resources);

	return 0;
	err:
	gao_free_descriptor_allocator_ring(resources);
	return ret;
}

inline static void gao_lock_descriptor_allocator(struct gao_descriptor_allocator_ring *ring) {
	log_debug("Spinlocking descriptor ring");
	spin_lock(&ring->lock);
	log_debug("Locked descriptor ring");
}

inline static void gao_unlock_descriptor_ring(struct gao_descriptor_allocator_ring *ring) {
	log_debug("Unlocking descriptor ring");
	spin_unlock(&ring->lock);
}


static void gao_free_descriptors(struct gao_resources *resources, struct gao_descriptor (*source_queue)[], uint64_t num_descriptors) {
	int64_t index;
	struct gao_descriptor_allocator_ring *ring = &resources->descriptor_ring;

	log_debug("Trying to free %lu descriptors for %p",
			(unsigned long)num_descriptors, source_queue);

	gao_lock_descriptor_allocator(ring);

	if(num_descriptors > (GAO_DESCRIPTORS - ring->left)) {
		log_bug("Trying to free more descriptors than we should have... (Freeing: %lu Need: %lu)",
				(unsigned long)num_descriptors, (unsigned long)(GAO_DESCRIPTORS - ring->left));
		//Truncate the free and return what we have space for
		//XXX: Better to crash here?
		num_descriptors = (GAO_DESCRIPTORS - ring->left);
	}

	ring->left += num_descriptors;

	//Copy the descriptors into the queue
	for(index = 0; index < num_descriptors; index++, ring->tail = CIRC_NEXT(ring->tail, GAO_DESCRIPTORS)) {
		(*ring->descriptors)[ring->tail].descriptor = (*source_queue)[index].descriptor;
		//TODO: More robuest error handling here
		if(!(*ring->descriptors)[ring->tail].descriptor) log_bug("Copied a zero descriptor into the ring!");
		(*source_queue)[index].descriptor = 0;
	}

	gao_unlock_descriptor_ring(ring);
	return;
}

/**
 * Copy descriptors from the ring into the targeted queue. Copies them starting at
 * index num_descriptors going backwards.
 * @warning Spinlocks the descriptor ring
 * @param resources
 * @param target_queue The descriptor buffer to copy into
 * @param num_descriptors The numbre of descriptors to take
 * @return 0 on success, -ENOMEM on failure. On failure, allocates no descriptors.
 */
static int64_t gao_get_descriptors(struct gao_resources *resources, struct gao_descriptor (*target_queue)[], uint64_t num_descriptors) {
	int64_t ret = 0, index;
	struct gao_descriptor_allocator_ring *ring = &resources->descriptor_ring;

	log_debug("Trying to get %lu descriptors for %p",
			(unsigned long)num_descriptors, target_queue);

	gao_lock_descriptor_allocator(ring);

	if(num_descriptors > ring->left) {
		gao_error_val(-ENOMEM, "Cannot allocate queue, insufficient descriptors. (Want: %lu have: %lu)",
				(unsigned long)num_descriptors, (unsigned long)ring->left);
	}

	ring->left -= num_descriptors;

	//Copy the descriptors into the queue
	for(index = 0; index < num_descriptors; index++, ring->head = CIRC_NEXT(ring->head, GAO_DESCRIPTORS)) {
		(*target_queue)[index].descriptor = (*ring->descriptors)[ring->head].descriptor;
		if(!(*target_queue)[index].descriptor) log_bug("Copied a zero descriptor into the target queue!");
		(*ring->descriptors)[ring->head].descriptor = 0;
	}

	err:
	gao_unlock_descriptor_ring(ring);
	return ret;
}


/**
 * Deletes a user queue, frees any descriptors it owns, and frees the user queue
 * memory. Depends on the parent queue still existing to know the number of descriptors to free.
 * @param resources
 * @param queue_index
 */
//inline static void	gao_delete_user_queue(struct gao_resources *resources, struct gao_queue *queue) {
//	void					*queue_kmalloc_ptr = queue->ring_kmalloc;
//	struct gao_descriptor_ring 	*user_queue = queue->ring;
//	uint64_t				num_descriptors = queue->descriptors;;
//
//
//	if(num_descriptors) {
//		if(!user_queue)
//			log_bug("Deleting user queue: there were descriptors but we lost the user queue!");
//		else
//			gao_free_descriptors(resources, &user_queue->descriptors, num_descriptors);
//
//		queue->descriptors = 0;
//	}
//
//	if(!queue_kmalloc_ptr)
//		log_bug("Deleting user queue: missing queue_kmalloc_ptr!");
//	else
//		kfree_null(queue_kmalloc_ptr);
//
//	queue->ring = NULL;
//	queue->ring_kmalloc = NULL;
//
//	return;
//}

inline static void	gao_free_descriptor_ring(struct gao_resources *resources, struct gao_descriptor_ring *ring) {

	if(!ring) {
		log_debug("Trying to free null descriptor ring.");
		return;
	}

	if(ring->header.capacity)
		gao_free_descriptors(resources, &ring->descriptors, ring->header.capacity);

	vfree(ring);

	return;
}

/**
 * Allocates an MMAPable user queue and allocates descriptors for it.
 * It will set the number of descriptors in the parent queue. The value can't be
 * held in the user queue, as userspace could mangle it.
 * @warning Caller must hold resource lock
 * @param resources
 * @param num_descriptors
 * @param queue_index The queue index to allocate for
 * @return 0 on success, -ENOMEM on failure, -EINVAL on out of bounds param.
 */
//static int64_t	gao_create_user_queue(struct gao_resources *resources, struct gao_queue *queue, uint64_t num_descriptors) {
//	int64_t 				ret = 0;
//	void					*queue_kmalloc_ptr = NULL;
//	struct gao_descriptor_ring 	*user_queue = NULL;
//	uint64_t				queue_size = 0;
//
//
//	queue_size = (sizeof(struct gao_descriptor_ring_header)
//			+ (sizeof(struct gao_descriptor)*num_descriptors))
//			+ (GAO_SMALLPAGE_SIZE * 2); //To guarantee page alignment
//
//	queue_kmalloc_ptr = kmalloc(queue_size, GFP_KERNEL);
//
//	if(!queue_kmalloc_ptr) {
//		gao_error_val(-ENOMEM, "User queue creation failed, kmalloc failed! (num_descriptors=%lu, size=%lu)",
//				(unsigned long)num_descriptors, (unsigned long)queue_size);
//	}
//
//	memset(queue_kmalloc_ptr, 0, queue_size);
//
//	//Make sure MMAP pointer is page aligned
//	user_queue = (struct gao_descriptor_ring*)((((uint64_t)queue_kmalloc_ptr) + (GAO_SMALLPAGE_SIZE - 1)) & PAGE_MASK);
//
//	//Get the descriptors for the queue, this locks the descriptor ring
//	ret = gao_get_descriptors(resources, &user_queue->descriptors, num_descriptors);
//	if(ret) gao_error_val(-ENOMEM, "User queue creation failed, insufficient descriptors.");
//
//	queue->ring = user_queue;
//	queue->ring_kmalloc = queue_kmalloc_ptr;
//	queue->descriptors = num_descriptors;
//
//	return 0;
//	err:
//	gao_delete_user_queue(resources, queue);
//	return ret;
//}


/**
 * Create and initialize a new descriptor ring by taking descriptors from the global allocator.
 * @warning Resource lock ... actually doesn't need to be held.
 * @param resources
 * @param num_descriptors
 * @return
 */
static struct gao_descriptor_ring*	gao_create_descriptor_ring(struct gao_resources *resources, uint64_t num_descriptors) {
	struct gao_descriptor_ring 	*ring = NULL;
	uint64_t				queue_size = 0, index;

	queue_size = (sizeof(struct gao_descriptor_ring_header)
			+ (sizeof(struct gao_descriptor)*num_descriptors));

	ring = vmalloc(queue_size);
	check_ptr(ring);

	memset((void*)ring, 0, queue_size);

	if(gao_get_descriptors(resources, &ring->descriptors, num_descriptors))
		gao_error("User queue creation failed, insufficient descriptors.");

	//Initialize the ring values
	for(index = 0; index < num_descriptors; index++) {
		ring->descriptors[index].len = 0;
		ring->descriptors[index].offset = GAO_DEFAULT_OFFSET;
	}

	ring->header.capacity = num_descriptors;

	init_waitqueue_head(&ring->control.head_wait_queue);
	init_waitqueue_head(&ring->control.tail_wait_queue);
	ring->control.head_wait_queue_ref = &ring->control.head_wait_queue;
	ring->control.tail_wait_queue_ref = &ring->control.tail_wait_queue;

	ring->control.head_wake_condition_ref = &ring->control.head_wake_condition;
	ring->control.tail_wake_condition_ref = &ring->control.tail_wake_condition;

	spin_lock_init(&ring->control.head_lock);
	spin_lock_init(&ring->control.tail_lock);

	return ring;

	err:
	gao_free_descriptor_ring(resources, ring);
	return NULL;
}




static void	gao_free_egress_subqueue(struct gao_resources *resources, struct gao_egress_subqueue *subqueue) {
	if(subqueue->ring) gao_free_descriptor_ring(resources, subqueue->ring);
	subqueue->ring = NULL;
}

/**
 * Create the subqueues for an egress queue.
 * @warning Caller must hold resource lock
 * @param resources
 * @param port
 */
static void gao_free_egress_subqueues(struct gao_resources *resources, struct gao_queue *queue) {
	int64_t index;
	log_debug("Free subqueues for queue %p", queue);
	if(!queue) return;
	for(index = 0; index < GAO_MAX_PORT_SUBQUEUE; index++) {
		gao_free_egress_subqueue(resources, &queue->subqueues[index]);
	}
}


static int64_t	gao_create_egress_subqueue(struct gao_resources *resources, struct gao_egress_subqueue *subqueue, uint64_t num_descriptors) {
	int64_t ret = 0;

	subqueue->ring = gao_create_descriptor_ring(resources, num_descriptors);
	check_ptr_val(-ENOMEM, subqueue->ring);

	subqueue->ring->header.head = 0;
	subqueue->ring->header.tail = 0;

	log_debug("Successfully created subqueue.");
	return 0;
	err:
	gao_free_egress_subqueue(resources, subqueue);
	return ret;
}



/**
 * Delete a queue from its index. Will return descriptor groups, but does not unbind it.
 * @warning Caller must hold resource lock.
 * @warning Caller must have synchronized_rcu
 * @param resources
 * @param queue_index
 */
static void	gao_free_queue(struct gao_resources *resources, struct gao_queue *queue) {
	size_t	alloc_size;
	void	*pipeline_addr;
	log_debug("Deleting queue at %p", queue);

	if(!queue) return;

	gao_free_egress_subqueues(resources, queue);
	gao_free_descriptor_ring(resources, queue->ring);

	if(queue->action_map) vfree(queue->action_map);

	if(queue->descriptor_pipeline) {
		pipeline_addr = queue->descriptor_pipeline;
		alloc_size = queue->descriptor_pipeline_size;
		for(pipeline_addr = queue->descriptor_pipeline; pipeline_addr < ((void*)queue->descriptor_pipeline) + alloc_size; pipeline_addr += PAGE_SIZE) {
			ClearPageReserved(vmalloc_to_page(pipeline_addr));
		}

		vfree(queue->descriptor_pipeline);
	}

	if(queue->action_pipeline) {
		pipeline_addr = queue->action_pipeline;
		alloc_size = queue->action_pipeline_size;
		for(pipeline_addr = queue->action_pipeline; pipeline_addr < ((void*)queue->action_pipeline) + alloc_size; pipeline_addr += PAGE_SIZE) {
			ClearPageReserved(vmalloc_to_page(pipeline_addr));
		}

		vfree(queue->action_pipeline);
	}


	vfree(queue);

	return;
}

/**
 * Create a new queue and fill it with valid descriptors. Does not bind the queue to anything.
 * @warning Caller must hold resource lock.
 * @param resources
 * @param size The size of the queue in descriptors.
 * @return The index of the new queue on success, -ENOMEM (if insufficient memory/resources), -EFBIG if queue too big.
 */
static struct gao_queue*	gao_create_queue(struct gao_resources *resources, uint64_t num_descriptors, gao_direction_t direction) {
	struct gao_queue* 	queue = NULL;
	size_t				alloc_size = 0;
	void*				pipeline_addr;
	uint64_t			index = 0;
	log_debug("Creating queue, size=%lu", (unsigned long)num_descriptors);


	queue = vmalloc(sizeof(struct gao_queue));
	check_ptr(queue);

	memset((void*)queue, 0, sizeof(struct gao_queue));



	queue->ring = gao_create_descriptor_ring(resources, num_descriptors);
	check_ptr(queue->ring);



	if(direction == GAO_DIRECTION_RX) {
		queue->action_map = vmalloc(sizeof(struct gao_action)*num_descriptors);
		check_ptr(queue->action_map);

		//The following two structs are mmap'd to userspace. Allocate them as a multiple of the page size.
		//I really suck at number theory.
		alloc_size = (sizeof(struct gao_descriptor)*num_descriptors*GAO_ING_PIPELINE_DEPTH);
		alloc_size = (alloc_size % PAGE_SIZE) ? alloc_size + (PAGE_SIZE-(alloc_size%PAGE_SIZE)) : alloc_size;
		queue->descriptor_pipeline = vmalloc(alloc_size);
		check_ptr(queue->descriptor_pipeline);
		queue->descriptor_pipeline_size = alloc_size;
		memset((void*)queue->descriptor_pipeline, 0, alloc_size);

		log_debug("Allocated descriptor pipeline size %lu B at %p", alloc_size, queue->descriptor_pipeline);

		//Reserve the pages
		for(pipeline_addr = queue->descriptor_pipeline; pipeline_addr < ((void*)queue->descriptor_pipeline) + alloc_size; pipeline_addr += PAGE_SIZE) {
			SetPageReserved(vmalloc_to_page(pipeline_addr));
		}

		alloc_size = (sizeof(struct gao_action)*num_descriptors*GAO_ING_PIPELINE_DEPTH);
		alloc_size = (alloc_size % PAGE_SIZE) ? alloc_size + (PAGE_SIZE-(alloc_size%PAGE_SIZE)) : alloc_size;
		queue->action_pipeline = vmalloc(sizeof(struct gao_action)*num_descriptors*GAO_ING_PIPELINE_DEPTH);
		check_ptr(queue->action_pipeline);
		queue->action_pipeline_size = alloc_size;
		memset((void*)queue->action_pipeline, 0, alloc_size);

		log_debug("Allocated action pipeline size %lu B at %p", alloc_size, queue->action_pipeline);

		//Reserve the pages
		for(pipeline_addr = queue->action_pipeline; pipeline_addr < ((void*)queue->action_pipeline) + alloc_size; pipeline_addr += PAGE_SIZE) {
			SetPageReserved(vmalloc_to_page(pipeline_addr));
		}
	}

	queue->descriptors = num_descriptors;
	queue->state = GAO_RESOURCE_STATE_REGISTERED;



	log_debug("Created queue of size=%lu at addr=%p", (unsigned long)num_descriptors, queue);
	return queue;

	err:
	gao_free_queue(resources, queue);
	return NULL;
}


/**
 * From the perspective of a port that is being deleted, traverse all other ports and
 * null bindings to our egress queues.
 * @param resources
 * @param port
 */
static void	gao_port_null_egress_to_ingress_queue_map(struct gao_resources *resources, struct gao_port *port) {
	uint64_t	index = 0, subqueue_index;
	struct gao_queue *ingress_queue = NULL;
	struct gao_port	 *other_port = NULL;

	if(!port) gao_bug("Null port");
	log_debug("Nulling queue maps destined to port %lu", (unsigned long)port->gao_ifindex);
	//TODO: For now, just consider the case of SW to SW queuing. In the future, allow HW QOS passthrough
	//and direct binding of HW queues to queue maps.


	for(index = 0; index < GAO_MAX_PORTS; index++) {
		other_port = &resources->ports[index];
		if(other_port->state != GAO_RESOURCE_STATE_ACTIVE) continue;

		ingress_queue = other_port->rx_queues[0];
		if(!ingress_queue) {
			log_bug("Ingress side queue on active port %lu missing.", (unsigned long)index);
			continue;
		}

		//Bind each subqueue on this queue to the other queue's map towards us
		for(subqueue_index = 0; subqueue_index < GAO_MAX_PORT_SUBQUEUE; subqueue_index++) {

			log_debug("Null port %lu queue %lu subqueue %lu ",
					(unsigned long)other_port->gao_ifindex, (unsigned long)0, (unsigned long)subqueue_index);

			ingress_queue->queue_map.port[port->gao_ifindex].ring[subqueue_index] = NULL;
		}


	}


	err:
	return;
}

/**
 * Try to free a HW bound queue from a port. If the queue is bound to a file
 * it will only set the state and wake the file. The queue is unbound from the
 * port, but the file must then clean it up.
 * @warning Caller must hold resource lock
 * @param resources
 * @param queue
 */
static void	gao_free_port_queue(struct gao_resources *resources, struct gao_queue* queue) {

	if(!queue) gao_error("Cannot delete queue, pointer null.");

	//Anyone using the queue now will finish
	queue->state = GAO_RESOURCE_STATE_DELETING;
	synchronize_rcu();

	//FIXME: Wake any file potentially waiting on the queue
	//queue->ring->header.head_wake_condition_ref

	queue->binding.port = NULL;
	queue->binding.gao_ifindex = 0;
	queue->binding.queue_index = 0;
	queue->binding.direction_txrx = GAO_DIRECTION_NONE;
	queue->binding.owner_type = GAO_QUEUE_OWNER_NONE;
	queue->hw_private = NULL;


	//If it is bound to a file, don't delete it. The file will see the state on next file op and clean it up.
	if(!queue->binding.gao_file) {
		gao_free_queue(resources, queue);
	} else {
		atomic_long_set(queue->ring->control.head_wake_condition_ref, 1);
		wake_up_interruptible(queue->ring->control.head_wait_queue_ref);
	}



	err:
	return;
}

/**
 * Delete all the queues allocated to an interface.
 * If the queues were bound to a file, don't delete them, but remove references.
 * @warning Caller must hold resource lock
 * @param resources
 * @param interface
 */
void	gao_delete_port_queues(struct gao_resources *resources, struct gao_port *port) {
	uint64_t index;
	struct gao_queue *queue = NULL;

	//Remove references to our port from other ports.
	gao_port_null_egress_to_ingress_queue_map(resources, port);
	//Make sure nobody can be in the middle of transmitting these queues
	//**This removes the requirement to check queue state in forwarding code (that is under RCU lock)
	synchronize_rcu();

	if(port->tx_arbiter_workqueue) {
	//FIXME: Clean this up, the queue deletion routines also set the deleting state
	//But we need to kill the arbiters here...
		log_debug("Port %s[%lu] arbiter cleanup begins", (char*)&port->name, (unsigned long)port->gao_ifindex);
		for(index = 0; index < port->num_tx_queues; index++) {
			queue = port->tx_queues[index];
			if(!queue) continue;
			queue->state = GAO_RESOURCE_STATE_DELETING;
			log_debug("Waking tx arbiter %lu for deletion", (unsigned long)index);
			atomic_long_set(queue->ring->control.head_wake_condition_ref, 1);
			wake_up_interruptible(queue->ring->control.head_wait_queue_ref);
			atomic_long_set(queue->ring->control.tail_wake_condition_ref, ~0);
			wake_up_interruptible(queue->ring->control.tail_wait_queue_ref);
		}

		log_debug("Port %s[%lu] draining arbiter workqueue...", (char*)&port->name, (unsigned long)port->gao_ifindex);
		//This will block until all the tx arbiters have terminated
		drain_workqueue(port->tx_arbiter_workqueue);
		log_debug("Port %s[%lu] destroying arbiter workqueue...", (char*)&port->name, (unsigned long)port->gao_ifindex);
		destroy_workqueue(port->tx_arbiter_workqueue);
		port->tx_arbiter_workqueue = NULL;
	}


	for(index = 0; index < port->num_rx_queues; index++) {
		queue = port->rx_queues[index];
		if(!queue) continue;
		port->rx_queues[index] = NULL;
		gao_free_port_queue(resources, queue);
	}

	for(index = 0; index < port->num_tx_queues; index++) {
		queue = port->tx_queues[index];
		if(!queue) continue;
		port->tx_queues[index] = NULL;
		gao_free_port_queue(resources, queue);
	}


}



/**
 * From the perspective of one port, visit all other ports and bind our egress queues to their
 * queue maps.
 * @warning Caller must hold resource lock
 * @param resources
 * @param port
 * @return
 */
static int64_t gao_port_bind_egress_to_ingress_queue_map(struct gao_resources *resources, struct gao_port *port) {
	int64_t 	ret = 0;
	uint64_t	index = 0, subqueue_index;
	struct gao_queue *egress_queue = NULL, *ingress_queue = NULL;
	struct gao_port	 *other_port = NULL;

	if(!port) gao_bug_val(-EINVAL, "Null port");

	//TODO: For now, just consider the case of SW to SW queuing. In the future, allow HW QOS passthrough
	//and direct binding of HW queues to queue maps.

	egress_queue = port->tx_queues[0];
	if(!egress_queue) gao_bug_val(-EINVAL, "Null egress queue");


	//Traverse the other ports
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		other_port = &resources->ports[index];
		//If its ourselves, also bind it
		if( (other_port->state != GAO_RESOURCE_STATE_ACTIVE) && (other_port != port)) continue;

		//For now visit just their default queue
		ingress_queue = other_port->rx_queues[0];
		if(!ingress_queue) {
			log_bug("Ingress side queue on active port %lu missing.", (unsigned long)index);
			continue;
		}

		//Bind each subqueue on this queue to the other queue's map towards us
		for(subqueue_index = 0; subqueue_index < GAO_MAX_PORT_SUBQUEUE; subqueue_index++) {

			log_debug("Bind port %lu queue %lu subqueue %lu > port %lu queue %lu subqueue %lu",
					(unsigned long)port->gao_ifindex, (unsigned long)0, (unsigned long)subqueue_index,
					(unsigned long)other_port->gao_ifindex, (unsigned long)0, (unsigned long)subqueue_index);

			ingress_queue->queue_map.port[port->gao_ifindex].ring[subqueue_index] =
					egress_queue->subqueues[subqueue_index].ring;
		}

	}




	return 0;
	err:
	return ret;
}

/**
 * From the perspective of one port, traverse the other port's egress queues and bind their subqueues
 * to our queue map.
 * @warning Caller must hold resource lock
 * @param resources
 * @param port
 * @return
 */
static int64_t gao_port_bind_ingress_to_egress_subqueues(struct gao_resources *resources, struct gao_port *port) {
	int64_t	ret;
	uint64_t index, subqueue_index;
	struct gao_port *other_port = NULL;
	struct gao_queue *ingress_queue = NULL, *egress_queue = NULL;

	if(!port) gao_bug_val(-EINVAL, "Null port");

	//TODO: For now, just consider the case of SW to SW queuing. In the future, allow HW QOS passthrough
	//and direct binding of HW queues to queue maps.

	ingress_queue = port->rx_queues[0];
	if(!ingress_queue) gao_bug_val(-EINVAL, "Null egress queue");


	for(index = 0; index < GAO_MAX_PORTS; index++) {
		other_port = &resources->ports[index];
		if(other_port->state != GAO_RESOURCE_STATE_ACTIVE) continue;

		egress_queue = other_port->tx_queues[0];
		if(!egress_queue) {
			log_bug("Egress side queue on active port %lu missing.", (unsigned long)index);
			continue;
		}

		for(subqueue_index = 0; subqueue_index < GAO_MAX_PORT_SUBQUEUE; subqueue_index++) {

			log_debug("Bind port %lu queue %lu subqueue %lu > port %lu queue %lu subqueue %lu",
					(unsigned long)other_port->gao_ifindex, (unsigned long)0, (unsigned long)subqueue_index,
					(unsigned long)port->gao_ifindex, (unsigned long)0, (unsigned long)subqueue_index);

			ingress_queue->queue_map.port[other_port->gao_ifindex].ring[subqueue_index] =
					egress_queue->subqueues[subqueue_index].ring;


		}

	}

	return 0;
	err:
	return ret;
}


/**
 * Create the subqueues for an egress queue.
 * @warning Caller must hold resource lock
 * @param resources
 * @param port
 */
static int64_t gao_create_egress_subqueues(struct gao_resources *resources, struct gao_queue *queue) {
	int64_t ret = 0;

	//Create one default subqueue for now
	ret = gao_create_egress_subqueue(resources, &queue->subqueues[0], queue->binding.port->num_rx_desc);
	if(ret) gao_error("Failed to create subqueue. (ret=%ld)", (long)ret);

	queue->subqueues[0].ring->control.tail_wait_queue_ref = &queue->ring->control.tail_wait_queue;
	queue->subqueues[0].ring->control.tail_wake_condition_ref = &queue->ring->control.tail_wake_condition;


	return 0;
	err:
	gao_free_egress_subqueues(resources, queue);
	return ret;
}

/**
 * Allocate and initialize queues for an activating interface.
 * @warning Caller must hold resource lock
 * @param resources
 * @param interface
 * @return 0 on success, -ENOMEM for insufficient resources.
 */
int64_t gao_create_port_queues(struct gao_resources* resources, struct gao_port *port) {
	int64_t ret = 0;
	uint64_t index;
	//uint64_t groups_required, queues_required, groups_rx_per_queue, groups_tx_per_queue;

	struct gao_queue* queue = NULL;

	//Sanity check the interface queue values, confirm enough resources
	if(!port) gao_bug_val(-EFAULT, "Null Port");

	if(port->num_rx_queues > GAO_MAX_PORT_HWQUEUE || port->num_tx_queues > GAO_MAX_PORT_HWQUEUE)
			gao_error_val(-ENOMEM, "Interface asking for too many queues! (%u/%u)", port->num_rx_queues, port->num_tx_queues);


	//Loop and allocate rx queues, assign pointers
	for(index = 0; index < port->num_rx_queues; index++) {
		queue = gao_create_queue(resources, port->num_rx_desc, GAO_DIRECTION_RX);
		if(!queue) gao_error_val(-ENOMEM, "Failed to alloc rx if queue idx %ld", (long)index);

		queue->binding.owner_type = GAO_QUEUE_OWNER_PORT;
		queue->binding.direction_txrx = GAO_DIRECTION_RX;
		queue->binding.gao_ifindex = port->gao_ifindex;
		queue->binding.queue_index = index;
		queue->binding.port = port;

		queue->state = GAO_RESOURCE_STATE_ACTIVE;
		port->rx_queues[index] = queue;
	}

	for(index = 0; index < port->num_tx_queues; index++) {
		queue = gao_create_queue(resources, port->num_tx_desc, GAO_DIRECTION_TX);
		if(!queue) gao_error_val(-ENOMEM, "Failed to alloc tx if queue idx %ld", (long)index);

		queue->binding.owner_type = GAO_QUEUE_OWNER_PORT;
		queue->binding.direction_txrx = GAO_DIRECTION_TX;
		queue->binding.gao_ifindex = port->gao_ifindex;
		queue->binding.queue_index = index;
		queue->binding.port = port;

		gao_create_egress_subqueues(resources, queue);

		queue->state = GAO_RESOURCE_STATE_ACTIVE;
		port->tx_queues[index] = queue;

	}


	//All queues created successfully, put them in other ports' queue maps.
	ret = gao_port_bind_egress_to_ingress_queue_map(resources, port);
	if(ret) gao_error("Failed to bind egress queues to other ports (ret=%llu)", ret);
	//Get other ports' queues and put them in our map.
	ret = gao_port_bind_ingress_to_egress_subqueues(resources, port);
	if(ret) gao_error("Failed to bind other egress queues to this port (ret=%llu)", ret);


	return 0;
	err:
	gao_delete_port_queues(resources, port);
	return ret;
}


/**
 * Userspace request to bind to a queue for forwarding tap.
 * @param resources
 * @param request
 * @return
 */
int64_t	gao_bind_queue(struct file* filep, struct gao_request_queue *request) {
	int64_t ret;
	struct gao_file_private* gao_file = (struct gao_file_private*)filep->private_data;
	struct gao_port *port = NULL;
	struct gao_queue *queue = NULL;
	struct gao_resources* resources = gao_get_resources();

	log_debug("File %p requesting to bind to if/q %llu/%llu", filep, request->gao_ifindex, request->queue_index);

	gao_dump_file(filep);

	gao_lock_resources(resources);

	/*Error validation*/

	//Are we ready and unbound?
	if(gao_file->state != GAO_RESOURCE_STATE_REGISTERED) {
		gao_error_val(-EBUSY, "File already registered to (if/q) %llu/%llu",
				gao_file->bound_gao_ifindex, gao_file->bound_queue_index);
	}

	if(request->gao_ifindex >= GAO_MAX_PORTS) {
		gao_error_val(-EINVAL, "Requested ifindex out of range. (want=%llu max=%lu)", request->gao_ifindex, (unsigned long)GAO_MAX_PORTS);
	}

	port = &resources->ports[request->gao_ifindex];

	if(port->state != GAO_RESOURCE_STATE_ACTIVE)
		gao_error_val(-EIO, "Port not in active state (state:%s)", gao_resource_state_string(port->state));

	if(request->direction_txrx != GAO_DIRECTION_RX)
		gao_error_val(-EINVAL, "Only RX binding supported right now.");

	if(request->queue_index >= GAO_MAX_PORT_HWQUEUE || request->queue_index >= port->num_rx_queues)
		gao_error_val(-EINVAL, "Requested queue index out of range.");

	queue = port->rx_queues[request->queue_index];

	if(!queue) gao_error_val(-EINVAL, "Queue does not exist.");

	if(queue->binding.gao_file) gao_error_val(-EBUSY, "Queue already bound to a file.");

	if(queue->state != GAO_RESOURCE_STATE_ACTIVE)
		gao_error_val(-EIO, "Queue is not active. (state:%s)", gao_resource_state_string(queue->state));

	//We're good, bind the port.
	queue->binding.gao_file = gao_file;
	gao_file->bound_gao_ifindex = request->gao_ifindex;
	gao_file->bound_queue_index = request->queue_index;
	gao_file->bound_direction = request->direction_txrx;
	gao_file->bound_queue = queue;
	gao_file->port_ops = port->port_ops;
	gao_file->state = GAO_RESOURCE_STATE_ACTIVE;

	request->action_pipeline_size = queue->action_pipeline_size;
	request->descriptor_pipeline_size = queue->descriptor_pipeline_size;
	request->queue_size = queue->ring->header.capacity;

	//gao_file->port_ops->gao_disable_tx_interrupts()

	gao_dump_file(filep);

	log_debug("Successfully bound file %p to if/q %llu/%llu", filep, request->gao_ifindex, request->queue_index);

	gao_unlock_resources(resources);
	return 0;
	err:
	gao_unlock_resources(resources);
	return ret;
}

void	gao_unbind_queue(struct file* filep) {
	struct gao_file_private* gao_file = (struct gao_file_private*)filep->private_data;
	struct gao_queue *queue = NULL;
	struct gao_resources* resources = gao_get_resources();

	log_debug("File %p requesting to unbind.", filep);
	gao_dump_file(filep);
	gao_lock_resources(resources);

	if(gao_file->state != GAO_RESOURCE_STATE_ACTIVE) {
		gao_error("File not bound, cannot unbind.");
	}

	queue = gao_file->bound_queue;
	if(!queue) gao_bug("File was active, but no queue pointer!");
	queue->binding.gao_file = NULL;

	log_debug("File %p requesting to unbind to if/q %llu/%llu", filep, gao_file->bound_gao_ifindex, gao_file->bound_queue_index);

	gao_file->bound_direction = GAO_DIRECTION_NONE;
	gao_file->bound_gao_ifindex = 0;
	gao_file->bound_queue_index = 0;
	gao_file->bound_queue = NULL;
	gao_file->port_ops = NULL;
	gao_file->state = GAO_RESOURCE_STATE_REGISTERED;


	if(queue->state == GAO_RESOURCE_STATE_DELETING) {
		log_debug("While unbinding file, queue was deleting. Finish deleting it.");
		//Free port does a sync RCU
		gao_free_port_queue(resources, queue);
	}

	err:
	gao_dump_file(filep);
	gao_unlock_resources(resources);
	return;
}

static void		gao_free_ports(struct gao_resources *resources) {
	gao_controller_unregister_port(resources);
}

static int64_t	gao_init_ports(struct gao_resources *resources) {
	resources->free_ports = GAO_MAX_PORTS;
	gao_controller_register_port(resources);
	return 0;
}

/**
 * Returns the number of free slots (minus 1)
 * @param
 * @return
 */
uint64_t	gao_ring_slots_left(struct gao_descriptor_ring* ring) {
	return ((ring->header.capacity - CIRC_DIFF64(ring->header.write, ring->header.read, ring->header.capacity)) - 1);
}
EXPORT_SYMBOL(gao_ring_slots_left);

uint64_t	gao_ring_num_elements(struct gao_descriptor_ring* ring) {
	return CIRC_DIFF64(ring->header.write, ring->header.read, ring->header.capacity);
}
EXPORT_SYMBOL(gao_ring_num_elements);


int		gao_lock_resources(struct gao_resources* resources) {
	int ret = 0;
	log_debug("Trying to lock GAO Resources");
	ret = down_interruptible(&resources->config_lock);
	log_debug("Locked GAO Resources");
	return ret;
}
EXPORT_SYMBOL(gao_lock_resources);


void	gao_unlock_resources(struct gao_resources* resources) {
	up(&resources->config_lock);
	log_debug("Unlocking GAO Resources");
}
EXPORT_SYMBOL(gao_unlock_resources);

void	gao_free_resources(struct gao_resources *resources) {
	log_debug("Start free resources.");

	gao_free_ports(resources);
	gao_free_descriptor_allocator_ring(resources);
	gao_free_buffer_groups(resources);

}


int64_t		gao_init_resources(struct gao_resources *resources) {
	int64_t	ret;
	log_debug("Start initialize resources.");

	memset((void*)resources, 0, sizeof(struct gao_resources));

	sema_init(&resources->allocation_lock, 1);
	spin_lock_init(&resources->queue_lock);
	sema_init(&resources->config_lock, 1);


	if( (ret = gao_init_buffer_groups(resources)) ) goto err;

	if( (ret = gao_init_descriptor_allocator_ring(resources)) ) goto err;

	if( (ret = gao_init_ports(resources)) ) goto err;


	return 0;
	err:
	gao_free_resources(resources);
	return ret;
}





























