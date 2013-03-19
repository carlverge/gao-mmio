#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#ifndef LINUX
#define LINUX
#endif

#include <linux/delay.h>

#include <linux/rcupdate.h>
#include <linux/mm.h>
#include "gao_mmio_resource.h"


#define GAO_BUFFER_FILL_VAL			(0xDEADBEEF)
#define GAO_BUFFER_TEST_STR_LEN		(16)
#define GAO_BUFFER_TEST_STR_FMT		"GAO:BFN%08x"
/**
 * This "validates" the buffers by checking if we kernel panic when we
 * write into them. Writes a unique string into each buffer we can check
 * in the descriptor and userspace validation later on. Can only be done on
 * module init, and the module will not come up if this fails (neither will the machine...)
 * @param resources
 * @return Void on success, a machine in need of reboot on failure.
 */
static void		gao_validate_buffer_groups(struct gao_resources *resources) {
	uint64_t 	i;
	uint32_t 	bfn;
	void		*buffer;
	char		strbuf[GAO_BUFFER_TEST_STR_LEN];
	log_info("Validating buffer groups.");

	for(i = 0; i < GAO_BUFFERS; i++) {


//		Put a unique string in each buffer, and fill the rest with dead cows.

		buffer = resources->buffers[i];
//		log_debug("Validate buffer %p:", buffer);
		bfn = (uint32_t)GAO_VIRT_TO_BFN(buffer);

		snprintf((char*)&strbuf, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, bfn);

//		log_debug("Write to %p: %s. Fill with cows for %d",
//					buffer, (char*)&strbuf, (GAO_BUFFER_SIZE-GAO_BUFFER_TEST_STR_LEN));

		snprintf((char*)buffer, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, bfn);
		memset((buffer + GAO_BUFFER_TEST_STR_LEN), GAO_BUFFER_FILL_VAL, (GAO_BUFFER_SIZE-GAO_BUFFER_TEST_STR_LEN));


	}

	log_info("Buffer validation successful. Start=%lx End=%lx Size=%lx (%lu MB)",
			resources->buffer_start_phys, resources->buffer_end_phys, resources->buffer_space_frame, resources->buffer_space_frame >> 20);

	return;
}


/**
 * Free a single smallpage allocated buffer
 * Will also unreserve all pages in the buffer.
 * @param buffer
 */
static void		gao_free_buffer(void *buffer) {
	int64_t page_i;

	if(!buffer) gao_bug("Cannot free null buffer group.");

//	log_debug("Freeing a buffer group: Virt=%p Phys=%lx GFN=%lx", buffer_group,
//				(unsigned long)virt_to_phys(buffer_group),
//				GAO_VIRT_TO_GFN(buffer_group));

	for(page_i = 0; page_i < (GAO_BUFFER_SIZE); page_i += GAO_SMALLPAGE_SIZE) {
		ClearPageReserved( virt_to_page( (((unsigned long)buffer) + page_i) ));
	}

	kfree_null(buffer);

	err:
	return;
}

/**
 * Free a single hugepage allocated buffer group.
 * Will also unreserve all pages in the buffers.
 * @param hugepage
 */
static void		gao_free_hugepage(void	*hugepage) {
	int64_t page_index;

	if(!hugepage) gao_bug("Cannot free null hugepage.");

//	log_debug("Freeing a buffer group: Virt=%p Phys=%lx GFN=%lx", buffer_group,
//				(unsigned long)virt_to_phys(buffer_group),
//				GAO_VIRT_TO_GFN(buffer_group));

	for(page_index = 0; page_index < (GAO_HUGEPAGE_SIZE); page_index += GAO_SMALLPAGE_SIZE) {
		ClearPageReserved( virt_to_page( (((unsigned long)hugepage) + page_index) ));
	}

	kfree_null(hugepage);

	err:
	return;
}

/**
 * Free all of the buffers that were ever allocated. Checks for hugepage mode.
 * @param resources
 */
static void		gao_free_buffers(struct gao_resources *resources) {
	uint64_t	i;
	log_debug("Freeing all buffers.");


	if(resources->hugepage_mode) {
		gao_free_hugepage(resources->dummy_buffer);
		for(i = 0; i < GAO_HUGEPAGES; i++)
			gao_free_hugepage(resources->hugepages[i]);
	} else {
		gao_free_buffer(resources->dummy_buffer);
		for(i = 0; i < GAO_BUFFERS; i++)
			gao_free_buffer(resources->buffers[i]);
	}

	return;
}

/**
 * Allocate a single hugepage buffer group, and reserve the pages.
 * @return A pointer to the buffers on success, NULL on failure.
 */
static void* 	gao_alloc_hugepage(void) {
	int64_t page_index;
	void* hugepage = NULL;

	hugepage = kmalloc((GAO_HUGEPAGE_SIZE), GFP_KERNEL | __GFP_COMP);

	if(!hugepage) gao_error("Failed to allocate a buffer group.");

	if( (((unsigned long)hugepage) & ~(GAO_HUGEPAGE_SIZE-1)) != ((unsigned long)hugepage) )
		gao_error("A buffer group not aligned to hugepage boundary.");

	for(page_index = 0; page_index < (GAO_HUGEPAGE_SIZE); page_index += GAO_SMALLPAGE_SIZE) {
		SetPageReserved(virt_to_page( (((unsigned long)hugepage) + page_index) ));
	}

	return hugepage;
	err:
	return NULL;
}

/**
 * Allocate a single smallpage buffer, and reserve the pages.
 * @return A pointer to the buffer on success, NULL on failure.
 */
static void*	gao_alloc_buffer(void) {
	int64_t page_index;
	void* buffer = NULL;

	buffer = kmalloc((GAO_BUFFER_SIZE), GFP_KERNEL | __GFP_COMP);

	if(!buffer) gao_error("Failed to allocate a buffer.");

	if( (((unsigned long)buffer) & ~GAO_BFN_MASK) != ((unsigned long)buffer) )
		gao_error("A buffer not aligned to BFN boundary.");

	for(page_index = 0; page_index < (GAO_BUFFER_SIZE); page_index += GAO_SMALLPAGE_SIZE) {
		SetPageReserved(virt_to_page( (((unsigned long)buffer) + page_index) ));
	}

//	log_debug("Allocated a buffer group: Virt=%p Phys=%lx GFN=%lx", buffer_group,
//			(unsigned long)virt_to_phys(buffer_group),
//			GAO_VIRT_TO_GFN(buffer_group));

	return buffer;
	err:
	return NULL;
}

/**
 * Try to allocate the buffers using larger allocation chunks.
 * TODO: Doesn't force hugepages, but with aggressive THP, might get hugepages (how to force?)
 * If this fails to allocate all the buffers using hugepages,
 *  it backs out and no memory is allocated.
 * @param resources
 * @return 0 on success, -ENOMEM if buffers could not be allocated.
 */
static int64_t	gao_init_buffers_hugepages(struct gao_resources *resources) {
	int64_t ret = 0;
	uint64_t i, buf_i;
	void*	hugepage = NULL;
	unsigned long buffer_min = -1, buffer_max = 0, phys_addr;

	resources->hugepage_mode = 1;

	resources->dummy_buffer = gao_alloc_hugepage();
	if(!resources->dummy_buffer) gao_error_val(-ENOMEM, "Failed to allocate dummy buffer.");


	for(i = 0; i < GAO_HUGEPAGES; i++) {
		hugepage = gao_alloc_hugepage();
		if(!hugepage) gao_error_val(-ENOMEM, "Failed to allocate buffers with hugepages.");
		resources->hugepages[i] = hugepage;

		//Set min and max range values
		phys_addr = ((unsigned long)virt_to_phys(hugepage));
		if( phys_addr < buffer_min ) buffer_min = phys_addr;
		if( phys_addr > buffer_max ) buffer_max = phys_addr;
	}

	for(i = 0; i < GAO_HUGEPAGES; i++) {
		hugepage = resources->hugepages[i];
		log_debug("Splitting hugepage %llu", i);
		for(buf_i = 0; buf_i < GAO_BUFFER_PER_HUGEPAGE; buf_i++) {
			resources->buffers[(i*GAO_BUFFER_PER_HUGEPAGE)+buf_i] = hugepage + (buf_i*GAO_BUFFER_SIZE);
		}
	}

	resources->buffer_start_phys = buffer_min;
	resources->buffer_end_phys = (buffer_max + GAO_HUGEPAGE_SIZE);
	resources->buffer_space_frame = (resources->buffer_end_phys - resources->buffer_start_phys);

	return 0;
	err:
	resources->hugepage_mode = 0;
	gao_free_buffers(resources);
	return ret;
}

/**
 * Try to allocate the buffers using normal pages.
 * If this fails to allocate all the buffers, it backs out and no memory is allocated.
 * The kmod cannot initialize if this fails.
 * @param resources
 * @return 0 on success, -ENOMEM if buffers could not be allocated.
 */
static int64_t	gao_alloc_buffers(struct gao_resources *resources) {
	int64_t ret = 0;
	uint64_t i;
	void*	buffer = NULL;
	unsigned long buffer_min = -1, buffer_max = 0, phys_addr;


	resources->dummy_buffer = gao_alloc_buffer();
	if(!resources->dummy_buffer) gao_error_val(-ENOMEM, "Failed to allocate dummy buffer.");

	for(i = 0; i < GAO_BUFFERS; i++) {
		buffer = gao_alloc_buffer();
		if(!buffer) gao_error_val(-ENOMEM, "Failed to allocate buffer at index %lu.", (unsigned long)i);
		resources->buffers[i] = buffer;
		//Set min and max range values
		phys_addr = ((unsigned long)virt_to_phys(buffer));
		if( phys_addr < buffer_min ) buffer_min = phys_addr;
		if( phys_addr > buffer_max ) buffer_max = phys_addr;
	}

	resources->buffer_start_phys = buffer_min;
	resources->buffer_end_phys = (buffer_max + GAO_BUFFER_SIZE);
	resources->buffer_space_frame = (resources->buffer_end_phys - resources->buffer_start_phys);


	return 0;
	err:
	gao_free_buffers(resources);
	return ret;
}

/**
 * Allocate the memory for the buffer groups. Each buffer group is physically
 * contiguous and page-locked in memory.
 * @param resources
 * @return 0 on success, -ENOMEM on failure.
 */
static int64_t gao_init_buffer_groups(struct gao_resources *resources) {
	int64_t ret = 0;

	log_info("Allocating buffer groups.");

	log_debug("Trying hugepage allocation first");

	//If allocating hugepages fails, try using normal pagesize
	if(gao_init_buffers_hugepages(resources)) {
		log_debug("Hugepage allocation failed, trying normal page allocation...");
		if(gao_alloc_buffers(resources))
			gao_error_val(-ENOMEM, "Cannot allocate bufferspace, cannot initialize.");
	}

	gao_validate_buffer_groups(resources);

	log_info("Successfully allocated %lu buffers (hugepage mode:%s). [Start=%lx End=%lx Frame=%lx (%lu MB) Gaps=%lu]",
			(unsigned long)GAO_BUFFERS,
			resources->hugepage_mode ? "on" : "off",
			(unsigned long)resources->buffer_start_phys, (unsigned long)resources->buffer_end_phys,
			(unsigned long)resources->buffer_space_frame,
			(unsigned long)resources->buffer_space_frame >> 20,
			(unsigned long)((resources->buffer_space_frame/GAO_BUFFER_SIZE) - GAO_BUFFERS));

	return 0;
	err:
	gao_free_buffers(resources);
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
	uint64_t 	i;
	uint32_t	bfn;
	char		descriptor_str[GAO_BUFFER_TEST_STR_LEN], buffer_str[GAO_BUFFER_TEST_STR_LEN];
	uint32_t	*dead_cows;
	struct gao_descriptor descriptor;
	struct gao_descriptor *descriptors = resources->descriptor_allocator.descriptors;

	log_info("Validating descriptors.");

	dead_cows = vmalloc(GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN);
	if(!dead_cows) gao_error_val(-ENOMEM, "No moooomery for cows.");
	memset(dead_cows, GAO_BUFFER_FILL_VAL, (GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN));


	for(i = 0; i < GAO_DESCRIPTORS; i++) {
		descriptor = descriptors[i];
//		log_debug("DescIdx=%08x Phys=%016lx Virt=%p",
//				descriptor.index,
//				GAO_DESC_TO_PHYS(descriptor),
//				GAO_DESC_TO_VIRT(descriptor));

		bfn = descriptor.index;

		snprintf((char*)&descriptor_str, GAO_BUFFER_TEST_STR_LEN, GAO_BUFFER_TEST_STR_FMT, bfn);
		strncpy((char*)&buffer_str, (char*)GAO_DESC_TO_VIRT(descriptor), GAO_BUFFER_TEST_STR_LEN);
		ret = strncmp((char*)&descriptor_str, (char*)&buffer_str, GAO_BUFFER_TEST_STR_LEN);

		if(ret) {
			gao_bug_val(-EINVAL, "Error while validating descriptors, strings unequal: Buffer=%s Descriptor=%s Equal=%ld",
					(char*)&buffer_str, (char*)&descriptor_str, (long)ret);
			log_bug("Buffer=%s Descriptor=%s Memcmp=%ld", (char*)&buffer_str, (char*)&descriptor_str, (long)ret);
		}

		ret = memcmp(dead_cows, GAO_DESC_TO_VIRT(descriptor) + GAO_BUFFER_TEST_STR_LEN,  (GAO_BUFFER_SIZE - GAO_BUFFER_TEST_STR_LEN));

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

	if(resources->descriptor_allocator.descriptors)
		vfree(resources->descriptor_allocator.descriptors);

	return;
}

/**
 * Initialize the descriptor ring. Creates a descriptor for each buffer.
 * @param resources
 * @return 0 on success, -ENOMEM on failure.
 */
static int64_t	gao_init_descriptor_allocator_ring(struct gao_resources *resources) {
	int64_t		ret = 0;
	uint32_t	i, bfn;
	void		*buffer;

	struct gao_descriptor *descriptors = NULL;
	struct gao_descriptor descriptor;

	log_info("Initializing descriptors.");

	descriptors = vmalloc(GAO_DESCRIPTORS*sizeof(struct gao_descriptor));
	if(!descriptors) gao_error_val(-ENOMEM, "Failed to allocate descriptor ring.");

	for(i = 0; i < GAO_BUFFERS; i++) {
		buffer = resources->buffers[i];
		bfn = (uint32_t)(GAO_VIRT_TO_BFN(buffer));
		//Fill each descriptor slot with information on every buffer

		descriptor.index = bfn;
		descriptor.len = 0;
		descriptor.flags = 0;
		descriptor.offset = 0;

		descriptors[i] = descriptor;
	}

	log_info("Created %lu descriptors (Max=%lu).",
			(unsigned long)i, (unsigned long)GAO_DESCRIPTORS);

	resources->descriptor_allocator.descriptors = descriptors;
	resources->descriptor_allocator.use = 0;
	resources->descriptor_allocator.avail = i;
	resources->descriptor_allocator.max_avail = i;
	spin_lock_init(&resources->descriptor_allocator.lock);

	if(i != GAO_DESCRIPTORS)
		gao_bug_val(-EINVAL, "Mismatch between number of descriptors and buffers!");


	gao_validate_descriptor_allocator_ring(resources);

	return 0;
	err:
	gao_free_descriptor_allocator_ring(resources);
	return ret;
}





/**
 * @warning Should only be called on module initialization.
 */
static void	gao_grid_free(struct gao_grid* grid) {
	uint32_t	page_id;

	if(!grid)
		return;

	for(page_id = 0; page_id < (sizeof(struct gao_grid) / GAO_SMALLPAGE_SIZE); page_id++) {
		ClearPageReserved(vmalloc_to_page(((void*)grid) + (page_id*GAO_SMALLPAGE_SIZE)));
	}

	vfree(grid);
}

/**
 * @warning Should only be called on module initialization.
 * @return Pointer to a new grid.
 */
static struct gao_grid*	gao_grid_create(void) {
	struct gao_grid* grid = NULL;
	uint32_t	page_id;


	grid = vmalloc(sizeof(struct gao_grid));
	check_ptr(grid);
	memset((void*)grid, 0, sizeof(struct gao_grid));

	for(page_id = 0; page_id < (sizeof(struct gao_grid) / GAO_SMALLPAGE_SIZE); page_id++) {
		SetPageReserved(vmalloc_to_page(((void*)grid) + (page_id*GAO_SMALLPAGE_SIZE)));
	}

	return grid;
	err:
	gao_grid_free(grid);
	return NULL;
}

static void	gao_dtor_grid_allocator(struct gao_grid_allocator *allocator) {
	uint16_t grid_id;

	log_debug("Freeing grid allocator.");

	if(!allocator) return;

	for(grid_id = 0; grid_id < GAO_GRIDS; grid_id++) {
		gao_grid_free(allocator->grids[grid_id]);
		allocator->grids[grid_id] = NULL;
	}

	return;
}

static int64_t	gao_init_grid_allocator(struct gao_grid_allocator *allocator) {
	uint16_t grid_id;
	log_debug("Initializing grid allocator.");
	if(!allocator) gao_error("Null allocator");

	for(grid_id = 0; grid_id < GAO_GRIDS; grid_id++) {
		allocator->grids[grid_id] = gao_grid_create();
		check_ptr(allocator->grids[grid_id]);
		allocator->grids[grid_id]->header.id = grid_id;
		allocator->grid_stack[grid_id] = allocator->grids[grid_id];
	}

	spin_lock_init(&allocator->lock);
	allocator->count = GAO_GRIDS;

	log_debug("Successfully created grids.");
	return 0;
	err:
	gao_dtor_grid_allocator(allocator);
	return -ENOMEM;
}

void gao_grid_return(struct gao_grid_allocator *allocator, struct gao_grid* grid) {

	if(!allocator || !grid) {
		log_bug("Null allocator or grid during grid return.");
		return;
	}

	gao_lock_grid_allocator(allocator);

	if(unlikely(allocator->count == GAO_GRIDS)) gao_bug("Already at max grids, cant return!");

	allocator->grid_stack[allocator->count] = grid;
	allocator->count++;

	log_debug("Returned grid id %hu", grid->header.id);

	err:
	gao_unlock_grid_allocator(allocator);
}

struct gao_grid* gao_grid_get(struct gao_grid_allocator *allocator) {
	struct gao_grid* grid = NULL;

	if(!allocator) return grid;

	gao_lock_grid_allocator(allocator);

	if(unlikely(!allocator->count)) gao_bug("Out of grids!");

	allocator->count--;
	grid = allocator->grid_stack[allocator->count];

	log_debug("Got grid id %hu", grid->header.id);

	err:
	gao_unlock_grid_allocator(allocator);

	grid->header.count = 0;
	grid->header.gao_ifindex = 0;
	grid->header.queue_idx = 0;

	return grid;
}


static void gao_init_queue_set(struct gao_queue_set* set) {
	memset((void*)set, 0, sizeof(struct gao_queue_set));
	spin_lock_init(&set->lock);
	init_waitqueue_head(&set->wait);
}

/**
 * Add the specified queue to the set. If the id/qid combination is valid,
 * the add must succeed.
 * @param set
 * @param port_id The gao port_id (not the kernel's)
 * @param qid The HW qid.
 */
void gao_queue_set_add(struct gao_queue_set* set, uint32_t port_id, uint32_t qid) {
	unsigned long flags = 0;

	if(unlikely( (port_id >= GAO_MAX_PORTS) || (qid >= GAO_MAX_PORT_HWQUEUE) ))
		return;

	spin_lock_irqsave(&set->lock, flags);

	if(unlikely( (set->avail-set->use) > (GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE) ))
		log_bug("Queue set at %p overflowed", set);

	if(!set->set_queues[port_id][qid]) {
		set->queues[set->avail & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].port_id = port_id;
		set->queues[set->avail & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].id = qid;
		set->set_queues[port_id][qid] = 1;
		set->avail++;
	}

	if(set->waitcount) {
		wake_up_interruptible(&set->wait);
	}

	spin_unlock_irqrestore(&set->lock, flags);
}

void gao_queue_set_add_ifindex(struct gao_queue_set* set, int ifindex, uint32_t qid) {
	struct gao_port* port;

	if(unlikely(((unsigned int)ifindex) >= GAO_MAX_IFINDEX))
		return;

	port = gao_global_resources.ifindex_to_port_lut[ifindex];
	if(likely(port)) gao_queue_set_add(set, port->gao_ifindex, qid);
}

/**
 * Blocking read on a queue set. Reads the next queue into the hwqueue struct
 * pointed to by hwq.
 * @warning Only called from user context
 * @param set
 * @param hwq A pointer to an empty hw_queue to read into
 * @return -EINTR if interrupted, 0 on success.
 */
int32_t gao_queue_set_get(struct gao_queue_set* set, struct gao_hw_queue* hwq) {
	unsigned long flags = 0;
	int32_t	ret = 0;
	uint32_t port_id, qid;

	spin_lock_irqsave(&set->lock, flags);

	while((set->avail == set->use) && !ret) {
		set->waitcount++;
		spin_unlock_irqrestore(&set->lock, flags);

		if(wait_event_interruptible(set->wait, (set->avail > set->use))) {
			spin_lock_irqsave(&set->lock, flags);
			set->waitcount--;
			spin_unlock_irqrestore(&set->lock, flags);
			log_debug("read queue set interrupted");
			return -EINTR;

		}

		spin_lock_irqsave(&set->lock, flags);
		set->waitcount--;
	}


	port_id = set->queues[set->use & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].port_id;
	qid = set->queues[set->use & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].id;
	hwq->port_id = port_id;
	hwq->id = qid;
	set->set_queues[port_id][qid] = 0;
	set->use++;

	spin_unlock_irqrestore(&set->lock, flags);
	return 0;
}

/**
 * Non blocking read on a queue set. Reads the next queue into the hwqueue
 * struct pointed to by hwq.
 * @param set
 * @param hwq A pointer to an empty hw_queue to read into
 * @return -EAGAIN if there is no queue. 0 on success.
 */
int32_t gao_queue_set_get_noblk(struct gao_queue_set* set, struct gao_hw_queue* hwq) {
	unsigned long flags = 0;
	int32_t	ret = -EAGAIN;
	uint32_t port_id, qid;

	spin_lock_irqsave(&set->lock, flags);

	if(set->avail > set->use) {
		port_id = set->queues[set->use & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].port_id;
		qid = set->queues[set->use & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].id;
		hwq->port_id = port_id;
		hwq->id = qid;
		set->set_queues[port_id][qid] = 0;
		set->use++;
		ret = 0;
	}

	spin_unlock_irqrestore(&set->lock, flags);
	return ret;
}





static void gao_dtor_descriptor_ring(struct gao_descriptor_ring* ring) {

}

static int64_t gao_init_descriptor_ring(struct gao_descriptor_ring* ring, uint32_t order) {
	memset((void*)ring, 0, ((1 << order)*sizeof(struct gao_descriptor)));

	ring->capacity = (1 << order);
	ring->mask = (ring->capacity - 1);
	ring->order = order;

	return 0;
}

static void gao_free_descriptor_ring(struct gao_descriptor_ring* ring) {
	if(ring) {
		gao_dtor_descriptor_ring(ring);
		kfree(ring);
	}
}

static  struct gao_descriptor_ring* gao_create_descriptor_ring(uint32_t order) {
	struct gao_descriptor_ring* ring = NULL;
	size_t	alloc_size;

	if( (order > GAO_MAX_QUEUE_ORDER) || (order < GAO_MIN_QUEUE_ORDER) )
		gao_error("Invalid descriptor ring order: %u", order);

	alloc_size = ((1 << order)*sizeof(struct gao_descriptor));
	log_debug("Creating descriptor ring with order %u, alloc size=%ldB", order, alloc_size);
	ring = kmalloc(alloc_size, GFP_KERNEL);
	check_ptr(ring);

	if(gao_init_descriptor_ring(ring, order)) gao_error("Failed to init descriptor ring");

	return ring;
	err:
	gao_free_descriptor_ring(ring);
	return NULL;
}



static void gao_free_rx_queue(struct gao_resources *resources, struct gao_rx_queue* queue) {
	if(queue) {
		log_debug("Freeing rx queue %u/%u", queue->port_id, queue->id);
		gao_empty_descriptors(&resources->descriptor_allocator, &queue->ring);
		kfree(queue);
	}
}

static struct gao_rx_queue* gao_create_rx_queue(struct gao_resources *resources, uint32_t order) {
	struct gao_rx_queue *queue = NULL;
	size_t	alloc_size;

	if( (order > GAO_MAX_QUEUE_ORDER) || (order < GAO_MIN_QUEUE_ORDER) )
		gao_error("Invalid rx queue order: %u", order);

	alloc_size = (sizeof(struct gao_rx_queue) + ((1 << order)*sizeof(struct gao_descriptor)));
	log_debug("Creating rx queue with order %u, alloc size=%ldB", order, alloc_size);
	queue = kmalloc(alloc_size, GFP_KERNEL);
	check_ptr(queue);

	memset((void*)queue, 0, alloc_size);
	spin_lock_init(&queue->lock);

	if(gao_init_descriptor_ring(&queue->ring, order)) gao_error("Failed ot init descriptor ring");

	gao_refill_descriptors(&resources->descriptor_allocator, &queue->ring);
	log_debug("Initial fill of ring got: use=%u avail=%u", queue->ring.use, queue->ring.avail);

	return queue;
	err:
	gao_free_rx_queue(resources, queue);
	return NULL;
}

static void gao_free_tx_queue(struct gao_resources *resources, struct gao_tx_queue* queue) {
	if(queue) {
		log_debug("Freeing tx queue %u/%u", queue->port_id, queue->id);
		gao_empty_descriptors(&resources->descriptor_allocator, &queue->ring);
		kfree(queue);
	}
}

static struct gao_tx_queue* gao_create_tx_queue(struct gao_resources *resources, uint32_t order) {
	struct gao_tx_queue *queue = NULL;
	size_t	alloc_size;

	if( (order > GAO_MAX_QUEUE_ORDER) || (order < GAO_MIN_QUEUE_ORDER) )
		gao_error("Invalid tx queue order: %u", order);

	log_debug("Creating tx queue with order %u", order);
	alloc_size = (sizeof(struct gao_rx_queue) + ((1 << order)*sizeof(struct gao_descriptor)));
	queue = kmalloc(alloc_size, GFP_KERNEL);
	check_ptr(queue);

	memset((void*)queue, 0, alloc_size);
	spin_lock_init(&queue->lock);


	if(gao_init_descriptor_ring(&queue->ring, order)) gao_error("Failed ot init descriptor ring");

	return queue;
	err:
	gao_free_tx_queue(resources, queue);
	return NULL;
}

void		gao_delete_port_queues(struct gao_resources *resources, struct gao_port *port) {
	uint64_t i;
	struct gao_rx_queue* rxq;
	struct gao_tx_queue* txq;

	if(port) {
		log_debug("Deleting port queues for port %llu", port->gao_ifindex);

		for(i = 0; i < GAO_MAX_PORT_HWQUEUE; i++) {
			rxq = port->rx_queues[i];
			rcu_assign_pointer(port->rx_queues[i], NULL);
			if(rxq) {
				synchronize_rcu();
				gao_free_rx_queue(resources, rxq);
			}

			txq = port->tx_queues[i];
			rcu_assign_pointer(port->tx_queues[i], NULL);
			if(txq) {
				synchronize_rcu();
				gao_free_tx_queue(resources, txq);
			}
		}


	}


}

int64_t 	gao_create_port_queues(struct gao_resources* resources, struct gao_port *port) {
	int64_t ret = 0;
	uint64_t i = 0;
	struct gao_rx_queue *rxq = NULL;
	struct gao_tx_queue *txq = NULL;


	if(!port)
		gao_bug_val(-EINVAL, "Null port");

	if(port->num_rx_queues > GAO_MAX_PORT_HWQUEUE || port->num_tx_queues > GAO_MAX_PORT_HWQUEUE)
		gao_bug_val(-EINVAL, "Port requesting too many queues. (%u/%u)", port->num_rx_queues, port->num_tx_queues);

	log_debug("Creating port queues for port %llu", port->gao_ifindex);


	for(i = 0; i < GAO_MAX_PORT_HWQUEUE; i++) {
		port->rx_queues[i] = NULL;
		port->tx_queues[i] = NULL;
	}

	for(i = 0; i < port->num_rx_queues; i++) {
		rxq = gao_create_rx_queue(resources, GAO_DEFAULT_QUEUE_ORDER);
		check_ptr(rxq);
		port->rx_queues[i] = rxq;
		//Fail if we don't get enough descriptors to fill the hardware queue on init.
		if( (rxq->ring.avail - rxq->ring.use) < port->num_rx_desc ) {
			log_error("Could not get enough descriptors to init port/q (%llu/%lld) needed/got (%u/%u)",
					port->gao_ifindex, i, port->num_rx_desc, (rxq->ring.avail - rxq->ring.use));
		}

		rxq->id = i;
		rxq->port_id = port->gao_ifindex;

	}

	for(i = 0; i < port->num_tx_queues; i++) {
		txq = gao_create_tx_queue(resources, GAO_DEFAULT_QUEUE_ORDER);
		check_ptr(txq);
		port->tx_queues[i] = txq;

		txq->id = i;
		txq->port_id = port->gao_ifindex;

	}



	return 0;
	err:
	gao_delete_port_queues(resources, port);
	return ret;
}

//static void		gao_dtor_queue_waitlist(struct gao_queue_waitlist *waitlist) {
//	if(waitlist) {
//		if(waitlist->rxq_list) gao_free_ll_cache(waitlist->rxq_list);
//	}
//}
//
//static int64_t	gao_init_queue_waitlist(struct gao_queue_waitlist *waitlist) {
//
//	spin_lock_init(&waitlist->lock);
//
//	waitlist->rxq_list = gao_create_ll_cache(256);
//	check_ptr(waitlist->rxq_list);
//	waitlist->is_blocking = 0;
//	init_waitqueue_head(&waitlist->rxq_wait);
//
//	return 0;
//	err:
//	gao_dtor_queue_waitlist(waitlist);
//	return -ENOMEM;
//}

static void gao_dtor_fabric(struct gao_fabric *fabric) {
	log_debug("Destroying fabric.");

	//Not returning descriptors here because the module is exiting.
	if(fabric->free_desc) gao_free_descriptor_ring(fabric->free_desc);

	log_debug("Killing fabric task.");
	tasklet_kill(&fabric->task);

}

static int64_t	gao_init_fabric(struct gao_fabric *fabric) {
	log_debug("Initializing fabric. Mmmm. Soft.");

	memset((void*)fabric, 0, sizeof(struct gao_fabric));

	fabric->free_desc = gao_create_descriptor_ring(GAO_GRID_ORDER);
	check_ptr(fabric->free_desc);

	tasklet_init(&fabric->task, gao_fabric_task, (unsigned long)fabric);

	return 0;
	err:
	gao_dtor_fabric(fabric);
	return -ENOMEM;
}


static void		gao_free_ports(struct gao_resources *resources) {

}

static int64_t	gao_init_ports(struct gao_resources *resources) {
	resources->free_ports = GAO_MAX_PORTS;

	return 0;
}



int		gao_lock_resources(struct gao_resources* resources) {
	int ret = 0;
	log_debug("Trying to lock GAO Resources");
	ret = down_interruptible(&resources->config_lock);
	log_debug("Locked GAO Resources");
	return ret;
}
EXPORT_SYMBOL(gao_lock_resources);


void	gao_unlock_file(struct gao_file_private *gao_file) {
	up(&gao_file->lock);
	//log_debug("Unlock GAO Filep bound to if/q %llu/%llu", gao_file->bound_gao_ifindex, gao_file->bound_queue_index);
}


int		gao_lock_file(struct gao_file_private *gao_file) {
	int ret = 0;
	//log_debug("Trying to lock GAO Filep bound to if/q %llu/%llu", gao_file->bound_gao_ifindex, gao_file->bound_queue_index);
	ret = down_interruptible(&gao_file->lock);
	log_debug("Locked GAO Resources");
	return ret;
}

void	__gao_dump_resources(struct gao_resources* resources) {
	uint64_t i,j;
	struct gao_port *port = NULL;
	struct gao_rx_queue *rxq = NULL;
	struct gao_tx_queue *txq = NULL;

	log_info("Dumping Global Resource State:");
	log_info("Buffers: hugepages:%s num=%lu start=%lx end=%lx frame=%lx (%lu MB) gaps=%lu range: %08lx <-> %08lx",
				resources->hugepage_mode ? "on" : "off",
				(unsigned long)GAO_BUFFERS,
				(unsigned long)resources->buffer_start_phys, (unsigned long)resources->buffer_end_phys,
				(unsigned long)resources->buffer_space_frame,
				(unsigned long)resources->buffer_space_frame >> 20,
				(unsigned long)((resources->buffer_space_frame/GAO_BUFFER_SIZE) - GAO_BUFFERS),
				resources->buffer_start_phys >> GAO_BFN_SHIFT, resources->buffer_end_phys >> GAO_BFN_SHIFT);
	log_info("Descriptor Allocator: free=(%u/%u) use=%u avail=%u max_avail=%u commit_delta=%u",
			resources->descriptor_allocator.avail - resources->descriptor_allocator.use, GAO_DESCRIPTORS, resources->descriptor_allocator.use,
			resources->descriptor_allocator.avail, resources->descriptor_allocator.max_avail, resources->descriptor_allocator.return_delta);
	log_info("Grid Allocator: free=(%u/%u) ",
			resources->grid_allocator.count, GAO_GRIDS);

	log_info("RX Waitlist: use=%u avail=%u", resources->rx_waitlist.use, resources->rx_waitlist.avail);
	for(i = ACCESS_ONCE(resources->rx_waitlist.use); i != resources->rx_waitlist.avail; i++) {
		log_info("%llu: port=%u id=%u", i,
				resources->rx_waitlist.queues[i & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].port_id,
				resources->rx_waitlist.queues[i & ((GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE)-1)].id);
	}


	log_info("Queues:");
	for(i = 0; i < GAO_MAX_PORTS; i++) {
		port = &resources->ports[i];
		if(port->state == GAO_RESOURCE_STATE_ACTIVE) {
			for(j = 0; j < port->num_rx_queues; j++) {
				rxq = port->rx_queues[j];
				log_info("rxq %llu/%u: (starving: %s) capacity=%u watermark=%u avail=%u/%u use=%u/%u clean=%u/%u forward=%u/%u left=%u",
						port->gao_ifindex, rxq->id, atomic_read(&rxq->starving) ? "yes" : "no",
						rxq->ring.capacity, rxq->ring.watermark, rxq->ring.avail, rxq->ring.avail&rxq->ring.mask,
						rxq->ring.use, rxq->ring.use&rxq->ring.mask, rxq->ring.clean, rxq->ring.clean&rxq->ring.mask, rxq->ring.forward,
						rxq->ring.forward&rxq->ring.mask, rxq->ring.avail - rxq->ring.forward);
			}
			for(j = 0; j < port->num_tx_queues; j++) {
				txq = port->tx_queues[j];
				log_info("txq %llu/%u: capacity=%u watermark=%u avail=%u/%u use=%u/%u clean=%u/%u forward=%u/%u left=%u",
						port->gao_ifindex, txq->id, txq->ring.capacity, txq->ring.watermark, txq->ring.avail, txq->ring.avail&txq->ring.mask,
						txq->ring.use, txq->ring.use&txq->ring.mask, txq->ring.clean, txq->ring.clean&txq->ring.mask, txq->ring.forward,
						txq->ring.forward&txq->ring.mask, txq->ring.avail - txq->ring.forward);
			}
		}
	}

}

void	gao_unlock_resources(struct gao_resources* resources) {
	up(&resources->config_lock);
	log_debug("Unlocking GAO Resources");
}
EXPORT_SYMBOL(gao_unlock_resources);


void	gao_free_resources(struct gao_resources *resources) {
	log_debug("Start free resources.");

	gao_dtor_fabric(&resources->fabric);
	gao_free_ports(resources);
	//gao_dtor_queue_waitlist(&resources->waitlist);
	gao_dtor_grid_allocator(&resources->grid_allocator);
	gao_free_descriptor_allocator_ring(resources);
	gao_free_buffers(resources);

}

void gao_ll_test(void) {
	int		n1 = 1, n3 = 3, n4 = 4, n5 = 5;
	struct gao_ll_cache *ll = gao_create_ll_cache(3);
	int *ret;
	log_debug("push 1 ret %d", gao_ll_push(ll, &n1));
	log_debug("push 3 ret %d", gao_ll_push(ll, &n3));
	log_debug("push 5 ret %d", gao_ll_push(ll, &n5));
	log_debug("push 4 ret %d", gao_ll_push(ll, &n4));
	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	log_debug("push 3 ret %d", gao_ll_push(ll, &n3));

	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	ret = gao_ll_remove(ll);
	if(ret) log_debug("remove ret %d", *ret);
	else log_debug("remove returned null");

	gao_free_ll_cache(ll);
}

int64_t		gao_init_resources(struct gao_resources *resources) {
	log_debug("Start initialize resources.");

	memset((void*)resources, 0, sizeof(struct gao_resources));

	sema_init(&resources->config_lock, 1);

	if(gao_init_buffer_groups(resources)) goto err;

	if(gao_init_descriptor_allocator_ring(resources)) goto err;

	if(gao_init_grid_allocator(&resources->grid_allocator)) goto err;

	gao_init_queue_set(&resources->rx_waitlist);

	if(gao_init_ports(resources)) goto err;

	if(gao_init_fabric(&resources->fabric)) goto err;


	return 0;
	err:
	gao_free_resources(resources);
	return -1;
}





























