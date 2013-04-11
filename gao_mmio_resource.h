/*
 * gao_mmio_resource.h
 *
 *  Created on: 2013-01-03
 *      Author: cverge
 */

#ifndef GAO_MMIO_RESOURCE_H_
#define GAO_MMIO_RESOURCE_H_


#define __NO_VERSION__

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <linux/types.h>
#include <linux/if.h>
#include <linux/netdevice.h>

#include <linux/bug.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#else
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

#include "gao_log.h"
#include "gao_mmio_constants.h"






typedef enum gao_resource_state_t {
	GAO_RESOURCE_STATE_UNUSED = 0,
	GAO_RESOURCE_STATE_REGISTERED,
	GAO_RESOURCE_STATE_ACTIVE,
	GAO_RESOURCE_STATE_CONFIGURING,
	GAO_RESOURCE_STATE_DELETING,
	GAO_RESOURCE_STATE_ERROR,
	GAO_RESOURCE_STATE_FINAL,
} gao_resource_state_t;




#define GAO_VIRT_TO_BFN(VIRTADDR) 	((unsigned long)((virt_to_phys(VIRTADDR)) >> GAO_BFN_SHIFT))
#define GAO_BFN_TO_VIRT(BFN)		(phys_to_virt( ((BFN) << GAO_BFN_SHIFT) ))
#define GAO_PHYS_TO_BFN(PHYSADDR) 	((unsigned long)((PHYSADDR) >> GAO_BFN_SHIFT))
#define GAO_BFN_TO_PHYS(BFN)	  	((BFN) << GAO_BFN_SHIFT)

#define GAO_DESC_TO_PHYS(DESC)	(((unsigned long)DESC.index << (unsigned long)GAO_BFN_SHIFT) + ((unsigned long)DESC.offset))
#define GAO_DESC_TO_VIRT(DESC)	phys_to_virt(GAO_DESC_TO_PHYS(DESC))

#ifndef __KERNEL__
#define GAO_DESC_TO_PKT(DESC, OFFSET) ((void*)(OFFSET + GAO_DESC_TO_PHYS(DESC)))
#endif


/* +---------------------------------------------+
 * | 63-32			| 31-16		| 15-8	| 7-0	 |
 * | index			| len		| flags	| offset |
 * +---------------------------------------------+
 * index:		The buffer index in physical memory (address = index << log2(buf_size))
 * len: 		The length of the frame
 * index:		The index for the buffer within the buffer group
 * offset:		The offset where the frame should begin within the buffer.
 */
struct	gao_descriptor {
	uint8_t		offset;		//Lower 13 bits
	uint8_t	 	flags;
	uint16_t	len;
	uint32_t	index;
};
GAO_STATIC_ASSERT( (sizeof(struct gao_descriptor) == 8), "gao_descriptor size=8");

struct gao_descriptor_context {
	uint64_t	resv;
};

typedef enum gao_action_id {
	GAO_ACTION_DROP = 0,
	GAO_ACTION_FWD = 1,
	GAO_ACTION_MCAST = 2,
	GAO_ACTION_SLOWPATH = 3,
} gao_action_id_t;

struct gao_action {
	uint8_t		action_id;
	uint8_t		new_offset;
	uint16_t	new_len;

	union {
		struct {
			uint8_t	 dport;
			uint8_t	 dqueue;
			uint16_t resv;
		}fwd;
		struct {
			uint32_t group_id;
		}mcast;
		struct {
			uint32_t resv;
		}slow;
	};
};


struct gao_grid_header {
	union {
		struct {
			uint16_t	id;
			uint16_t	count;
			uint32_t	gao_ifindex;
			uint32_t	queue_idx;
			uint32_t	resv;
		};
	char pad[4096];
	};
};
GAO_STATIC_ASSERT(sizeof(struct gao_grid_header) == GAO_SMALLPAGE_SIZE, "grid header is not page sized");

//For expansion later, for userspace to signal the kernel
struct gao_grid_user {
	union {
		struct {
			uint32_t	resv;
		};
	char pad[4096];
	};
};
GAO_STATIC_ASSERT(sizeof(struct gao_grid_user) == GAO_SMALLPAGE_SIZE, "grid user header is not page sized");



struct gao_grid {
	struct gao_grid_header 	header;
	struct gao_grid_user	user;
	struct gao_descriptor	desc[GAO_GRID_SIZE];
	struct gao_descriptor_context desc_ctx[GAO_GRID_SIZE];
	struct gao_action		actions[GAO_GRID_SIZE];
};

GAO_STATIC_ASSERT((sizeof(struct gao_grid) % GAO_SMALLPAGE_SIZE) == 0, "grid not multiple of page size");
GAO_STATIC_ASSERT((sizeof(struct gao_descriptor[GAO_GRID_SIZE]) % GAO_SMALLPAGE_SIZE) == 0, "grid desc not multiple of page size");



#ifdef __KERNEL__


#define GAO_VALIDATE_DESC_ON 1
#ifdef GAO_VALIDATE_DESC_ON
#define GAO_VALIDATE_DESC(DESC) do {\
	__gao_validate_desc(DESC);\
	} while(0)
#else
#define GAO_VALIDATE_DESC(DESC)
#endif
static inline void __gao_validate_desc(struct gao_descriptor);


//Power of 2 circular buffer, absolute indicies.
struct gao_descriptor_ring {
	uint16_t	order; //log2 of the size of the ring
	uint16_t	_pad1;
	uint32_t	capacity; //total capacity in the ring, always power of 2
	uint32_t	mask; //Mask to access descriptor array (= capacity-1)
	uint32_t	watermark;
	uint32_t	avail; //Last descriptor that can be given to the NIC
	uint32_t	use; //Next descriptor to give to NIC
	uint32_t	clean; //Next descriptor to reclaim from NIC
	uint32_t	forward; //Next descriptor to either place in grid or return to allocator
	struct gao_descriptor	desc[];
};

//Power of 2 circular buffer, absolute indicies.
struct gao_descriptor_allocator_ring {
	spinlock_t		lock;
	struct gao_descriptor	*descriptors;
	uint32_t		use; //Index of the next descriptor that can be taken
	uint32_t		avail; //Index one past the last valid descriptor

	uint32_t		max_avail; //The uncommited but reserved avail space by returners
	uint32_t		return_delta; //The count of outstanding uncommited slots
};


static inline void __gao_lock_descriptor_allocator(struct gao_descriptor_allocator_ring *ring) {
	spin_lock_bh(&ring->lock);
}
#define gao_lock_descriptor_allocator(x) do {\
	log_lock("lock desc ring");\
	__gao_lock_descriptor_allocator(x);\
	log_lock("locked desc ring");\
	} while(0)

static inline void __gao_unlock_descriptor_ring(struct gao_descriptor_allocator_ring *ring) {
	spin_unlock_bh(&ring->lock);
}
#define gao_unlock_descriptor_ring(x) do {\
	log_lock("unlock desc ring");\
	__gao_unlock_descriptor_ring(x);\
	} while(0)



/**
 * Refill the descriptor ring starting at avail. Will get num_to_copy
 * descriptors, or less if there aren't enough left (could return 0).
 * @param allocator
 * @param ring
 * @param num_to_copy
 * @return The number of descriptors actually copied.
 */
static inline uint32_t	__gao_take_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_descriptor_ring* ring, uint32_t num_to_copy) {
	//struct gao_descriptor_allocator_ring *ring = &gao_get_resources()->descriptor_ring;
	uint32_t num_left, use;


	gao_lock_descriptor_allocator(allocator);
	use = allocator->use;

	//Get the minimum of the number of slots in the ring that need refilling, or the number of descriptors in the allocator
	num_to_copy = (num_to_copy > (allocator->avail - allocator->use) ? (allocator->avail - allocator->use) : num_to_copy);
	num_left = num_to_copy;

	allocator->use += num_to_copy; //pre-increment the index so we can unlock early
	log_debug("refill desc: use=%u avail=%u num_to_copy=%u", use, allocator->avail, num_to_copy);
	gao_unlock_descriptor_ring(allocator);
	//In theory, there should not be a case where descriptors are returned over us while we are copying
	//because there should be a finite number of descriptors in the system.

	while(num_left--) {
		GAO_VALIDATE_DESC(allocator->descriptors[use & (GAO_DESCRIPTORS-1)]);
		ring->desc[ring->avail & ring->mask] = allocator->descriptors[use & (GAO_DESCRIPTORS-1)];
		ring->avail++, use++;
	}


	log_debug("refill desc: use=%u avail=%u copied=%u total_desc=%u", use, allocator->avail, num_to_copy, allocator->avail - allocator->use);
	return num_to_copy;
}

/**
 * Refill the descriptor ring from avail until forward. If there are not
 * enough descriptors in the allocator, allocate as many as possible.
 * @param allocator
 * @param ring
 * @return
 */
static inline uint32_t	gao_refill_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_descriptor_ring* ring) {
	return __gao_take_descriptors(allocator, ring, (ring->capacity - (ring->avail - ring->forward)) );
}


/**
 * Return empty descriptors back to the descriptor ring. Uses the forward
 * index in the ring to begin returning.
 * @warning Should not be directly called -- I know I will flub the math somewhere!
 * @param allocator
 * @param ring
 * @param num_to_copy Number of descriptors to copy back.
 */
static inline void	__gao_release_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_descriptor_ring* ring, uint32_t num_to_copy) {
	//struct gao_descriptor_allocator_ring *ring = &gao_get_resources()->descriptor_ring;
	uint32_t num_left = num_to_copy, avail, start_avail;

	//First lock to reserve return space
	gao_lock_descriptor_allocator(allocator);

	start_avail = allocator->max_avail;
	avail = allocator->max_avail;

	//The number of outstanding copies in progress by returners
	allocator->return_delta += num_to_copy;
	//The max reserved but uncommited index
	allocator->max_avail += num_to_copy;

	//Check for logging purposes, we can't do anything about it, though. XXX: Crash here?
	if(unlikely( (allocator->max_avail - allocator->use) > GAO_DESCRIPTORS) ) {
		log_bug("DESCRIPTOR GOOF: Somebody is making up descriptors! ring=%p avail=%u max_avail=%u num_to_copy=%u delta=%u",
				ring, allocator->avail, allocator->max_avail, num_to_copy, allocator->return_delta);
	}

	log_debug("return desc start: avail=%u max_avail=%u num_to_copy=%u delta=%u", allocator->avail, allocator->max_avail, num_to_copy, allocator->return_delta);
	gao_unlock_descriptor_ring(allocator);

	//Perform the descriptor transfer
	while(num_left--) {
		GAO_VALIDATE_DESC(ring->desc[ring->forward & ring->mask]);
		allocator->descriptors[avail & (GAO_DESCRIPTORS-1)] = ring->desc[ring->forward & ring->mask];
		avail++, ring->forward++;
	}

	//Second lock to commit the reservation
	gao_lock_descriptor_allocator(allocator);

	allocator->return_delta -= num_to_copy;

	if(!allocator->return_delta) {
		//All of the transfers are finished, commit everything.
		allocator->avail = allocator->max_avail;
	} else if (allocator->avail == start_avail) {
		//Not at transfers done, but we are the bottom of the commit chain
		//So advance the avail up what we transferred.
		allocator->avail = avail;
	}
	log_debug("return desc done: use=%u avail=%u max_avail=%u num_to_copy=%u delta=%u total_desc=%u",
			allocator->use, allocator->avail, allocator->max_avail, num_to_copy, allocator->return_delta, allocator->avail - allocator->use);
	gao_unlock_descriptor_ring(allocator);

	return;
}



static inline void	gao_release_grid_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_grid *grid) {
	//struct gao_descriptor_allocator_ring *ring = &gao_get_resources()->descriptor_ring;
	uint32_t num_left = grid->header.count, avail, start_avail;

	//First lock to reserve return space
	gao_lock_descriptor_allocator(allocator);

	start_avail = allocator->max_avail;
	avail = allocator->max_avail;

	//The number of outstanding copies in progress by returners
	allocator->return_delta += grid->header.count;
	//The max reserved but uncommited index
	allocator->max_avail += grid->header.count;

	//Check for logging purposes, we can't do anything about it, though. XXX: Crash here?
	if(unlikely( (allocator->max_avail - allocator->use) > GAO_DESCRIPTORS) ) {
		log_bug("DESCRIPTOR GOOF: Somebody is making up descriptors! grid=%p avail=%u max_avail=%u num_to_copy=%u delta=%u",
				grid, allocator->avail, allocator->max_avail, grid->header.count, allocator->return_delta);
	}

	log_debug("return desc start: avail=%u max_avail=%u num_to_copy=%u delta=%u", allocator->avail, allocator->max_avail, grid->header.count, allocator->return_delta);
	gao_unlock_descriptor_ring(allocator);

	//Perform the descriptor transfer
	while(num_left--) {
		GAO_VALIDATE_DESC(grid->desc[num_left]);
		allocator->descriptors[avail & (GAO_DESCRIPTORS-1)] = grid->desc[num_left];
		avail++;
	}

	//Second lock to commit the reservation
	gao_lock_descriptor_allocator(allocator);

	allocator->return_delta -= grid->header.count;

	if(!allocator->return_delta) {
		//All of the transfers are finished, commit everything.
		allocator->avail = allocator->max_avail;
	} else if (allocator->avail == start_avail) {
		//Not at transfers done, but we are the bottom of the commit chain
		//So advance the avail up what we transferred.
		allocator->avail = avail;
	}
	log_debug("return desc done: use=%u avail=%u max_avail=%u num_to_copy=%u delta=%u total_desc=%u",
			allocator->use, allocator->avail, allocator->max_avail, grid->header.count, allocator->return_delta, allocator->avail - allocator->use);
	gao_unlock_descriptor_ring(allocator);

	return;
}



/**
 * Return empty descriptors back to the descriptor ring. Uses the forward
 * index in the ring to begin returning. Will return up to the clean index.
 * @param allocator
 * @param ring
 */
static inline void gao_return_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_descriptor_ring* ring) {
	if(ring->clean == ring->forward) return; //ring is empty, return without locking anything
	__gao_release_descriptors(allocator, ring, (ring->clean - ring->forward));
}

/**
 * Empty a descriptor ring, starting at the forward index until the avail index.
 * This should be used only on destruction or when it is certain that no other component
 * owns the other descriptor sections.
 * @param allocator
 * @param ring
 */
static inline void gao_empty_descriptors(struct gao_descriptor_allocator_ring *allocator, struct gao_descriptor_ring* ring) {
	if(ring->avail == ring->forward) return; //ring is empty, return without locking anything
	__gao_release_descriptors(allocator, ring, (ring->avail - ring->forward));
}

struct gao_grid_allocator {
	spinlock_t			lock;
	uint16_t			count;
	struct gao_grid*	grid_stack[GAO_GRIDS]; //stack of free grid IDs
	struct gao_grid*	grids[GAO_GRIDS]; //Keep a copy of the pointers so we can always dealloc
};


struct gao_rx_queue {
	uint32_t				id;
	uint32_t				port_id;
	spinlock_t				lock;

	atomic_t				starving; //If set, the queue ran out of descriptors and needs a kickoff again
	//Pointer for drivers to store rings/adapter structs for quick access
	void					*hw_private;

	struct gao_grid				*grid;

	struct gao_descriptor_ring 	ring;
};



struct gao_tx_queue {
	uint32_t				id;
	uint32_t				port_id;
	spinlock_t				lock;

	//Pointer for drivers to store rings/adapter structs for quick access
	void					*hw_private;

	struct gao_descriptor_ring ring;
};



struct gao_ll_node {
	void	*data;
	struct list_head list;
};

struct gao_ll_cache {
	uint32_t	capacity;
	uint32_t	count;
	struct gao_ll_node	list;
	struct gao_ll_node* nodes;
	struct gao_ll_node* free_nodes[];
};

static inline void gao_free_ll_cache(struct gao_ll_cache* cache) {
	if(cache) {
		if(cache->nodes) kfree(cache->nodes);
		kfree(cache);
	}
}

static inline struct gao_ll_cache* gao_create_ll_cache(uint32_t capacity) {
	struct gao_ll_cache* cache = NULL;
	uint32_t	i;

	cache = kmalloc(sizeof(struct gao_ll_cache) + (sizeof(struct gao_ll_node*)*capacity), GFP_KERNEL);
	check_ptr(cache);
	memset((void*)cache, 0, sizeof(struct gao_ll_cache) + (sizeof(struct gao_ll_node*)*capacity));

	cache->nodes = kmalloc((sizeof(struct gao_ll_node)*capacity), GFP_KERNEL);
	check_ptr(cache->nodes);

	cache->capacity = capacity;
	cache->count = capacity;

	INIT_LIST_HEAD(&cache->list.list);

	for(i = 0; i < capacity; i++) {
		cache->free_nodes[i] = &cache->nodes[i];
	}

	return cache;
	err:
	gao_free_ll_cache(cache);
	return NULL;
}

static inline struct gao_ll_node * gao_get_ll_cache_node(struct gao_ll_cache* cache) {
	struct gao_ll_node *tmp = NULL;
	if(unlikely(!cache->count)) {
		log_warn("Out of cache nodes!");
		return NULL;
	}
	cache->count--;
	tmp = cache->free_nodes[cache->count];
	cache->free_nodes[cache->count] = 0;
	return tmp;
}

static inline void gao_release_ll_cache_node(struct gao_ll_cache* cache, struct gao_ll_node *node) {
	if(unlikely((!node) || (cache->count == cache->capacity))) {
		log_bug("Returning null node");
		return;
	}
	cache->free_nodes[cache->count] = node;
	cache->count++;
	return;
}

static inline int32_t gao_ll_push(struct gao_ll_cache* cache, void *data) {
	struct gao_ll_node *node = gao_get_ll_cache_node(cache);
	if(!node) return -ENOMEM;
	node->data = data;
	list_add_tail(&node->list, &cache->list.list);
	return 0;
}

static inline void* gao_ll_remove(struct gao_ll_cache* cache) {
	struct gao_ll_node *node = NULL;
	void *data = NULL;
	if(cache->list.list.next == &cache->list.list) return NULL;

	node = list_entry(cache->list.list.next, struct gao_ll_node, list);
	data = node->data;
	list_del_init(&node->list);
	gao_release_ll_cache_node(cache, node);
	return data;
}


struct gao_queue_waitlist {
	spinlock_t			lock;

	uint32_t			is_blocking;

	wait_queue_head_t	rxq_wait; //waitlist for userspace
	struct gao_ll_cache	*rxq_list; //List of rx queues that need servicing

};


struct gao_hw_queue {
	uint32_t	port_id;
	uint32_t	id;
};

/**
 *
 * 1. A FIFO queue with unique entries, and guaranteed success on add/remove.
 * 2. A synchronization point for configuration (static index to pointers protected by RCU)
 * 3. Safe from any context (including hard interrupts)
 *
 * While the struct is wasteful, the size is reasonably bounded, and it has good performance.
 */
struct gao_queue_set {
	spinlock_t			lock;
	wait_queue_head_t	wait;
	uint32_t			waitcount;
	uint8_t				set_queues[GAO_MAX_PORTS][GAO_MAX_PORT_HWQUEUE];
	struct gao_hw_queue queues[GAO_MAX_PORTS*GAO_MAX_PORT_HWQUEUE];
	uint32_t			avail; //Points to next slot to put queues in
	uint32_t			use; //Points to next valid queue. If equal to avail queue is empty.
};










/**
 * The fabric applies actions to descriptors. It will forward
 * the descriptors to the appropriate queues and kick off schedulers
 * if required.
 *
 * It contains a queue of grids that are pending forwarding. Because it
 * runs on one CPU with only one instance, no locking is used for forwarding.
 */
struct gao_fabric {

	struct tasklet_struct	task;

	spinlock_t				lock; //Synchronizes the grid queue
	uint32_t				avail; //Points past the last grid to forward (add them here)
	uint32_t				use; //Points to next grid to forward (take them from here)
	struct gao_grid*		grids[GAO_GRIDS];



	//Descriptors to be returned to allocator (from drops/etc)
	struct gao_descriptor_ring* free_desc;
};




struct gao_file_private {
	/* Unused: File is being initialized.
	 * Registered: File has been created but not bound.
	 * Active: File has been bound to an interface queue.
	 * Deleting: File is being closed.
	 */
	gao_resource_state_t	state;
	struct semaphore		lock; //Only permit one call to FD at once
	struct file				*filep; //Backpointer
	struct gao_grid			*grid;




};

struct gao_port_ops {
	int64_t		(*gao_enable)(struct net_device*);
	int64_t		(*gao_disable)(struct net_device*);
	int32_t		(*gao_clean)(struct gao_descriptor_ring* ring, uint32_t num_to_clean, void *hw_private);
	int32_t		(*gao_recv)(struct gao_descriptor_ring* ring, uint32_t num_to_read, void *hw_private);
	int32_t		(*gao_xmit)(struct gao_descriptor_ring* ring, uint32_t num_to_xmit, void *hw_private);
	void		(*gao_enable_rx_intr)(struct gao_rx_queue*);
	void		(*gao_enable_tx_intr)(struct gao_tx_queue*);
	void		(*gao_disable_rx_intr)(struct gao_rx_queue*);
	void		(*gao_disable_tx_intr)(struct gao_tx_queue*);
};



typedef enum gao_port_type_t {
	GAO_PORT_PHYSICAL = 0,
	GAO_PORT_CONTROLLER,
} gao_port_type_t;



struct gao_port {
	//TODO: Persistence: map an constant identifier like the HW address to the gao_ifindex
	uint64_t				gao_ifindex; //gao internal gao_ifindex
	uint64_t				ifindex; //Kernel ifindex
	//FIXME: This is not updated if an interface name changes.
	char					_name[IFNAMSIZ];

	gao_resource_state_t 	state;
	gao_port_type_t			type;
	struct net_device		*netdev; //Set by ethernet driver
	struct gao_port_ops		*port_ops; //Set by ethernet driver

	uint32_t				num_rx_queues; //Set by ethernet driver
	uint32_t				num_rx_desc; //Set by ethernet driver
	struct gao_rx_queue		*rx_queues[GAO_MAX_PORT_HWQUEUE];
	uint32_t				num_tx_queues; //Set by ethernet driver
	uint32_t				num_tx_desc; //Set by ethernet driver
	struct gao_tx_queue		*tx_queues[GAO_MAX_PORT_HWQUEUE];

	//Scheduling arbiters attached to HW queues that serialize SW queues to the NIC ring
	int64_t					(*port_scheduler)(struct gao_tx_queue*);
};



struct gao_resources {
	/*Control*/
	/* Unused: GAO is initializing.
	 * Active: GAO is fully initialized and resources can be consumed.
	 * Deleting: GAO is exiting.
	 */
	gao_resource_state_t		state;
	//Resource allocation can sleep, should only be done on mod init and exit.
	struct semaphore 			config_lock; //Must be held to configure interfaces


	/*Buffers*/
	uint8_t						hugepage_mode;
	void						*hugepages[GAO_HUGEPAGES];
	void						*buffers[GAO_BUFFERS]; //MMAP'd to userspace
	void						*dummy_buffer; //Group mmap'd to any gaps in the bufferspace
	unsigned long				buffer_start_phys; //The first byte of physical space used by buffers
	unsigned long				buffer_end_phys; //Points to the first byte after the end of the space
	unsigned long				buffer_space_frame; //The total span of the buffers in physical memory.



	/*Descriptors*/
	struct gao_descriptor_allocator_ring	descriptor_allocator;
	struct gao_grid_allocator				grid_allocator;

	/*Queues*/
	struct gao_queue_set		rx_waitlist;

	struct gao_fabric			fabric;


	/*Interfaces*/
	struct gao_port				ports[GAO_MAX_PORTS];
	uint64_t					free_ports;
	//TODO: Replace with a hashmap down the road (maybe)
	//Used by ethernet drivers to lookup their GAO interface
	struct gao_port				*ifindex_to_port_lut[GAO_MAX_IFINDEX];
};


static inline unsigned long gao_descriptor_to_phys_addr(struct gao_descriptor descriptor) {
	return GAO_DESC_TO_PHYS(descriptor);
}

static inline void* gao_descriptor_to_virt_addr(struct gao_descriptor descriptor) {
	return GAO_DESC_TO_VIRT(descriptor);
}


static inline void __gao_lock_grid_allocator(struct gao_grid_allocator *allocator) {
	spin_lock_bh(&allocator->lock);
}
#define gao_lock_grid_allocator(x) do {\
	log_lock("lock grid allocator");\
	__gao_lock_grid_allocator(x);\
	log_lock("locked grid allocator");\
	} while(0)

static inline void __gao_unlock_grid_allocator(struct gao_grid_allocator *allocator) {
	spin_unlock_bh(&allocator->lock);
}
#define gao_unlock_grid_allocator(x) do {\
	log_lock("unlock grid allocator");\
	__gao_unlock_grid_allocator(x);\
	} while(0)





/* End of kernel-only structs */
#else
/* Userspace only Structs*/

struct gao_context {
	void*			buffer_addr;
	size_t			buffer_size;
	unsigned long	buffer_offset; //Difference between addr of first buffer and address 0 in phys mem
	unsigned long	phys_offset; //Difference between addr of first buffer and address 0 in phys mem
	void*			grid_addr;
	size_t			grid_size;
	int				fd; //Used for control
};


#endif



struct gao_request_mmap {
	unsigned long	bufferspace_size;
	unsigned long	gridspace_size;
	unsigned long	offset;
};



typedef enum gao_request_port_num_t {
	GAO_REQUEST_PORT_ENABLE = 0,
	GAO_REQUEST_PORT_DISABLE,
	GAO_REQUEST_PORT_LIST,
	GAO_REQUEST_PORT_GET_INFO,
} gao_request_port_num_t;

typedef enum gao_response_port_num_t {
	GAO_RESPONSE_PORT_OK = 0,
	GAO_RESPONSE_PORT_NOK,
} gao_response_port_num_t;


struct gao_request_port_info {
	uint64_t				gao_ifindex; //gao internal gao_ifindex
	uint64_t				ifindex; //Kernel ifindex
	char					name[IFNAMSIZ];
	gao_resource_state_t 	state;
	uint32_t				num_rx_queues;
	uint32_t				num_tx_queues;
};

struct gao_request_port_list {
	struct gao_request_port_info port[GAO_MAX_PORTS];
};

struct gao_request_port {
	gao_request_port_num_t 			request_code;
	gao_response_port_num_t 		response_code;
	uint64_t						gao_ifindex;
	void							*data;
};



/* IOCTL And Kernel/Userspace Communication */
#define GAO_MAJOR_NUM	0x10
#define GAO_IOCTL_COMMAND_GET_MMAP_SIZE _IOWR(GAO_MAJOR_NUM, 0x10, struct gao_request_mmap)
#define GAO_IOCTL_COMMAND_PORT _IOWR(GAO_MAJOR_NUM, 0x12, struct gao_request_port)
#define GAO_IOCTL_DUMP_RESC		_IO(GAO_MAJOR_NUM, 0x14)
#define GAO_IOCTL_RECV_GRID		_IO(GAO_MAJOR_NUM, 0x15)
#define GAO_IOCTL_SEND_GRID		_IO(GAO_MAJOR_NUM, 0x16)
#define GAO_IOCTL_EXCH_GRID		_IO(GAO_MAJOR_NUM, 0x17)


#ifdef __KERNEL__
/* Kernel-only functions */
extern struct gao_resources gao_global_resources;

static inline struct gao_resources*	gao_get_resources(void) {
	return &gao_global_resources;
}
static inline struct gao_port* gao_ifindex_to_port(int ifindex) {
	if(unlikely((unsigned int)ifindex >= GAO_MAX_IFINDEX)) return NULL;
	else return gao_global_resources.ifindex_to_port_lut[ifindex];
}

/**
 * Get an RCU safe pointer to an rxq from its gao port_id and qid.
 * @warning Pointer only valid under RCU lock
 * @param port_id
 * @param qid The hw queue id
 * @return May return NULL if the queue is invalid or does not exist.
 */
static inline struct gao_rx_queue* gao_rcu_get_rxq(uint32_t port_id, uint32_t qid) {
	struct gao_rx_queue* rxq = NULL;

	if(unlikely( (port_id >= GAO_MAX_PORTS) || (qid >= GAO_MAX_PORT_HWQUEUE) ))
		gao_error("get rxq: invalid port range");

	rxq = rcu_dereference(gao_global_resources.ports[port_id].rx_queues[qid]);

	err:
	return rxq;
}

/**
 * Get an RCU safe pointer to an rxq from its kernel ifindex and qid.
 * @warning Pointer only valid under RCU lock
 * @param ifindex The kernel ifindex of the port
 * @param qid The hw queue id
 * @return May return NULL if the queue is invalid or does not exist.
 */
static inline struct gao_rx_queue* gao_rcu_get_rxq_ifindex(int ifindex, uint32_t qid) {
	struct gao_port* port;

	if(unlikely(((unsigned int)ifindex) >= GAO_MAX_IFINDEX))
		return NULL;

	port = gao_global_resources.ifindex_to_port_lut[ifindex];

	if(likely(port)) return gao_rcu_get_rxq(port->gao_ifindex, qid);
	else return NULL;
}

/**
 * Get an RCU safe pointer to a txq from its gao port_id and qid.
 * @warning Pointer only valid under RCU lock
 * @param port_id
 * @param qid The hw queue id
 * @return May return NULL if the queue is invalid or does not exist.
 */
static inline struct gao_tx_queue* gao_rcu_get_txq(uint32_t port_id, uint32_t qid) {
	struct gao_tx_queue* txq = NULL;

	if(unlikely( (port_id >= GAO_MAX_PORTS) || (qid >= GAO_MAX_PORT_HWQUEUE) ))
		gao_error("get txq: invalid port range");

	txq = rcu_dereference(gao_global_resources.ports[port_id].tx_queues[qid]);

	err:
	return txq;
}

/**
 * Get an RCU safe pointer to a txq from its kernel ifindex and qid.
 * @warning Pointer only valid under RCU lock
 * @param ifindex The kernel ifindex of the port
 * @param qid The hw queue id
 * @return May return NULL if the queue is invalid or does not exist.
 */
static inline struct gao_tx_queue* gao_rcu_get_txq_ifindex(int ifindex, uint32_t qid) {
	struct gao_port* port;

	if(unlikely(((unsigned int)ifindex) >= GAO_MAX_IFINDEX))
		return NULL;

	port = gao_global_resources.ifindex_to_port_lut[ifindex];

	if(likely(port)) return gao_rcu_get_txq(port->gao_ifindex, qid);
	else return NULL;
}





static inline void __gao_validate_desc(struct gao_descriptor desc) {
	if(unlikely(
			((desc.index) < (gao_global_resources.buffer_start_phys >> GAO_BFN_SHIFT)) ||
			((desc.index) >= (gao_global_resources.buffer_end_phys >> GAO_BFN_SHIFT))
			)) {
		log_fatal("DESCRIPTOR GOOF: INVALID DESCRIPTOR INDEX %08x (%lx <-> %lx)",\
			desc.index, gao_global_resources.buffer_start_phys, gao_global_resources.buffer_end_phys);\
		WARN_ON(1);
	}
}


void 		gao_free_port_list(struct gao_request_port_list* list);
struct gao_request_port_list* gao_get_port_list(struct gao_resources* resources);
void		gao_free_port_info(struct gao_request_port_info* info);
struct gao_request_port_info* gao_get_port_info(struct gao_resources* resources, uint64_t gao_ifindex);


static inline const char*	gao_resource_state_string(gao_resource_state_t state) {
	switch(state) {
	case GAO_RESOURCE_STATE_UNUSED:
		return "Unused";
	case GAO_RESOURCE_STATE_REGISTERED:
		return "Registered";
	case GAO_RESOURCE_STATE_ACTIVE:
		return "Active";
	default:
		return "Invalid State";
	}
}

void		__gao_dump_resources(struct gao_resources* resources);
static inline void gao_dump_resources(void) {
	__gao_dump_resources(&gao_global_resources);
}

void		gao_free_resources(struct gao_resources* resources);
int64_t		gao_init_resources(struct gao_resources* resources);

int64_t 	gao_create_port_queues(struct gao_resources* resources, struct gao_port *port);
void		gao_delete_port_queues(struct gao_resources *resources, struct gao_port *port);

int64_t		gao_enable_gao_port(struct gao_resources *resources, uint64_t ifindex);
int64_t		gao_disable_gao_port(struct gao_resources *resources, uint64_t ifindex);

void		gao_controller_unregister_port(struct gao_resources *resources);
int64_t		gao_controller_register_port(struct gao_resources *resources);

void		gao_unlock_file(struct gao_file_private *gao_file);
int			gao_lock_file(struct gao_file_private *gao_file);

void 		gao_grid_return(struct gao_grid_allocator *allocator, struct gao_grid* grid);
struct gao_grid* gao_grid_get(struct gao_grid_allocator *allocator);

void 		gao_queue_set_add(struct gao_queue_set* set, uint32_t port_id, uint32_t qid);
void 		gao_queue_set_add_ifindex(struct gao_queue_set* set, int ifindex, uint32_t qid);
int32_t 	gao_queue_set_get(struct gao_queue_set* set, struct gao_hw_queue* hwq);
int32_t 	gao_queue_set_get_noblk(struct gao_queue_set* set, struct gao_hw_queue* hwq);

/* Exported functions */
int			gao_lock_resources(struct gao_resources* resources);
void		gao_unlock_resources(struct gao_resources* resources);

void		gao_unregister_port(struct net_device *netdev);
int64_t		gao_register_port(struct net_device *netdev, struct gao_port_ops* if_ops);
int64_t		gao_activate_port(struct gao_port* port);
void		gao_deactivate_port(struct gao_port* port);

char*		gao_get_port_name(struct gao_port* port);

void		gao_rx_clean(int ifindex, uint32_t qid);
void		gao_rx_interrupt_handle(int ifindex, uint32_t qid);
void 		gao_tx_interrupt_handle(int ifindex);

void		gao_fabric_task(unsigned long);

/* End of kernel-only functions */
#endif

static inline void* gao_desc_to_pkt(struct gao_descriptor descriptor, unsigned long offset) {
	return (void*)(offset + GAO_DESC_TO_PHYS(descriptor));
}

//
//inline void swap_descriptors(struct gao_descriptor *desc1, struct gao_descriptor *desc2);

#endif /* GAO_MMIO_RESOURCE_H_ */
