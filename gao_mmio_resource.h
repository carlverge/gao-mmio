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
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/circ_buf.h>
//#include <asm-generic/page.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/fcntl.h>
#include <linux/wait.h>
#include <linux/rcupdate.h>
#else
#include <stdint.h>
#include <net/if.h>
#endif
#include "log.h"
#include "gao_mmio_constants.h"


typedef enum gao_owner_type_t {
	GAO_QUEUE_OWNER_NONE = 0,
	GAO_QUEUE_OWNER_USERSPACE,
	GAO_QUEUE_OWNER_PORT,
} gao_owner_type_t;

typedef enum gao_direction_t {
	GAO_DIRECTION_NONE = 0,
	GAO_DIRECTION_RX,
	GAO_DIRECTION_TX,
} gao_direction_t;

typedef enum gao_resource_state_t {
	GAO_RESOURCE_STATE_UNUSED = 0,
	GAO_RESOURCE_STATE_REGISTERED,
	GAO_RESOURCE_STATE_ACTIVE,
	GAO_RESOURCE_STATE_CONFIGURING,
	GAO_RESOURCE_STATE_DELETING,
	GAO_RESOURCE_STATE_ERROR,
	GAO_RESOURCE_STATE_FINAL,
} gao_resource_state_t;

typedef enum gao_dump_nested {
	GAO_DUMP_NESTED = 0,
	GAO_DUMP_TRUNCATED,
} gao_dump_nested ;

typedef enum gao_request_dump_t {
	GAO_REQUEST_DUMP_BUFFERS = 0,
	GAO_REQUEST_DUMP_DESCRIPTORS,
	GAO_REQUEST_DUMP_PORTS,
	GAO_REQUEST_DUMP_PORTS_NESTED,
	GAO_REQUEST_DUMP_FILE,
} gao_request_dump_t;


typedef enum gao_queue_request_t {
	GAO_QUEUE_REQUEST_NONE = 0,
	/* Create:
	 * Args: length
	 */
	GAO_QUEUE_REQUEST_CREATE,
	GAO_QUEUE_REQUEST_DELETE,
	GAO_QUEUE_REQUEST_BIND,
	GAO_QUEUE_REQUEST_DETACH,
} gao_queue_request_t;




#define GAO_BUFFER_FILL_VAL			(0xDEADBEEF)
#define GAO_BUFFER_TEST_STR_LEN		(16)
#define GAO_BUFFER_TEST_STR_FMT		"GAO:GFN%04hx%04hx"


#define GAO_DESCRIPTOR_LEN(DESCRIPTOR) 		((DESCRIPTOR & 0xFFFF000000000000) >> 48)
#define GAO_DESCRIPTOR_GFN(DESCRIPTOR) 		((DESCRIPTOR & 0x0000FFFF00000000) >> 32)
#define GAO_DESCRIPTOR_INDEX(DESCRIPTOR) 	((DESCRIPTOR & 0x00000000FFFF0000) >> 16)
#define GAO_DESCRIPTOR_OFFSET(DESCRIPTOR) 	((DESCRIPTOR & 0x000000000000FFFF))
/* +----------------------------------------------------------------+
 * | 63-48			| 32-47			| 31-16			| 15-0			|
 * | len			| gfn			| index			| offset		|
 * +----------------------------------------------------------------+
 * len:			The length of the frame
 * gfn: 		The group frame number of the buffer group (offset in group size aligned phys mem)
 * index:		The index for the buffer within the buffer group
 * offset:		The offset where the frame should begin within the buffer.
 */
struct	gao_descriptor {
	union {
		struct {
			union {
				uint16_t				offset;		//Lower 13 bits
				uint16_t				queue_id; 	//Upper 3 bits
			};
			uint16_t				index;
			uint16_t				gfn;
			uint16_t				len;
		};
		uint64_t descriptor;
	};
};


struct gao_descriptor_ring_header {
	union {
		uint64_t				head;
		uint64_t				read;
	};
	union {
		uint64_t				tail;
		uint64_t				write;
	};

	uint64_t				capacity; //Total space in the queue, regardless of occupancy
	uint64_t				size; //Total number of occupants
};

#define GAO_VIRT_TO_GFN(VIRTADDR) 	((unsigned long)((virt_to_phys(VIRTADDR)) >> GAO_GFN_SHIFT))
#define GAO_GFN_TO_VIRT(GFN)		(phys_to_virt( ((GFN) << GAO_GFN_SHIFT) ))
#define GAO_PHYS_TO_GFN(PHYSADDR) 	((unsigned long)((PHYSADDR) >> GAO_GFN_SHIFT))
#define GAO_GFN_TO_PHYS(GFN)	  	((GFN) << GAO_GFN_SHIFT)

#define GAO_DESC_TO_PHYS(DESC) 	((unsigned long)\
		((GAO_DESCRIPTOR_GFN(DESC) << GAO_GFN_SHIFT) + \
		(GAO_DESCRIPTOR_INDEX(DESC)*GAO_BUFFER_SIZE) + \
		GAO_DESCRIPTOR_OFFSET(DESC)))

#define GAO_DESC_TO_VIRT(DESC)	phys_to_virt(GAO_DESC_TO_PHYS(DESC))

#ifndef __KERNEL__
#define GAO_DESC_TO_PKT(DESC, OFFSET) (OFFSET + GAO_DESC_TO_PHYS(DESC))
#endif





#ifndef __KERNEL__
#define GAO_QUEUE(BASE, INDEX)		((struct gao_user_queue*)(((uint64_t)BASE) + (INDEX * GAO_MAX_QUEUE_SIZE_BYTES)))
#endif


typedef enum gao_action_id {
	GAO_ACTION_DROP = 0,
	GAO_ACTION_FORWARD,
} gao_action_id;

#define GAO_INVALID_ACTION_MASK	(~(0x00077F01))

struct 			gao_action {
	union {
		struct {
			uint8_t		action_id;
			uint8_t		port_id;
			uint8_t		queue_id;
			uint8_t		padding;
		};
		uint32_t	action;
	};

};






#ifdef __KERNEL__
/* Kernel-only structs */
struct gao_queue_binding {
	gao_owner_type_t			owner_type;
	struct gao_port				*port;
	struct gao_file_private		*gao_file;
	uint64_t					gao_ifindex;
	uint64_t					queue_index;
	gao_direction_t				direction_txrx;
};


typedef enum gao_queue_attach_t {
	GAO_QUEUE_ATTACH_NONE 		= (1 << 0),
	GAO_QUEUE_ATTACH_INTERFACE 	= (1 << 1),
	GAO_QUEUE_ATTACH_QUEUE_MAP 	= (1 << 2),
} gao_queue_attach_t;

struct gao_queue_rx_attach {
	gao_queue_attach_t	type;


};

struct gao_queue_tx_attach {

};

struct gao_descriptor_ring_control {
	/*Writer locking primitives*/
	//These are locked by whoever is adding to the queue
	//XXX: Can we make the MPSC transparently lockless with the SPSC variant?
	spinlock_t			tail_lock;

	//Each bit in the wake condition represents which queues in the egress map are waiting
	atomic_long_t		tail_wake_condition;
	//If the queue terminates on an interface, this points to the atomic above
	//If the queue points to another queue, it points to that queue's tail_wake_condition
	atomic_long_t		*tail_wake_condition_ref;

	//Same for this one -- point to the queue's wait queue that is actually being waited on
	wait_queue_head_t	tail_wait_queue;
	wait_queue_head_t	*tail_wait_queue_ref;


	/*Reader locking primitives*/
	//TODO: Align cache here
	//XXX: Do we need head locking?
	spinlock_t			head_lock;

	//Also pretty sure these don't need to be longs
//	atomic_long_t		head_wake_condition;
//	atomic_long_t		*head_wake_condition_ref;

	atomic_long_t		head_wake_condition;
	atomic_long_t		*head_wake_condition_ref;


	wait_queue_head_t	head_wait_queue;
	wait_queue_head_t	*head_wait_queue_ref;

	//TODO: Align cache here

};



/**
 * The descriptor rings always have one empty slot at the end
 */
struct gao_descriptor_ring {
	//This gets mapped, but userspace jumps over it (doesn't need to see it)
	struct		gao_descriptor_ring_control	control;
	//Userspace does see this
	struct		gao_descriptor_ring_header 	header;
	struct 		gao_descriptor				descriptors[];
	//This is really hackish, but the actions go after the descriptors here.
	//When it gets malloc'd, we malloc enough for the actions, too.
	//Userspace gets offset values to find each in here.
	//Basically, actions[0] = descriptors[capacity], likewise last slot is actions[capacity-1]
};

struct gao_egress_subqueue {
	struct gao_descriptor_ring	*ring;
//	uint64_t					size;
//	uint64_t					weight;
};

struct gao_ingress_port_queue_map {
	struct gao_descriptor_ring	*ring[GAO_MAX_PORT_SUBQUEUE];
};

struct gao_ingress_queue_map {
	struct gao_ingress_port_queue_map	port[GAO_MAX_PORTS];
};

struct gao_queue {
	uint64_t					index; //Back-index to the main resources array
	/* Unused: Queue is free and in an invalid state.
	 * Registered: Queue has resources allocated, but not connected to an interface.
	 * Active: Queue has been bound to another resource (file or interface)
	 * Deleting: Queue is being deleted, will return to unused.
	 * See GAO Queue Lifecycle diagram for more details.
	 */
	gao_resource_state_t		state;
	uint64_t					flags;
	uint64_t					descriptors;

	//Who owns the queue?
	struct gao_queue_binding 	binding;


	//The ring that shadows the hardware queue
	struct gao_descriptor_ring		*ring;

	//The mapping of port/queue id to egress queue.
	struct gao_ingress_queue_map	queue_map;
	//Pointer to a buffer of actions to map to packets to forward
	struct gao_action				*action_map;

	//Allocated on RX only and is mmaped to userspace.
	//Allows for pipelined Sched and forwarding + easy batching.
	//Sized to num_descriptors * GAO_ING_PIPELINE_DEPTH elements
	struct gao_descriptor			*descriptor_pipeline;
	uint64_t						descriptor_pipeline_size;
	struct gao_action				*action_pipeline;
	uint64_t						action_pipeline_size;

	//The queues used for SW QOS, just make rings, don't need full queue struct.
	struct gao_egress_subqueue		subqueues[GAO_MAX_PORT_SUBQUEUE];



	//Pointer for drivers to store rings/adapter structs for quick access
	void							*hw_private;
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
	uint64_t				bound_gao_ifindex;
	uint64_t				bound_queue_index;
	gao_direction_t			bound_direction;
	struct gao_queue		*bound_queue;
	struct gao_port_ops		*port_ops;
};

struct gao_port_ops {
	int64_t		(*gao_enable)(struct net_device*);
	int64_t		(*gao_disable)(struct net_device*);
	ssize_t		(*gao_read)(struct gao_file_private*, size_t size);
	ssize_t		(*gao_write)(struct gao_file_private*, size_t size);
	ssize_t		(*gao_clean)(struct gao_queue*, size_t num_to_clean);
	ssize_t		(*gao_recv)(struct gao_queue*, size_t num_to_read);
	ssize_t		(*gao_xmit)(struct gao_queue*);
	void		(*gao_enable_rx_interrupts)(struct gao_queue* queue);
	void		(*gao_enable_tx_interrupts)(struct gao_queue* queue);
	void		(*gao_disable_rx_interrupts)(struct gao_queue* queue);
	void		(*gao_disable_tx_interrupts)(struct gao_queue* queue);
};


typedef enum gao_port_qos_mode {
	GAO_PORT_QOS_MODE_NONE = 0,
	GAO_PORT_QOS_MODE_SW,
	GAO_PORT_QOS_MODE_HW,
} gao_port_qos_mode ;

struct gao_tx_arbiter {
	struct work_struct	work;
	struct gao_queue	*tx_queue;
	struct gao_port		*port;
};

struct gao_port {
	//TODO: Persistence: map an constant identifier like the HW address to the gao_ifindex
	uint64_t				gao_ifindex; //gao internal gao_ifindex
	uint64_t				ifindex; //Kernel ifindex
	char					name[IFNAMSIZ];

	gao_resource_state_t 	state;
	struct net_device		*netdev; //Set by ethernet driver
	struct gao_port_ops		*port_ops; //Set by ethernet driver

	gao_port_qos_mode		qos_mode; //Set by ethernet driver
	uint32_t				num_rx_queues; //Set by ethernet driver
	uint32_t				num_rx_desc; //Set by ethernet driver
	struct gao_queue		*rx_queues[GAO_MAX_PORT_HWQUEUE];
	uint32_t				num_tx_queues; //Set by ethernet driver
	uint32_t				num_tx_desc; //Set by ethernet driver
	struct gao_queue		*tx_queues[GAO_MAX_PORT_HWQUEUE];

	//Scheduling arbiters attached to HW queues that serialize SW queues to the NIC ring
	struct workqueue_struct	*tx_arbiter_workqueue;
	struct gao_tx_arbiter	tx_arbiters[GAO_MAX_PORT_HWQUEUE];
};


struct gao_descriptor_allocator_ring {
	spinlock_t		lock;
	struct gao_descriptor	(*descriptors)[GAO_DESCRIPTORS];
	uint64_t		head; //Pointer to the next descriptor that can be taken
	uint64_t		tail; //Pointer to the next descriptor that can be freed
	uint64_t		left; //How many are left
};


struct gao_resources {
	/*Control*/
	/* Unused: GAO is initializing.
	 * Active: GAO is fully initialized and resources can be consumed.
	 * Deleting: GAO is exiting.
	 */
	gao_resource_state_t		state;
	//Resource allocation can sleep, should only be done on mod init and exit.
	struct semaphore 			allocation_lock; //Must be held to allocate, and free.
	spinlock_t					queue_lock; //Must be held to create and delete queues
	struct semaphore 			config_lock; //Must be held to configure interfaces


	/*Buffers*/
	void						*buffer_groups[GAO_BUFFER_GROUPS]; //MMAP'd to userspace
	void						*dummy_group; //Group mmap'd to any gaps in the bufferspace
	unsigned long				buffer_start_phys; //The first byte of physical space used by buffers
	unsigned long				buffer_end_phys; //Points to the first byte after the end of the space
	unsigned long				buffer_space_frame; //The total span of the buffers in physical memory.


	/*Descriptors*/
	struct gao_descriptor_allocator_ring	descriptor_ring;


	/*Queues*/
	struct gao_queue			*queues[GAO_MAX_QUEUES];


	/*Interfaces*/
	struct gao_port				ports[GAO_MAX_PORTS];
	uint64_t					free_ports;
	//TODO: Replace with a hashmap down the road (maybe)
	//Used by ethernet drivers to lookup their GAO interface
	struct gao_port				*ifindex_to_port_lut[GAO_MAX_IFINDEX];
};





/* End of kernel-only structs */
#else
/* Userspace only Structs*/

struct gao_context {
	void*			mmap_addr; //The base address of the mmap area
	unsigned long	offset; //Used for calculating descriptor addresses
	int				fd; //Used for control
};


#endif



struct gao_request_mmap {
	unsigned long	size;
	unsigned long	offset;
};

typedef enum gao_request_queue_num_t {
	GAO_REQUEST_QUEUE_CREATE = 0,
	GAO_REQUEST_QUEUE_DELETE,
	GAO_REQUEST_QUEUE_BIND,
	GAO_REQUEST_QUEUE_UNBIND,
} gao_request_queue_num_t;

typedef enum gao_response_queue_num_t {
	GAO_RESPONSE_QUEUE_OK = 0,
	GAO_RESPONSE_QUEUE_NOK,
} gao_response_queue_num_t;

struct gao_request_queue {
	gao_request_queue_num_t 	request_code;
	gao_response_queue_num_t	response_code;

	uint64_t					queue_size;
	uint64_t					gao_ifindex;
	uint64_t					queue_index;
	uint64_t					descriptor_pipeline_size;
	uint64_t					action_pipeline_size;
	gao_direction_t				direction_txrx;
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




struct gao_request_port_list {
	struct {
		uint64_t				gao_ifindex; //gao internal gao_ifindex
		uint64_t				ifindex; //Kernel ifindex
		char					name[IFNAMSIZ];
		gao_resource_state_t 	state;
		uint32_t				num_rx_queues;
		uint32_t				num_tx_queues;
	}port [GAO_MAX_PORTS];
};

struct gao_request_port {
	gao_request_port_num_t 			request_code;
	gao_response_port_num_t 		response_code;
	uint64_t						gao_ifindex;
	struct gao_request_port_list	*port_list;
};



/* IOCTL And Kernel/Userspace Communication */
#define GAO_MAJOR_NUM	0x10
#define GAO_IOCTL_COMMAND_GET_MMAP_SIZE _IOWR(GAO_MAJOR_NUM, 0x10, struct gao_request_mmap)
#define GAO_IOCTL_COMMAND_QUEUE _IOWR(GAO_MAJOR_NUM, 0x11, struct gao_request_queue)
#define GAO_IOCTL_COMMAND_PORT _IOWR(GAO_MAJOR_NUM, 0x12, struct gao_request_port)
#define GAO_IOCTL_COMMAND_DUMP _IOWR(GAO_MAJOR_NUM, 0x13, gao_request_dump_t)
#define GAO_IOCTL_SYNC_QUEUE	_IO(GAO_MAJOR_NUM, 0x14)


#ifdef __KERNEL__
/* Kernel-only functions */
inline struct gao_resources*	gao_get_resources(void);
inline struct gao_port* 	gao_get_port_from_ifindex(int ifindex);

void	gao_dump_buffers(struct gao_resources *resources);
void	gao_dump_descriptor(struct	gao_descriptor *desc);
void	gao_dump_descriptors(struct gao_resources *resources);
void	gao_dump_action(struct gao_action *action);
void	gao_dump_descriptor_ring(struct gao_descriptor_ring *queue);
void	gao_dump_descriptor_ring_nested(struct gao_descriptor_ring *ring);
void	gao_dump_user_queues(struct gao_resources *resources);
void	gao_dump_resources(struct gao_resources *resources);
void	gao_dump_ingress_queue_map(struct gao_ingress_queue_map *map);
void	gao_dump_queue_binding(struct gao_queue_binding *binding);
void	gao_dump_queue(struct gao_queue *queue);
void	gao_dump_queue_nested(struct gao_queue *queue);
void	gao_dump_port(struct gao_port* port);
void 	gao_dump_port_nested(struct gao_port* port);
void	gao_dump_ports(struct gao_resources *resources);
void 	gao_dump_ports_nested(struct gao_resources *resources);
void	gao_dump_file(struct file *filep);

void 		gao_free_port_list(struct gao_request_port_list* list);
struct gao_request_port_list* gao_get_port_list(struct gao_resources* resources);

const char*	gao_resource_state_string(gao_resource_state_t state);

void		gao_free_resources(struct gao_resources* resources);
int64_t		gao_init_resources(struct gao_resources* resources);

int64_t 	gao_create_port_queues(struct gao_resources* resources, struct gao_port *port);
void		gao_delete_port_queues(struct gao_resources *resources, struct gao_port *port);

int64_t		gao_enable_gao_port(struct gao_resources *resources, uint64_t ifindex);
int64_t		gao_disable_gao_port(struct gao_resources *resources, uint64_t ifindex);

int64_t		gao_bind_queue(struct file* filep, struct gao_request_queue *request);
void		gao_unbind_queue(struct file* filep);

/* Exported functions */
inline 		unsigned long descriptor_to_phys_addr(uint64_t descriptor);

int			gao_lock_resources(struct gao_resources* resources);
void		gao_unlock_resources(struct gao_resources* resources);

void		gao_unregister_port(struct net_device *netdev);
int64_t		gao_register_port(struct net_device *netdev, struct gao_port_ops* if_ops);
int64_t		gao_activate_port(struct gao_port* port);
void		gao_deactivate_port(struct gao_port* port);

uint64_t	gao_ring_slots_left(struct gao_descriptor_ring*);
uint64_t	gao_ring_num_elements(struct gao_descriptor_ring*);

/* End of kernel-only functions */
#endif


inline void swap_descriptors(struct gao_descriptor *desc1, struct gao_descriptor *desc2);

#endif /* GAO_MMIO_RESOURCE_H_ */
