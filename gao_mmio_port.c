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

#ifndef CONFIG_HZ
//FIXME: Take this out, just to make eclipse happy. Shouldn't affect the actual compilation...
#define CONFIG_HZ 1000
#endif

const static char *gao_resource_state_str[] = {"Unused", "Registered", "Active", "Configuring", "Deleting"};
//const static char *gao_owner_str[] = {"None", "Userspace", "Interface"};
//const static char *gao_direction_str[] = {"NA", "RX", "TX"};



void	gao_unregister_port(struct net_device *netdev) {
	struct gao_port *port = NULL;
	struct gao_resources *resources = gao_get_resources();

	gao_lock_resources(resources);

	port = gao_get_port_from_ifindex(netdev->ifindex);
	if(!port) gao_error("Cannot unregister interface -- already unregistered: %s[%d]", netdev->name, netdev->ifindex);

	log_debug("Unegistering interface %s, kifindex %d, ifindex %lu", netdev->name, netdev->ifindex, (unsigned long)port->gao_ifindex);
	resources->ifindex_to_port_lut[netdev->ifindex] = NULL;


	synchronize_rcu();
	memset((void*)port, 0, sizeof(struct gao_port));

	err:
	gao_unlock_resources(resources);
	return;
}
EXPORT_SYMBOL(gao_unregister_port);


int64_t		gao_register_port(struct net_device *netdev, struct gao_port_ops* if_ops) {
	int64_t ret = 0;
	uint64_t index;
	struct gao_resources *resources = gao_get_resources();
	struct gao_port *port = NULL;

	log_debug("Registering interface %s, kifindex %d", netdev->name, netdev->ifindex);

	if(((unsigned int)netdev->ifindex) >= GAO_MAX_IFINDEX)
		gao_error_val(-EFAULT, "Cannot register, kifindex %d out of range.", netdev->ifindex);


	gao_lock_resources(resources);

	//Walk the interface slots and find a free one
	//Start at index 1 for openflow
	for(index = 1; index < GAO_MAX_PHYS_PORT; index++) {
		if(resources->ports[index].state == GAO_RESOURCE_STATE_UNUSED) {
			port = &resources->ports[index];
			memset((void*)port, 0, sizeof(struct gao_port));

			port->gao_ifindex = index;
			port->ifindex = netdev->ifindex;
			strncpy((char*)&port->_name, (char*)&netdev->name, IFNAMSIZ);
			port->netdev = netdev;
			port->port_ops = if_ops;
			port->state = GAO_RESOURCE_STATE_REGISTERED;
			port->type = GAO_PORT_PHYSICAL;

			//Make sure everything is set before the pointer is.
			wmb();

			resources->ifindex_to_port_lut[port->ifindex] = port;
			break;
		}
	}

	if(!port) gao_error_val(-ENOMEM, "Cannot register any more interfaces.");

	err:
	gao_unlock_resources(resources);
	return ret;
}
EXPORT_SYMBOL(gao_register_port);

/**
 *
 * @warning Called under RCU read lock
 * @param queue
 * @return
 */
//static int64_t gao_default_port_scheduler(struct gao_tx_queue* queue) {
//	int64_t ret = 0;
//
//	if(unlikely(!queue)) gao_error("Scheduling null queue");
//	if(unlikely(queue->state != GAO_RESOURCE_STATE_ACTIVE)) gao_error("Scheduling inactive queue");
//
//
//
//
//
//	err:
//	return ret;
//}

//
//static void	gao_priority_scheduler(struct work_struct *work) {
//	struct gao_tx_arbiter 		*tx_arbiter = (struct gao_tx_arbiter*) work;
//	struct gao_port				*port = tx_arbiter->port;
//	struct gao_queue 			*queue = tx_arbiter->tx_queue;
//	struct gao_descriptor_subring 	*ring = queue->ring, *subqueue = NULL;
//	struct gao_descriptor		*descriptors = (struct gao_descriptor*)&queue->ring->descriptors;
//
//	uint64_t	sq_index, sq_bits, sq_head, sq_size, sq_limit;
//	uint64_t	index, size, frames_this_round;
//
//	log_debug("Starting scheduler for queue %lu", (unsigned long)queue->index);
//
//
//	frames_this_round = ring->header.capacity - 1;
//
//	for(;;) {
//		/*
//		 * 1. Do we need to stop scheduling?
//		 * 2. Block on egress queues
//		 * 3. Begin scheduling
//		 * 		a. How many can we schedule this round?
//		 * 		b. Schedule SW queues into HW queue.
//		 * 4. Xmit Frames (hw specific)
//		 * 		a. Reconcile HW Queue and NIC Ring
//		 * 		b. How many can we xmit now?
//		 * 		c. Below threshold?
//		 * 			yes: block until above min tx threshold again
//		 * 		d. Return number we can xmit
//		 */
//
//
//
//		//Block on the egress queues, wait to schedule.
//		wait_event_interruptible(ring->control.tail_wait_queue, (sq_bits = atomic_long_read(ring->control.tail_wake_condition_ref)));
//		rcu_read_lock();
//		if(queue->state != GAO_RESOURCE_STATE_ACTIVE) goto deleting;
//
//
//		index = ring->header.tail;
//		size = ring->header.capacity;
//
//		log_dp("start sched: ftr=%llu index/tail=%llu sq_bits=%llx", frames_this_round, index, sq_bits);
//
//		//Fully schedule each queue in increasing order
//		for(sq_index = (GAO_FFSL(sq_bits)-1); sq_bits && frames_this_round; sq_index = (GAO_FFSL(sq_bits)-1)) {
//
//			subqueue = queue->subqueues[sq_index].ring;
//
//			//Skip this queue if it's null -- this should never happen.
//			if(unlikely(!subqueue)) {
//				log_bug("xmit: null subqueue");
//				sq_bits &= ~(1 << sq_index);
//				continue;
//			}
//
//			sq_limit = gao_ring_num_elements(subqueue);
//			sq_head = subqueue->header.head;
//			sq_size = subqueue->header.capacity;
//
//			log_dp("start sq: ftr=%llu sq_head=%llu sq_limit=%llu index=%llu sq_bits=%llx", frames_this_round, sq_head, sq_limit, index, sq_bits);
//
//			rmb();
//
//			for(; sq_limit && frames_this_round; sq_limit--, frames_this_round--) {
//				//log_dp("sched sq: ftr=%llu sq_head=%llu sq_limit=%llu index=%llu sq_desc=%016llx desc=%016llx", frames_this_round, sq_head, sq_limit, index, subqueue->descriptors[sq_head].descriptor, descriptors[index].descriptor);
//				//swap_descriptors(&subqueue->descriptors[sq_head], &descriptors[index]);
//				descriptors[index] = subqueue->descriptors[sq_head];
//				sq_head = CIRC_NEXT(sq_head, sq_size), index = CIRC_NEXT(index, size);
//			}
//
//			wmb();
//			subqueue->header.head = sq_head;
//
//
//			if(!sq_limit) sq_bits &= ~(1 << sq_index);
//			log_dp("done sq: ftr=%llu sq_head=%llu index=%llu sq_bits=%llx", frames_this_round, sq_head, index, sq_bits);
//		}
//
//
//
//		atomic_long_set(ring->control.tail_wake_condition_ref, sq_bits);
//		log_dp("done sched: ftr=%llu index/tail=%llu sq_bits=%llx", frames_this_round, index, sq_bits);
//		//Scheduling over, xmit the frames from this round. Set the frames for next round to what the TX ring has left.
//		ring->header.tail = index;
//		frames_this_round = port->port_ops->gao_xmit(queue);
//
//		//TODO: Blocking code goes here
//		rcu_read_unlock();
//
//
//
//
//	}
//
//
//
//	deleting:
//	rcu_read_unlock();
//	log_debug("Stopping scheduler for queue %lu", (unsigned long)queue->index);
//	return;
//}


/**
 * Allocate and configure generic parameters for an interface coming up.
 * @warning Caller must hold resource lock
 * @param interface The interface to activate. Module specific parameters must already be filled in.
 * @return 0 on success, -ENOMEM if insufficient resources, -EFAULT for bad values.
 */
int64_t		gao_activate_port(struct gao_port* port) {
	int64_t ret = 0;
	struct gao_resources* resources = gao_get_resources();

//	port->port_scheduler = gao_default_port_scheduler;
//
	ret = gao_create_port_queues(resources, port);
	if(ret) goto err;

	return ret;
	err:
	gao_deactivate_port(port);
	return ret;
}
EXPORT_SYMBOL(gao_activate_port);

/**
 * Deactivate and cleanup gao resources for an interface.
 * @warning Caller must hold resource lock
 * @param interface
 * @return
 */
void		gao_deactivate_port(struct gao_port* port) {
	struct gao_resources* resources = gao_get_resources();

	//Make sure everyone sees that it is no longer active
	port->state = GAO_RESOURCE_STATE_REGISTERED;
	synchronize_rcu();

	//Return the queues to the manager
	gao_delete_port_queues(resources, port);

	port->num_rx_desc = 0;
	port->num_tx_desc = 0;
	port->num_rx_queues = 0;
	port->num_tx_queues = 0;

	//Return control to gao driver code
	return;
}
EXPORT_SYMBOL(gao_deactivate_port);

int64_t		gao_enable_gao_port(struct gao_resources *resources, uint64_t ifindex) {
	int64_t ret;
	struct gao_port 	*port = NULL;
	struct net_device		*netdev = NULL;
	struct gao_port_ops		*if_ops = NULL;


	rcu_read_lock();

	if(ifindex < 1 || ifindex >= GAO_MAX_PHYS_PORT) gao_error_val(-EFAULT, "Ifindex out of range: %lu.", (unsigned long)ifindex);
	port = &resources->ports[ifindex];


	if(port->state == GAO_RESOURCE_STATE_ACTIVE) {
		gao_error_val(0, "Cannot enable, interface %lu already enabled: (state: %s).",
						(unsigned long)ifindex, gao_resource_state_string(port->state));

	} else if(port->state != GAO_RESOURCE_STATE_REGISTERED) {
		gao_error_val(-EFAULT, "Cannot enable, interface %lu not in registered state: (state: %s).",
						(unsigned long)ifindex, gao_resource_state_string(port->state));
	}

	netdev = port->netdev;
	if_ops = port->port_ops;

	rcu_read_unlock();

	if_ops->gao_enable(netdev);


	return 0;
	err:
	rcu_read_unlock();
	return ret;
}


int64_t		gao_disable_gao_port(struct gao_resources *resources, uint64_t ifindex) {
	int64_t ret;
	struct gao_port 	*port = NULL;
	struct net_device		*netdev = NULL;
	struct gao_port_ops		*if_ops = NULL;

	rcu_read_lock();

	if(ifindex < 1 || ifindex >= GAO_MAX_PHYS_PORT)
		gao_error_val(-EFAULT, "Ifindex out of range: %lu.", (unsigned long)ifindex);

	port = &resources->ports[ifindex];

	if(port->state == GAO_RESOURCE_STATE_UNUSED)
		gao_error_val(-EFAULT, "Interface unused: %lu.", (unsigned long)ifindex);

	netdev = port->netdev;
	if_ops = port->port_ops;

	rcu_read_unlock();

	if_ops->gao_disable(netdev);


	return 0;
	err:
	rcu_read_unlock();
	return ret;
}


void gao_free_port_list(struct gao_request_port_list* list) {
	if(list) kfree(list);
}


struct gao_request_port_list* gao_get_port_list(struct gao_resources* resources) {
	uint64_t	index;
	struct gao_request_port_list* list = NULL;
	struct gao_port *port = NULL;

	list = kmalloc(sizeof(struct gao_request_port_list), GFP_KERNEL);
	check_ptr(list);

	memset((void*)list, 0, sizeof(struct gao_request_port_list));

	for(index = 0; index < GAO_MAX_PORTS; index++) {
		port = &resources->ports[index];

		list->port[index].state = port->state;
		if(port->state == GAO_RESOURCE_STATE_UNUSED) continue;

		list->port[index].gao_ifindex = port->gao_ifindex;
		list->port[index].ifindex = port->ifindex;
		memcpy(&list->port[index].name, gao_get_port_name(port), IFNAMSIZ);
		list->port[index].num_rx_queues = port->num_rx_queues;
		list->port[index].num_tx_queues = port->num_tx_queues;
	}

	return list;
	err:
	gao_free_port_list(list);
	return NULL;
}



void gao_free_port_info(struct gao_request_port_info* info) {
	if(info) kfree(info);
}

struct gao_request_port_info* gao_get_port_info(struct gao_resources* resources, uint64_t gao_ifindex) {
	struct gao_request_port_info* info = NULL;
	struct gao_port *port = NULL;


	if(gao_ifindex < 1 || gao_ifindex >= GAO_MAX_PORTS) gao_error("Invalid port number");

	info = kmalloc(sizeof(struct gao_request_port_info), GFP_KERNEL);
	check_ptr(info);

	memset((void*)info, 0, sizeof(struct gao_request_port_info));


	port = &resources->ports[gao_ifindex];

	info->state = port->state;
	info->gao_ifindex = port->gao_ifindex;
	info->ifindex = port->ifindex;
	memcpy(&info->name, gao_get_port_name(port), IFNAMSIZ);
	info->num_rx_queues = port->num_rx_queues;
	info->num_tx_queues = port->num_tx_queues;


	return info;
	err:
	gao_free_port_info(info);
	return NULL;
}

char*		gao_get_port_name(struct gao_port* port) {
	if(!port) gao_error("Trying to get name of null port.");
	if(port->netdev) return (char*)&port->netdev->name;
	else return (char*)&port->_name;
	err:
	return NULL;
}













