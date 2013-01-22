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


void	gao_dump_interface(struct gao_port *interface) {
	uint64_t	index;
	log_debug("Dump Interface: ifindex=%lu kifindex=%lu name=%s state=%s netdev=%p if_ops=%p",
			(unsigned long)interface->gao_ifindex, (unsigned long)interface->ifindex, interface->name,
			gao_resource_state_str[interface->state], interface->netdev, interface->port_ops);

	log_debug("RX Queues: num_rx_queues=%u num_rx_desc=%u",
			(unsigned)interface->num_rx_queues, (unsigned)interface->num_rx_desc);

	for(index = 0; index < interface->num_rx_queues; index++) {
		if(interface->rx_queues[index]) gao_dump_queue(interface->rx_queues[index]);
	}

	log_debug("TX Queues: num_tx_queues=%u num_tx_desc=%u",
			(unsigned)interface->num_tx_queues, (unsigned)interface->num_tx_desc);

	for(index = 0; index < interface->num_tx_queues; index++) {
		if(interface->tx_queues[index]) gao_dump_queue(interface->tx_queues[index]);
	}
}

void	gao_dump_interfaces(struct gao_resources *resources) {
	uint64_t index;
	log_debug("Dump Interfaces:");
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		gao_dump_interface(&resources->ports[index]);
	}
	log_debug("Dump kifindex LUT:");
	for(index = 0; index < GAO_MAX_IFINDEX; index++) {
		log_debug("kifindex=%lu interface=%p", (unsigned long)index, resources->ifindex_to_port_lut[index]);
	}
}



void	gao_unregister_port(struct net_device *netdev) {
	struct gao_port *interface = NULL;
	struct gao_resources *resources = gao_get_resources();

	gao_lock_resources(resources);

	interface = gao_get_port_from_ifindex(netdev->ifindex);
	if(!interface) gao_error("Cannot unregister interface -- already unregistered: %s[%d]", netdev->name, netdev->ifindex);

	log_debug("Unegistering interface %s, kifindex %d, ifindex %lu", netdev->name, netdev->ifindex, (unsigned long)interface->gao_ifindex);
	resources->ifindex_to_port_lut[netdev->ifindex] = NULL;


	synchronize_rcu();
	memset(interface, 0, sizeof(struct gao_port));

	err:
	gao_unlock_resources(resources);
	return;
}
EXPORT_SYMBOL(gao_unregister_port);


int64_t		gao_register_port(struct net_device *netdev, struct gao_port_ops* if_ops) {
	int64_t ret = 0;
	uint64_t index;
	struct gao_resources *resources = gao_get_resources();
	struct gao_port *interface = NULL;

	log_debug("Registering interface %s, kifindex %d", netdev->name, netdev->ifindex);

	if(((unsigned int)netdev->ifindex) >= GAO_MAX_IFINDEX)
		gao_error_val(-EFAULT, "Cannot register, kifindex %d out of range.", netdev->ifindex);


	gao_lock_resources(resources);

	//Walk the interface slots and find a free one
	//Start at index 1 for openflow
	for(index = 1; index < GAO_MAX_PORTS; index++) {
		if(resources->ports[index].state == GAO_RESOURCE_STATE_UNUSED) {
			interface = &resources->ports[index];
			memset(interface, 0, sizeof(struct gao_port));

			interface->gao_ifindex = index;
			interface->ifindex = netdev->ifindex;
			strncpy((char*)&interface->name, (char*)&netdev->name, IFNAMSIZ);
			interface->netdev = netdev;
			interface->port_ops = if_ops;
			interface->state = GAO_RESOURCE_STATE_REGISTERED;

			//Make sure everything is set before the pointer is.
			wmb();

			resources->ifindex_to_port_lut[interface->ifindex] = interface;
			break;
		}
	}

	if(!interface) gao_error_val(-ENOMEM, "Cannot register any more interfaces.");

	err:
	gao_unlock_resources(resources);
	return ret;
}
EXPORT_SYMBOL(gao_register_port);


static void	gao_transmit_arbiter(struct work_struct *work) {
	struct gao_tx_arbiter *tx_arbiter = (struct gao_tx_arbiter*) work;
	struct gao_queue *queue = tx_arbiter->tx_queue;
	struct gao_descriptor_ring *ring = queue->ring;
	struct gao_descriptor_ring *subqueue = NULL;
	uint64_t	subqueue_index, subqueue_bits;
	uint64_t	subqueue_head, subqueue_tail, subqueue_capacity;
	uint64_t	hwqueue_head, hwqueue_tail, hwqueue_capacity, frames_this_round;
	log_debug("Starting scheduler for queue %lu", (unsigned long)queue->index);

	hwqueue_head = ring->header.head;
	hwqueue_tail = ring->header.tail;
	hwqueue_capacity = ring->header.capacity;

	for(;;) {
		if(queue->state != GAO_RESOURCE_STATE_ACTIVE) goto deleting;



		/*
		 * Block on egress queues, schedule into HW queue
		 */

		wait_event_interruptible(ring->control.tail_wait_queue, (subqueue_bits = atomic_long_read(ring->control.tail_wake_condition_ref)));
		if(queue->state != GAO_RESOURCE_STATE_ACTIVE) goto deleting;

		if(unlikely(!subqueue_bits)) {
			log_bug("Woke with zero subqueue bits");
			continue;
		}

		frames_this_round = hwqueue_capacity - CIRC_DIFF64(hwqueue_tail, hwqueue_head, hwqueue_capacity);

		log_debug("Woke arbiter, subqueue_bits=%lx, frames_this_round=%lu", (unsigned long)subqueue_bits, (unsigned long)frames_this_round);
		for(subqueue_index = __builtin_ffsl(subqueue_bits) - 1; subqueue_bits; subqueue_index = __builtin_ffsl(subqueue_bits) - 1) {
			log_dp("Would schedule subqueue_index=%lu", (unsigned long)subqueue_index);

			subqueue = queue->subqueues[subqueue_index].ring;
			if(unlikely(!subqueue)) {
				log_bug("Null subqueue was flagged!");
				continue;
			}

			//Empty the subqueue
			rmb();
			subqueue_head = subqueue->header.head;
			subqueue_tail = subqueue->header.tail;
			subqueue_capacity = subqueue->header.capacity;

			log_dp("Start scheduling subqueue %lu, tail=%lu head=%lu", (unsigned long)subqueue_index, (unsigned long)subqueue_tail, (unsigned long)subqueue_head);
			subqueue_tail = CIRC_NEXT(subqueue_tail, subqueue_capacity);
			for(; (subqueue_tail != subqueue_head) && frames_this_round; frames_this_round-- ) {
				log_dp("Schedule subqueue_tail=%lu hwqueue_tail=%lu subqueue_desc=%lx hwqueue_desc=%lx frames_this_round=%lu",
						(unsigned long)subqueue_tail,  (unsigned long)hwqueue_tail,
						(unsigned long)subqueue->descriptors[subqueue_tail].descriptor, (unsigned long)ring->descriptors[hwqueue_tail].descriptor,
						(unsigned long)frames_this_round);
				swap_descriptors(&subqueue->descriptors[subqueue_tail], &ring->descriptors[hwqueue_tail]);
				subqueue_tail = CIRC_NEXT(subqueue_tail, subqueue_capacity);
				hwqueue_tail = CIRC_NEXT(hwqueue_tail, hwqueue_capacity);
			}
			subqueue_tail = CIRC_PREV(subqueue_tail, subqueue_capacity);
			log_dp("Done scheduling subqueue %lu, setting tail=%lu", (unsigned long)subqueue_index, (unsigned long)subqueue_tail);

			subqueue->header.tail = subqueue_tail;
			wmb();
			subqueue_bits &= ~(1 << subqueue_index);
		}

		atomic_long_set(ring->control.tail_wake_condition_ref, subqueue_bits);

		if(frames_this_round < 64) log_dp("Would block on xmit");

		/*
		 * Transmit to HW, block until we have enough space for another scheduling loop
		 */

//		log_debug("Starting scheduler loop for queue %lu", (unsigned long)queue->index);
//		atomic_long_set(ring->control.head_wake_condition_ref, 0);
//		wait_event_interruptible_timeout(ring->control.head_wait_queue, atomic_long_read(&ring->control.head_wake_condition), 2*HZ);


	}


	deleting:
	log_debug("Stopping scheduler for queue %lu", (unsigned long)queue->index);
	return;
}

/**
 * Allocate and configure generic parameters for an interface coming up.
 * @warning Caller must hold resource lock
 * @param interface The interface to activate. Module specific parameters must already be filled in.
 * @return 0 on success, -ENOMEM if insufficient resources, -EFAULT for bad values.
 */
int64_t		gao_activate_port(struct gao_port* port) {
	int64_t ret = 0;
	uint64_t index;
	struct gao_resources* resources = gao_get_resources();


	ret = gao_create_port_queues(resources, port);
	if(ret) goto err;

	port->tx_arbiter_workqueue = alloc_workqueue((char*)&port->name, 0, port->num_tx_queues);
	if(!port->tx_arbiter_workqueue)
		gao_error_val(-ENOMEM, "Failed to create TX arbiter workqueue on port %s[%lu].", port->name, (unsigned long)port->gao_ifindex);

	//Start the transmit arbiters
	for(index = 0; index < port->num_tx_queues; index++) {
		port->tx_arbiters[index].tx_queue = port->tx_queues[index];
		INIT_WORK(&port->tx_arbiters[index].work, gao_transmit_arbiter);
		queue_work(port->tx_arbiter_workqueue, &port->tx_arbiters[index].work);
	}

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

	if(ifindex < 0 || ifindex >= GAO_MAX_PORTS) gao_error_val(-EFAULT, "Ifindex out of range: %lu.", (unsigned long)ifindex);
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

	if(ifindex < 0 || ifindex >= GAO_MAX_PORTS)
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
	if(list) vfree(list);
}

struct gao_request_port_list* gao_get_port_list(struct gao_resources* resources) {
	uint64_t	index;
	struct gao_request_port_list* list = NULL;
	struct gao_port *port = NULL;

	list = vmalloc(sizeof(struct gao_request_port_list));
	check_ptr(list);

	memset((void*)list, 0, sizeof(struct gao_request_port_list));

	for(index = 0; index < GAO_MAX_PORTS; index++) {
		port = &resources->ports[index];

		list->port[index].state = port->state;
		if(port->state == GAO_RESOURCE_STATE_UNUSED) continue;

		list->port[index].gao_ifindex = port->gao_ifindex;
		list->port[index].ifindex = port->ifindex;
		memcpy(&list->port[index].name, &port->name, sizeof(port->name));
		list->port[index].num_rx_queues = port->num_rx_queues;
		list->port[index].num_tx_queues = port->num_tx_queues;
	}

	return list;
	err:
	gao_free_port_list(list);
	return NULL;
}













