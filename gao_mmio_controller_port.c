/*
 * gao_mmio_controller_port.c
 *
 *  Created on: 2013-01-27
 *      Author: cverge
 */

#include "gao_mmio_resource.h"

/**
 * Stub function, always returns 0.
 * @param netdev
 * @return 0.
 */
int64_t	gao_controller_enable_gao_mode(struct net_device* netdev) {
	return 0;
}

/**
 * Stub function, always returns 0.
 * @param netdev
 * @return 0.
 */
int64_t	gao_controller_disable_gao_mode(struct net_device* netdev) {
	return 0;
}

/**
 * Stub function
 * @param queue
 */
void gao_controller_enable_rx_interrupts(struct gao_queue *queue) {
	return;
}

/**
 * Stub function
 * @param queue
 */
void gao_controller_enable_tx_interrupts(struct gao_queue *queue) {
	return;
}

/**
 * Stub function
 * @param queue
 */
void gao_controller_disable_rx_interrupts(struct gao_queue *queue) {
	return;
}

/**
 * Stub function
 * @param queue
 */
void gao_controller_disable_tx_interrupts(struct gao_queue *queue) {
	return;
}


ssize_t	gao_controller_xmit(struct gao_queue *gao_queue) {
	struct gao_descriptor_ring_header	*header = gao_queue->hw_private;
	uint64_t				index = header->tail, size = gao_queue->ring->header.capacity, limit, num_to_xmit;

	//We will advance the controller queue tail to the gao tail
	limit = gao_queue->ring->header.tail;
	num_to_xmit = CIRC_DIFF64(limit, index, size);

	log_dp("start xmit: index/tail=%llu limit=%llu num_to_xmit=%llu", index, limit, num_to_xmit);

	//The condition acts like a semaphore in this case, set it to the number of packets to xmit
	atomic_long_set(gao_queue->ring->control.head_wake_condition_ref, num_to_xmit);
	//And wake anyone waiting on it.
	wake_up_interruptible(gao_queue->ring->control.head_wait_queue_ref);
	//When there are no more packets left, we are woken and can return.
	wait_event_interruptible( gao_queue->ring->control.head_wait_queue, !atomic_long_read(&gao_queue->ring->control.head_wake_condition) );

	header->tail = limit;
	return (gao_queue->ring->header.capacity - 1);
}

ssize_t	gao_controller_clean(struct gao_queue *gao_queue, size_t num_to_clean) {
	uint64_t	index = 0;
	struct gao_descriptor_ring_header	*header = gao_queue->hw_private;
	struct gao_descriptor				*ring_descriptors = (struct gao_descriptor*)&gao_queue->ring->descriptors;

	//Use this to save the head to trick the sync routine later
	header->head = num_to_clean;
	gao_queue->ring->header.head = 0;

	//Reset the offsets of the new descriptors from the destination queues.
	for(index = 0; index < num_to_clean; index++) {
		ring_descriptors[index].offset = GAO_DEFAULT_OFFSET;
	}

	return 0; //Ignored
}

ssize_t	gao_controller_recv(struct gao_queue *gao_queue, size_t num_to_read) {
	struct gao_descriptor_ring_header	*header = gao_queue->hw_private;

	//Effectively set the head to the last number of frames we forwarded so the sync routine
	//copies the new descriptors into the mmap ring.
	gao_queue->ring->header.head = header->head;
	//Always return 1 here so we don't block. This routine cannot fail.
	return 1;
}


static struct gao_port_ops gao_controller_port_ops = {
		.gao_enable = gao_controller_enable_gao_mode,
		.gao_disable = gao_controller_disable_gao_mode,
		.gao_clean = gao_controller_clean,
		.gao_recv = gao_controller_recv,
		.gao_xmit = gao_controller_xmit,
		.gao_enable_rx_interrupts = gao_controller_enable_rx_interrupts,
		.gao_enable_tx_interrupts = gao_controller_enable_tx_interrupts,
		.gao_disable_rx_interrupts = gao_controller_disable_rx_interrupts,
		.gao_disable_tx_interrupts = gao_controller_disable_tx_interrupts,
};



void	gao_controller_unregister_port(struct gao_resources *resources) {
	struct gao_port *port = NULL;

	log_debug("Destroying controller port with port_id %d.", GAO_CONTROLLER_PORT_ID);

	gao_lock_resources(resources);

	port = &resources->ports[GAO_CONTROLLER_PORT_ID];

	if(port->state == GAO_RESOURCE_STATE_UNUSED)
		gao_bug("Controller port ID unused, can't unregister.");

	if(port->rx_queues[0]) {
		if(port->rx_queues[0]->hw_private) kfree_null(port->rx_queues[0]->hw_private);
	}

	if(port->tx_queues[0]) {
		if(port->tx_queues[0]->hw_private) kfree_null(port->tx_queues[0]->hw_private);
	}

	gao_deactivate_port(port);


	synchronize_rcu();
	memset((void*)port, 0, sizeof(struct gao_port));

	err:
	gao_unlock_resources(resources);
	return;
}


int64_t	gao_controller_register_port(struct gao_resources *resources) {
	int64_t 				ret = 0, index = 0;
	struct gao_port 		*port = NULL;
	char					*port_name = "controller";
	struct gao_descriptor	*ring_descriptors, *mmap_descriptors;

	log_debug("Creating controller port with port_id %d.", GAO_CONTROLLER_PORT_ID);

	gao_lock_resources(resources);

	port = &resources->ports[GAO_CONTROLLER_PORT_ID];

	if(port->state != GAO_RESOURCE_STATE_UNUSED)
		gao_bug_val(-EINVAL, "Controller port ID already registered!");

	memset((void*)port, 0, sizeof(struct gao_port));

	port->gao_ifindex = GAO_CONTROLLER_PORT_ID;
	port->ifindex = ~((uint64_t)0);
	strncpy((char*)&port->name, port_name, strlen(port_name));
	port->netdev = NULL;
	port->port_ops = &gao_controller_port_ops;
	port->state = GAO_RESOURCE_STATE_REGISTERED;
	port->type = GAO_PORT_CONTROLLER;

	port->num_rx_queues = 1;
	port->num_rx_desc = GAO_CONTROLLER_BUFFERS;
	port->num_tx_queues = 1;
	port->num_tx_desc = GAO_CONTROLLER_BUFFERS;


	ret = gao_activate_port(port);
	if(ret) gao_error("Failed to activate controller port.");


	//Initialize the queue with all the descriptors already available so userspace can copy into them right away
	ring_descriptors = (struct gao_descriptor*)&port->rx_queues[0]->ring->descriptors;
	mmap_descriptors = port->rx_queues[0]->descriptor_pipeline;
	for(index = 0; index < GAO_CONTROLLER_BUFFERS; index++) {
		mmap_descriptors[index].descriptor = ring_descriptors[index].descriptor;
	}

	//Use a ring header to store next_to_use/clean values.
	port->rx_queues[0]->hw_private = kmalloc(sizeof(struct gao_descriptor_ring_header), GFP_KERNEL);
	check_ptr(port->rx_queues[0]->hw_private);

	port->tx_queues[0]->hw_private = kmalloc(sizeof(struct gao_descriptor_ring_header), GFP_KERNEL);
	check_ptr(port->tx_queues[0]->hw_private);

	((struct gao_descriptor_ring_header*)port->tx_queues[0]->hw_private)->tail = 0;


	port->state = GAO_RESOURCE_STATE_ACTIVE;
	gao_unlock_resources(resources);
	return ret;

	err:
	port->state = GAO_RESOURCE_STATE_ERROR;
	gao_unlock_resources(resources);
	return ret;
}






















