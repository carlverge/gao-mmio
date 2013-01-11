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
	for(index = 0; index < GAO_MAX_PORTS; index++) {
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


/**
 * Allocate and configure generic parameters for an interface coming up.
 * @warning Caller must hold resource lock
 * @param interface The interface to activate. Module specific parameters must already be filled in.
 * @return 0 on success, -ENOMEM if insufficient resources, -EFAULT for bad values.
 */
int64_t		gao_activate_port(struct gao_port* port) {
	int64_t ret = 0;
	struct gao_resources* resources = gao_get_resources();


	ret = gao_create_port_queues(resources, port);


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

	if(port->state != GAO_RESOURCE_STATE_REGISTERED) {
		gao_error_val(-EFAULT, "Cannot enable, interface %lu not in registered state: (state: %s).",
				(unsigned long)ifindex, gao_resource_state_string(port->state));
	}

	netdev = port->netdev;
	if_ops = port->port_ops;

	rcu_read_unlock();

	if_ops->gao_enable(netdev);


	return 0;
	err:
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
	return ret;
}
















