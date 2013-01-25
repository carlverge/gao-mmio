/*
 * gao_e1000.h
 *
 *  Created on: 2013-01-22
 *      Author: cverge
 */

#ifndef GAO_E1000_H_
#define GAO_E1000_H_

#include <linux/netdevice.h>

#include "e1000.h"
#include "../gao_mmio_resource.h"
#include "../gao_log.h"


int64_t		gao_e1000_enable_gao_mode(struct net_device *netdev) {
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netdev->priv_flags |= IFF_GAO_ENABLED;

	//It the interface was up, reset it to reinit resources.
	if (netif_running(netdev)) {
		log_debug("Enabling gao on %s and bouncing interface.", netdev->name);
		rtnl_lock();
		e1000_reinit_locked(adapter);
		rtnl_unlock();
	} else {//If it wasn't, well, all the intel stuff does this, so do this.
		log_debug("Enabling gao on %s. Interface stays down.", netdev->name);
		e1000_reset(adapter);
	}

	return 0;
}


int64_t		gao_e1000_disable_gao_mode(struct net_device *netdev) {
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netdev->priv_flags &= ~IFF_GAO_ENABLED;

	//It the interface was up, reset it to reinit resources.
	if (netif_running(netdev)) {
		log_debug("Disabling gao on %s and bouncing interface.", netdev->name);
		rtnl_lock();
		e1000_reinit_locked(adapter);
		rtnl_unlock();
	} else {//If it wasn't, well, all the intel stuff does this, so do this.
		//FIXME: But I'm pretty sure we don't need to...
		log_debug("Disabling gao on %s. Interface stays down.", netdev->name);
		e1000_reset(adapter);
	}

	return 0;
}


/**
 * Dummy function to replace the original. This shouldn't get called.
 * @param rx_ring
 * @param cleaned_count
 * @param gfp
 */
void gao_e1000_alloc_rx_buffers(struct e1000_adapter *adapter, struct e1000_rx_ring *rx_ring, int cleaned_count) {
	//log_error("alloc_rx_buffers was called.");
}

/**
 * Dummy function to replace the original. This shouldn't get called.
 * @param rx_ring
 * @param work_done
 * @param work_to_do
 * @return
 */
bool gao_e1000_clean_rx_irq(struct e1000_adapter *adapter, struct e1000_rx_ring *rx_ring, int *work_done, int work_to_do) {
	//log_error("clean_rx_irq was called.");
	return true;
}

void gao_e1000_enable_rx_interrupts(struct gao_queue *queue) {
//	struct e1000_adapter *adapter = queue->hw_private;
//	struct e1000_hw *hw = &adapter->hw;
//	log_dp("Enabling RX interrupts");
//	//Enable the RX Timer interrupt
//	ew32(IMS, (E1000_IMS_RXT0 | E1000_IMS_RXQ0 | E1000_IMS_OTHER | E1000_IMS_LSC));
//	e1e_flush();
	return;
}

void gao_e1000_enable_tx_interrupts(struct gao_queue *queue) {
//	struct e1000_adapter *adapter = queue->hw_private;
//	struct e1000_hw *hw = &adapter->hw;
//	//TODO: Set the TXD_LOW Interrupt, and set the Low thresh in the TXDCTL Reg
//	uint32_t flags = ( E1000_IMS_OTHER | E1000_IMS_LSC | E1000_IMS_TXDW | E1000_IMS_TXQ0 | E1000_IMS_TXQE | E1000_IMS_TXD_LOW);
//	log_dp("Enabling TX interrupts");
//	ew32(IMS, flags);
//	e1e_flush();
//	log_debug("Ena TX IRQ IMS=%x IAM=%x", er32(IMS) ,er32(IAM));
	return;
}

void gao_e1000_disable_rx_interrupts(struct gao_queue *queue) {
//	struct e1000_adapter *adapter = queue->hw_private;
//	struct e1000_hw *hw = &adapter->hw;
//
//	log_dp("Disabling RX Interrupts");
//	//Disable the interrupts
//	ew32(IMC, ( E1000_IMS_RXT0 | //RX Timer
//			E1000_IMS_RXO | //RX Overrun
//			E1000_IMS_RXQ0 | //RX Queue 0
//			E1000_IMS_RXDMT0 | //RX Desc Min Threshold
//			E1000_IMS_RXSEQ //RX Sequence Error
//			));
//
//	e1e_flush();
	return;
}

void gao_e1000_disable_tx_interrupts(struct gao_queue *queue) {
//	struct e1000_adapter *adapter = queue->hw_private;
//	struct e1000_hw *hw = &adapter->hw;
//
//	log_dp("Disabling TX Interrupts");
//	//Disable the interrupts
//	ew32(IMC, ( E1000_IMS_TXDW | //TX Desc Written Back
//			E1000_IMS_TXQE | //TX Queue Empty
//			E1000_IMS_TXQ0 | //TX Queue 0
//			E1000_IMS_TXD_LOW //Transmit low threshold
//			));
//
//	e1e_flush();
	return;
}

/**
 * Initialize the parameters on the hardware ring and sync them with the gao ring.
 * @param hw_ring
 * @param gao_ring
 */
void	gao_e1000_init_rx_ring(struct e1000_hw *hw, struct e1000_rx_ring *hw_ring, struct gao_queue *gao_ring) {
	int64_t 						index;
	struct e1000_rx_desc	 		*hw_desc;
	uint64_t						gao_desc;


	log_debug("Initializing E1000E RX Ring:");
	log_debug("RX Ring Head=%u Tail=%u", readl(hw->hw_addr + hw_ring->rdh), readl(hw->hw_addr + hw_ring->rdt));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	//Set the data on the RX desc.
	for(index = 0; index < hw_ring->count; index++) {
		hw_ring->buffer_info[index].skb = NULL;
		gao_desc = (gao_ring->ring->descriptors[index].descriptor);
//		log_debug("Setting RXDESC %ld to phys addr %016lx", (long)index, descriptor_to_phys_addr(gao_desc));
		hw_desc = E1000_RX_DESC(*hw_ring, index);
		hw_desc->buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_desc));
	}

	wmb();
	writel(hw_ring->count - 1, hw->hw_addr + hw_ring->rdt);


	gao_ring->ring->header.head = 0;
	gao_ring->ring->header.tail = hw_ring->count - 1;
	gao_ring->ring->header.capacity = hw_ring->count;
	gao_ring->ring->header.size = 0;

	return;
}

/**
 * Initialize the parameters on the hardware ring and sync them with the gao ring.
 * @param hw_ring
 * @param gao_ring
 */
void	gao_e1000_init_tx_ring(struct e1000_hw *hw, struct e1000_tx_ring *hw_ring, struct gao_queue *gao_ring) {

	log_debug("Initializing E1000E TX Ring:");
	log_debug("TX Ring Head=%u Tail=%u", readl(hw->hw_addr + hw_ring->tdh), readl(hw->hw_addr + hw_ring->tdt));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	wmb();
	writel(hw_ring->count - 1, hw->hw_addr + hw_ring->tdt);

	gao_ring->ring->header.head = 0;
	gao_ring->ring->header.tail = 0;
	gao_ring->ring->header.capacity = hw_ring->count;
	gao_ring->ring->header.size = 0;


	return;
}

/**
 * Activate an interface in GAO mode. Allocate all resources required and
 * configure the interface parameters. Sets state to ACTIVE.
 * Called by e1000_configure
 * @warning Locks gao resources
 * @param netdev The device to activate
 */
void	gao_e1000_activate_port(struct net_device *netdev) {
	int64_t 				ret = 0;
	struct e1000_adapter 	*adapter = NULL;
	struct e1000_hw			*hw = NULL;
	struct gao_port 	*port = NULL;
	struct gao_resources	*resources = gao_get_resources();

	log_debug("Activating GAO on interface %s[%d]", netdev->name, netdev->ifindex);

	gao_lock_resources(resources);

	adapter = netdev_priv(netdev);
	port = gao_get_port_from_ifindex(netdev->ifindex);
	hw = &adapter->hw;

	if(!port)
		gao_error("Unknown interface, cannot activate.");

	if(port->state != GAO_RESOURCE_STATE_REGISTERED)
		gao_error("Interface not in registered state, cannot activate (state: %u)", port->state);


	//E1000E Specific setup information
	port->num_rx_queues = 1; //e1000e only has 1 queue
	port->num_rx_desc = adapter->rx_ring->count;
	port->num_tx_queues = 1;
	port->num_tx_desc = adapter->tx_ring->count;

	//Override the existing adapter functions
	adapter->alloc_rx_buf = gao_e1000_alloc_rx_buffers;
	adapter->clean_rx = gao_e1000_clean_rx_irq;


	//Allocate and configure the generic parameters for queues from the above settings
	ret = gao_activate_port(port);
	if(ret) goto err;

	//Set HW specific information
	port->rx_queues[0]->hw_private = adapter;
	port->tx_queues[0]->hw_private = adapter;

	//Just init the one queue in either direction
	gao_e1000_init_rx_ring(hw, adapter->rx_ring, port->rx_queues[0]);
	gao_e1000_init_tx_ring(hw, adapter->tx_ring, port->tx_queues[0]);

	gao_e1000_disable_rx_interrupts(port->rx_queues[0]);
	gao_e1000_disable_tx_interrupts(port->tx_queues[0]);


	port->state = GAO_RESOURCE_STATE_ACTIVE;
	gao_unlock_resources(resources);
	return;

	err:
	port->state = GAO_RESOURCE_STATE_ERROR;
	gao_unlock_resources(resources);
	return;
}


/**
 * Deactivates and deallocates interface resources.
 * @warning Locks gao resources
 * @param netdev
 * @return
 */
int64_t	gao_e1000_deactivate_port(struct net_device *netdev) {
	struct gao_port *port = NULL;
	struct gao_resources *resources = gao_get_resources();
	log_debug("Deactivating GAO on interface %s[%d]", netdev->name, netdev->ifindex);

	gao_lock_resources(resources);

	port = gao_get_port_from_ifindex(netdev->ifindex);

	if(!port)
		gao_error("Unknown interface, cannot deactivate.");

	if(port->state == GAO_RESOURCE_STATE_UNUSED)
		gao_error("Interface in unused state, cannot dectivate.");

	gao_deactivate_port(port);

	err:
	gao_unlock_resources(resources);
	return 0;
}

ssize_t		gao_e1000_read(struct gao_file_private *file_priv, size_t num_to_read) {
	return num_to_read;
}


ssize_t		gao_e1000_write(struct gao_file_private *file_priv, size_t num_to_clean) {
	return num_to_clean;
}


struct gao_port_ops gao_e1000_port_ops = {
		.gao_enable = gao_e1000_enable_gao_mode,
		.gao_disable = gao_e1000_disable_gao_mode,
		.gao_read = gao_e1000_read,
		.gao_write = gao_e1000_write,
		.gao_enable_rx_interrupts = gao_e1000_enable_rx_interrupts,
		.gao_enable_tx_interrupts = gao_e1000_enable_tx_interrupts,
		.gao_disable_rx_interrupts = gao_e1000_disable_rx_interrupts,
		.gao_disable_tx_interrupts = gao_e1000_disable_tx_interrupts,
};

void	gao_e1000_register_port(struct net_device *netdev) {
	gao_register_port(netdev, &gao_e1000_port_ops);
	return;
}

void	gao_e1000_unregister_port(struct net_device *netdev) {
	gao_unregister_port(netdev);
	return;
}


#endif /* GAO_E1000_H_ */
