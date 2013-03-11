/*
 * gao_e1000e.h
 *
 *  Created on: 2012-12-29
 *      Author: cverge
 */

#ifndef GAO_E1000E_H_
#define GAO_E1000E_H_


#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/netdevice.h>

#include "e1000.h"
#include "../gao_mmio_resource.h"
#include "../gao_log.h"


/* Send an interrupt when there is 8*8=64 frames pending to TX*/
//#define GAO_E1000E_TXD_LOW_THRESHOLD 8
#define GAO_E1000E_TXD_DESC_LOW_THRESH (32)
/* End of packet flag and insert FCS) */
#define GAO_E1000E_TXD_FLAGS (E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS)


int64_t		gao_e1000e_enable_gao_mode(struct net_device *netdev) {
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netdev->priv_flags |= IFF_GAO_ENABLED;

	//It the interface was up, reset it to reinit resources.
	if (netif_running(netdev)) {
		log_debug("Enabling gao on %s and bouncing interface.", netdev->name);
		e1000e_reinit_locked(adapter);
	} else {//If it wasn't, well, all the intel stuff does this, so do this.
		log_debug("Enabling gao on %s. Interface stays down.", netdev->name);
		e1000e_reset(adapter);
	}

	return 0;
}


int64_t		gao_e1000e_disable_gao_mode(struct net_device *netdev) {
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netdev->priv_flags &= ~IFF_GAO_ENABLED;

	//It the interface was up, reset it to reinit resources.
	if (netif_running(netdev)) {
		log_debug("Disabling gao on %s and bouncing interface.", netdev->name);
		e1000e_reinit_locked(adapter);
	} else {//If it wasn't, well, all the intel stuff does this, so do this.
		//FIXME: But I'm pretty sure we don't need to...
		log_debug("Disabling gao on %s. Interface stays down.", netdev->name);
		e1000e_reset(adapter);
	}

	return 0;
}



/**
 * Dummy function to replace the original. This shouldn't get called.
 * @param rx_ring
 * @param cleaned_count
 * @param gfp
 */
void gao_e1000e_alloc_rx_buffers(struct e1000_ring *rx_ring, int cleaned_count, gfp_t gfp) {
	//log_error("alloc_rx_buffers was called.");
}

/**
 * Dummy function to replace the original. This shouldn't get called.
 * @param rx_ring
 * @param work_done
 * @param work_to_do
 * @return
 */
bool gao_e1000e_clean_rx_irq(struct e1000_ring *rx_ring, int *work_done, int work_to_do) {
	//log_error("clean_rx_irq was called.");
	return true;
}

/**
 * Initialize the parameters on the hardware ring and sync them with the gao ring.
 * @param hw_ring
 * @param gao_ring
 */
void	gao_e1000e_init_rx_ring(struct e1000_ring *hw_ring, struct gao_rx_queue *gao_queue) {
	int64_t 						index;
	union e1000_rx_desc_extended 	*hw_desc;
	uint32_t						use;

	log_debug("Initializing E1000E RX Ring:");
	log_debug("RX Ring Head=%u Tail=%u", readl(hw_ring->head), readl(hw_ring->tail));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	//Set the data on the RX desc.
	for(index = 0; index < hw_ring->count; index++) {
		hw_ring->buffer_info[index].skb = NULL;
		use = gao_queue->ring.use & (gao_queue->ring.capacity - 1);
		gao_queue->ring.desc[use].offset = GAO_DEFAULT_OFFSET;
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		hw_desc->read.buffer_addr = cpu_to_le64(gao_descriptor_to_phys_addr(gao_queue->ring.desc[use]));
		gao_queue->ring.use++;
	}

	wmb();
	writel(hw_ring->count - 1, hw_ring->tail);

	return;
}


/**
 * Initialize the parameters on the hardware ring and sync them with the gao ring.
 * @param hw_ring
 * @param gao_ring
 */
void	gao_e1000e_init_tx_ring(struct e1000_ring *hw_ring, struct gao_tx_queue *gao_ring) {

	log_debug("Initializing E1000E TX Ring:");
	log_debug("TX Ring Head=%u Tail=%u", readl(hw_ring->head), readl(hw_ring->tail));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	wmb();
	writel(0, hw_ring->tail);


	return;
}




static inline void _gao_e1000e_enable_rx_intr(struct e1000_adapter *adapter) {
	struct e1000_hw *hw = &adapter->hw;
	log_debug("Enabling RX interrupts");
	//Enable the RX Timer interrupt
	ew32(IMS, (E1000_IMS_RXT0 | E1000_IMS_RXQ0 | E1000_IMS_RXDMT0 | E1000_IMS_OTHER | E1000_IMS_LSC));
	e1e_flush();
}
static void gao_e1000e_enable_rx_intr(struct gao_rx_queue* rxq) {
	_gao_e1000e_enable_rx_intr(rxq->hw_private);
}


static inline void _gao_e1000e_enable_tx_intr(struct e1000_adapter *adapter) {
	struct e1000_hw *hw = &adapter->hw;
	//TODO: Set the TXD_LOW Interrupt, and set the Low thresh in the TXDCTL Reg
	uint32_t flags = ( E1000_IMS_OTHER | E1000_IMS_LSC | E1000_IMS_TXDW | E1000_IMS_TXQ0 | E1000_IMS_TXQE | E1000_IMS_TXD_LOW);
	log_dp("Enabling TX interrupts");
	ew32(IMS, flags);
	e1e_flush();
	//log_debug("Ena TX IRQ IMS=%x IAM=%x", er32(IMS) ,er32(IAM));
}
static void gao_e1000e_enable_tx_intr(struct gao_tx_queue* txq) {
	_gao_e1000e_enable_tx_intr(txq->hw_private);
}


static inline void _gao_e1000e_disable_rx_intr(struct e1000_adapter *adapter) {
	struct e1000_hw *hw = &adapter->hw;

	log_debug("Disabling RX Interrupts");
	//Disable the interrupts
	ew32(IMC, ( E1000_IMS_RXT0 | //RX Timer
			E1000_IMS_RXO | //RX Overrun
			E1000_IMS_RXQ0 | //RX Queue 0
			E1000_IMS_RXDMT0 | //RX Desc Min Threshold
			E1000_IMS_RXSEQ //RX Sequence Error
			));

	e1e_flush();
}
static void gao_e1000e_disable_rx_intr(struct gao_rx_queue* rxq) {
	_gao_e1000e_disable_rx_intr(rxq->hw_private);
}



static inline void _gao_e1000e_disable_tx_intr(struct e1000_adapter *adapter) {
	struct e1000_hw *hw = &adapter->hw;

	log_dp("Disabling TX Interrupts");
	//Disable the interrupts
	ew32(IMC, ( E1000_IMS_TXDW | //TX Desc Written Back
			E1000_IMS_TXQE | //TX Queue Empty
			E1000_IMS_TXQ0 | //TX Queue 0
			E1000_IMS_TXD_LOW //Transmit low threshold
			));

	e1e_flush();
}
static inline void gao_e1000e_disable_tx_intr(struct gao_tx_queue* txq) {
	_gao_e1000e_disable_tx_intr(txq->hw_private);
}



void gao_e1000e_handle_rx_irq(struct net_device* netdev, struct e1000_adapter *adapter, struct e1000_ring* hw_ring) {
	struct e1000_hw	*hw = &adapter->hw;
	uint32_t icr = er32(ICR);//, ims = er32(IMS);

	if(icr & E1000_ICR_RXQ0) {
		log_debug("Handling RX ICR=%x", icr);
		//if(icr & E1000_ICR_RXDMT0) gao_rx_interrupt_threshold_handle(netdev->ifindex, 0);
		if((icr & E1000_ICR_RXT0) || (icr & E1000_ICR_RXDMT0)) {
			gao_rx_interrupt_handle(netdev->ifindex, 0);
		}

	}

	return;
}

void gao_e1000e_handle_tx_irq(struct net_device* netdev, struct e1000_adapter *adapter, struct e1000_ring* hw_ring) {
	struct e1000_hw	*hw = &adapter->hw;
	uint32_t icr = er32(ICR);

	if(icr & E1000_ICR_TXQ0) {
		log_debug("Handling TX ICR=%x", icr);
		if(icr & E1000_ICR_TXDW) {
			gao_tx_interrupt_handle(netdev->ifindex);
		}
	}

	return;
}


/**
 * Activate an interface in GAO mode. Allocate all resources required and
 * configure the interface parameters. Sets state to ACTIVE.
 * Called by e1000e_configure
 * @warning Locks gao resources
 * @param netdev The device to activate
 */
void	gao_e1000e_activate_port(struct net_device *netdev) {
	int64_t 				ret = 0;
	struct e1000_adapter 	*adapter = NULL;
	struct e1000_hw			*hw = NULL;
	struct gao_port 	*port = NULL;
	struct gao_resources	*resources = gao_get_resources();

	log_debug("Activating GAO on interface %s[%d]", netdev->name, netdev->ifindex);

	gao_lock_resources(resources);

	adapter = netdev_priv(netdev);
	port = gao_ifindex_to_port(netdev->ifindex);
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
	adapter->alloc_rx_buf = gao_e1000e_alloc_rx_buffers;
	adapter->clean_rx = gao_e1000e_clean_rx_irq;


	//Allocate and configure the generic parameters for queues from the above settings
	ret = gao_activate_port(port);
	if(ret) goto err;

	//Set HW specific information
	port->rx_queues[0]->hw_private = adapter;
	port->tx_queues[0]->hw_private = adapter;

	//Just init the one queue in either direction
	gao_e1000e_init_rx_ring(adapter->rx_ring, port->rx_queues[0]);
	gao_e1000e_init_tx_ring(adapter->tx_ring, port->tx_queues[0]);

	gao_e1000e_enable_rx_intr(port->rx_queues[0]);
	gao_e1000e_enable_tx_intr(port->tx_queues[0]);


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
int64_t	gao_e1000e_deactivate_port(struct net_device *netdev) {
	struct gao_port *port = NULL;
	struct e1000_adapter 	*adapter = NULL;
	struct gao_resources *resources = gao_get_resources();
	log_debug("Deactivating GAO on interface %s[%d]", netdev->name, netdev->ifindex);

	gao_lock_resources(resources);

	adapter = netdev_priv(netdev);
	port = gao_ifindex_to_port(netdev->ifindex);

	if(!port)
		gao_error("Unknown interface, cannot deactivate.");

	if(port->state == GAO_RESOURCE_STATE_UNUSED)
		gao_error("Interface in unused state, cannot dectivate.");

	_gao_e1000e_disable_rx_intr(adapter);
	_gao_e1000e_disable_tx_intr(adapter);
	gao_deactivate_port(port);

	err:
	gao_unlock_resources(resources);
	return 0;
}



int32_t	gao_e1000e_clean(struct gao_descriptor_ring* ring, uint32_t num_to_clean, void *hw_private)  {
	struct e1000_adapter 	*adapter = hw_private;
	struct e1000_ring 		*hw_ring = adapter->rx_ring;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint16_t	hw_idx = hw_ring->next_to_clean, hw_lim = hw_ring->next_to_use;
	uint32_t 	hw_size = hw_ring->count, num_left = num_to_clean, gao_use = ring->use;

	if(unlikely(test_bit(__E1000_DOWN, &adapter->state))) {
		log_bug("abort clean: adapter down");
		return -EIO;
	}

	log_dp("start clean: hw_idx/next_to_clean=%hu gao_use=%u left=%u", hw_idx, gao_use, num_left);

	while( (hw_idx != hw_lim) && num_left ) {
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_idx);
		ring->desc[gao_use & ring->mask].offset = GAO_DEFAULT_OFFSET;
		hw_desc->read.buffer_addr = cpu_to_le64(gao_descriptor_to_phys_addr(ring->desc[gao_use & ring->mask]));
		GAO_VALIDATE_DESC(ring->desc[gao_use & ring->mask]);
		log_dp("clean: hw_idx=%hu gao_use=%u left=%u desc_idx=%x desc_len=%hu", hw_idx, gao_use, num_left,
				ring->desc[gao_use & ring->mask].index, ring->desc[gao_use & ring->mask].len);

		gao_use++;
		hw_idx = (hw_idx+1) & (hw_size-1);
		num_left--;
	}

	hw_ring->next_to_clean = hw_idx;


	wmb();
	//Rewind the index by one for the tail value
	writel(((hw_idx-1) & (hw_size-1)), hw_ring->tail);

	log_dp("done clean: hw_idx/next_to_clean=%hu gao_use=%u left=%u cleaned=%u", hw_idx, gao_use, num_left, (num_to_clean - num_left));

	return num_to_clean - num_left;
}

/**
 * Receive new frames into the GAO queue.
 * @param gao_queue
 * @return The number of frames received.
 */
int32_t	gao_e1000e_recv(struct gao_descriptor_ring* ring, uint32_t num_to_read, void *hw_private) {
	struct e1000_adapter 	*adapter = hw_private;
	struct e1000_ring 		*hw_ring = adapter->rx_ring;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint16_t				hw_idx = hw_ring->next_to_use;
	uint32_t				staterr, hw_size = hw_ring->count, num_left = num_to_read, gao_clean = ring->clean;

	if(unlikely(test_bit(__E1000_DOWN, &adapter->state))) {
		log_bug("abort recv: adapter down");
		return -EIO;
	}

	hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_idx);
	staterr = le32_to_cpu(hw_desc->wb.upper.status_error);

	log_dp("start recv: hw_idx/head=%hu gao_clean=%u left=%u staterr=%x", hw_idx, gao_clean, num_left, staterr);

	while( (staterr & E1000_RXD_STAT_DD) && num_left) {
		ring->desc[gao_clean & ring->mask].len = le16_to_cpu(hw_desc->wb.upper.length);
		hw_desc->wb.upper.status_error &= cpu_to_le32(~0xFF);

		log_dp("recv: hw_idx=%hu gao_clean=%u left=%u desc_idx=%x desc_len=%hu", hw_idx, gao_clean, num_left,
				ring->desc[gao_clean & ring->mask].index, ring->desc[gao_clean & ring->mask].len);

		hw_idx = (hw_idx+1) & (hw_size-1);
		gao_clean++;

		hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_idx);
		staterr = le32_to_cpu(hw_desc->wb.upper.status_error);

		num_left--;
	}

	hw_ring->next_to_use = hw_idx;
	log_dp("done recv: hw_idx/head=%hu gao_clean=%u left=%u total_read=%u", hw_idx, gao_clean, num_left, num_to_read - num_left);

	return num_to_read - num_left;
}

static int32_t gao_e1000e_xmit(struct gao_descriptor_ring* ring, uint32_t num_to_xmit, void *hw_private) {
	struct e1000_adapter 	*adapter = hw_private;
	struct e1000_ring 		*hw_ring = adapter->tx_ring;
	struct e1000_tx_desc 	*hw_desc = NULL;
	uint16_t hw_idx = hw_ring->next_to_use, hw_lim, hw_size = hw_ring->count;
	uint32_t num_left = num_to_xmit;

	if(unlikely(test_bit(__E1000_DOWN, &adapter->state))) {
		log_bug("abort xmit: adapter down");
		return -EIO;
	}

	hw_lim = (hw_ring->next_to_clean-1) & (hw_size-1);
	log_dp("start xmit: hw_idx/next_to_use=%hu hw_lim=%hu gao_use=%u left=%u", hw_idx, hw_lim, ring->use, num_left);


	while((hw_idx != hw_lim) && num_left) {
		hw_desc = E1000_TX_DESC(*hw_ring, hw_idx);
		log_dp("xmit: hw_idx=%hu gao_use=%u left=%u desc_idx=%x desc_len=%hu", hw_idx, ring->use, num_left,
				ring->desc[ring->use & ring->mask].index, ring->desc[ring->use & ring->mask].len);

		hw_desc->buffer_addr = cpu_to_le64(gao_descriptor_to_phys_addr(ring->desc[ring->use & ring->mask]));

		if(!(hw_idx % (hw_size/2)))
			hw_desc->lower.data  = cpu_to_le32(ring->desc[ring->use & ring->mask].len | GAO_E1000E_TXD_FLAGS | E1000_TXD_CMD_RS);
		else
			hw_desc->lower.data  = cpu_to_le32(ring->desc[ring->use & ring->mask].len | GAO_E1000E_TXD_FLAGS);

		hw_desc->upper.data  = 0;

		ring->use++;
		hw_idx = (hw_idx+1) & (hw_size-1);
		num_left--;
	}

	wmb();
	hw_ring->next_to_use = hw_idx;
	writel(hw_idx, hw_ring->tail);

	log_dp("done xmit: hw_idx/next_to_clean=%hu gao_use=%u left=%u xmited=%u",
			hw_idx, ring->use, num_left, (num_to_xmit - num_left));

	//Make sure the IO writes from the NIC have completed before we read the new head
	mmiowb();
	hw_idx = readl(hw_ring->head);
	ring->clean += CIRC_DIFF16(hw_idx, hw_ring->next_to_clean, hw_size);
	log_dp("done xmit clean: hw_idx/next_to_clean=%hu gao_clean=%u cleaned=%u",
					hw_idx, ring->clean, CIRC_DIFF16(hw_idx, hw_ring->next_to_clean, hw_size));
	hw_ring->next_to_clean = hw_idx;


	return (num_to_xmit - num_left);
}


struct gao_port_ops gao_e1000e_port_ops = {
		.gao_enable = gao_e1000e_enable_gao_mode,
		.gao_disable = gao_e1000e_disable_gao_mode,
		.gao_clean = gao_e1000e_clean,
		.gao_recv = gao_e1000e_recv,
		.gao_xmit = gao_e1000e_xmit,
		.gao_enable_rx_intr = gao_e1000e_enable_rx_intr,
		.gao_enable_tx_intr = gao_e1000e_enable_tx_intr,
		.gao_disable_rx_intr = gao_e1000e_disable_rx_intr,
		.gao_disable_tx_intr = gao_e1000e_disable_tx_intr,
};


void	gao_e1000e_register_port(struct net_device *netdev) {
	gao_register_port(netdev, &gao_e1000e_port_ops);
	return;
}

void	gao_e1000e_unregister_port(struct net_device *netdev) {
	gao_unregister_port(netdev);
	return;
}


#endif /* GAO_E1000E_H_ */
