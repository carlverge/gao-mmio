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
<<<<<<< HEAD
=======
#include "../gao_log.h"
>>>>>>> branch 'master' of https://github.com/carlverge/gao-mmio.git


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
void	gao_e1000e_init_rx_ring(struct e1000_ring *hw_ring, struct gao_queue *gao_ring) {
	int64_t 						index;
	union e1000_rx_desc_extended 	*hw_desc;
	uint64_t						gao_desc;

	log_debug("Initializing E1000E RX Ring:");
	log_debug("RX Ring Head=%u Tail=%u", readl(hw_ring->head), readl(hw_ring->tail));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	//Set the data on the RX desc.
	for(index = 0; index < hw_ring->count; index++) {
		hw_ring->buffer_info[index].skb = NULL;
		gao_desc = (gao_ring->ring->descriptors[index].descriptor);
//		log_debug("Setting RXDESC %ld to phys addr %016lx", (long)index, descriptor_to_phys_addr(gao_desc));
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_desc));
	}

	wmb();
	writel(hw_ring->count - 1, hw_ring->tail);


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
void	gao_e1000e_init_tx_ring(struct e1000_ring *hw_ring, struct gao_queue *gao_ring) {

	log_debug("Initializing E1000E TX Ring:");
	log_debug("TX Ring Head=%u Tail=%u", readl(hw_ring->head), readl(hw_ring->tail));

	hw_ring->next_to_use = 0;
	hw_ring->next_to_clean = 0;

	wmb();
	writel(0, hw_ring->tail);

	gao_ring->ring->header.head = 0;
	gao_ring->ring->header.tail = 0;
	gao_ring->ring->header.capacity = hw_ring->count;
	gao_ring->ring->header.size = 0;


	return;
}

void gao_e1000e_enable_rx_interrupts(struct gao_queue *queue) {
	struct e1000_adapter *adapter = queue->hw_private;
	struct e1000_hw *hw = &adapter->hw;
	//log_dp("Enabling RX interrupts");
	//Enable the RX Timer interrupt
	ew32(IMS, (E1000_IMS_RXT0 | E1000_IMS_RXQ0 | E1000_IMS_OTHER | E1000_IMS_LSC));
	e1e_flush();
}

void gao_e1000e_enable_tx_interrupts(struct gao_queue *queue) {
	struct e1000_adapter *adapter = queue->hw_private;
	struct e1000_hw *hw = &adapter->hw;
	//TODO: Set the TXD_LOW Interrupt, and set the Low thresh in the TXDCTL Reg
	uint32_t flags = ( E1000_IMS_OTHER | E1000_IMS_LSC | E1000_IMS_TXDW | E1000_IMS_TXQ0 | E1000_IMS_TXQE | E1000_IMS_TXD_LOW);
	//log_dp("Enabling TX interrupts");
	ew32(IMS, flags);
	e1e_flush();
	//log_debug("Ena TX IRQ IMS=%x IAM=%x", er32(IMS) ,er32(IAM));
}

void gao_e1000e_disable_rx_interrupts(struct gao_queue *queue) {
	struct e1000_adapter *adapter = queue->hw_private;
	struct e1000_hw *hw = &adapter->hw;

	//log_dp("Disabling RX Interrupts");
	//Disable the interrupts
	ew32(IMC, ( E1000_IMS_RXT0 | //RX Timer
			E1000_IMS_RXO | //RX Overrun
			E1000_IMS_RXQ0 | //RX Queue 0
			E1000_IMS_RXDMT0 | //RX Desc Min Threshold
			E1000_IMS_RXSEQ //RX Sequence Error
			));

	e1e_flush();
}

void gao_e1000e_disable_tx_interrupts(struct gao_queue *queue) {
	struct e1000_adapter *adapter = queue->hw_private;
	struct e1000_hw *hw = &adapter->hw;

	//log_dp("Disabling TX Interrupts");
	//Disable the interrupts
	ew32(IMC, ( E1000_IMS_TXDW | //TX Desc Written Back
			E1000_IMS_TXQE | //TX Queue Empty
			E1000_IMS_TXQ0 | //TX Queue 0
			E1000_IMS_TXD_LOW //Transmit low threshold
			));

	e1e_flush();
}

void gao_e1000e_handle_rx_irq(struct net_device* netdev, struct e1000_adapter *adapter, struct e1000_ring* hw_ring) {
	struct e1000_hw	*hw = &adapter->hw;
	//FIXME: gao_get_interface is too slow (scans interfaces)
	struct gao_port* port = gao_get_port_from_ifindex(netdev->ifindex);
	struct gao_queue* gao_queue = NULL;
	uint32_t icr = er32(ICR);
	//log_dp("Handling RX ICR=%x", icr);

	if(unlikely(!port)) goto err;
	gao_queue = port->rx_queues[0];
	if(unlikely(!gao_queue)) goto err;

	atomic_long_set(gao_queue->ring->control.head_wake_condition_ref, 1);
	wake_up_interruptible(gao_queue->ring->control.head_wait_queue_ref);

	err:
	return;
}

//void gao_e1000e_handle_tx_irq(struct net_device* netdev, struct e1000_adapter *adapter, struct e1000_ring* hw_ring) {
//	struct e1000_hw *hw = &adapter->hw;
//	//FIXME: gao_get_interface is too slow (scans interfaces)
//	struct gao_interface* interface = gao_get_interface(netdev->ifindex);
//	struct gao_queue* gao_queue = NULL;
//	uint32_t icr = er32(ICR);
//
//	if(unlikely(!interface)) goto err;
//	gao_queue = interface->tx_queues[0];
//	if(unlikely(!gao_queue)) goto err;
//
//	log_debug("Handling TX ICR=%x", icr);
//
//	gao_queue->wake_condition = 1;
//	wmb();
//	wake_up_interruptible(&gao_queue->wait_queue);
//
//	err:
//	return;
//}


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

	gao_e1000e_disable_rx_interrupts(port->rx_queues[0]);
	gao_e1000e_disable_tx_interrupts(port->tx_queues[0]);


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




///**
// * Transmit frames.
// * It will first send the new frames, then free completed TX descriptors.
// * There will likely be more
// * @param file_priv
// * @param size
// * @return
// */
//ssize_t gao_e1000e_write(struct gao_file_private *file_priv, size_t size) {
//	uint32_t 				descriptors_left = 0, left_to_write;
//	uint32_t				hw_index, gao_index, gao_ring_size, hw_ring_size;
//	uint64_t				gao_desc, *gao_descriptors;
//	struct e1000_adapter 	*adapter = NULL;
//	struct e1000_ring 		*hw_ring = NULL;
//	struct gao_queue 	*gao_ring = NULL;
//	struct e1000_tx_desc 	*hw_desc = NULL;
//	struct e1000_hw 		*hw = NULL;
//
//
//	gao_ring = file_priv->gao_ring;
//	gao_descriptors = (uint64_t*)(&gao_ring->userspace->descriptors);
//	//TODO: lock the ring
//
//	adapter = netdev_priv(gao_ring->binding.interface->netdev);
//	hw_ring = adapter->tx_ring;
//	hw = &adapter->hw;
//
//	//hw_ring->next_to_clean[gao.head]: Last known position before hw head, can't TX more than this!
//	//hw_ring->next_to_use[gao.tail]: Last known tail -- place new frames in here.
//	gao_ring_size = gao_ring->ring->header.capacity;
//	hw_ring_size = hw_ring->count;
//
//	/* Transmit: Send the descriptors userspace set
//	 * Both indicies are set to the last tail.
//	 * Do a quick unsafe check on the head, see if we need to set threshold
//	 */
//	hw_ring->next_to_clean = readl(hw_ring->head);
//	descriptors_left = hw_ring_size - CIRC_DIFF16(hw_ring->next_to_use, hw_ring->next_to_clean, hw_ring_size);
//
//	//Make sure we're not writing more than we can
//	size = ((unlikely(size > descriptors_left)) ? descriptors_left : size);
//	left_to_write = size;
//
//	log_dp("Start Write: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u next_to_use=%u left=%u",
//					readl(hw_ring->tail), readl(hw_ring->head),	gao_ring->ring->header.head,
//					gao_ring->ring->header.tail, hw_ring->next_to_clean, hw_ring->next_to_use, descriptors_left);
//
//	//If size is greater that is an error condition. We will return the correct number of transmitted frames.
//
//	log_dp("Start Transmit: left_to_write=%u size=%lu left=%u", left_to_write, size, descriptors_left);
//	//Fill the descriptor ring with frames to transmit
//	gao_index = gao_ring->ring->header.tail;
//	hw_index = hw_ring->next_to_use;
//	for(; left_to_write; left_to_write--, gao_index = CIRC_NEXT(gao_index, gao_ring_size), hw_index = CIRC_NEXT(hw_index, hw_ring_size)) {
//		hw_desc = E1000_TX_DESC(*hw_ring, hw_index);
//		gao_desc = gao_descriptors[gao_index];
//		log_dp("Transmit: gao_index=%u hw_index=%u desc=%016lx", gao_index, hw_index, (unsigned long)gao_desc);
//		hw_desc->buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_desc));
//		hw_desc->lower.data = cpu_to_le32(GAO_DESCRIPTOR_LEN(gao_desc) | GAO_E1000E_TXD_FLAGS);
//		hw_desc->upper.data = 0;
//	}
//
//
//	//If we're consuming descriptors past the descriptor low threshold, set the
//	if(((descriptors_left - size) < GAO_E1000E_TXD_DESC_LOW_THRESH) && ((int32_t)(descriptors_left-GAO_E1000E_TXD_DESC_LOW_THRESH) >= 0)) {
//		E1000_TX_DESC(*hw_ring,
//				((hw_ring->next_to_use + (descriptors_left-GAO_E1000E_TXD_DESC_LOW_THRESH)) % hw_ring_size)
//				)->lower.data |= cpu_to_le32(E1000_TXD_CMD_RS);
//
//	}
//
//
//	//Set the tail so it begins transmitting
//	wmb();
//	hw_ring->next_to_use = hw_index;
//	writel(hw_index, hw_ring->tail);
//	gao_ring->ring->header.tail = gao_index;
//
//	log_dp("Done Transmit: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u next_to_use=%u left=%u",
//					readl(hw_ring->tail), readl(hw_ring->head),	gao_ring->ring->header.head,
//					gao_ring->ring->header.tail, hw_ring->next_to_clean, hw_ring->next_to_use, descriptors_left);
//
//	/*
//	 * XXX: Performance Tradeoff
//	 * The mmiowb(); is required to make sure the buffer data is in sync with what the head says, but
//	 * I don't think it will make a difference for us. Keeping it in for safety, but this should be checked for impact.
//	 * It syncs writes from the chipset (slow), but based on the below I think it is needed.
//	 * Netmap uses it, they also do not use the DD bit check to determine write completion.
//	 * From the E1000E SDM Section 3.3 (Transmit Descriptor Ring Structure):
//		Software can determine if a packet has been sent by setting the RS bit in the transmit descriptor
//		command field. Checking the transmit descriptor DD bit in memory eliminates a potential race
//		condition. All descriptor data is written to the IO bus prior to incrementing the head register, but a
//		read of the head register could “pass” the data write in systems performing IO write buffering.
//		Updates to transmit descriptors use the same IO write path and follow all data writes.
//		Consequently, they are not subject to the race condition. Other potential conditions also prohibit
//		software reading the head pointer.
//	 */
//	//Can probably be combined with the wmb(); above, but it expands to nothing? ...
//
//	cleanup:
//	mmiowb(); //It expands to "do {} while (0)" on x86_64... (E1000E driver notes it is needed on NUMA and IA64/Alpha archs)
//	/* Cleanup: Check how many frames have been transmitted and get the latest head
//	 *
//	 */
//	//XXX: The SDM says the head represents frames that are in progress, but that have been loaded in the FIFO
//	// Because we're not doing any writeback, I'm assuming we can just use the head.
//	// That said, if data is coming out garbled, this is a point of investigation. (Do we need to rewind?)
//	hw_index = readl(hw_ring->head);
//	//Increment the gao head by the delta the hw_index was incremented by
//	//FIXME: I don't think we even need to do this...
//	gao_ring->ring->header.head = ((gao_ring->ring->header.head + CIRC_DIFF16(hw_index, hw_ring->next_to_clean, hw_ring_size)) % gao_ring_size);
//	hw_ring->next_to_clean = hw_index;
//
//	descriptors_left = hw_ring_size - CIRC_DIFF16(hw_ring->next_to_use, hw_ring->next_to_clean, hw_ring_size);
//	gao_ring->ring->header.size = descriptors_left;
//
//	log_dp("Done Cleanup: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u next_to_use=%u left=%u",
//						readl(hw_ring->tail), readl(hw_ring->head),	gao_ring->ring->header.head,
//						gao_ring->ring->header.tail, hw_ring->next_to_clean, hw_ring->next_to_use, descriptors_left);
//
//	//Do we need to block?
//	if( (descriptors_left < GAO_E1000E_TXD_DESC_LOW_THRESH) && !(file_priv->filep->f_flags & O_NONBLOCK) ) {
//		log_dp("Write will try to block.");
//		gao_ring->wake_condition = 0;
//		gao_e1000e_enable_tx_interrupts(adapter);
//		//Check the TX desc one final time
//		//XXX: mmiowb();?
//		hw_ring->next_to_clean = readl(hw_ring->head);
//		descriptors_left = (hw_ring_size - CIRC_DIFF16(hw_ring->next_to_use, hw_ring->next_to_clean, hw_ring_size));
//		if( (descriptors_left < GAO_E1000E_TXD_DESC_LOW_THRESH) ) {
//			log_dp("Write starting to block, calculated left=%u.", descriptors_left);
//			log_debug("Write IMS=%x", er32(IMS));
//			if(wait_event_interruptible(gao_ring->wait_queue, gao_ring->wake_condition)) {
//				//The wait was interrupted by a signal
//				log_dp("Write interrupted.");
//				descriptors_left = -1;
//				gao_e1000e_disable_tx_interrupts(adapter);
//				goto interrupted;
//			}
//		}
//		//Either there was something there or we were woken up by an interrupt
//		log_dp("Write wakes, disabling interrupts.");
//		if(unlikely(!gao_ring)) return -1;
//		if(unlikely(!gao_ring->binding.interface)) return -1;
//		gao_e1000e_disable_tx_interrupts(adapter);
//		goto cleanup;
//	}
//
//
//	interrupted:
//
//	gao_ring->userspace->header.head = gao_ring->ring->header.head;
//	gao_ring->userspace->header.tail = gao_ring->ring->header.tail;
//	gao_ring->userspace->header.capacity = gao_ring->ring->header.capacity;
//	gao_ring->userspace->header.size = gao_ring->ring->header.size;
//
//	return descriptors_left;
//}
//




/**
 * @warning Caller must hold RCU read lock
 * @param file_priv
 * @param num_to_read
 * @return
 */
ssize_t		gao_e1000e_read(struct gao_file_private *file_priv, size_t num_to_read) {
	//TODO: Clean up pointer infrastructure here
	ssize_t						ret = 0;
	struct gao_queue			*queue = NULL;
	struct gao_descriptor_ring	*gao_ring = NULL;
	struct gao_descriptor		(*gao_descriptors)[];
	struct e1000_adapter		*adapter = NULL;
	struct e1000_ring			*hw_ring = NULL;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint64_t	index, size, left_to_read = num_to_read; //GAO and HW ring always aligned
	uint32_t	staterr;

	queue = file_priv->bound_queue;
	gao_ring = queue->ring;
	gao_descriptors = &gao_ring->descriptors;
	adapter = queue->hw_private;
	hw_ring = adapter->rx_ring;
	size = hw_ring->count;

//	//Clean
//	head = gao_ring->header.head;
//	left_to_clean =
//
//	log_debug("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));
//
//	wmb();
//	writel(CIRC_PREV(index , size), hw_ring->tail);
//
//	log_debug("Rx clean: wrote tail=%lu", (unsigned long)CIRC_PREV(index , size));
//
//	log_debug("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));
//
////		log_dp("Start Read: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clea6an=%u",
////					readl(hw_ring->tail), readl(hw_ring->head),
////					gao_ring->ring->header.head, gao_ring->ring->header.tail, hw_ring->next_to_clean);
//
//	log_debug("Start Rx: left=%lu next_to_clean/index=%lu", (unsigned long)left_to_read, (unsigned long)index);
//
//	rmb();


/*
	//Clean
	head = gao_ring->header.head;
	//The next one is the next to clean
	index = hw_ring->next_to_clean;
	//left_to_clean = CIRC_DIFF16(head,index,size);


	log_dp("index=%lu head=%lu left_to_clean=%lu", (unsigned long)index, (unsigned long)head, (unsigned long)CIRC_DIFF16(head,index,size));

	for(; (index != head); index = CIRC_NEXT(index, size)) {
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr((*gao_descriptors)[index].descriptor));
		log_dp("Cleaning: index=%lu addr=%lx", (unsigned long)index, (unsigned long)hw_desc->read.buffer_addr);
	}

	hw_ring->next_to_clean = index;

	gao_ring->header.tail = CIRC_PREV(index, size);

	wmb();
	writel(gao_ring->header.tail, hw_ring->tail);
*/


	//Read new packets
	index = gao_ring->header.head;

	while(left_to_read) {
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		staterr = le32_to_cpu(hw_desc->wb.upper.status_error);

		log_dp("Checking Desc: GFN=%hx Idx=%hx Len=%hu Staterr=%08x",
				(*gao_descriptors)[index].gfn, (*gao_descriptors)[index].index, (*gao_descriptors)[index].len,
				staterr);

		if(!(staterr & E1000_RXD_STAT_DD)) {
			log_dp("DD not set, don't use this descriptor.");
			break;
		}

		(*gao_descriptors)[index].len = le16_to_cpu(hw_desc->wb.upper.length);
		log_dp("Rx Index=%lu len=%hu left=%lu", (unsigned long)index, (*gao_descriptors)[index].len, (unsigned long)left_to_read);
		hw_desc->wb.upper.status_error &= cpu_to_le32(~0xFF);

		left_to_read--;
		index = CIRC_NEXT(index, size);

	}

	log_dp("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));

//	hw_ring->next_to_clean = index;
	hw_ring->next_to_use = index;
	gao_ring->header.head = index;

	//gao_e1000e_dump_rx_ring(hw_ring);
	log_dp("Complete Rx: next_to_clean/index=%lu, left_to_read=%lu", (unsigned long)index, (unsigned long)left_to_read);



	ret = num_to_read - left_to_read;



	return ret;
}


/**
 * @warning Caller must hold RCU read lock
 * @param file_priv
 * @param num_to_read
 * @return
 */
ssize_t		gao_e1000e_write(struct gao_file_private *file_priv, size_t num_to_clean) {

	//TODO: Clean up pointer infrastructure here

	struct gao_queue			*queue = NULL;
	struct gao_descriptor_ring	*gao_ring = NULL;
	struct gao_descriptor		(*gao_descriptors)[];
	struct e1000_adapter		*adapter = NULL;
	struct e1000_ring			*hw_ring = NULL;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint64_t	index, head, size, left_to_clean = num_to_clean; //GAO and HW ring always aligned





	queue = file_priv->bound_queue;
	gao_ring = queue->ring;
	gao_descriptors = &gao_ring->descriptors;
	adapter = queue->hw_private;
	hw_ring = adapter->rx_ring;
	size = hw_ring->count;

	//Clean
	head = gao_ring->header.head;
	//The next one is the next to clean
	index = hw_ring->next_to_clean;
	//left_to_clean = CIRC_DIFF16(head,index,size);


	log_dp("index=%lu head=%lu left_to_clean=%lu", (unsigned long)index, (unsigned long)head, (unsigned long)CIRC_DIFF16(head,index,size));

	for(; (index != head) && left_to_clean; index = CIRC_NEXT(index, size), left_to_clean--) {
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr((*gao_descriptors)[index].descriptor));
		log_dp("Cleaning: index=%lu addr=%lx", (unsigned long)index, (unsigned long)hw_desc->read.buffer_addr);
	}

	hw_ring->next_to_clean = index;
	gao_ring->header.tail = CIRC_PREV(index, size);

	wmb();
	writel(gao_ring->header.tail, hw_ring->tail);

	return (num_to_clean - left_to_clean);
}

///**
// * @warning Called under RCU Read Lock
// */
//ssize_t		gao_e1000e_rx_clean(struct gao_file_private *file_priv, char __user *descriptor_buf, size_t num_to_clean) {
//	//TODO: Clean up pointer infrastructure here
//	ssize_t						ret = 0;
//	struct gao_queue			*queue = NULL;
//	struct gao_descriptor_ring	*gao_ring = NULL;
//	struct gao_descriptor		(*gao_descriptors)[];
//	struct e1000_adapter		*adapter = NULL;
//	struct e1000_ring			*hw_ring = NULL;
//	union e1000_rx_desc_extended *hw_desc = NULL;
//	uint64_t	index, head, tail, size, left_to_clean = num_to_clean; //GAO and HW ring always aligned
//	uint32_t	staterr;
//
//	queue = file_priv->bound_queue;
//	gao_ring = queue->ring;
//	gao_descriptors = &gao_ring->descriptors;
//	adapter = queue->hw_private;
//	hw_ring = adapter->rx_ring;
//	size = hw_ring->count;
//
//	//Clean
//	head = gao_ring->header.head;
//	//The next one is the next to clean
//	index = hw_ring->next_to_clean;
//	left_to_clean = num_to_clean;
//
//
//	log_debug("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));
//
//	for(; left_to_clean && (index != head); left_to_clean--, index = CIRC_NEXT(index, size)) {
//		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
//		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr((*gao_descriptors)[index].descriptor));
//		log_dp("Cleaning: index=%lu addr=%lx", (unsigned long)index, (unsigned long)hw_desc->read.buffer_addr);
//	}
//
//
//
//	log_debug("Rx clean: wrote tail=%lu", (unsigned long)CIRC_PREV(index , size));
//
//	log_debug("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));
//
////		log_dp("Start Read: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clea6an=%u",
////					readl(hw_ring->tail), readl(hw_ring->head),
////					gao_ring->ring->header.head, gao_ring->ring->header.tail, hw_ring->next_to_clean);
//
//	log_debug("Start Rx: left=%lu next_to_clean/index=%lu", (unsigned long)left_to_read, (unsigned long)index);
//
//
//	wmb();
//		writel(CIRC_PREV(index , size), hw_ring->tail);
////
////
////	rmb();
////
////	index = gao_ring->header.head;
////
////	while(left_to_read) {
////		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
////		staterr = le32_to_cpu(hw_desc->wb.upper.status_error);
////
////		log_debug("Checking Desc: GFN=%hx Idx=%hx Len=%hu Staterr=%08x",
////				(*gao_descriptors)[index].gfn, (*gao_descriptors)[index].index, (*gao_descriptors)[index].len,
////				staterr);
////
////		if(!(staterr & E1000_RXD_STAT_DD)) {
////			log_debug("DD not set, don't use this descriptor.");
////			break;
////		}
////
////		(*gao_descriptors)[index].len = le16_to_cpu(hw_desc->wb.upper.length);
////		log_debug("Rx Index=%lu len=%hu left=%lu", (unsigned long)index, (*gao_descriptors)[index].len, (unsigned long)left_to_read);
////		hw_desc->wb.upper.status_error &= cpu_to_le32(~0xFF);
////
////		left_to_read--;
////		index = CIRC_NEXT(index, size);
////
////	}
////
////	log_debug("index=%lu hw_head=%u hw_tail=%u", (unsigned long)index, readl(hw_ring->head), readl(hw_ring->tail));
////
//////	hw_ring->next_to_clean = index;
////	hw_ring->next_to_use = index;
////	gao_ring->header.head = index;
//
//	gao_e1000e_dump_rx_ring(hw_ring);
//	log_debug("Complete Rx: next_to_clean/index=%lu, left_to_read=%lu", (unsigned long)index, (unsigned long)left_to_read);
//
//
//
//	ret = num_to_read - left_to_read;
//
//
//
//	return ret;
//}

//ssize_t	gao_e1000e_read(struct gao_file_private *file_priv, size_t size) {
//	ssize_t 				descriptors_read = 0;
//	uint32_t				hw_index, gao_index, limit, gao_ring_size, hw_ring_size, staterr;
//	uint64_t				gao_desc, length;
//	uint64_t				*gao_descriptors;
//	struct e1000_adapter 	*adapter = NULL;
//	struct e1000_ring 		*hw_ring = NULL;
//	struct gao_queue 	*gao_ring = NULL;
//	union e1000_rx_desc_extended *hw_desc = NULL;
//
//	log_dp("Called gao_e1000e_read");
//	gao_ring = file_priv->gao_ring;
//	gao_descriptors = (uint64_t*)(&gao_ring->userspace->descriptors);
//	//TODO: lock the ring
//
//	adapter = netdev_priv(gao_ring->binding.interface->netdev);
//	hw_ring = adapter->rx_ring;
//
//	gao_ring_size = gao_ring->ring->header.capacity;
//	hw_ring_size = hw_ring->count;
//
//	log_dp("Start Read: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u",
//				readl(hw_ring->tail), readl(hw_ring->head),
//				gao_ring->ring->header.head, gao_ring->ring->header.tail, hw_ring->next_to_clean);
//
//
//	/* Cleanup: Reclaim the descriptors gao held and return to HW ring
//	 * Move the gao tail to the position right before the current gao head, then save tail in hw
//	 * Save the new descriptors in the HW (userspace might have changed them)
//	 */
//	hw_index = hw_ring->next_to_clean;
//	gao_index = CIRC_NEXT(gao_ring->ring->header.tail, gao_ring_size);
//	limit = gao_ring->ring->header.head;
//	log_dp("Start Clean: gao_index=%u hw_index=%u limit=%u", gao_index, hw_index, limit);
//
//	for(;gao_index != limit; gao_index = CIRC_NEXT(gao_index, gao_ring_size), hw_index = CIRC_NEXT(hw_index, hw_ring_size)) {
//		hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_index);
//		gao_desc = gao_descriptors[gao_index];
//		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_desc));
//		log_dp("Cleaning: gao_index=%u hw_index=%u addr=%lu", gao_index, hw_index, (unsigned long)hw_desc->read.buffer_addr);
//	}
//
//	//The indices now equal the head
//	//Rewind the indices to be one before the head and write to tails
//	wmb();
//	writel(CIRC_PREV(hw_index , hw_ring_size), hw_ring->tail);
//	gao_ring->ring->header.tail = CIRC_PREV(gao_index , gao_ring_size);
//	hw_ring->next_to_clean = hw_index;
//
//	log_dp("Cleanup Finished: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u",
//				readl(hw_ring->tail), readl(hw_ring->head),
//				gao_ring->ring->header.head, gao_ring->ring->header.tail, hw_ring->next_to_clean);
//
//
//
//	catchup:
//	/* Process new frames for userspace to access
//	 * Move the gao head to the current hw head
//	 * Index is already at the current head
//	 */
//	hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_index);
//	staterr = le32_to_cpu(hw_desc->wb.upper.status_error);
//
//	log_dp("Starting RX Catchup. gao_index=%u hw_index=%u", gao_index, hw_index);
//	//While there are unprocessed frames
//	while (staterr & E1000_RXD_STAT_DD) {
//		//XXX: Can we get rid of the rmb, pretty please?
//		rmb(); //Make sure reads to descriptor are after staterr read completes
//
//		//Copy the length into our descriptor
//		length = le16_to_cpu(hw_desc->wb.upper.length);
//		gao_desc = gao_descriptors[gao_index];
//		gao_descriptors[gao_index] = GAO_DESCRIPTOR_SET_LEN(gao_desc, length);
//
//		descriptors_read++;
//		log_dp("Catchup: gao_index=%u hw_index=%u old_desc=%lu new_desc=%lu",
//				gao_index, hw_index, (unsigned long)gao_desc, (unsigned long)gao_descriptors[gao_index]);
//
//		//Clear the status bits
//		hw_desc->wb.upper.status_error &= cpu_to_le32(~0xFF);
//
//		//Setup the next descriptor
//		gao_index = CIRC_NEXT(gao_index, gao_ring_size);
//		hw_index = CIRC_NEXT(hw_index, hw_ring_size);
//		hw_desc = E1000_RX_DESC_EXT(*hw_ring, hw_index);
//		staterr = le32_to_cpu(hw_desc->wb.upper.status_error);
//	}
//
//
//	//Do we need to block?
//	if( !descriptors_read && !(file_priv->filep->f_flags & O_NONBLOCK) ) {
//		log_dp("Read will try to block.");
//		gao_ring->wake_condition = 0;
//		gao_e1000e_enable_rx_interrupts(adapter);
//		//Check the RX desc one final time
//		if(!(le32_to_cpu(hw_desc->wb.upper.status_error) & E1000_RXD_STAT_DD)) {
//			log_dp("Read starting to block.");
//			if(wait_event_interruptible(gao_ring->wait_queue, gao_ring->wake_condition)) {
//			//if(wait_event_interruptible(gao_ring->wait_queue, (le32_to_cpu(hw_desc->wb.upper.status_error) & E1000_RXD_STAT_DD))) {
//				//The wait was interrupted by a signal
//				//TODO: Can we continue to the bottom? This leaves ring inconsistent...
//				log_dp("Read interrupted.");
//				descriptors_read = -1;
//				gao_e1000e_disable_rx_interrupts(adapter);
//				goto interrupted;
//				//return -1;
//			}
//		}
//		//Either there was something there or we were woken up by an interrupt
//		log_dp("Read wakes, disabling interrupts.");
//		if(unlikely(!gao_ring)) return -1;
//		if(unlikely(!gao_ring->binding.interface)) return -1;
//		gao_e1000e_disable_rx_interrupts(adapter);
//		goto catchup;
//	}
//
//	interrupted:
//
//	hw_ring->next_to_use = hw_index;
//	gao_ring->ring->header.head = gao_index;
//	gao_ring->ring->header.size = descriptors_read;
//
//	gao_ring->userspace->header.head = gao_ring->ring->header.head;
//	gao_ring->userspace->header.tail = gao_ring->ring->header.tail;
//	gao_ring->userspace->header.capacity = gao_ring->ring->header.capacity;
//	gao_ring->userspace->header.size = gao_ring->ring->header.size;
//
//	log_dp("Read Finished: hw_tail=%u hw_head=%u gao_head=%u gao_tail=%u next_to_clean=%u",
//				readl(hw_ring->tail), readl(hw_ring->head),
//				gao_ring->ring->header.head, gao_ring->ring->header.tail, hw_ring->next_to_clean);
//
//	return descriptors_read;
//}


/**
 * Receive new frames into the GAO queue.
 * @param gao_queue
 * @return The number of frames received.
 */
ssize_t	gao_e1000e_clean(struct gao_queue *gao_queue, size_t num_to_clean) {
	struct gao_descriptor	*gao_descriptors = (struct gao_descriptor*)&gao_queue->ring->descriptors;
	struct e1000_adapter 	*adapter = (struct e1000_adapter*)gao_queue->hw_private;
	struct e1000_ring 		*hw_ring = adapter->rx_ring;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint64_t				index = hw_ring->next_to_use, size = hw_ring->count, num_cleaned, head;


	//Clean
	head = gao_queue->ring->header.head;
	//The next one is the next to clean
	index = hw_ring->next_to_clean;

	log_dp("start clean: index/next_to_clean=%llu left=%lu", index, num_to_clean);

	while( (index != head) && num_to_clean ) {
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		gao_descriptors[index].offset = GAO_DEFAULT_OFFSET;
		hw_desc->read.buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_descriptors[index].descriptor));

		log_dp("clean: index=%llu addr=%llx", index, hw_desc->read.buffer_addr);

		index = CIRC_NEXT(index, size);
		num_to_clean--;
	}

	num_cleaned = CIRC_DIFF16(index, hw_ring->next_to_clean, size);
	hw_ring->next_to_clean = index;
	gao_queue->ring->header.tail = CIRC_PREV(index, size);

	wmb();
	writel(gao_queue->ring->header.tail, hw_ring->tail);

	log_dp("done clean: index/next_to_clean=%llu left=%lu cleaned=%llu", index, num_to_clean, num_cleaned);

	return num_cleaned;
}


/**
 * Receive new frames into the GAO queue.
 * @param gao_queue
 * @return The number of frames received.
 */
ssize_t	gao_e1000e_recv(struct gao_queue *gao_queue, size_t num_to_read) {
	struct gao_descriptor	*gao_descriptors = (struct gao_descriptor*)&gao_queue->ring->descriptors;
	struct e1000_adapter 	*adapter = (struct e1000_adapter*)gao_queue->hw_private;
	struct e1000_ring 		*hw_ring = adapter->rx_ring;
	union e1000_rx_desc_extended *hw_desc = NULL;
	uint64_t				index = hw_ring->next_to_use, size = hw_ring->count, num_read;
	uint32_t				staterr;

	if(unlikely(test_bit(__E1000_DOWN, &adapter->state))) {
		log_bug("abort recv: adapter down");
		return -EIO;
	}

	hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
	staterr = le32_to_cpu(hw_desc->wb.upper.status_error);

	log_dp("start recv: index/head=%llu left=%lu staterr=%x", index, num_to_read, staterr);

	while( (staterr & E1000_RXD_STAT_DD) && num_to_read) {
		gao_descriptors[index].len = le16_to_cpu(hw_desc->wb.upper.length);
		hw_desc->wb.upper.status_error &= cpu_to_le32(~0xFF);

		log_dp("recv: index=%llu len=%hu left=%lu", index, gao_descriptors[index].len, num_to_read);

		index = CIRC_NEXT(index, size);
		num_to_read--;
		hw_desc = E1000_RX_DESC_EXT(*hw_ring, index);
		staterr = le32_to_cpu(hw_desc->wb.upper.status_error);
	}

	num_read = CIRC_DIFF64(index, gao_queue->ring->header.head, size);
	hw_ring->next_to_use = index;
	gao_queue->ring->header.head = index;

	log_dp("done recv: index/head=%llu left=%lu read=%llu", index, num_to_read, num_read);

	return num_read;
}



/**
 * Transmit the frames on the GAO queue.
 * @warning Assumes the tail is not mangled.
 * @warning Caller must hold RCU read lock
 * @param gao_queue
 * @return The number of descriptors available on the nic tx queue.
 */
ssize_t	gao_e1000e_xmit(struct gao_queue *gao_queue) {
	struct gao_descriptor	*gao_descriptors = (struct gao_descriptor*)&gao_queue->ring->descriptors;
	struct e1000_adapter 	*adapter = (struct e1000_adapter*)gao_queue->hw_private;
	struct e1000_ring 		*hw_ring = adapter->tx_ring;
	struct e1000_tx_desc 	*hw_desc = NULL;
	uint64_t				index = hw_ring->next_to_use, size = hw_ring->count, limit;

	//We will advance the nic tail to the gao tail
	limit = gao_queue->ring->header.tail;

	log_dp("start xmit: index/tail=%llu limit=%llu", index, limit);

	if(unlikely(test_bit(__E1000_DOWN, &adapter->state) || !netif_carrier_ok(adapter->netdev))) {
		log_bug("abort xmit: adapter down");
		hw_ring->next_to_use = limit;
		return (ssize_t)gao_ring_slots_left(gao_queue->ring);
	}

	for(; index != limit; index = CIRC_NEXT(index, size) ) {
		hw_desc = E1000_TX_DESC(*hw_ring, index);
		log_dp("xmit: index=%llu desc=%016llx", index, gao_descriptors[index].descriptor);
		hw_desc->buffer_addr = cpu_to_le64(descriptor_to_phys_addr(gao_descriptors[index].descriptor));
		hw_desc->lower.data  = cpu_to_le32(gao_descriptors[index].len | GAO_E1000E_TXD_FLAGS);
		hw_desc->upper.data  = 0;
	}

	//Update the tails on the NIC ring
	wmb();
	hw_ring->next_to_use = index;
	writel(index, hw_ring->tail);

	//Make sure the IO writes from the NIC have completed before we read the new head
	mmiowb();
	index = readl(hw_ring->head);
	hw_ring->next_to_clean = index;
	gao_queue->ring->header.head = index;

	log_dp("done xmit: index/head=%llu free=%llu", index, gao_ring_slots_left(gao_queue->ring));

	return (ssize_t)gao_ring_slots_left(gao_queue->ring);

}


struct gao_port_ops gao_e1000e_port_ops = {
		.gao_enable = gao_e1000e_enable_gao_mode,
		.gao_disable = gao_e1000e_disable_gao_mode,
		.gao_clean = gao_e1000e_clean,
		.gao_recv = gao_e1000e_recv,
		.gao_xmit = gao_e1000e_xmit,
		.gao_enable_rx_interrupts = gao_e1000e_enable_rx_interrupts,
		.gao_enable_tx_interrupts = gao_e1000e_enable_tx_interrupts,
		.gao_disable_rx_interrupts = gao_e1000e_disable_rx_interrupts,
		.gao_disable_tx_interrupts = gao_e1000e_disable_tx_interrupts,
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
