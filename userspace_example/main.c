/*
 * mian.c
 *
 *  Created on: 2012-12-16
 *      Author: cverge
 */


#include "gao_user.h"


void gao_mmio_example(void) {
	int64_t		ret, index;
	uint64_t	highest_port_id;
	struct gao_context* context = NULL;
	struct gao_request_port_list *list = NULL;

	//Almost all GAO functions require a "context" object. You only need to create one of these.
	//This function will perform memory mappings and set required initialization parameters for you.
	log_debug("Getting a GAO context.");
	context = gao_create_context();
	log_debug("Got a GAO context at: %p.", context);

	//Get the list of registered GAO ports in the system.
	//A linux interface will only show up if it was loaded with a GAO compatible driver.
	//This does not update automatically. A new one needs to be fetched for updated information.
	log_debug("Getting port list");
	list = gao_get_port_list(context);
	if(!list) gao_error("Failed to get port list.");



	log_debug("Printing port list.");
	/* There are three values used to identify the port:
	 * 	gao_ifindex: This is used by GAO functions to id the port. Also used by openflow.
	 * 	ifindex: The kernel ifindex on the port. Used by things like ethtool.
	 * 	name: The name of the port -- universal, but usually can't be used in function calls.
	 */
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		if(list->port[index].state == GAO_RESOURCE_STATE_UNUSED) continue;

		//Save one of these for later, we will enable it.
		highest_port_id = list->port[index].gao_ifindex;

		log_debug("Port %02lu[%s/%ld]: Operational State: %s	Num Queues[RX/TX]: %u/%u",
				list->port[index].gao_ifindex, (char*)&list->port[index].name, list->port[index].ifindex,
				//A port can be unused, registered, or active. If it is unused, there is no port in that slot.
				//if it is registered, it is GAO compatible but not in GAO mode or is down.
				//if the port is active, it is up and in GAO mode, and can be used.
				gao_resource_state_string(list->port[index].state),
				//The number of hardware queues on the port that can be bound to.
				list->port[index].num_rx_queues, list->port[index].num_tx_queues);
	}

	//When any gao function that allocates memory is called, the related free function must be called.
	gao_free_port_list(list);



	//Next we'll enable GAO mode on one of the ports that we listed out.
	log_debug("Enabling GAO Mode on port %lu", highest_port_id);
	ret = gao_enable_port(context, highest_port_id);

	//That function returns 0 on success.
	if(ret) {
		gao_error("Failed to enable GAO Mode on port %lu! Return: %ld", highest_port_id, ret);
	}else{
		log_debug("Successfully enabled GAO Mode on port %lu", highest_port_id);
	}


	//We'll list out the ports again now that one has been put into GAO mode.
	//If the port was down via ifconfig, it will still be registered. The port should
	//have been turned up with ifconfig <name> up first.
	log_debug("Getting port list");
	list = gao_get_port_list(context);
	if(!list) gao_error("Failed to get port list.");

	log_debug("Printing port list.");
	for(index = 0; index < GAO_MAX_PORTS; index++) {
		if(list->port[index].state == GAO_RESOURCE_STATE_UNUSED) continue;
		log_debug("Port %02lu[%s/%ld]: Operational State: %s	Num Queues[RX/TX]: %u/%u",
				list->port[index].gao_ifindex, (char*)&list->port[index].name, list->port[index].ifindex,
				gao_resource_state_string(list->port[index].state),
				list->port[index].num_rx_queues, list->port[index].num_tx_queues);
	}

	gao_free_port_list(list);


	//Ports remain in GAO mode even if your program is closed. If you need to, disable GAO mode.
	log_debug("Disabling GAO Mode on port %lu", highest_port_id);
	gao_disable_port(context, highest_port_id);



	err:
	//To clean up properly, we should free the context.
	//After we do this, we can no longer access packet buffers.
	gao_free_context(context);

	return;
}

int main(void) {
	gao_mmio_example();
	return 0;
}

