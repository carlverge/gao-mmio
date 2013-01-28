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

		//Save one of these for later, we will enable it. Don't use logical ports.
		if(index < GAO_MAX_PHYS_PORT) highest_port_id = list->port[index].gao_ifindex;

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



void gao_rx_tx_example(void) {
	int64_t		ret, index;
	struct gao_descriptor 	*descriptors;
	struct gao_action		*actions, action = {.action_id = GAO_ACTION_FORWARD, .port_id = 1, .queue_id = 0};
	//char					data_buf[8192];
	void					*buf;
	struct gao_context* context = gao_create_context();
	struct gao_queue_context *queue = NULL;



//	struct sched_param sp = { .sched_priority = 50 };
//
//	ret = sched_setscheduler(0, SCHED_RR, &sp);
//	log_info("Setting scheduling policy to RT, ret: %ld", ret);


	ret = gao_enable_port(context, 1);
	if(ret) gao_error("Failed to enable gao port 1");


	log_info("Binding to queue 0 on port 1.");
	queue = gao_bind_queue(1, 0);
	if(!queue) gao_error("Failed to bind to queue.");

	actions = (queue->offset + queue->descriptors_size);
	for(index = 0; index < queue->num_descriptors; index++) actions[index] = action;


	log_info("Reading from FD.");
//	while(ret >= 0) {
//
//		ret = read(queue->fd, &descriptors, 256);
//		if(ret < 0) gao_error("FD died.");
//
//		log_info("Read %ld pkts", ret);
//		for(index = 0; index < ret; index++) {
//			buf = (void*) GAO_DESC_TO_PKT(descriptors[index].descriptor, context->offset);
//			log_info("Pkt %ld: Size %hu Buf %p", index, descriptors[index].len, buf);
//			hexdump(buf, descriptors[index].len);
//		}
//
//		log_debug("Forwarding...");
//		ret = write(queue->fd, &actions, ret);
//		if(ret < 0) gao_error("FD died.");
//		log_debug("Done.");
//	}

	descriptors = queue->offset;

	while(ret >= 0) {

		ret = gao_sync_queue(queue);
		if(ret < 0) gao_error("FD died.");

		if(ret > 200) log_info("Read %ld pkts", ret);
//		for(index = 0; index < ret; index++) {
//			buf = (void*) GAO_DESC_TO_PKT(descriptors[index].descriptor, context->offset);
//			log_info("Pkt %ld: Size %hu Buf %p", index, descriptors[index].len, buf);
//			hexdump(buf, descriptors[index].len);
//		}

	}







	err:
	gao_unbind_queue(queue);
	gao_free_context(context);
	return;
}


void gao_controller_port_example(void) {
	int64_t		ret, index;
	struct gao_descriptor 	*descriptors;
	struct gao_action		*actions, action = {.action_id = GAO_ACTION_FORWARD, .port_id = GAO_CONTROLLER_PORT_ID, .queue_id = 0};
	char					data_buf[8192];
	void					*buf;
	struct gao_context* context = gao_create_context();
	struct gao_queue_context *queue = NULL, *p1 = NULL;




//	struct sched_param sp = { .sched_priority = 50 };
//
//	ret = sched_setscheduler(0, SCHED_RR, &sp);
//	log_info("Setting scheduling policy to RT, ret: %ld", ret);

	ret = gao_enable_port(context, 1);
	if(ret) gao_error("Failed to enable gao port 1");


	log_info("Binding to queue 0 on port 1.");
	p1 = gao_bind_queue(1, 0);
	if(!p1) gao_error("Failed to bind to queue.");

	actions = (p1->offset + p1->descriptors_size);
	for(index = 0; index < p1->num_descriptors; index++) actions[index] = action;


	log_info("Binding to controller port queue.");
	queue = gao_bind_queue(GAO_CONTROLLER_PORT_ID, 0);
	if(!queue) gao_error("Failed to bind to controller port queue.");

	actions = (queue->offset + queue->descriptors_size);
	for(index = 0; index < queue->num_descriptors; index++) actions[index] = action;
	descriptors = queue->offset;

	for(index = 0; index < 5; index++) {
		descriptors[index].len = 100;
	}

	log_info("Pushing 5 descriptors.");
	ret = write(queue->fd, NULL, 5);
	log_info("Returned %ld", ret);
	//Oh hey look we got something on the controller port! Let us Rx it.
	log_info("Sync queue to send descriptors");
	ret = gao_sync_queue(queue);
	log_info("Returned %ld", ret);


	log_info("Reading from controller port");

	while(ret >= 0) {

		ret = gao_sync_queue(p1);
		if(ret < 0) gao_error("FD died.");

		ret = read(queue->fd, &data_buf, 8192);
		if(ret < 0) gao_error("FD died.");
		log_info("Got packet size %ld", ret);
		hexdump(&data_buf, ret);
	}


	err:
	gao_unbind_queue(queue);
	gao_free_context(context);
	return;
}


int main(void) {
	//gao_mmio_example();
	//gao_rx_tx_example();
	gao_controller_port_example();
	return 0;
}


//int main(void) {
//	int fd;
//	//int64_t ret = 0, pkts_in = 0, rollover = 0, cycles = 0, max = 0, index;
//	int64_t	ret = 0, index;
//	struct gao_context* context = gao_create_context();
////	struct gao_descriptor 	descriptors[1024];
////	struct gao_action		actions[1024];
////	char					data_buf[8192];
////	void					*buf;
////	struct sched_param sp = { .sched_priority = 50 };
//
//	//ret = sched_setscheduler(0, SCHED_RR, &sp);
//	//log_info("Setting scheduling policy to RT, ret: %ld", ret);
//
//	struct gao_request_port_list *list = gao_get_port_list(context);
//	if(!list) gao_error("Failed to get port list.");
//
//	for(index = 0; index < GAO_MAX_PORTS; index++) {
//		log_debug("Port %02lu[%s/%ld]: Operational State: %s	Num Queues[RX/TX]: %u/%u",
//				list->port[index].gao_ifindex, (char*)&list->port[index].name, list->port[index].ifindex,
//				gao_resource_state_string(list->port[index].state),
//				list->port[index].num_rx_queues, list->port[index].num_tx_queues);
//	}
//
//	gao_free_port_list(list);
//
//	//gao_dump(context, GAO_REQUEST_DUMP_PORTS_NESTED);
//	log_info("Enabling port 2.");
//	gao_enable_port(context, 2);
//	gao_enable_port(context, 1);
////	gao_dump(context, GAO_REQUEST_DUMP_PORTS_NESTED);
////	gao_enable_port(context, 1);
////	gao_dump(context, GAO_REQUEST_DUMP_PORTS_NESTED);
//
//	list = gao_get_port_list(context);
//	for(index = 0; index < GAO_MAX_PORTS; index++) {
//		log_debug("Port %02lu[%s/%ld]: Operational State: %s	Num Queues[RX/TX]: %u/%u",
//				list->port[index].gao_ifindex, (char*)&list->port[index].name, list->port[index].ifindex,
//				gao_resource_state_string(list->port[index].state),
//				list->port[index].num_rx_queues, list->port[index].num_tx_queues);
//	}
//
//	log_info("Opening FD.");
//	if( (fd = gao_open_fd()) < 0 ) gao_error("Failed to get FD.");
//
//	log_info("Binding to queue 0 on port 0.");
//	if (gao_bind_queue(fd, 2, 0)) gao_error("Failed to bind to queue.");
//
//
////	actions[0].action_id = GAO_ACTION_FORWARD;
////	actions[0].port_id = 0;
////	actions[0].queue_id = 0;
////	actions[1].action_id = GAO_ACTION_FORWARD;
////	actions[1].port_id = 0;
////	actions[1].queue_id = 0;
////	actions[2].action_id = GAO_ACTION_FORWARD;
////	actions[2].port_id = 0;
////	actions[2].queue_id = 0;
////	actions[3].action_id = GAO_ACTION_FORWARD;
////	actions[3].port_id = 1;
////	actions[3].queue_id = 0;
////	actions[4].action_id = GAO_ACTION_FORWARD;
////	actions[4].port_id = 1;
////	actions[4].queue_id = 0;
////
////	log_info("Reading from FD.");
////	while(ret >= 0) {
////
////		ret = read(fd, &descriptors, 5);
////		if(ret < 0) gao_error("FD died.");
////
////		log_debug("Read %ld pkts", ret);
////		for(index = 0; index < ret; index++) {
////			buf = (void*) GAO_DESC_TO_PKT(descriptors[index].descriptor, context->offset);
////			log_info("Pkt %ld: Size %hu Buf %p", index, descriptors[index].len, buf);
////			hexdump(buf, descriptors[index].len);
////		}
////		log_debug("Forwarding...");
////		ret = write(fd, &actions, ret);
////		if(ret < 0) gao_error("FD died.");
////		log_debug("Done.");
////
//////		ret = read(fd, &descriptors, 1024);
//////		pkts_in += ret;
//////		cycles++;
//////		rollover++;
//////		if(ret > max) max = ret;
//////		if(rollover > 10000) {
//////			rollover = 0;
//////			log_info("pkts_in=%ld avg=%ld max=%lu", pkts_in, pkts_in/cycles, max);
//////		}
//////		//log_info("Read returned %ld.", ret);
////	}
//
//	err:
//	gao_free_context(context);
//	return 0;
//}

//#define GAO_MAX_BUFFER_GROUPS 1024			//2GB
//#define GAO_INITIAL_BUFFER_GROUPS 256		//512MB
//#define GAO_BUFFER_GROUP_SIZE (2*1024*1024) //2MB
//#define GAO_SMALLPAGE_SIZE (4096)

//int 		gao_fd = 0, gao_fd2 = 0;
//
//uint64_t	mmap_size = 0;
//uint64_t	arg = 0;
//int64_t		ret = 0;
//unsigned long mmap_offset;
//struct gao_request_mmap mmap_info;
//char		dummybuf[65535];


//inline void* gao_descriptor_to_buffer(uint64_t	descriptor, void* mmap_address) {
//	return (void*) (mmap_address
//			+ (GAO_MAX_QUEUE_SIZE_BYTES*GAO_MAX_QUEUES) //Go to the buffer area
//			+ (GAO_DESCRIPTOR_GRPIDX(descriptor)*GAO_BUFFER_GROUP_SIZE) //Go to the buffer group
//			+ (GAO_DESCRIPTOR_INDEX(descriptor)*GAO_BUFFER_SIZE) //Go to the buffer
//			+ GAO_DESCRIPTOR_OFFSET(descriptor)); //Go to the packet
//}
//
//inline struct gao_user_queue* gao_queue_index_to_queue(uint64_t index, void* mmap_address) {
//	return (struct gao_user_queue*) (mmap_address
//			+ (index * GAO_MAX_QUEUE_SIZE_BYTES));
//}


//	log_debug("Attempting to create queue of size 3");
//	ioctlarg = 3;
//	queue_index = ioctl(fd, GAO_IOCTL_COMMAND_CREATE_QUEUE, &ioctlarg);
//	if(queue_index < 0) gao_error_val(queue_index, "Failed to create queue! Error %ld", queue_index);
//	log_debug("Got a queue with index %ld", queue_index);

//	gao_dump_user_queue(GAO_QUEUE(mapaddr, queue_index));
//
//	log_debug("Attempting to delete queue %ld", queue_index);
//	ret = ioctl(fd, GAO_IOCTL_COMMAND_DELETE_QUEUE, &queue_index);
//	if(ret) gao_error_val(ret, "Failed to delete queue! Error: %ld", ret);
//	log_debug("Deleted queue.");




//void	process_command(char (*cmd)[]) {
//	uint32_t	index;
//	struct gao_user_queue* queue = NULL;
////	struct gao_descriptor test_desc;
////	test_desc.info = 0;
////	test_desc.buffer_id.index = 10;
//	gao_request_dump_t request_dump;
//	char	testbuf[16];
//	struct gao_request_interface if_request;
//	struct gao_request_queue queue_request;
//	struct gao_descriptor		descriptor_buf[50];
//	*(strchr((char*) cmd, '\n')) = 0;
//	if(!strlen((char*) cmd)) return;
//
//	switch((*cmd)[0]) {
//	case 'x':
//		printf("Exiting\n");
//		exit(0);
//	case 'o':
//		log_debug("Opening GAOMMIO FD.");
//		if((gao_fd = open("/dev/gaommio", O_RDWR)) < 0) log_error("Couldn't open FD to GAOMMIO!");
//		if((gao_fd2 = open("/dev/gaommio", O_RDWR)) < 0) log_error("Couldn't open FD2 to GAOMMIO!");
//		log_debug("Got FD num %d and %d", gao_fd, gao_fd2);
//		break;
//
//	case 'm':
//		log_debug("Getting MMAP Area size.");
//
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_GET_MMAP_SIZE, &mmap_info);
//		log_debug("Got a size of %ldB, %ldMB. offset=%lx",
//				mmap_info.size, mmap_info.size >> 20, mmap_info.offset);
//
//		log_debug("Attempting to MMAP GAOMMIO space");
//		mmap_addr = mmap(0, mmap_info.size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, gao_fd, 0);
//		if(mmap_addr < 0) {
//			log_error("Failed to mmap.");
//		} else {
//			log_debug("MMAP successful, got a pointer to %p", mmap_addr);
//		}
//
//
//
//		mmap_offset = ((unsigned long)mmap_addr) - mmap_info.offset;
//		log_debug("Calculated offset of %lx", mmap_offset);
//		strncpy((char*)&testbuf, (char*)mmap_addr, 16);
//		log_debug("First bytes: %s", (char*)&testbuf);
//
//
//		break;
//
//	case 'e':
//		log_debug("Attempting to enable GAO on interface index 0.");
//		if_request.request_code = GAO_REQUEST_INTERFACE_ENABLE;
//		if_request.gao_ifindex = 0;
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_INTERFACE, &if_request);
//		log_debug("Hopefully kernel did not panic. We're done.");
//		break;
//
//	case 'd':
//		log_debug("Attempting to disable GAO on interface index 0.");
//		if_request.request_code = GAO_REQUEST_INTERFACE_DISABLE;
//		if_request.gao_ifindex = 0;
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_INTERFACE, &if_request);
//		log_debug("Hopefully kernel did not panic. We're done.");
//		break;
//
//	case 'b':
//		log_debug("Attemping to bind interface");
//		queue_request.gao_ifindex = 0;
//		queue_request.queue_index = 0;
//		queue_request.direction_txrx = GAO_DIRECTION_RX;
//		queue_request.request_code = GAO_REQUEST_QUEUE_BIND;
//		ret = ioctl(gao_fd, GAO_IOCTL_COMMAND_QUEUE, &queue_request);
//		if(ret) {
//			log_error("Failed to bind interface, ret=%ld", ret);
//		} else {
//			log_debug("Bound interface successfully, ret=%ld", ret);
//		}
//		break;
//
//	case 'u':
//		log_debug("Attemping to unbind interface");
//		queue_request.request_code = GAO_REQUEST_QUEUE_UNBIND;
//		ret = ioctl(gao_fd, GAO_IOCTL_COMMAND_QUEUE, &queue_request);
//		log_debug("Done. Hopefully the kernel is calm.");
//		break;
//
//	case 'r':
//		log_debug("Attemping to read the FD. Stand by.");
//		ret = read(gao_fd, &descriptor_buf, 50);
//		log_debug("Read returned %ld", ret);
//		if(ret > 0) {
//			for(index = 0; index < ret; index++) {
//				log_debug("Got Desc: GFN=%hx Idx=%hx Len=%hu", descriptor_buf[index].gfn, descriptor_buf[index].index, descriptor_buf[index].len);
//			}
//		}
//		break;
//
//	case 'w':
//		log_debug("Attemping to write the FD. Stand by.");
//		ret = write(gao_fd, NULL, 250);
//		log_debug("Write returned %ld", ret);
//		break;
//
//	case 'l':
//		log_debug("Starting infinite write loop");
//		ret = write(gao_fd, NULL, 250);
//		while(1) {
//			ret = write(gao_fd, NULL, ret-1);
//			//log_debug("Free %ld", ret);
//		}
//		//log_debug("Write returned %ld", ret);
//		break;
//
//	case 't':
//		//log_debug("Putting things in the TX queue.");
////		log_debug("Trying to write to buffers");
////		*((uint64_t*)gao_descriptor_to_buffer(test_desc.info, mmap_addr)) = 22;
////		log_debug("Trying to write to queues");
////		queue = gao_queue_index_to_queue(0, mmap_addr);
////		queue->header.tail = 20;
////		log_debug("Done");
////		for(index = 0; index < queue->header.capacity; index++) {
////			queue->descriptors[index].len = 64;
////		}
////		log_debug("We're done.");
////		break;
//		break;
//	case 'q':
//		request_dump = GAO_REQUEST_DUMP_QUEUES;
//		log_debug("Dumping queues.");
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP, &request_dump);
//		break;
//	case 'f':
//		request_dump = GAO_REQUEST_DUMP_BUFFERS;
//		log_debug("Dumping buffers.");
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP, &request_dump);
//		break;
//	case 'p':
//		request_dump = GAO_REQUEST_DUMP_DESCRIPTORS;
//		log_debug("Dumping descriptors.");
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP, &request_dump);
//		break;
//	case 'i':
//		request_dump = GAO_REQUEST_DUMP_INTERFACES;
//		log_debug("Dumping interfaces.");
//		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP, &request_dump);
//		break;
//	case 'c':
//		log_debug("Closing GAOMMIO FD.");
//		close(gao_fd);
//		close(gao_fd2);
//		break;
//
////	case 'p':
////		log_debug("Dumping descriptors");
////		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP_DESCRIPTORS, NULL);
////		break;
////
////	case 'i':
////		log_debug("Dumping interfaces.");
////		ioctl(gao_fd, GAO_IOCTL_COMMAND_DUMP_INTERFACES, NULL);
////		break;
//
//	case '?':
//		printf("Help:\n\
//x - Exit\n\
//o - Open FD\n\
//m - MMAP\n\
//e - Enable GAO\n\
//d - Disable GAO\n\
//b - Bind Interface\n\
//u - Detach Interface\n\
//c - Close FD\n\
//p - Dump Descriptors\n\
//i - Dump Interfaces\n\
//r - Read FD\n\
//w - Write FD\n\
//q - Dump queues\n\
//f - Dump buffers\n\
//t - Setup TX Descriptors FD\n");
//		break;
//	default:
//		printf("Unknown command.\n");
//		break;
//	}
//
//
//}
//
//int		main(void) {
//	char buf[4096];
//	memset(&buf, 0, sizeof(buf));
//
//	while(1) {
//		printf("gao> ");
//		fflush(stdout);
//		fgets(buf, 4096, stdin);
//		process_command(&buf);
//		memset(&buf, 0, sizeof(buf));
//	}
//
//	return 0;
//
//}
//







