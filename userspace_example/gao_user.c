/*
 * gao_user.c
 *
 *  Created on: 2013-01-22
 *      Author: cverge
 */

#include "gao_user.h"

/**
 * Taken from http://sws.dett.de/mini/hexdump-c/
 */
void hexdump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4lx",
               ((unsigned long)p-(unsigned long)data) );
        }

        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) {
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}


const static char *gao_resource_state_str[] = {"Unused", "Registered", "Active", "Configuring", "Deleting", "Error", "Invalid State"};

const char*	gao_resource_state_string(gao_resource_state_t state) {
	if(state >= GAO_RESOURCE_STATE_FINAL) return gao_resource_state_str[GAO_RESOURCE_STATE_FINAL];
	else return gao_resource_state_str[state];
}



/**
 * Open a file descriptor to the GAO driver.
 * @return An FD to GAO. Return value < 0 is an error.
 */
int	gao_open_fd() {
	return open("/dev/gaommio", O_RDWR);
}

/**
 * Close a file descriptor to the GAO driver.
 * @param fd The FD to close.
 * @return The return code of the close.
 */
int gao_close_fd(int fd) {
	return close(fd);
}

/**
 * Free a GAO context. It cannot be used after this.
 * @param context The context to free.
 */
void gao_free_context(struct gao_context* context) {
	if(context) {
		close(context->fd);
	}
	free_null(context);
}

/**
 * For driver debugging, triggers a dump function in the kernel.
 * @param context
 * @param type
 */
void gao_dump(struct gao_context *context, gao_queue_request_t type) {
	ioctl(context->fd, GAO_IOCTL_COMMAND_DUMP, &type);
}


/**
 * Create and setup a GAO context hook. This context is required for most GAO
 * functions and is required to access packet buffers. Only one context is needed
 * for a process (and only one should be opened). Must be freed by the caller with
 * gao_free_context.
 * @return A pointer to a new context.
 */
struct gao_context* gao_create_context() {
	log_debug("Creating GAO Context.");
	struct gao_request_mmap mmap_info;
	void*					mmap_addr = NULL;
	int 					fd = 0;
	struct gao_context *context = malloc(sizeof(struct gao_context));
	check_ptr(context);

	//Open the device
	fd = gao_open_fd();
	if(fd < 0) gao_error("Unable to open /dev/gaommio.");


	//Get the info required to MMAP
	if(ioctl(fd, GAO_IOCTL_COMMAND_GET_MMAP_SIZE, &mmap_info)) gao_error("MMAP IOCTL Failed.");

	log_debug("Got a size of %ldB, %ldMB, offset=%lx gridspace_size=%ldMB",
			mmap_info.bufferspace_size, mmap_info.bufferspace_size >> 20, mmap_info.offset, mmap_info.gridspace_size);


	//Perform the MMAP
	log_debug("Attempting to MMAP GAOMMIO bufferspace");
	context->buffer_addr = mmap(0, mmap_info.bufferspace_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, fd, 0);

	if(mmap_addr < 0) gao_error("MMAP Failed.");


	context->mmap_addr = mmap_addr;
	context->offset = ((unsigned long)mmap_addr) - mmap_info.offset;
	context->fd = fd;

	return context;
	err:
	gao_free_context(context);
	return NULL;
}


void gao_free_port_list(struct gao_request_port_list* list) {
	if(list) free(list);
}

/**
 * Get a list of all GAO registered ports in the system. Caller must free the
 * port list with gao_free_port_list. Refer to struct gao_request_port_list for
 * the information this contains.
 * @param context
 * @return A pointer to a new port list.
 */
struct gao_request_port_list*	gao_get_port_list(struct gao_context* context) {
	int64_t ret = 0;
	struct gao_request_port_list* list = NULL;
	struct gao_request_port request = {
			.request_code = GAO_REQUEST_PORT_LIST,
	};

	list = malloc(sizeof(struct gao_request_port_list));
	check_ptr(list);

	request.port_list = list;

	ret = ioctl(context->fd, GAO_IOCTL_COMMAND_PORT, &request);

	if(ret) gao_error("Get port list failed: %ld", ret);

	return list;
	err:
	gao_free_port_list(list);
	return NULL;
}


/**
 * Enable a GAO port for GAO mode. This will disconnect the port from the linux networking stack.
 * If the port was down, it will remain down. If the port was up, it will be reset and brought
 * up in GAO mode. A port in GAO mode will still be visible to linux, but any sockets sending to it
 * will transparently fail. However, a port may still be reconfigured by ifconfig and ethtool.
 * @param context
 * @param gao_ifindex The GAO ifindex of the port to enable (not the kernel index).
 * @return 0 on success, negative on error.
 */
int64_t gao_enable_port(struct gao_context* context, uint64_t gao_ifindex) {
	int64_t ret = 0;
	struct gao_request_port request = {
			.request_code = GAO_REQUEST_PORT_ENABLE,
			.gao_ifindex = gao_ifindex,
	};

	log_debug("Enable GAO on port index %lu.", gao_ifindex);
	ret = ioctl(context->fd, GAO_IOCTL_COMMAND_PORT, &request);
	if(ret) gao_error("Failed to enable GAO on port %lu.", gao_ifindex);

	return 0;
	err:
	return ret;
}

/**
 * Disable GAO on a port. This will reconnect the port to the linux networking stack.
 * If the port was down, it will remain down. If the port was up, it will be reset and brought
 * up in normal mode.
 * @param context
 * @param gao_ifindex The GAO ifindex of the port to enable (not the kernel index).
 * @return 0 on success, negative on failure.
 */
int64_t gao_disable_port(struct gao_context* context, uint64_t gao_ifindex) {
	int64_t ret = 0;
	struct gao_request_port request = {
			.request_code = GAO_REQUEST_PORT_DISABLE,
			.gao_ifindex = gao_ifindex,
	};

	log_debug("Enable GAO on port index %lu.", gao_ifindex);
	ret = ioctl(context->fd, GAO_IOCTL_COMMAND_PORT, &request);
	if(ret) gao_error("Failed to enable GAO on port %lu.", gao_ifindex);

	return 0;
	err:
	return ret;
}

/**
 * Unbinds a file descriptor from a queue. Reads and writes will fail after this is done.
 * @param fd
 * @return 0 on success, negative on failure.
 */
void gao_unbind_queue(struct gao_queue_context* context) {

	struct gao_request_queue request = {
			.request_code = GAO_REQUEST_QUEUE_UNBIND,
	};

	if(context) {
		ioctl(context->fd, GAO_IOCTL_COMMAND_QUEUE, &request);
		gao_close_fd(context->fd);
		free(context);
	}


	return;
}

/**
 * Bind to an RX queue on a port. This allows for read/write operations. There can only be one
 * binding to a queue at once.
 * @param gao_ifindex The GAO ifindex of the port to enable (not the kernel index).
 * @param queue_index The queue index within the port. Starts at 0.
 * @return A new queue context containing information about the binding.
 */
struct gao_queue_context*	gao_bind_queue(uint64_t gao_ifindex, uint64_t queue_index) {
	struct gao_queue_context *context = NULL;
	int64_t ret = 0;
	void	*mmap_addr = NULL;
	size_t	mmap_size;
	int fd;

	struct gao_request_queue request = {
			.request_code = GAO_REQUEST_QUEUE_BIND,
			.gao_ifindex = gao_ifindex,
			.queue_index = queue_index,
			.direction_txrx = GAO_DIRECTION_RX,
	};

	context = malloc(sizeof(struct gao_queue_context));
	check_ptr(context);
	memset((void*)context, 0, sizeof(struct gao_queue_context));

	//Open a new FD -- one to one mapping between queue and FDs
	fd = gao_open_fd();
	if(fd < 0) gao_error("Unable to open /dev/gaommio.");

	//Perform the binding
	ret = ioctl(fd, GAO_IOCTL_COMMAND_QUEUE, &request);
	if(ret) gao_error("Failed to bind to port %lu queue %lu.", gao_ifindex, queue_index);


	//Get the descriptor and action buffers
	log_debug("Attempting to MMAP Queue space");
	mmap_size = request.descriptor_pipeline_size + request.action_pipeline_size;
	mmap_addr = mmap(0, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, fd, 0);
	if(mmap_addr == (void*)~0) gao_error("MMAP Failed.");
	log_debug("MMAP Worked, got %p", mmap_addr);

	context->fd = fd;
	context->port_id = gao_ifindex;
	context->queue_id = queue_index;
	context->offset = mmap_addr;
	context->descriptors_size = request.descriptor_pipeline_size;
	context->actions_size = request.action_pipeline_size;
	context->num_descriptors = request.queue_size;
	context->current_grid = 0;

	log_debug("Successfully bound to queue: fd=%d port=%lu queue=%lu addr=%p desc_size=%lu action_size=%lu queue_size=%lu grid=%lu",
			context->fd, context->port_id, context->queue_id, context->offset, context->descriptors_size, context->actions_size,
			context->num_descriptors, context->current_grid);


	return context;
	err:
	gao_unbind_queue(context);
	return NULL;
}

int64_t gao_sync_queue(struct gao_queue_context* queue) {
	int64_t ret;
	ret = ioctl(queue->fd, GAO_IOCTL_SYNC_QUEUE, NULL);
	return ret;
}





