/*
 * gao_user.h
 *
 *  Created on: 2013-01-22
 *      Author: cverge
 */

#ifndef GAO_USER_H_
#define GAO_USER_H_
#undef __KERNEL__

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <ctype.h>
#include <gao_log.h>
#include <gao_mmio_resource.h>

/**
 * Taken from http://sws.dett.de/mini/hexdump-c/
 */
void hexdump(void *data, int size);

int	gao_open_fd();
int gao_close_fd(int fd);
struct gao_context* gao_create_context();
void gao_free_context(struct gao_context* context);

void gao_dump(struct gao_context *context, gao_queue_request_t type);

void gao_free_port_list(struct gao_request_port_list* list);
struct gao_request_port_list*	gao_get_port_list(struct gao_context* context);
int64_t gao_enable_port(struct gao_context* context, uint64_t gao_ifindex);
int64_t gao_disable_port(struct gao_context* context, uint64_t gao_ifindex);
int64_t	gao_bind_queue(int fd, uint64_t gao_ifindex, uint64_t queue_index);
int64_t gao_unbind_queue(int fd);
const char*	gao_resource_state_string(gao_resource_state_t state);

#endif /* GAO_USER_H_ */
