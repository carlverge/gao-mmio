/*
 * gao_mmio.h
 *
 *  Created on: 2013-01-04
 *      Author: cverge
 */

#ifndef GAO_MMIO_H_
#define GAO_MMIO_H_

#undef __KERNEL__
#define __KERNEL__
#undef MODULE
#define MODULE
#undef LINUX
#define LINUX

#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "log.h"
#include "gao_mmio_resource.h"

#endif /* GAO_MMIO_H_ */
