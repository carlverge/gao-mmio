/*
 * gao_mmio_constants.h
 *
 *  Created on: 2012-12-18
 *      Author: cverge
 */

#ifndef GAO_MMIO_CONSTANTS_H_
#define GAO_MMIO_CONSTANTS_H_

//Memory
#define GAO_HUGEPAGE_SIZE 			(2*1024*1024)
#define GAO_SMALLPAGE_SIZE 			(4096)

//Buffers

//Configurable
#define GAO_BUFFER_GROUPS 			(64)
#define GAO_BUFFER_GROUP_SIZE 		(4*1024*1024) 	//4MB
#define GAO_BUFFER_SIZE				(8192)		//8kB
#define GAO_READ_WRITE_MEMORY_PROT	0	//Set to 1 to turn on copy_to_user/copy_from_user in read/writes


//Non-Configurable
#define GAO_BUFFER_SPACE_SIZE		(GAO_BUFFER_GROUPS*GAO_BUFFER_GROUP_SIZE)
#define GAO_BUFFERS_PER_GROUP		(GAO_BUFFER_GROUP_SIZE/GAO_BUFFER_SIZE)
#define GAO_BUFFERS					(GAO_BUFFERS_PER_GROUP*GAO_BUFFER_GROUPS)

#define GAO_GFN_SHIFT				22				//log2(GAO_BUFFER_GROUP_SIZE)
#define GAO_GFN_MASK				0x00000000003FFFFF //GAO_BUFFER_GFN_SHIFT right most bits set
#define GAO_PAGES_PER_GROUP 		(GAO_BUFFER_GROUP_SIZE/GAO_SMALLPAGE_SIZE)


#define GAO_DESCRIPTORS				GAO_BUFFERS


//OLD
#define GAO_MAX_BUFFER_GROUPS 		(2)			//1GB
#define GAO_BUFFER_GROUP_ORDER 		9			//2^9 = 2MB (of 4kB pages)





//Descriptors
#define GAO_MAX_DESCRIPTORS			(GAO_BUFFERS_PER_GROUP*GAO_MAX_BUFFER_GROUPS)
#define GAO_MAX_DESCRIPTOR_GROUPS	64
#define GAO_DESCRIPTORS_PER_GROUP	(GAO_MAX_DESCRIPTORS/GAO_MAX_DESCRIPTOR_GROUPS)
#define GAO_DESCRIPTOR_SIZE			8

//Queues
//#define GAO_MAX_QUEUE_SIZE			32 //Size in descriptor groups
//#define GAO_MAX_BOUND_QUEUES		32
#define GAO_MAX_QUEUES				128
#define GAO_MAX_PORT_QUEUES			8
#define GAO_ING_PIPELINE_DEPTH		2
//XXX: These calculations need to be done better...
//#define GAO_MAX_QUEUE_SIZE_BYTES	((GAO_MAX_QUEUE_SIZE*GAO_DESCRIPTORS_PER_GROUP*GAO_DESCRIPTOR_SIZE)*2) //32
//#define GAO_PAGES_PER_QUEUE			(GAO_MAX_QUEUE_SIZE_BYTES/GAO_SMALLPAGE_SIZE) //32
//#define GAO_QUEUE_ORDER				5 //log2(32) (get_free_pages order)

//MMAP
//#define GAO_MMAP_SIZE				((unsigned long)((GAO_MAX_QUEUE_SIZE_BYTES*GAO_MAX_QUEUES)+(GAO_BUFFER_GROUP_SIZE*GAO_MAX_BUFFER_GROUPS)))


//Interfaces
#define GAO_MAX_PORTS				64
#define GAO_MAX_PORT_HWQUEUE		64
#define GAO_MAX_PORT_SUBQUEUE		8
#define GAO_MAX_IFINDEX				256
#define IFF_GAO_ENABLED				0x400000


//Circular buffer branchless calculations
#define CIRC_NEXT(INDEX, MAX) ( ((INDEX)+1) % MAX )
#define CIRC_ADD(INDEX, NUM, MAX) ( ((INDEX)+NUM) % MAX )
#define CIRC_PREV(INDEX, MAX) (( MAX + ((INDEX)-1) ) % MAX)
#define CIRC_SUB(INDEX, NUM, MAX) (( MAX + ((INDEX)-NUM) ) % MAX)
#define CIRC_DIFF16(b,a,max) ((b-a) + (max*(((b-a) & 0x8000)>>15)))
#define CIRC_DIFF32(b,a,max) ((b-a) + (max*(((b-a) & 0x80000000)>>31)))
#define CIRC_DIFF64(b,a,max) ((b-a) + (max*(((b-a) & 0x8000000000000000)>>63)))

#define GAO_FFSL(x)	__builtin_ffsl(x)


#endif /* GAO_MMIO_CONSTANTS_H_ */

