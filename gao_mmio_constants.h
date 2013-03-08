/*
 * gao_mmio_constants.h
 *
 *  Created on: 2012-12-18
 *      Author: cverge
 */

#ifndef GAO_MMIO_CONSTANTS_H_
#define GAO_MMIO_CONSTANTS_H_

//Assert that the condition is true
#ifdef __KERNEL__
#define GAO_STATIC_ASSERT(cond, msg)	_Static_assert(cond, msg)
#else
#define GAO_STATIC_ASSERT(cond, msg)
#endif
//Make sure that the bitfield is the log2 of the parent value
#define GAO_ASSERT_LOG2(bitval, decval)	GAO_STATIC_ASSERT( ((1 << bitval) == decval), #bitval" is not the log2 of "#decval)
//Make sure the value is a power of 2
#define GAO_ASSERT_POW2(val)	GAO_STATIC_ASSERT( ((val > 1) & !(val & (val - 1))) , #val" is not a power of 2")




/*Memory*/
#define GAO_SMALLPAGE_SIZE 			4096
#define GAO_SMALLPAGE_PFN_SHIFT		12
GAO_ASSERT_POW2(GAO_SMALLPAGE_SIZE);
GAO_ASSERT_LOG2(GAO_SMALLPAGE_PFN_SHIFT, GAO_SMALLPAGE_SIZE);
//We will try to allocate in larger memory chunks if possible
#define GAO_HUGEPAGE_SIZE 			(2*1024*1024)
#define GAO_HUGEPAGE_PFN_SHIFT		21
GAO_ASSERT_POW2(GAO_HUGEPAGE_SIZE);
GAO_ASSERT_LOG2(GAO_HUGEPAGE_PFN_SHIFT, GAO_HUGEPAGE_SIZE);


/*Buffers*/
#define GAO_BUFFERS			(131072/4)
GAO_ASSERT_POW2(GAO_BUFFERS);
#define GAO_BUFFER_SIZE		8192
GAO_ASSERT_POW2(GAO_BUFFER_SIZE);
GAO_STATIC_ASSERT((GAO_BUFFER_SIZE >= GAO_SMALLPAGE_SIZE), "GAO_BUFFER_SIZE is not at least GAO_SMALLPAGE_SIZE");
#define GAO_BFN_MASK		((unsigned long)(GAO_BUFFER_SIZE-1))
#define GAO_BFN_SHIFT 		13
GAO_ASSERT_LOG2(GAO_BFN_SHIFT, GAO_BUFFER_SIZE);
#define GAO_DEFAULT_OFFSET	128
#define GAO_OFFSET_MASK		0x00000000000000FF
GAO_STATIC_ASSERT(GAO_DEFAULT_OFFSET >= 0 && GAO_DEFAULT_OFFSET <= 255, "GAO_BUFFER_SIZE is not at least GAO_SMALLPAGE_SIZE");
#define GAO_PAGE_PER_BUFFER	(GAO_BUFFER_SIZE/GAO_SMALLPAGE_SIZE)
#define GAO_HUGEPAGES		((GAO_BUFFER_SIZE*GAO_BUFFERS)/GAO_HUGEPAGE_SIZE)
#define GAO_BUFFER_PER_HUGEPAGE	(GAO_HUGEPAGE_SIZE/GAO_BUFFER_SIZE)
GAO_STATIC_ASSERT( ((GAO_BUFFERS*GAO_BUFFER_SIZE) % GAO_HUGEPAGE_SIZE) == 0,
		"Bufferspace must be larger than a single hugepage" );
GAO_STATIC_ASSERT( (GAO_BUFFERS*GAO_BUFFER_SIZE) >= GAO_HUGEPAGE_SIZE,
		"Bufferspace must be evenly divisible by a hugepage" );


/*Descriptors*/
#define GAO_DESCRIPTORS		GAO_BUFFERS




//Queues
#define GAO_MAX_QUEUES				128
#define GAO_MAX_PORT_QUEUES			8
#define GAO_ING_PIPELINE_DEPTH		2
#define GAO_CONTROLLER_BUFFERS		256


//Ports
#define GAO_MAX_PORTS				64
#define GAO_CONTROLLER_PORT_ID		(GAO_MAX_PORTS - 1)
#define GAO_MAX_PHYS_PORT			(GAO_MAX_PORTS - 2)



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
#define GAO_PAGEALIGN(alloc_size) (alloc_size % GAO_SMALLPAGE_SIZE) ? alloc_size + (GAO_SMALLPAGE_SIZE-(alloc_size%GAO_SMALLPAGE_SIZE)) : alloc_size;

#endif /* GAO_MMIO_CONSTANTS_H_ */

