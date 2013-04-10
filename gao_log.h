/*
 * log.h
 *
 *  Created on: Oct 13, 2012
 *      Author: cverge
 */

#ifndef GAO_LOG_H_
#define GAO_LOG_H_


#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#else
#include <string.h>
#include <errno.h>
#include <stdio.h>
#endif


#define	LOG_LEVEL_DP		0x0012
#define	LOG_LEVEL_DEBUG		0x0010
#define	LOG_LEVEL_INFO		0x0008
#define	LOG_LEVEL_WARN		0x0006
#define	LOG_LEVEL_BUG		0x0005
#define	LOG_LEVEL_ERROR		0x0004
#define LOG_LEVEL_FATAL		0x0002
#define LOG_LEVEL_OFF		0x0000
#define GAO_LOG_LEVEL		LOG_LEVEL_INFO
#define GAO_LOG_LOCK_ENABLE	0
#define GAO_OUTPUT_FILE		stderr


#ifdef __KERNEL__
#if GAO_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_dp(FMT, ...)	printk("[DATAPLANE:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_dp(FMT, ...)
#endif


#if GAO_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(FMT, ...)	printk("[DEBUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_debug(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(FMT, ...)	printk("[INFO:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_info(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(FMT, ...)	printk("[WARN:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_warn(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_BUG
#define log_bug(FMT, ...)	printk("[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_warn(FMT, ...)
#endif


#if GAO_LOG_LEVEL >= LOG_LEVEL_ERROR
#define log_error(FMT, ...)	printk("[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_error(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_FATAL
#define log_fatal(FMT, ...)	printk("[FATAL:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_fatal(FMT, ...)
#endif

#if GAO_LOG_LOCK_ENABLE > 0
#define log_lock(FMT, ...)	printk("[LOCK:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_lock(FMT, ...)
#endif

#define check_ptr(PTR) if(PTR == NULL) { log_error("malloc Failed!"); goto err; }
#define check_ptr_val(VAL, PTR) if(PTR == NULL) { ret = VAL; log_error("malloc Failed!"); goto err; }
#ifdef GAO_USERSPACE
#define free_null(PTR) { free(PTR); PTR = NULL; }
#else
#define kfree_null(PTR) { kfree(PTR); PTR = NULL; }
#endif
#define gao_error(FMT, ...)	{ printk("[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_error_val(VAL, FMT, ...)	{ ret = VAL; printk("[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_bug(FMT, ...)	{ printk("[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_bug_val(VAL, FMT, ...)	{ ret = VAL; printk("[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }

#else

#if GAO_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_dp(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[DATAPLANE:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_dp(FMT, ...)
#endif


#if GAO_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[DEBUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_debug(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[INFO:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_info(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[WARN:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_warn(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_BUG
#define log_bug(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_error(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_ERROR
#define log_error(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_error(FMT, ...)
#endif

#if GAO_LOG_LEVEL >= LOG_LEVEL_FATAL
#define log_fatal(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[FATAL:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_fatal(FMT, ...)
#endif

#if GAO_LOG_LOCK_ENABLE > 0
#define log_lock(FMT, ...)	fprintf(GAO_OUTPUT_FILE, "[LOCK:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_lock(FMT, ...)
#endif

#define check_ptr(PTR) if(PTR == NULL) { log_error("Malloc Failed!"); goto err; }
#define free_null(PTR) free(PTR); PTR = NULL;
#define gao_error(FMT, ...)	{ fprintf(GAO_OUTPUT_FILE, "[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_error_val(VAL, FMT, ...)	{ ret = VAL; fprintf(GAO_OUTPUT_FILE, "[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_bug(FMT, ...)	{ fprintf(GAO_OUTPUT_FILE, "[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }
#define gao_bug_val(VAL, FMT, ...)	{ ret = VAL; fprintf(GAO_OUTPUT_FILE, "[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); goto err; }

#ifdef __cplusplus
#define gao_error_throw(VAL, FMT, ...)	{ fprintf(GAO_OUTPUT_FILE, "[ERROR:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); throw (VAL); }
#define gao_bug_throw(VAL, FMT, ...)	{ fprintf(GAO_OUTPUT_FILE, "[BUG:%s:%d] " FMT "\n", __FILE__, __LINE__, ##__VA_ARGS__); throw (VAL); }
#endif


#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)



#endif /* LOG_H_ */
