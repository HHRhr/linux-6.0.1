/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_CMA_H__
#define __MM_CMA_H__

#include <linux/debugfs.h>
#include <linux/kobject.h>

struct cma_kobject
{
	struct kobject kobj;
	struct cma *cma;
};

struct cma
{
	unsigned long base_pfn; // 起始页框号
	unsigned long count;	// 大小，即页面的个数
	unsigned long *bitmap;	// 位图，记录页面的分配情况
	// bitmap中，1 bit所代表的页面数量，2^order个page
	unsigned int order_per_bit; /* Order of pages represented by one bit */
	spinlock_t lock;
#ifdef CONFIG_CMA_DEBUGFS
	struct hlist_head mem_head;
	spinlock_t mem_head_lock;
	struct debugfs_u32_array dfs_bitmap;
#endif
	char name[CMA_MAX_NAME];
#ifdef CONFIG_CMA_SYSFS
	/* the number of CMA page successful allocations */
	atomic64_t nr_pages_succeeded;
	/* the number of CMA page allocation failures */
	atomic64_t nr_pages_failed;
	/* kobject requires dynamic object */
	struct cma_kobject *cma_kobj;
#endif
	bool reserve_pages_on_error;
};

/*
 cma区域大致可以分为两种
	1.Global CMA area，可通过boot参数进行配置
		通过dma_contiguous_reserve让DMA引用，在所有驱动间共享
	2.per device，每个设备在设备树上通过reserved memory node声明，该设备独享
*/
extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned cma_area_count;

static inline unsigned long cma_bitmap_maxno(struct cma *cma)
{
	return cma->count >> cma->order_per_bit;
}

#ifdef CONFIG_CMA_SYSFS
void cma_sysfs_account_success_pages(struct cma *cma, unsigned long nr_pages);
void cma_sysfs_account_fail_pages(struct cma *cma, unsigned long nr_pages);
#else
static inline void cma_sysfs_account_success_pages(struct cma *cma,
												   unsigned long nr_pages){};
static inline void cma_sysfs_account_fail_pages(struct cma *cma,
												unsigned long nr_pages){};
#endif
#endif
