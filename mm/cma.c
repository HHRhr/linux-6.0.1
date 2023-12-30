// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Contiguous Memory Allocator
 *
 * Copyright (c) 2010-2011 by Samsung Electronics.
 * Copyright IBM Corporation, 2013
 * Copyright LG Electronics Inc., 2014
 * Written by:
 *	Marek Szyprowski <m.szyprowski@samsung.com>
 *	Michal Nazarewicz <mina86@mina86.com>
 *	Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *	Joonsoo Kim <iamjoonsoo.kim@lge.com>
 */

#define pr_fmt(fmt) "cma: " fmt

#ifdef CONFIG_CMA_DEBUG
#ifndef DEBUG
#  define DEBUG
#endif
#endif
#define CREATE_TRACE_POINTS

#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/cma.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/kmemleak.h>
#include <trace/events/cma.h>

#include "cma.h"

// hhr 原来可以有多个CMA区域，一直以为只有一个
// *** 内核启动配置中指定的cma=128M是用来创建默认CMA区域的
// 因此，最大CMA区域数量要+1
// #define MAX_CMA_AREAS	(1 + CONFIG_CMA_AREAS)
struct cma cma_areas[MAX_CMA_AREAS];
unsigned cma_area_count;
static DEFINE_MUTEX(cma_mutex);

phys_addr_t cma_get_base(const struct cma *cma)
{
	return PFN_PHYS(cma->base_pfn);
}

unsigned long cma_get_size(const struct cma *cma)
{
	return cma->count << PAGE_SHIFT;
}

const char *cma_get_name(const struct cma *cma)
{
	return cma->name;
}

static unsigned long cma_bitmap_aligned_mask(const struct cma *cma,
					     unsigned int align_order)
{
	if (align_order <= cma->order_per_bit)
		return 0;
	return (1UL << (align_order - cma->order_per_bit)) - 1;
}

/*
 * Find the offset of the base PFN from the specified align_order.
 * The value returned is represented in order_per_bits.
 */
static unsigned long cma_bitmap_aligned_offset(const struct cma *cma,
					       unsigned int align_order)
{
	return (cma->base_pfn & ((1UL << align_order) - 1))
		>> cma->order_per_bit;
}

static unsigned long cma_bitmap_pages_to_bits(const struct cma *cma,
					      unsigned long pages)
{
	return ALIGN(pages, 1UL << cma->order_per_bit) >> cma->order_per_bit;
}

static void cma_clear_bitmap(struct cma *cma, unsigned long pfn,
			     unsigned long count)
{
	unsigned long bitmap_no, bitmap_count;
	unsigned long flags;

	bitmap_no = (pfn - cma->base_pfn) >> cma->order_per_bit;
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	spin_lock_irqsave(&cma->lock, flags);
	bitmap_clear(cma->bitmap, bitmap_no, bitmap_count);
	spin_unlock_irqrestore(&cma->lock, flags);
}


// hhr 针对每个CMA区域进行初始化，包括位图初始化、页面初始化
static void __init cma_activate_area(struct cma *cma)
{
	unsigned long base_pfn = cma->base_pfn, pfn;
	struct zone *zone;

	// 页面占用情况
	cma->bitmap = bitmap_zalloc(cma_bitmap_maxno(cma), GFP_KERNEL);
	if (!cma->bitmap)
		goto out_error;

	/*
	 * alloc_contig_range() requires the pfn range specified to be in the
	 * same zone. Simplify by forcing the entire CMA resv range to be in the
	 * same zone.
	 */

	// 分配CMA时调用的alloc_contig_range()要求页框号位于同一个zone，所以这里要先做检查
	WARN_ON_ONCE(!pfn_valid(base_pfn));
	zone = page_zone(pfn_to_page(base_pfn));
	for (pfn = base_pfn + 1; pfn < base_pfn + cma->count; pfn++) {
		WARN_ON_ONCE(!pfn_valid(pfn));
		if (page_zone(pfn_to_page(pfn)) != zone)
			goto not_in_zone;
	}
	
	// *** 在Linux内核中，物理内存被划分为几个不同的"区域"（zones）。这些区域包括：
	//		ZONE_DMA：这个区域包含了可以进行DMA（直接内存访问）的内存。一些硬件设备只能在这个区域中进行DMA。
	//		ZONE_NORMAL：这个区域包含了可以被内核直接访问的内存。大部分的系统内存都在这个区域中。
	//		ZONE_HIGHMEM：这个区域包含了不能被内核直接访问的内存。
	//			在一些硬件架构中，内核不能直接访问所有的物理内存，这部分内存就被放在了ZONE_HIGHMEM区域中。
	// 在大多数情况下，CMA区域会被配置在ZONE_DMA或ZONE_NORMAL中。
	// 这是因为这两个区域的内存可以被内核直接访问，并且可以用于DMA（直接内存访问）操作
	

	for (pfn = base_pfn; pfn < base_pfn + cma->count;
	     pfn += pageblock_nr_pages)
		// 针对每个页块进行初始化操作，设置页块的状态，标记为CMA预留，*** 并交由buddy管理
		init_cma_reserved_pageblock(pfn_to_page(pfn));	// mm/page_alloc.c


	// *** 页框号（Page Frame Number，PFN）是标识每个页面的唯一编号，每个页面通常4KB大小
	// 页块（Pageblock）是一组连续的页框，在物理内存中相邻。页块的大小由pageblock_nr_pages确定


	spin_lock_init(&cma->lock);

#ifdef CONFIG_CMA_DEBUGFS
	INIT_HLIST_HEAD(&cma->mem_head);
	spin_lock_init(&cma->mem_head_lock);
#endif

	return;

not_in_zone:
	bitmap_free(cma->bitmap);
out_error:
	/* Expose all pages to the buddy, they are useless for CMA. */
	if (!cma->reserve_pages_on_error) {
		for (pfn = base_pfn; pfn < base_pfn + cma->count; pfn++)
			free_reserved_page(pfn_to_page(pfn));
	}
	totalcma_pages -= cma->count;
	cma->count = 0;
	pr_err("CMA area %s could not be activated\n", cma->name);
	return;
}


// 初始化位于cma_areas数组中所有cma内存
static int __init cma_init_reserved_areas(void)
{
	int i;

	for (i = 0; i < cma_area_count; i++)
		cma_activate_area(&cma_areas[i]);

	return 0;
}
// core_initcall是一种初始化调用，它会在内核启动过程的早期阶段被执行。
// 这个阶段发生在内核的主要子系统（如内存管理和设备驱动）初始化之后，但在启动用户空间之前。
core_initcall(cma_init_reserved_areas);

void __init cma_reserve_pages_on_error(struct cma *cma)
{
	cma->reserve_pages_on_error = true;
}

/**
 * cma_init_reserved_mem() - create custom contiguous area from reserved memory
 * @base: Base address of the reserved area
 * @size: Size of the reserved area (in bytes),
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @name: The name of the area. If this parameter is NULL, the name of
 *        the area will be set to "cmaN", where N is a running counter of
 *        used areas.
 * @res_cma: Pointer to store the created cma region.
 *
 * This function creates custom contiguous area from already reserved memory.
 */

 // hhr 上一步找到了base开始的一片连续内存，此处要将这块内存纳入cma_areas管理
int __init cma_init_reserved_mem(phys_addr_t base, phys_addr_t size,
				 unsigned int order_per_bit,
				 const char *name,
				 struct cma **res_cma)
{
	struct cma *cma;

	/* Sanity checks */
	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	if (!size || !memblock_is_region_reserved(base, size))
		return -EINVAL;

	/* alignment should be aligned with order_per_bit */
	if (!IS_ALIGNED(CMA_MIN_ALIGNMENT_PAGES, 1 << order_per_bit))
		return -EINVAL;

	/* ensure minimal alignment required by mm core */
	if (!IS_ALIGNED(base | size, CMA_MIN_ALIGNMENT_BYTES))
		return -EINVAL;

	/*
	 * Each reserved area must be initialised later, when more kernel
	 * subsystems (like slab allocator) are available.
	 */

	// 获取cma数组中下一个cma区域的指针
	// 之后设置该cma区域
	//		name："reserved"
	// 		起始地址：地址向下取整
	//		大小：向右移页大小，即将单位转换为Byte
	//		每位对应的页框数：???后面再研究
	cma = &cma_areas[cma_area_count];

	if (name)
		snprintf(cma->name, CMA_MAX_NAME, name);
	else
		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);

	cma->base_pfn = PFN_DOWN(base);
	cma->count = size >> PAGE_SHIFT;
	cma->order_per_bit = order_per_bit;
	*res_cma = cma;
	cma_area_count++;
	totalcma_pages += (size / PAGE_SIZE);

	return 0;
}

/**
 * cma_declare_contiguous_nid() - reserve custom contiguous area
 * @base: Base address of the reserved area optional, use 0 for any
 * @size: Size of the reserved area (in bytes),
 * @limit: End address of the reserved memory (optional, 0 for any).
 * @alignment: Alignment for the CMA area, should be power of 2 or zero
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @fixed: hint about where to place the reserved area
 * @name: The name of the area. See function cma_init_reserved_mem()
 * @res_cma: Pointer to store the created cma region.
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * This function reserves memory from early allocator. It should be
 * called by arch specific code once the early allocator (memblock or bootmem)
 * has been activated and all other subsystems have already allocated/reserved
 * memory. This function allows to create custom reserved areas.
 *
 * If @fixed is true, reserve contiguous area at exactly @base.  If false,
 * reserve in range from @base to @limit.
 */
 // hhr 主要功能为申请CMA内存，及初始化CMA内存
 // 虽然跟DMA密切相关，但这个函数比较通用，适用于创建自定义的保留内存
int __init cma_declare_contiguous_nid(phys_addr_t base,
			phys_addr_t size, phys_addr_t limit,
			phys_addr_t alignment, unsigned int order_per_bit,
			bool fixed, const char *name, struct cma **res_cma,
			int nid)
{
	phys_addr_t memblock_end = memblock_end_of_DRAM();
	phys_addr_t highmem_start;
	int ret = 0;

	/*
	 * We can't use __pa(high_memory) directly, since high_memory
	 * isn't a valid direct map VA, and DEBUG_VIRTUAL will (validly)
	 * complain. Find the boundary by adding one to the last valid
	 * address.
	 */
	highmem_start = __pa(high_memory - 1) + 1;
	pr_debug("%s(size %pa, base %pa, limit %pa alignment %pa)\n",
		__func__, &size, &base, &limit, &alignment);

	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	if (!size)
		return -EINVAL;

	if (alignment && !is_power_of_2(alignment))
		return -EINVAL;

	/* Sanitise input arguments. */
	alignment = max_t(phys_addr_t, alignment, CMA_MIN_ALIGNMENT_BYTES);
	if (fixed && base & (alignment - 1)) {
		ret = -EINVAL;
		pr_err("Region at %pa must be aligned to %pa bytes\n",
			&base, &alignment);
		goto err;
	}
	base = ALIGN(base, alignment);
	size = ALIGN(size, alignment);
	limit &= ~(alignment - 1);

	if (!base)
		fixed = false;

	/* size should be aligned with order_per_bit */
	if (!IS_ALIGNED(size >> PAGE_SHIFT, 1 << order_per_bit))
		return -EINVAL;

	/*
	 * If allocating at a fixed base the request region must not cross the
	 * low/high memory boundary.
	 */
	if (fixed && base < highmem_start && base + size > highmem_start) {
		ret = -EINVAL;
		pr_err("Region at %pa defined on low/high memory boundary (%pa)\n",
			&base, &highmem_start);
		goto err;
	}

	/*
	 * If the limit is unspecified or above the memblock end, its effective
	 * value will be the memblock end. Set it explicitly to simplify further
	 * checks.
	 */
	// 前面先计算了memblock的末端地址memblock_end
	// CMA的limit不应超过这个地址值
	if (limit == 0 || limit > memblock_end)
		limit = memblock_end;

	if (base + size > limit) {
		ret = -EINVAL;
		pr_err("Size (%pa) of region at %pa exceeds limit (%pa)\n",
			&size, &base, &limit);
		goto err;
	}

	/* Reserve memory */
	if (fixed) {
		// 判断特定位置是否占用,如果已占用，返回失败
		// 如果未占用，就调用memblock_reserve来保留这块内存
		if (memblock_is_region_reserved(base, size) ||
		    memblock_reserve(base, size) < 0) {
			ret = -EBUSY;
			goto err;
		}
	} else {
		phys_addr_t addr = 0;

		/*
		 * All pages in the reserved area must come from the same zone.
		 * If the requested region crosses the low/high memory boundary,
		 * try allocating from high memory first and fall back to low
		 * memory in case of failure.
		 */
		if (base < highmem_start && limit > highmem_start) {

			// *** CMA内存是通过memblock来分配的
			addr = memblock_alloc_range_nid(size, alignment,
					highmem_start, limit, nid, true);
			limit = highmem_start;
		}

		/*
		 * If there is enough memory, try a bottom-up allocation first.
		 * It will place the new cma area close to the start of the node
		 * and guarantee that the compaction is moving pages out of the
		 * cma area and not into it.
		 * Avoid using first 4GB to not interfere with constrained zones
		 * like DMA/DMA32.
		 */
#ifdef CONFIG_PHYS_ADDR_T_64BIT
		if (!memblock_bottom_up() && memblock_end >= SZ_4G + size) {
			memblock_set_bottom_up(true);
			addr = memblock_alloc_range_nid(size, alignment, SZ_4G,
							limit, nid, true);
			memblock_set_bottom_up(false);
		}
#endif

		if (!addr) {
			addr = memblock_alloc_range_nid(size, alignment, base,
					limit, nid, true);
			if (!addr) {
				ret = -ENOMEM;
				goto err;
			}
		}

		/*
		 * kmemleak scans/reads tracked objects for pointers to other
		 * objects but this address isn't mapped and accessible
		 */
		kmemleak_ignore_phys(addr);
		base = addr;
	}

	// 将分配到的这块CMA区域放入cma_areas数组中，待core_initcall调用统一初始化
	ret = cma_init_reserved_mem(base, size, order_per_bit, name, res_cma);
	if (ret)
		goto free_mem;

	pr_info("Reserved %ld MiB at %pa\n", (unsigned long)size / SZ_1M,
		&base);
	return 0;

free_mem:
	memblock_phys_free(base, size);
err:
	pr_err("Failed to reserve %ld MiB\n", (unsigned long)size / SZ_1M);
	return ret;
}

#ifdef CONFIG_CMA_DEBUG
static void cma_debug_show_areas(struct cma *cma)
{
	unsigned long next_zero_bit, next_set_bit, nr_zero;
	unsigned long start = 0;
	unsigned long nr_part, nr_total = 0;
	unsigned long nbits = cma_bitmap_maxno(cma);

	spin_lock_irq(&cma->lock);
	pr_info("number of available pages: ");
	for (;;) {
		next_zero_bit = find_next_zero_bit(cma->bitmap, nbits, start);
		if (next_zero_bit >= nbits)
			break;
		next_set_bit = find_next_bit(cma->bitmap, nbits, next_zero_bit);
		nr_zero = next_set_bit - next_zero_bit;
		nr_part = nr_zero << cma->order_per_bit;
		pr_cont("%s%lu@%lu", nr_total ? "+" : "", nr_part,
			next_zero_bit);
		nr_total += nr_part;
		start = next_zero_bit + nr_zero;
	}
	pr_cont("=> %lu free of %lu total pages\n", nr_total, cma->count);
	spin_unlock_irq(&cma->lock);
}
#else
static inline void cma_debug_show_areas(struct cma *cma) { }
#endif

/**
 * cma_alloc() - allocate pages from contiguous area
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @count: Requested number of pages.
 * @align: Requested alignment of pages (in PAGE_SIZE order).
 * @no_warn: Avoid printing message about failed allocation
 *
 * This function allocates part of contiguous memory on specific
 * contiguous memory area.
 */
 // hhr 用于从CMA中分配
 // 需要告诉这个函数，你想从哪个cma区域中申请，即dev_get_cma_area()的返回值
 //	如果指定设备且配置了cma，则使用指定区域，否则也使用dma_contiguous_default_area
 // 如果未指定设备，则使用dma_contiguous_default_area
 // *** 所以说，如果在设备树中没有为设备定义特殊的cma，那么系统里所有申请使用cma的区域都来自dma_contiguous_default_area
struct page *cma_alloc(struct cma *cma, unsigned long count,
		       unsigned int align, bool no_warn)
{
	unsigned long mask, offset;
	unsigned long pfn = -1;
	unsigned long start = 0;
	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
	unsigned long i;
	struct page *page = NULL;
	int ret = -ENOMEM;

	if (!cma || !cma->count || !cma->bitmap)
		goto out;

	pr_debug("%s(cma %p, count %lu, align %d)\n", __func__, (void *)cma,
		 count, align);

	if (!count)
		goto out;

	trace_cma_alloc_start(cma->name, count, align);

	mask = cma_bitmap_aligned_mask(cma, align);
	offset = cma_bitmap_aligned_offset(cma, align);
	bitmap_maxno = cma_bitmap_maxno(cma);
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	if (bitmap_count > bitmap_maxno)
		goto out;

	for (;;) {
		spin_lock_irq(&cma->lock);
		// 1.找到空闲块位置
		bitmap_no = bitmap_find_next_zero_area_off(cma->bitmap,
				bitmap_maxno, start, bitmap_count, mask,
				offset);
		if (bitmap_no >= bitmap_maxno) {
			spin_unlock_irq(&cma->lock);
			break;
		}
		// 2.标记为占用
		bitmap_set(cma->bitmap, bitmap_no, bitmap_count);
		/*
		 * It's safe to drop the lock here. We've marked this region for
		 * our exclusive use. If the migration fails we will take the
		 * lock again and unmark it.
		 */
		spin_unlock_irq(&cma->lock);

		pfn = cma->base_pfn + (bitmap_no << cma->order_per_bit);
		mutex_lock(&cma_mutex);


		// *** 3.申请分配CMA空闲页
		ret = alloc_contig_range(pfn, pfn + count, MIGRATE_CMA,
				     GFP_KERNEL | (no_warn ? __GFP_NOWARN : 0));
		mutex_unlock(&cma_mutex);
		if (ret == 0) {
			page = pfn_to_page(pfn);
			break;
		}

		cma_clear_bitmap(cma, pfn, count);
		if (ret != -EBUSY)
			break;

		pr_debug("%s(): memory range at %p is busy, retrying\n",
			 __func__, pfn_to_page(pfn));

		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
					   count, align);
		/* try again with a bit different memory target */
		start = bitmap_no + mask + 1;
	}

	trace_cma_alloc_finish(cma->name, pfn, page, count, align);

	/*
	 * CMA can allocate multiple page blocks, which results in different
	 * blocks being marked with different tags. Reset the tags to ignore
	 * those page blocks.
	 */
	if (page) {
		for (i = 0; i < count; i++)
			page_kasan_tag_reset(page + i);
	}

	if (ret && !no_warn) {
		pr_err_ratelimited("%s: %s: alloc failed, req-size: %lu pages, ret: %d\n",
				   __func__, cma->name, count, ret);
		cma_debug_show_areas(cma);
	}

	pr_debug("%s(): returned %p\n", __func__, page);
out:
	if (page) {
		count_vm_event(CMA_ALLOC_SUCCESS);
		cma_sysfs_account_success_pages(cma, count);
	} else {
		count_vm_event(CMA_ALLOC_FAIL);
		if (cma)
			cma_sysfs_account_fail_pages(cma, count);
	}

	return page;
}

bool cma_pages_valid(struct cma *cma, const struct page *pages,
		     unsigned long count)
{
	unsigned long pfn;

	if (!cma || !pages)
		return false;

	pfn = page_to_pfn(pages);

	if (pfn < cma->base_pfn || pfn >= cma->base_pfn + cma->count) {
		pr_debug("%s(page %p, count %lu)\n", __func__,
						(void *)pages, count);
		return false;
	}

	return true;
}

/**
 * cma_release() - release allocated pages
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @pages: Allocated pages.
 * @count: Number of allocated pages.
 *
 * This function releases memory allocated by cma_alloc().
 * It returns false when provided pages do not belong to contiguous area and
 * true otherwise.
 */
bool cma_release(struct cma *cma, const struct page *pages,
		 unsigned long count)
{
	unsigned long pfn;

	if (!cma_pages_valid(cma, pages, count))
		return false;

	pr_debug("%s(page %p, count %lu)\n", __func__, (void *)pages, count);

	pfn = page_to_pfn(pages);

	VM_BUG_ON(pfn + count > cma->base_pfn + cma->count);

	free_contig_range(pfn, count);
	cma_clear_bitmap(cma, pfn, count);
	trace_cma_release(cma->name, pfn, pages, count);

	return true;
}

int cma_for_each_area(int (*it)(struct cma *cma, void *data), void *data)
{
	int i;

	for (i = 0; i < cma_area_count; i++) {
		int ret = it(&cma_areas[i], data);

		if (ret)
			return ret;
	}

	return 0;
}
