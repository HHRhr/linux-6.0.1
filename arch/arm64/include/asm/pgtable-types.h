/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Page table types definitions.
 *
 * Copyright (C) 2014 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#ifndef __ASM_PGTABLE_TYPES_H
#define __ASM_PGTABLE_TYPES_H

#include <asm/types.h>

typedef u64 pteval_t;
typedef u64 pmdval_t;
typedef u64 pudval_t;
typedef u64 p4dval_t;
typedef u64 pgdval_t;

/*
 * These are used to make use of C type-checking..
 */
/*
    页表项，存储物理地址和权限位
    内核这里使用 struct 结构来包裹 unsigned long 类型的目的是要确保这些页目录项以及页表项只能被专门的辅助函数访问，不能直接访问
    TODO，暂时不理解这种设计思想，类似的可能还有pid_t这种
*/
typedef struct
{
    pteval_t pte;
} pte_t;
#define pte_val(x) ((x).pte)
#define __pte(x) ((pte_t){(x)})

#if CONFIG_PGTABLE_LEVELS > 2
typedef struct
{
    pmdval_t pmd;
} pmd_t;
#define pmd_val(x) ((x).pmd)
#define __pmd(x) ((pmd_t){(x)})
#endif

#if CONFIG_PGTABLE_LEVELS > 3
typedef struct
{
    pudval_t pud;
} pud_t;
#define pud_val(x) ((x).pud)
#define __pud(x) ((pud_t){(x)})
#endif

typedef struct
{
    pgdval_t pgd;
} pgd_t;
#define pgd_val(x) ((x).pgd)
#define __pgd(x) ((pgd_t){(x)})

typedef struct
{
    pteval_t pgprot;
} pgprot_t;
#define pgprot_val(x) ((x).pgprot)
#define __pgprot(x) ((pgprot_t){(x)})

#if CONFIG_PGTABLE_LEVELS == 2
#include <asm-generic/pgtable-nopmd.h>
#elif CONFIG_PGTABLE_LEVELS == 3
#include <asm-generic/pgtable-nopud.h>
#elif CONFIG_PGTABLE_LEVELS == 4
#include <asm-generic/pgtable-nop4d.h>
#endif

#endif /* __ASM_PGTABLE_TYPES_H */
