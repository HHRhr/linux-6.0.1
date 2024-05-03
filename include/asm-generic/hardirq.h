/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_HARDIRQ_H
#define __ASM_GENERIC_HARDIRQ_H

#include <linux/cache.h>
#include <linux/threads.h>

/*
	软件寄存器，主要用于跟踪当前 CPU 上等待处理的软中断数量
	每个CPU上一个irq_cpustat_t实例
	softirq采用谁触发，谁负责处理
		例如：当一个驱动的硬件中断被分发给了指定的CPU，并且在该中断handler中触发了一个softirq，
			那么该CPU负责调用该softirq number对应的action callback来处理该软中断
*/
typedef struct
{
	unsigned int __softirq_pending;
#ifdef ARCH_WANTS_NMI_IRQSTAT
	unsigned int __nmi_count;
#endif
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);

#include <linux/irq.h>

#ifndef ack_bad_irq
static inline void ack_bad_irq(unsigned int irq)
{
	printk(KERN_CRIT "unexpected IRQ trap at vector %02x\n", irq);
}
#endif

#endif /* __ASM_GENERIC_HARDIRQ_H */
