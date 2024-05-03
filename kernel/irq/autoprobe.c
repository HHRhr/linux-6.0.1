// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains the interrupt probing code and driver APIs.
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/async.h>

#include "internals.h"

/*
 * Autodetection depends on the fact that any interrupt that
 * comes in on to an unassigned handler will get stuck with
 * "IRQS_WAITING" cleared and the interrupt disabled.
 */
static DEFINE_MUTEX(probing_active);

/**
 *	probe_irq_on	- begin an interrupt autodetect
 *
 *	Commence probing for an interrupt. The interrupts are scanned
 *	and a mask of potential interrupt lines is returned.
 *
 */
/*
	什么情况下会出现设备已经注册中断号，但是驱动不知道这个中断号是多少的情况？
		热插拔，比如usb接口已经注册了中断，但是键盘驱动程序并不知道这个中断号是多少
*/
unsigned long probe_irq_on(void)
{
	struct irq_desc *desc;
	unsigned long mask = 0;
	int i;

	/*
	 * quiesce the kernel, or at least the asynchronous portion
	 */
	async_synchronize_full();
	mutex_lock(&probing_active);
	/*
	 * something may have generated an irq long ago and we want to
	 * flush such a longstanding irq before considering it as spurious.
	 */
	/*
		有些中断没有处理函数，被触发后长时间存在，可能会被当作虚假中断（spurious）被屏蔽，
			那么在自动探测时就先清空这些中断事件，然后等待它重新触发来完成自动探测

		在Linux系统中，虚假中断是指没有任何设备实际发出的中断，可能是由于硬件噪声或配置错误造成的。
			系统会追踪这些虚假中断，如果它们频繁发生，会导致IRQ被禁用，以避免对系统性能的影响。

		下面这个循环的作用就是先清空未处理的中断并重新开启
	*/

	for_each_irq_desc_reverse(i, desc)
	{
		raw_spin_lock_irq(&desc->lock);
		/*
			能被探测的中断需要具备两个条件：
				1.不存在specific handler
				2.该中断描述符允许自动探测（不能设定IRQ_NOPROBE）
		*/
		if (!desc->action && irq_settings_can_probe(desc))
		{
			/*
			 * Some chips need to know about probing in
			 * progress:
			 */
			if (desc->irq_data.chip->irq_set_type)
				desc->irq_data.chip->irq_set_type(&desc->irq_data,
												  IRQ_TYPE_PROBE);
			/*
				控制irq chip上该irq的生命周期
					irq_activate -> 设置该irq state为IRQD_ACTIVATED
					irq_startup -> 设置该irq state为IRQD_IRQ_STARTED，内部包括清除disable和mask标志

				这一步相当于丢弃之前未处理的中断事件，然后重新启用该中断
			*/
			irq_activate_and_startup(desc, IRQ_NORESEND);
		}
		raw_spin_unlock_irq(&desc->lock);
	}

	/* Wait for longstanding interrupts to trigger. */
	msleep(20);

	/*
	 * enable any unassigned irqs
	 * (we must startup again here because if a longstanding irq
	 * happened in the previous stage, it may have masked itself)
	 */
	/*
		TODO不理解为什么两次遍历不能放到一起
	*/
	for_each_irq_desc_reverse(i, desc)
	{
		raw_spin_lock_irq(&desc->lock);
		if (!desc->action && irq_settings_can_probe(desc))
		{
			/*
				加上IRQS_AUTODETECT和IRQS_WAITING标志

				IRQS_AUTODETECT表示内核将尝试自动检测这个中断

				IRQS_WAITING表示中断描述符正在等待内核进行进一步的配置或处理，还没有进入high level event handler

				IRQS_PENDING表示中断已经发生，并且内核已经检测到这个中断，但
					是中断处理程序还没有运行specific handler来处理这个中断请求，即请求待处理

				中断处理时，highlevel irq event handler会清除IRQS_WAITING标志
					然后清除IRQS_PENDING并加上IRQD_IRQ_INPROGRESS标志
				handle_fasteoi_irq -> desc->istate &= ~(IRQS_REPLAY | IRQS_WAITING);
								   -> handle_irq_event -> desc->istate &= ~IRQS_PENDING;
													   -> irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);

			*/
			desc->istate |= IRQS_AUTODETECT | IRQS_WAITING;
			if (irq_activate_and_startup(desc, IRQ_NORESEND))
				desc->istate |= IRQS_PENDING;
		}
		raw_spin_unlock_irq(&desc->lock);
	}

	/*
	 * Wait for spurious interrupts to trigger
	 */
	msleep(100);

	/*
	 * Now filter out any obviously spurious interrupts
	 */
	for_each_irq_desc(i, desc)
	{
		raw_spin_lock_irq(&desc->lock);

		if (desc->istate & IRQS_AUTODETECT)
		{
			/*
				驱动里还没手动触发，IRQS_WAITING标志就没了，说明不是目标中断，需要去掉IRQS_AUTODETECT标志
			*/
			/* It triggered already - consider it spurious. */
			if (!(desc->istate & IRQS_WAITING))
			{
				desc->istate &= ~IRQS_AUTODETECT;
				irq_shutdown_and_deactivate(desc);
			}
			else if (i < 32)
				mask |= 1 << i;
		}
		raw_spin_unlock_irq(&desc->lock);
	}

	return mask;
}
EXPORT_SYMBOL(probe_irq_on);

/**
 *	probe_irq_mask - scan a bitmap of interrupt lines
 *	@val:	mask of interrupts to consider
 *
 *	Scan the interrupt lines and return a bitmap of active
 *	autodetect interrupts. The interrupt probe logic state
 *	is then returned to its previous value.
 *
 *	Note: we need to scan all the irq's even though we will
 *	only return autodetect irq numbers - just so that we reset
 *	them all to a known state.
 */
unsigned int probe_irq_mask(unsigned long val)
{
	unsigned int mask = 0;
	struct irq_desc *desc;
	int i;

	for_each_irq_desc(i, desc)
	{
		raw_spin_lock_irq(&desc->lock);
		if (desc->istate & IRQS_AUTODETECT)
		{
			if (i < 16 && !(desc->istate & IRQS_WAITING))
				mask |= 1 << i;

			desc->istate &= ~IRQS_AUTODETECT;
			irq_shutdown_and_deactivate(desc);
		}
		raw_spin_unlock_irq(&desc->lock);
	}
	mutex_unlock(&probing_active);

	return mask & val;
}
EXPORT_SYMBOL(probe_irq_mask);

/**
 *	probe_irq_off	- end an interrupt autodetect
 *	@val: mask of potential interrupts (unused)
 *
 *	Scans the unused interrupt lines and returns the line which
 *	appears to have triggered the interrupt. If no interrupt was
 *	found then zero is returned. If more than one interrupt is
 *	found then minus the first candidate is returned to indicate
 *	their is doubt.
 *
 *	The interrupt probe logic state is returned to its previous
 *	value.
 *
 *	BUGS: When used in a module (which arguably shouldn't happen)
 *	nothing prevents two IRQ probe callers from overlapping. The
 *	results of this are non-optimal.
 */
int probe_irq_off(unsigned long val)
{
	int i, irq_found = 0, nr_of_irqs = 0;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc)
	{
		raw_spin_lock_irq(&desc->lock);

		if (desc->istate & IRQS_AUTODETECT) // 只有处于IRQ自动探测中的描述符才会被处理
		{
			/*
				在highlevel irq event handler中会清除IRQS_WAITING状态
				如果不存在IRQS_WAITING状态，说明可能是目标中断
			*/
			if (!(desc->istate & IRQS_WAITING)) // 找到一个
			{
				if (!nr_of_irqs)
					irq_found = i;
				nr_of_irqs++;
			}
			desc->istate &= ~IRQS_AUTODETECT;
			irq_shutdown_and_deactivate(desc);
		}
		raw_spin_unlock_irq(&desc->lock);
	}
	mutex_unlock(&probing_active);

	if (nr_of_irqs > 1) // 如果找到多于1个的IRQ，说明探测失败，返回负的IRQ个数信息
		irq_found = -irq_found;

	return irq_found;
}
EXPORT_SYMBOL(probe_irq_off);
