/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_IRQDESC_H
#define _LINUX_IRQDESC_H

#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/mutex.h>

/*
 * Core internal functions to deal with irq descriptors
 */

struct irq_affinity_notify;
struct proc_dir_entry;
struct module;
struct irq_desc;
struct irq_domain;
struct pt_regs;

/**
 * struct irq_desc - interrupt descriptor
 * @irq_common_data:	per irq and chip data passed down to chip functions
 * @kstat_irqs:		irq stats per cpu
 * @handle_irq:		highlevel irq-events handler
 * @action:		the irq action chain
 * @status_use_accessors: status information
 * @core_internal_state__do_not_mess_with_it: core internal status information
 * @depth:		disable-depth, for nested irq_disable() calls
 * @wake_depth:		enable depth, for multiple irq_set_irq_wake() callers
 * @tot_count:		stats field for non-percpu irqs
 * @irq_count:		stats field to detect stalled irqs
 * @last_unhandled:	aging timer for unhandled count
 * @irqs_unhandled:	stats field for spurious unhandled interrupts
 * @threads_handled:	stats field for deferred spurious detection of threaded handlers
 * @threads_handled_last: comparator field for deferred spurious detection of threaded handlers
 * @lock:		locking for SMP
 * @affinity_hint:	hint to user space for preferred irq affinity
 * @affinity_notify:	context for notification of affinity changes
 * @pending_mask:	pending rebalanced interrupts
 * @threads_oneshot:	bitfield to handle shared oneshot threads
 * @threads_active:	number of irqaction threads currently running
 * @wait_for_threads:	wait queue for sync_irq to wait for threaded handlers
 * @nr_actions:		number of installed actions on this descriptor
 * @no_suspend_depth:	number of irqactions on a irq descriptor with
 *			IRQF_NO_SUSPEND set
 * @force_resume_depth:	number of irqactions on a irq descriptor with
 *			IRQF_FORCE_RESUME set
 * @rcu:		rcu head for delayed free
 * @kobj:		kobject used to represent this struct in sysfs
 * @request_mutex:	mutex to protect request/free before locking desc->lock
 * @dir:		/proc/irq/ procfs entry
 * @debugfs_file:	dentry for the debugfs file
 * @name:		flow handler name for /proc/interrupts output
 */
struct irq_desc
{
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;		   // 可以说是数据中心，包含了chip、domain、irq number、hwirq等
	unsigned int __percpu *kstat_irqs; // 存储每个CPU上自系统启动以来的中断计数

	/*
		1.highlevel irq-events handler

		在Linux内核中，高级别的IRQ事件处理器（highlevel irq-events handler）是中断处理机制的一部分，它主要负责以下两个操作：
			（1）中断流控制（Interrupt Flow Control）：
				高级别处理器会调用中断描述符（irq_desc）的底层IRQ芯片驱动（irq_chip driver）来执行mask、ack等回调函数。
					这些操作是为了控制中断流程，例如，mask操作会阻止中断信号到达处理器，而ack操作则是确认中断信号已被接收。
					这些回调函数的目的是管理中断信号的处理状态，确保中断被正确地识别和响应。
			（2）特定处理器的调用（Specific Handler Invocation）：
				中断描述符上维护着一个动作列表（action list），高级别处理器会根据需要调用这个列表中的特定处理器（specific handler）。
				这些特定处理器是为了处理具体的中断信号而设计的函数。
				是否调用特定处理器取决于中断描述符的当前状态。例如，如果中断已经被处理，或者处于被屏蔽状态，则可能不会调用特定处理器。

		中断流控制是一个由软件和硬件共同完成的过程。
			软件部分涉及设置标志位，以便根据这些标志位来决定如何处理中断。
			硬件部分则涉及到实际的中断控制器操作，如屏蔽（mask）或解除屏蔽（unmask）中断。
	*/
	irq_flow_handler_t handle_irq;
	/*
		2.specific handler

		处理具体的事务
	*/
	struct irqaction *action; /* IRQ action list */

	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	/*
		depth用于追踪嵌套的irq_disable()调用
		每次调用irq_disable()时，@depth会增加，而每次调用irq_enable()时，@depth会减少

		可能在下面场景需要调用irq_disable()：
			中断和进程上下文之间的同步：当中断处理程序和进程上下文需要访问同一个资源时，为了防止数据不一致，可能需要禁用中断。
			设备驱动程序中的并发操作：设备驱动程序可能会在处理中断时访问硬件资源，而这些资源也可能被其他上下文（如进程上下文或其他中断上下文）访问。
	*/
	unsigned int depth;								   /* nested irq disables */
	unsigned int wake_depth; /* nested wake enables */ // 电源管理中的wake up source相关
	unsigned int tot_count;
	unsigned int irq_count;		  /* For detecting broken IRQs */
	unsigned long last_unhandled; /* Aging timer for unhandled count */
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
#ifdef CONFIG_SMP
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
#ifdef CONFIG_GENERIC_PENDING_IRQ
	cpumask_var_t pending_mask;
#endif
#endif
	/*
		IRQ thread相关
	*/
	unsigned long threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
#ifdef CONFIG_PM_SLEEP
	unsigned int nr_actions;
	unsigned int no_suspend_depth;
	unsigned int cond_suspend_depth;
	unsigned int force_resume_depth;
#endif
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *dir;
#endif
#ifdef CONFIG_GENERIC_IRQ_DEBUGFS
	struct dentry *debugfs_file;
	const char *dev_name;
#endif
#ifdef CONFIG_SPARSE_IRQ
	struct rcu_head rcu;
	struct kobject kobj;
#endif
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
} ____cacheline_internodealigned_in_smp;

#ifdef CONFIG_SPARSE_IRQ
extern void irq_lock_sparse(void);
extern void irq_unlock_sparse(void);
#else
static inline void irq_lock_sparse(void) {}
static inline void irq_unlock_sparse(void) {}
extern struct irq_desc irq_desc[NR_IRQS];
#endif

static inline unsigned int irq_desc_kstat_cpu(struct irq_desc *desc,
											  unsigned int cpu)
{
	return desc->kstat_irqs ? *per_cpu_ptr(desc->kstat_irqs, cpu) : 0;
}

static inline struct irq_desc *irq_data_to_desc(struct irq_data *data)
{
	return container_of(data->common, struct irq_desc, irq_common_data);
}

static inline unsigned int irq_desc_get_irq(struct irq_desc *desc)
{
	return desc->irq_data.irq;
}

static inline struct irq_data *irq_desc_get_irq_data(struct irq_desc *desc)
{
	return &desc->irq_data;
}

static inline struct irq_chip *irq_desc_get_chip(struct irq_desc *desc)
{
	return desc->irq_data.chip;
}

static inline void *irq_desc_get_chip_data(struct irq_desc *desc)
{
	return desc->irq_data.chip_data;
}

static inline void *irq_desc_get_handler_data(struct irq_desc *desc)
{
	return desc->irq_common_data.handler_data;
}

/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt.
 */
static inline void generic_handle_irq_desc(struct irq_desc *desc)
{
	desc->handle_irq(desc);
}

int handle_irq_desc(struct irq_desc *desc);
int generic_handle_irq(unsigned int irq);
int generic_handle_irq_safe(unsigned int irq);

#ifdef CONFIG_IRQ_DOMAIN
/*
 * Convert a HW interrupt number to a logical one using a IRQ domain,
 * and handle the result interrupt number. Return -EINVAL if
 * conversion failed.
 */
int generic_handle_domain_irq(struct irq_domain *domain, unsigned int hwirq);
int generic_handle_domain_nmi(struct irq_domain *domain, unsigned int hwirq);
#endif

/* Test to see if a driver has successfully requested an irq */
static inline int irq_desc_has_action(struct irq_desc *desc)
{
	return desc && desc->action != NULL;
}

/**
 * irq_set_handler_locked - Set irq handler from a locked region
 * @data:	Pointer to the irq_data structure which identifies the irq
 * @handler:	Flow control handler function for this interrupt
 *
 * Sets the handler in the irq descriptor associated to @data.
 *
 * Must be called with irq_desc locked and valid parameters. Typical
 * call site is the irq_set_type() callback.
 */
static inline void irq_set_handler_locked(struct irq_data *data,
										  irq_flow_handler_t handler)
{
	struct irq_desc *desc = irq_data_to_desc(data);

	desc->handle_irq = handler;
}

/**
 * irq_set_chip_handler_name_locked - Set chip, handler and name from a locked region
 * @data:	Pointer to the irq_data structure for which the chip is set
 * @chip:	Pointer to the new irq chip
 * @handler:	Flow control handler function for this interrupt
 * @name:	Name of the interrupt
 *
 * Replace the irq chip at the proper hierarchy level in @data and
 * sets the handler and name in the associated irq descriptor.
 *
 * Must be called with irq_desc locked and valid parameters.
 */
static inline void
irq_set_chip_handler_name_locked(struct irq_data *data,
								 const struct irq_chip *chip,
								 irq_flow_handler_t handler, const char *name)
{
	struct irq_desc *desc = irq_data_to_desc(data);

	desc->handle_irq = handler;
	desc->name = name;
	data->chip = (struct irq_chip *)chip;
}

bool irq_check_status_bit(unsigned int irq, unsigned int bitmask);

static inline bool irq_balancing_disabled(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_NO_BALANCING_MASK);
}

static inline bool irq_is_percpu(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_PER_CPU);
}

static inline bool irq_is_percpu_devid(unsigned int irq)
{
	return irq_check_status_bit(irq, IRQ_PER_CPU_DEVID);
}

void __irq_set_lockdep_class(unsigned int irq, struct lock_class_key *lock_class,
							 struct lock_class_key *request_class);
static inline void
irq_set_lockdep_class(unsigned int irq, struct lock_class_key *lock_class,
					  struct lock_class_key *request_class)
{
	if (IS_ENABLED(CONFIG_LOCKDEP))
		__irq_set_lockdep_class(irq, lock_class, request_class);
}

#endif
