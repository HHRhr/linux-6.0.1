// SPDX-License-Identifier: GPL-2.0-only
/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 *	Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/local_lock.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <linux/tick.h>
#include <linux/irq.h>
#include <linux/wait_bit.h>

#include <asm/softirq_stack.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
	 by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
	 execution. Hence, we get something sort of weak cpu binding.
	 Though it is still not clear, will it result in better locality
	 or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
	 any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
	 it is logically serialized per device, but this serialization
	 is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
DEFINE_PER_CPU_ALIGNED(irq_cpustat_t, irq_stat);
EXPORT_PER_CPU_SYMBOL(irq_stat);
#endif
/*
	soft irq中断向量表
	softirq_action只有一个handler成员

	另..__cacheline_aligned_in_smp声明将该数组对齐到各个CPU的cache line的起始边界上，
		避免和更新频繁的其他数据放置在同一个cache line上，从而避免伪共享，提高性能
*/
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

const char *const softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"};

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

	if (tsk)
		wake_up_process(tsk);
}

/*
 * If ksoftirqd is scheduled, we do not want to process pending softirqs
 * right now. Let ksoftirqd handle this at its own rate, to get fairness,
 * unless we're doing some of the synchronous softirqs.
 */
#define SOFTIRQ_NOW_MASK ((1 << HI_SOFTIRQ) | (1 << TASKLET_SOFTIRQ))
static bool ksoftirqd_running(unsigned long pending)
{
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

	if (pending & SOFTIRQ_NOW_MASK)
		return false;
	return tsk && task_is_running(tsk) && !__kthread_should_park(tsk);
}

#ifdef CONFIG_TRACE_IRQFLAGS
DEFINE_PER_CPU(int, hardirqs_enabled);
DEFINE_PER_CPU(int, hardirq_context);
EXPORT_PER_CPU_SYMBOL_GPL(hardirqs_enabled);
EXPORT_PER_CPU_SYMBOL_GPL(hardirq_context);
#endif

/*
 * SOFTIRQ_OFFSET usage:
 *
 * On !RT kernels 'count' is the preempt counter, on RT kernels this applies
 * to a per CPU counter and to task::softirqs_disabled_cnt.
 *
 * - count is changed by SOFTIRQ_OFFSET on entering or leaving softirq
 *   processing.
 *
 * - count is changed by SOFTIRQ_DISABLE_OFFSET (= 2 * SOFTIRQ_OFFSET)
 *   on local_bh_disable or local_bh_enable.
 *
 * This lets us distinguish between whether we are currently processing
 * softirq and whether we just have bh disabled.
 */
#ifdef CONFIG_PREEMPT_RT

/*
 * RT accounts for BH disabled sections in task::softirqs_disabled_cnt and
 * also in per CPU softirq_ctrl::cnt. This is necessary to allow tasks in a
 * softirq disabled section to be preempted.
 *
 * The per task counter is used for softirq_count(), in_softirq() and
 * in_serving_softirqs() because these counts are only valid when the task
 * holding softirq_ctrl::lock is running.
 *
 * The per CPU counter prevents pointless wakeups of ksoftirqd in case that
 * the task which is in a softirq disabled section is preempted or blocks.
 */
struct softirq_ctrl
{
	local_lock_t lock;
	int cnt;
};

static DEFINE_PER_CPU(struct softirq_ctrl, softirq_ctrl) = {
	.lock = INIT_LOCAL_LOCK(softirq_ctrl.lock),
};

/**
 * local_bh_blocked() - Check for idle whether BH processing is blocked
 *
 * Returns false if the per CPU softirq::cnt is 0 otherwise true.
 *
 * This is invoked from the idle task to guard against false positive
 * softirq pending warnings, which would happen when the task which holds
 * softirq_ctrl::lock was the only running task on the CPU and blocks on
 * some other lock.
 */
bool local_bh_blocked(void)
{
	return __this_cpu_read(softirq_ctrl.cnt) != 0;
}

void __local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
	unsigned long flags;
	int newcnt;

	WARN_ON_ONCE(in_hardirq());

	/* First entry of a task into a BH disabled section? */
	if (!current->softirq_disable_cnt)
	{
		if (preemptible())
		{
			local_lock(&softirq_ctrl.lock);
			/* Required to meet the RCU bottomhalf requirements. */
			rcu_read_lock();
		}
		else
		{
			DEBUG_LOCKS_WARN_ON(this_cpu_read(softirq_ctrl.cnt));
		}
	}

	/*
	 * Track the per CPU softirq disabled state. On RT this is per CPU
	 * state to allow preemption of bottom half disabled sections.
	 */
	newcnt = __this_cpu_add_return(softirq_ctrl.cnt, cnt);
	/*
	 * Reflect the result in the task state to prevent recursion on the
	 * local lock and to make softirq_count() & al work.
	 */
	current->softirq_disable_cnt = newcnt;

	if (IS_ENABLED(CONFIG_TRACE_IRQFLAGS) && newcnt == cnt)
	{
		raw_local_irq_save(flags);
		lockdep_softirqs_off(ip);
		raw_local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(__local_bh_disable_ip);

static void __local_bh_enable(unsigned int cnt, bool unlock)
{
	unsigned long flags;
	int newcnt;

	DEBUG_LOCKS_WARN_ON(current->softirq_disable_cnt !=
						this_cpu_read(softirq_ctrl.cnt));

	if (IS_ENABLED(CONFIG_TRACE_IRQFLAGS) && softirq_count() == cnt)
	{
		raw_local_irq_save(flags);
		lockdep_softirqs_on(_RET_IP_);
		raw_local_irq_restore(flags);
	}

	newcnt = __this_cpu_sub_return(softirq_ctrl.cnt, cnt);
	current->softirq_disable_cnt = newcnt;

	if (!newcnt && unlock)
	{
		rcu_read_unlock();
		local_unlock(&softirq_ctrl.lock);
	}
}

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
	bool preempt_on = preemptible();
	unsigned long flags;
	u32 pending;
	int curcnt;

	/*
		不应该在硬中断上下文里调用local_bh_disable/enable
			因为硬中断上下文本身就是不可被抢占的，
		local_bh_enable/disable真正的用处是给进程上下文使用的，
			用于防止softirq handler抢占local_bh_enable/disable之间的临界区的
	*/
	WARN_ON_ONCE(in_hardirq());
	lockdep_assert_irqs_enabled();

	local_irq_save(flags);
	curcnt = __this_cpu_read(softirq_ctrl.cnt);

	/*
	 * If this is not reenabling soft interrupts, no point in trying to
	 * run pending ones.
	 */
	if (curcnt != cnt)
		goto out;

	pending = local_softirq_pending();
	if (!pending || ksoftirqd_running(pending))
		goto out;

	/*
	 * If this was called from non preemptible context, wake up the
	 * softirq daemon.
	 */
	if (!preempt_on)
	{
		wakeup_softirqd();
		goto out;
	}

	/*
	 * Adjust softirq count to SOFTIRQ_OFFSET which makes
	 * in_serving_softirq() become true.
	 */
	cnt = SOFTIRQ_OFFSET;
	__local_bh_enable(cnt, false);
	__do_softirq();

out:
	__local_bh_enable(cnt, preempt_on);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__local_bh_enable_ip);

/*
 * Invoked from ksoftirqd_run() outside of the interrupt disabled section
 * to acquire the per CPU local lock for reentrancy protection.
 */
static inline void ksoftirqd_run_begin(void)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
	local_irq_disable();
}

/* Counterpart to ksoftirqd_run_begin() */
static inline void ksoftirqd_run_end(void)
{
	__local_bh_enable(SOFTIRQ_OFFSET, true);
	WARN_ON_ONCE(in_interrupt());
	local_irq_enable();
}

static inline void softirq_handle_begin(void) {}
static inline void softirq_handle_end(void) {}

static inline bool should_wake_ksoftirqd(void)
{
	return !this_cpu_read(softirq_ctrl.cnt);
}

static inline void invoke_softirq(void)
{
	if (should_wake_ksoftirqd())
		wakeup_softirqd();
}

/*
 * flush_smp_call_function_queue() can raise a soft interrupt in a function
 * call. On RT kernels this is undesired and the only known functionality
 * in the block layer which does this is disabled on RT. If soft interrupts
 * get raised which haven't been raised before the flush, warn so it can be
 * investigated.
 */
void do_softirq_post_smp_call_flush(unsigned int was_pending)
{
	if (WARN_ON_ONCE(was_pending != local_softirq_pending()))
		invoke_softirq();
}

#else /* CONFIG_PREEMPT_RT */

/*
 * This one is for softirq.c-internal use, where hardirqs are disabled
 * legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
void __local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
	unsigned long flags;

	WARN_ON_ONCE(in_hardirq());

	raw_local_irq_save(flags);
	/*
	 * The preempt tracer hooks into preempt_count_add and will break
	 * lockdep because it calls back into lockdep after SOFTIRQ_OFFSET
	 * is set and before current->softirq_enabled is cleared.
	 * We must manually increment preempt_count here and manually
	 * call the trace_preempt_off later.
	 */
	__preempt_count_add(cnt);
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == (cnt & SOFTIRQ_MASK))
		lockdep_softirqs_off(ip);
	raw_local_irq_restore(flags);

	if (preempt_count() == cnt)
	{
#ifdef CONFIG_DEBUG_PREEMPT
		current->preempt_disable_ip = get_lock_parent_ip();
#endif
		trace_preempt_off(CALLER_ADDR0, get_lock_parent_ip());
	}
}
EXPORT_SYMBOL(__local_bh_disable_ip);
#endif /* CONFIG_TRACE_IRQFLAGS */

static void __local_bh_enable(unsigned int cnt)
{
	lockdep_assert_irqs_disabled();

	if (preempt_count() == cnt)
		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());

	if (softirq_count() == (cnt & SOFTIRQ_MASK))
		lockdep_softirqs_on(_RET_IP_);

	__preempt_count_sub(cnt);
}

/*
 * Special-case - softirqs can safely be enabled by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	WARN_ON_ONCE(in_hardirq());
	__local_bh_enable(SOFTIRQ_DISABLE_OFFSET);
}
EXPORT_SYMBOL(_local_bh_enable);

/*
	这是非preempt_rt选项下的bh_enable实现
	TODOpreempt_rt选项打开时有不同的行为,待探索
*/
void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
	/*
		中断上下文本身就是不可被抢占的，没有必要关soft irq
		local_bh_enable/disable真正的用途是给进程上下文使用的，
			可用于防止soft irq handler抢占local_bh_enable/disable之间的临界区
	*/
	WARN_ON_ONCE(in_hardirq());
	lockdep_assert_irqs_enabled();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_disable();
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_DISABLE_OFFSET)
		lockdep_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
	 */
	/*
		进程在bh_diable期间,可能有硬中断raise了softirq,所以在离开临界区(执行bh_enable)后，需要立刻检查是否有soft irq等待运行
		但是在__do_softirq给preempt_count置位之前，可能存在preempt_count为0的真空期,如果当前进程在这段时间被抢占,
			它再次执行时可能会被移到其他CPU上,使得之前CPU上被raise的soft irq的执行时机被滞后，所以要为该进程开启禁止抢占

		具体措施是增加preempt count位,cnt等于SOFTIRQ_DISABLE_OFFSET,
			和disable对应,需要减去SOFTIRQ_DISABLE_OFFSET大小,但是再加1位,表示禁止抢占(效果等同调用preempt_disable函数)
	*/
	__preempt_count_sub(cnt - 1);

	if (unlikely(!in_interrupt() && local_softirq_pending()))
	{
		/*
		 * Run softirq if any pending. And do it in its own stack
		 * as we may be calling this deep in a task call stack already.
		 */
		/*
			在当前进程的上下文中处理soft irq
			但是用独立的栈空间(但其实arm没有设定独立栈空间,do_softirq_own_stack是个空壳子)
		*/
		do_softirq();
	}

	/*
		把之前给preempt count位加的值减回来
	*/
	preempt_count_dec();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_enable();
#endif
	/*
		soft irq可能唤醒了高优先级任务,优先执行它们
	*/
	preempt_check_resched();
}
EXPORT_SYMBOL(__local_bh_enable_ip);

static inline void softirq_handle_begin(void)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
}

static inline void softirq_handle_end(void)
{
	__local_bh_enable(SOFTIRQ_OFFSET);
	WARN_ON_ONCE(in_interrupt());
}

static inline void ksoftirqd_run_begin(void)
{
	local_irq_disable();
}

static inline void ksoftirqd_run_end(void)
{
	local_irq_enable();
}

static inline bool should_wake_ksoftirqd(void)
{
	return true;
}

static inline void invoke_softirq(void)
{
	if (ksoftirqd_running(local_softirq_pending()))
		return;

	/*
		非强制线程化,在中断上下文里执行soft irq handler
		TODO为什么这里不需要禁用中断??
			感觉虽然处于可抢占状态，但上下文中的寄存器、栈都还没切换回来，所以也不能被调度？？
	*/
	if (!force_irqthreads() || !__this_cpu_read(ksoftirqd))
	{
#ifdef CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK
		/*
		 * We can safely execute softirq on the current stack if
		 * it is the irq stack, because it should be near empty
		 * at this stage.
		 */
		__do_softirq();
#else
		/*
		 * Otherwise, irq_exit() is called on the task stack that can
		 * be potentially deep already. So call softirq in its own stack
		 * to prevent from any overrun.
		 */
		do_softirq_own_stack();
#endif
	}
	/*
		强制线程化,交给softirqd内核线程来执行soft irq handler,这样softirqd的执行时机会由调度器来决定
			而不是占据着用户进程上下文处理soft irq
	*/
	else
	{
		wakeup_softirqd();
	}
}

asmlinkage __visible void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

	if (in_interrupt())
		return;

	local_irq_save(flags);

	pending = local_softirq_pending();

	if (pending && !ksoftirqd_running(pending))
		do_softirq_own_stack();

	local_irq_restore(flags);
}

#endif /* !CONFIG_PREEMPT_RT */

/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10

#ifdef CONFIG_TRACE_IRQFLAGS
/*
 * When we run softirqs from irq_exit() and thus on the hardirq stack we need
 * to keep the lockdep irq context tracking as tight as possible in order to
 * not miss-qualify lock contexts and miss possible deadlocks.
 */

static inline bool lockdep_softirq_start(void)
{
	bool in_hardirq = false;

	if (lockdep_hardirq_context())
	{
		in_hardirq = true;
		lockdep_hardirq_exit();
	}

	lockdep_softirq_enter();

	return in_hardirq;
}

static inline void lockdep_softirq_end(bool in_hardirq)
{
	lockdep_softirq_exit();

	if (in_hardirq)
		lockdep_hardirq_enter();
}
#else
static inline bool lockdep_softirq_start(void) { return false; }
static inline void lockdep_softirq_end(bool in_hardirq) {}
#endif

asmlinkage __visible void __softirq_entry __do_softirq(void)
{
	unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
	unsigned long old_flags = current->flags;
	int max_restart = MAX_SOFTIRQ_RESTART;
	struct softirq_action *h;
	bool in_hardirq;
	__u32 pending;
	int softirq_bit;

	/*
	 * Mask out PF_MEMALLOC as the current task context is borrowed for the
	 * softirq. A softirq handled, such as network RX, might set PF_MEMALLOC
	 * again if the socket is related to swapping.
	 */
	current->flags &= ~PF_MEMALLOC;

	pending = local_softirq_pending(); // 获取softirq pending的状态

	/*
		preempt_count_add(SOFTIRQ_OFFSET)
	*/
	softirq_handle_begin(); // 标识下面的代码是正在处理softirq
	in_hardirq = lockdep_softirq_start();
	account_softirq_enter(current);

restart:
	/* Reset the pending bitmask before enabling irqs */
	set_softirq_pending(0); // 清除pending标志

	local_irq_enable(); // 打开中断，softirq handler是开中断执行的

	h = softirq_vec; // 指向soft irq中断向量表

	while ((softirq_bit = ffs(pending))) // 寻找pending中第一个被设定为1的bit
	{
		unsigned int vec_nr;
		int prev_count;

		h += softirq_bit - 1; // 指向pending的那个软中断描述符

		vec_nr = h - softirq_vec; // 计算soft irq number
		prev_count = preempt_count();

		kstat_incr_softirqs_this_cpu(vec_nr);

		trace_softirq_entry(vec_nr);
		h->action(h); // 执行softirq handler
		trace_softirq_exit(vec_nr);
		if (unlikely(prev_count != preempt_count()))
		{
			pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
				   vec_nr, softirq_to_name[vec_nr], h->action,
				   prev_count, preempt_count());
			preempt_count_set(prev_count);
		}
		h++;
		pending >>= softirq_bit;
	}

	if (!IS_ENABLED(CONFIG_PREEMPT_RT) &&
		__this_cpu_read(ksoftirqd) == current)
		rcu_softirq_qs();

	local_irq_disable();

	/*
		处理完pending状态一遍后,再次检查pending状态,看是否需要跳到restart处理新到来的soft irq

		但是不能一直只处理soft irq,在出现下面三个条件时,要把soft irq交给softirqd来继续执行
			跳转次数超过MAX_SOFTIRQ_RESTART(10次)
			处理时间超过MAX_SOFTIRQ_TIME(2ms)
			上次的softirq中没有设定TIF_NEED_RESCHED，也就是说没有有高优先级任务需要调度
	*/
	pending = local_softirq_pending();
	if (pending)
	{
		if (time_before(jiffies, end) && !need_resched() &&
			--max_restart)
			goto restart;

		wakeup_softirqd();
	}

	account_softirq_exit(current);
	lockdep_softirq_end(in_hardirq);
	softirq_handle_end(); // 标识softirq处理完毕
	current_restore_flags(old_flags, PF_MEMALLOC);
}

/**
 * irq_enter_rcu - Enter an interrupt context with RCU watching
 */
void irq_enter_rcu(void)
{
	__irq_enter_raw();

	if (tick_nohz_full_cpu(smp_processor_id()) ||
		(is_idle_task(current) && (irq_count() == HARDIRQ_OFFSET)))
		tick_irq_enter();

	account_hardirq_enter(current);
}

/**
 * irq_enter - Enter an interrupt context including RCU update
 */
void irq_enter(void)
{
	ct_irq_enter();
	irq_enter_rcu();
}

static inline void tick_irq_exit(void)
{
#ifdef CONFIG_NO_HZ_COMMON
	int cpu = smp_processor_id();

	/* Make sure that timer wheel updates are propagated */
	if ((idle_cpu(cpu) && !need_resched()) || tick_nohz_full_cpu(cpu))
	{
		if (!in_hardirq())
			tick_nohz_irq_exit();
	}
#endif
}

/*
	调用irq_exit()时检查是否有soft irq等待处理
*/
static inline void __irq_exit_rcu(void)
{
#ifndef __ARCH_IRQ_EXIT_IRQS_DISABLED
	local_irq_disable();
#else
	lockdep_assert_irqs_disabled();
#endif
	account_hardirq_exit(current);
	preempt_count_sub(HARDIRQ_OFFSET);

	/*
		在非中断上下文情况下(硬中断打断的是进程上下文),才会执行soft irq handler
	*/
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

	tick_irq_exit();
}

/**
 * irq_exit_rcu() - Exit an interrupt context without updating RCU
 *
 * Also processes softirqs if needed and possible.
 */
void irq_exit_rcu(void)
{
	__irq_exit_rcu();
	/* must be last! */
	lockdep_hardirq_exit();
}

/**
 * irq_exit - Exit an interrupt context, update RCU and lockdep
 *
 * Also processes softirqs if needed and possible.
 */
void irq_exit(void)
{
	__irq_exit_rcu();
	ct_irq_exit();
	/* must be last! */
	lockdep_hardirq_exit();
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
	/*
		更改软件寄存器irq_cpustat_t -> __softirq_pending的标志位，
			标识正在触发的soft irq
	*/
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	/*
		如果在中断上下文（包括irq、softirq、softirq-disabled的临界区内）调用raise，只要set __softirq_pending的某个bit就OK了，
			在中断上下文结束的时候自然会检测__softirq_pending的置位情况，并进行软中断处理
		但是，如果是在进程上下文调用的raise，就必须显式调用wakeup_softirqd函数来让softirqd进行软中断处理
	*/
	if (!in_interrupt() && should_wake_ksoftirqd())
		wakeup_softirqd();
}

/*
	在local cpu上触发soft irq
	如果已经关中断了，比如在specific handler中触发soft irq，可以直接调用另一个接口：raise_softirq_irqoff

	即使是local cpu的变量，为了保证操作的原子性（操作要一口气完成，不被打断），也需要关硬中断
*/
void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}

void __raise_softirq_irqoff(unsigned int nr)
{
	lockdep_assert_irqs_disabled();
	trace_softirq_raise(nr);
	or_softirq_pending(1UL << nr);
}

// 注册soft irq handler
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}

/*
 * Tasklets
 */
struct tasklet_head
{
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

/*
	每个CPU都有管理tasklet的两种链表
	sofirq的优先级就是其枚举类型代表的数值，与__softirq_pending从右向左的位数对应
		HI_SOFTIRQ占据了bit 0，其优先级甚至高过timer，需要慎用
		TASKLET_SOFTIRQ优先级较低，

*/
static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

static void __tasklet_schedule_common(struct tasklet_struct *t,
									  struct tasklet_head __percpu *headp,
									  unsigned int softirq_nr)
{
	struct tasklet_head *head;
	unsigned long flags;

	// 下面的链表操作是per-cpu的，因此这里禁止本地中断就可以拦截所有的并发。
	local_irq_save(flags);
	// 将一个tasklet挂入链表的尾部
	head = this_cpu_ptr(headp);
	t->next = NULL;
	*head->tail = t;
	head->tail = &(t->next);

	// raise TASKLET_SOFTIRQ类型的softirq
	raise_softirq_irqoff(softirq_nr);
	local_irq_restore(flags);
}

void __tasklet_schedule(struct tasklet_struct *t)
{
	__tasklet_schedule_common(t, &tasklet_vec,
							  TASKLET_SOFTIRQ);
}
EXPORT_SYMBOL(__tasklet_schedule);

void __tasklet_hi_schedule(struct tasklet_struct *t)
{
	__tasklet_schedule_common(t, &tasklet_hi_vec,
							  HI_SOFTIRQ);
}
EXPORT_SYMBOL(__tasklet_hi_schedule);

static bool tasklet_clear_sched(struct tasklet_struct *t)
{
	if (test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
	{
		wake_up_var(&t->state);
		return true;
	}

	WARN_ONCE(1, "tasklet SCHED state not set: %s %pS\n",
			  t->use_callback ? "callback" : "func",
			  t->use_callback ? (void *)t->callback : (void *)t->func);

	return false;
}

/*
	通用的tasklet handler，其实就是调用用户为tasklet_struct注册的回调函数
*/
static void tasklet_action_common(struct softirq_action *a,
								  struct tasklet_head *tl_head,
								  unsigned int softirq_nr)
{
	struct tasklet_struct *list;

	/*
		把tasklet_vec链表交给list临时变量，然后重置tasklet_vec
		因为这里是对tasklet_head操作，为了防止有硬中断把新的tasklet排队到链表里，需要禁用硬中断
	*/
	local_irq_disable();
	list = tl_head->head;
	tl_head->head = NULL;
	tl_head->tail = &tl_head->head;
	local_irq_enable();

	while (list) // 遍历tasklet链表
	{
		struct tasklet_struct *t = list;

		list = list->next;

		/*
			假如CPU0执行到callback时被硬中断打断，此时TASKLET_STATE_SCHED标记已清除，同时有TASKLET_STATE_RUN标记
				则在CPU1上被sched的tasklet有可能进入CPU1的tasklet_vec链表，
				如果CPU1到达了执行tasklet_vec链表时刻，就需要检查TASKLET_STATE_RUN标记，如果发现tasklet在其他CPU上处于执行状态，就先跳过
			这也说明同一个tasklet在不同CPU上是不能并发执行的，而是要等待其他CPU执行完毕才能有执行机会
		*/
		if (tasklet_trylock(t))
		{
			if (!atomic_read(&t->count)) // 是enable状态？
			{
				if (tasklet_clear_sched(t)) // 清除TASKLET_STATE_SCHED标记
				{
					if (t->use_callback)
						t->callback(t);
					else
						t->func(t->data);
				}
				tasklet_unlock(t); // 清除TASKLET_STATE_RUN标记，换下一个tasklet
				continue;
			}
			tasklet_unlock(t); // 清除TASKLET_STATE_RUN标记，重新排入tasklet_vec
		}

		/*
			当前的tasklet_struct没法执行，把它重新安排到tasklet_vec里面，等待下次执行时机到来
		*/
		local_irq_disable();
		t->next = NULL;
		*tl_head->tail = t;
		tl_head->tail = &t->next;
		__raise_softirq_irqoff(softirq_nr);
		local_irq_enable();
	}
}

static __latent_entropy void tasklet_action(struct softirq_action *a)
{
	tasklet_action_common(a, this_cpu_ptr(&tasklet_vec), TASKLET_SOFTIRQ);
}

static __latent_entropy void tasklet_hi_action(struct softirq_action *a)
{
	tasklet_action_common(a, this_cpu_ptr(&tasklet_hi_vec), HI_SOFTIRQ);
}

void tasklet_setup(struct tasklet_struct *t,
				   void (*callback)(struct tasklet_struct *))
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->callback = callback;
	t->use_callback = true;
	t->data = 0;
}
EXPORT_SYMBOL(tasklet_setup);

void tasklet_init(struct tasklet_struct *t,
				  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->use_callback = false;
	t->data = data;
}
EXPORT_SYMBOL(tasklet_init);

#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT)
/*
 * Do not use in new code. Waiting for tasklets from atomic contexts is
 * error prone and should be avoided.
 */
void tasklet_unlock_spin_wait(struct tasklet_struct *t)
{
	while (test_bit(TASKLET_STATE_RUN, &(t)->state))
	{
		if (IS_ENABLED(CONFIG_PREEMPT_RT))
		{
			/*
			 * Prevent a live lock when current preempted soft
			 * interrupt processing or prevents ksoftirqd from
			 * running. If the tasklet runs on a different CPU
			 * then this has no effect other than doing the BH
			 * disable/enable dance for nothing.
			 */
			local_bh_disable();
			local_bh_enable();
		}
		else
		{
			cpu_relax();
		}
	}
}
EXPORT_SYMBOL(tasklet_unlock_spin_wait);
#endif

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		pr_notice("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
		wait_var_event(&t->state, !test_bit(TASKLET_STATE_SCHED, &t->state));

	tasklet_unlock_wait(t);
	tasklet_clear_sched(t);
}
EXPORT_SYMBOL(tasklet_kill);

#if defined(CONFIG_SMP) || defined(CONFIG_PREEMPT_RT)
void tasklet_unlock(struct tasklet_struct *t)
{
	smp_mb__before_atomic();
	clear_bit(TASKLET_STATE_RUN, &t->state);
	smp_mb__after_atomic();
	wake_up_var(&t->state);
}
EXPORT_SYMBOL_GPL(tasklet_unlock);

void tasklet_unlock_wait(struct tasklet_struct *t)
{
	wait_var_event(&t->state, !test_bit(TASKLET_STATE_RUN, &t->state));
}
EXPORT_SYMBOL_GPL(tasklet_unlock_wait);
#endif

/*
	名字叫softirq init，实际上是tasklet init，因为softirq的注册应该在各驱动中，而tasklet需要内核来注册，以备驱动用到tasklet
*/
void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
	{
		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
	}

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}

static int ksoftirqd_should_run(unsigned int cpu)
{
	return local_softirq_pending();
}

static void run_ksoftirqd(unsigned int cpu)
{
	ksoftirqd_run_begin();
	if (local_softirq_pending())
	{
		/*
		 * We can safely run softirq on inline stack, as we are not deep
		 * in the task stack here.
		 */
		__do_softirq();
		ksoftirqd_run_end();
		cond_resched();
		return;
	}
	ksoftirqd_run_end();
}

#ifdef CONFIG_HOTPLUG_CPU
static int takeover_tasklets(unsigned int cpu)
{
	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	if (&per_cpu(tasklet_vec, cpu).head != per_cpu(tasklet_vec, cpu).tail)
	{
		*__this_cpu_read(tasklet_vec.tail) = per_cpu(tasklet_vec, cpu).head;
		__this_cpu_write(tasklet_vec.tail, per_cpu(tasklet_vec, cpu).tail);
		per_cpu(tasklet_vec, cpu).head = NULL;
		per_cpu(tasklet_vec, cpu).tail = &per_cpu(tasklet_vec, cpu).head;
	}
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	if (&per_cpu(tasklet_hi_vec, cpu).head != per_cpu(tasklet_hi_vec, cpu).tail)
	{
		*__this_cpu_read(tasklet_hi_vec.tail) = per_cpu(tasklet_hi_vec, cpu).head;
		__this_cpu_write(tasklet_hi_vec.tail, per_cpu(tasklet_hi_vec, cpu).tail);
		per_cpu(tasklet_hi_vec, cpu).head = NULL;
		per_cpu(tasklet_hi_vec, cpu).tail = &per_cpu(tasklet_hi_vec, cpu).head;
	}
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
	return 0;
}
#else
#define takeover_tasklets NULL
#endif /* CONFIG_HOTPLUG_CPU */

static struct smp_hotplug_thread softirq_threads = {
	.store = &ksoftirqd,
	.thread_should_run = ksoftirqd_should_run,
	.thread_fn = run_ksoftirqd,
	.thread_comm = "ksoftirqd/%u",
};

static __init int spawn_ksoftirqd(void)
{
	cpuhp_setup_state_nocalls(CPUHP_SOFTIRQ_DEAD, "softirq:dead", NULL,
							  takeover_tasklets);
	BUG_ON(smpboot_register_percpu_thread(&softirq_threads));

	return 0;
}
early_initcall(spawn_ksoftirqd);

/*
 * [ These __weak aliases are kept in a separate compilation unit, so that
 *   GCC does not inline them incorrectly. ]
 */

int __init __weak early_irq_init(void)
{
	return 0;
}

int __init __weak arch_probe_nr_irqs(void)
{
	return NR_IRQS_LEGACY;
}

int __init __weak arch_early_irq_init(void)
{
	return 0;
}

unsigned int __weak arch_dynirq_lower_bound(unsigned int from)
{
	return from;
}
