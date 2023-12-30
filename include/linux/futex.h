/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FUTEX_H
#define _LINUX_FUTEX_H

#include <linux/sched.h>
#include <linux/ktime.h>

#include <uapi/linux/futex.h>

struct inode;
struct mm_struct;
struct task_struct;

/*
 * Futexes are matched on equal values of this key.
 * The key type depends on whether it's a shared or private mapping.
 * Don't rearrange members without looking at hash_futex().
 *
 * offset is aligned to a multiple of sizeof(u32) (== 4) by definition.
 * We use the two low order bits of offset to tell what is the kind of key :
 *  00 : Private process futex (PTHREAD_PROCESS_PRIVATE)
 *       (no reference on an inode or mm)
 *  01 : Shared futex (PTHREAD_PROCESS_SHARED)
 *	mapped on a file (reference on the underlying inode)
 *  10 : Shared futex (PTHREAD_PROCESS_SHARED)
 *       (but private mapping on an mm, and reference taken on it)
*/

#define FUT_OFF_INODE    1 /* We set bit 0 if key has a reference on inode */
#define FUT_OFF_MMSHARED 2 /* We set bit 1 if key has a reference on mm */

/*
	**
	offset表示futex的类型，私有的00，共享内存的为01，匿名共享内存的为10

	**
	对于私有的futex，通过进程地址空间mm和futex word虚拟地址addr就可以唯一确定一个futex_key
	而共享的futex由于保存在共享内存中，不同进程中的futex word虚拟地址不同，但物理地址是一致的，故采用inode序号的方式作为futex_key
*/
union futex_key {
	struct {
		u64 i_seq;				// inode序号，所在文件的索引节点
		unsigned long pgoff;	// 物理页的偏移量
		unsigned int offset;	// 页内偏移量
	} shared;
	struct {
		union {
			struct mm_struct *mm;	// 进程的内存管理结构，保存了进程的虚拟地址空间的信息，可用来区分不同进程
			u64 __tmp;
		};
		unsigned long address;	// futex word虚拟内存地址
		unsigned int offset;
	} private;
	struct {
		u64 ptr;	
		unsigned long word;
		unsigned int offset;
	} both;
};

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

#ifdef CONFIG_FUTEX
enum {
	FUTEX_STATE_OK,
	FUTEX_STATE_EXITING,
	FUTEX_STATE_DEAD,
};

static inline void futex_init_task(struct task_struct *tsk)
{
	tsk->robust_list = NULL;
#ifdef CONFIG_COMPAT
	tsk->compat_robust_list = NULL;
#endif
	INIT_LIST_HEAD(&tsk->pi_state_list);
	tsk->pi_state_cache = NULL;
	tsk->futex_state = FUTEX_STATE_OK;
	mutex_init(&tsk->futex_exit_mutex);
}

void futex_exit_recursive(struct task_struct *tsk);
void futex_exit_release(struct task_struct *tsk);
void futex_exec_release(struct task_struct *tsk);

long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
	      u32 __user *uaddr2, u32 val2, u32 val3);
#else
static inline void futex_init_task(struct task_struct *tsk) { }
static inline void futex_exit_recursive(struct task_struct *tsk) { }
static inline void futex_exit_release(struct task_struct *tsk) { }
static inline void futex_exec_release(struct task_struct *tsk) { }
static inline long do_futex(u32 __user *uaddr, int op, u32 val,
			    ktime_t *timeout, u32 __user *uaddr2,
			    u32 val2, u32 val3)
{
	return -EINVAL;
}
#endif

#endif
