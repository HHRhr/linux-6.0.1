/* SPDX-License-Identifier: GPL-2.0 */
/*
 * You SHOULD NOT be including this unless you're vsyscall
 * handling code or timekeeping internal code!
 */

#ifndef _LINUX_TIMEKEEPER_INTERNAL_H
#define _LINUX_TIMEKEEPER_INTERNAL_H

#include <linux/clocksource.h>
#include <linux/jiffies.h>
#include <linux/time.h>

/**
 * struct tk_read_base - base structure for timekeeping readout
 * @clock:	Current clocksource used for timekeeping.
 * @mask:	Bitmask for two's complement subtraction of non 64bit clocks
 * @cycle_last: @clock cycle value at last update
 * @mult:	(NTP adjusted) multiplier for scaled math conversion
 * @shift:	Shift value for scaled math conversion
 * @xtime_nsec: Shifted (fractional) nano seconds offset for readout
 * @base:	ktime_t (nanoseconds) base time for readout
 * @base_real:	Nanoseconds base value for clock REALTIME readout
 *
 * This struct has size 56 byte on 64 bit. Together with a seqcount it
 * occupies a single 64byte cache line.
 *
 * The struct is separate from struct timekeeper as it is also used
 * for a fast NMI safe accessors.
 *
 * @base_real is for the fast NMI safe accessor to allow reading clock
 * realtime from any context.
 */
/*
		NMI是不可屏蔽中断，fast NMI safe
   accessor是一种用于在非屏蔽中断（NMI）环境中安全地访问共享数据的机制
*/
struct tk_read_base
{
	struct clocksource *clock;
	u64 mask;
	u64 cycle_last; // 上次读到的计数寄存器值
	u32 mult;
	u32 shift;
	u64 xtime_nsec; // real的纳秒值，经过shift右移处理，在获取时间时需要左移回来
	ktime_t base;
	u64 base_real;
};

/**
 * struct timekeeper - Structure holding internal timekeeping values.
 * @tkr_mono:		The readout base structure for CLOCK_MONOTONIC
 * @tkr_raw:		The readout base structure for CLOCK_MONOTONIC_RAW
 * @xtime_sec:		Current CLOCK_REALTIME time in seconds
 * @ktime_sec:		Current CLOCK_MONOTONIC time in seconds
 * @wall_to_monotonic:	CLOCK_REALTIME to CLOCK_MONOTONIC offset
 * @offs_real:		Offset clock monotonic -> clock realtime
 * @offs_boot:		Offset clock monotonic -> clock boottime
 * @offs_tai:		Offset clock monotonic -> clock tai
 * @tai_offset:		The current UTC to TAI offset in seconds
 * @clock_was_set_seq:	The sequence number of clock was set events
 * @cs_was_changed_seq:	The sequence number of clocksource change events
 * @next_leap_ktime:	CLOCK_MONOTONIC time value of a pending leap-second
 * @raw_sec:		CLOCK_MONOTONIC_RAW  time in seconds
 * @monotonic_to_boot:	CLOCK_MONOTONIC to CLOCK_BOOTTIME offset
 * @cycle_interval:	Number of clock cycles in one NTP interval
 * @xtime_interval:	Number of clock shifted nano seconds in one NTP
 *			interval.
 * @xtime_remainder:	Shifted nano seconds left over when rounding
 *			@cycle_interval
 * @raw_interval:	Shifted raw nano seconds accumulated per NTP interval.
 * @ntp_error:		Difference between accumulated time and NTP time in ntp
 *			shifted nano seconds.
 * @ntp_error_shift:	Shift conversion between clock shifted nano seconds and
 *			ntp shifted nano seconds.
 * @last_warning:	Warning ratelimiter (DEBUG_TIMEKEEPING)
 * @underflow_seen:	Underflow warning flag (DEBUG_TIMEKEEPING)
 * @overflow_seen:	Overflow warning flag (DEBUG_TIMEKEEPING)
 *
 * Note: For timespec(64) based interfaces wall_to_monotonic is what
 * we need to add to xtime (or xtime corrected for sub jiffie times)
 * to get to monotonic time.  Monotonic is pegged at zero at system
 * boot time, so wall_to_monotonic will be negative, however, we will
 * ALWAYS keep the tv_nsec part positive so we can use the usual
 * normalization.
 * mono在系统启动时被置为0，所以wall_to_monotonic是负数，但是其tv_nsec保持为正数
 **
 *
 * wall_to_monotonic is moved after resume from suspend for the
 * monotonic time not to jump. We need to add total_sleep_time to
 * wall_to_monotonic to get the real boot based time offset.
 * mono的时间线在系统休眠时会暂停，所以系统唤醒时由wall_to_monotonic计算出的mono时间存在跳变，
 * 需要结合wall_to_monotonic + total_sleep_time来计算
 *
 * wall_to_monotonic is no longer the boot time, getboottime must be
 * used instead.
 *
 * @monotonic_to_boottime is a timespec64 representation of @offs_boot to
 * accelerate the VDSO update for CLOCK_BOOTTIME.
 */
struct timekeeper
{
	struct tk_read_base tkr_mono;
	struct tk_read_base tkr_raw;
	u64 xtime_sec;						 // real的秒部分
	unsigned long ktime_sec;			 // mono的秒部分
	struct timespec64 wall_to_monotonic; // mono距real的差值
	// h mono时间与其他时间之间偏移量
	ktime_t offs_real;
	ktime_t offs_boot;
	ktime_t offs_tai;
	s32 tai_offset;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
	ktime_t next_leap_ktime;
	u64 raw_sec;
	struct timespec64 monotonic_to_boot;

	/* The following members are for timekeeping internal use */
	u64 cycle_interval; // h ntp相关，略过
	u64 xtime_interval;
	s64 xtime_remainder;
	u64 raw_interval;
	/* The ntp_tick_length() value currently being used.
	 * This cached copy ensures we consistently apply the tick
	 * length for an entire tick, as ntp_tick_length may change
	 * mid-tick, and we don't want to apply that new value to
	 * the tick in progress.
	 */
	u64 ntp_tick;
	/* Difference between accumulated time and NTP time in ntp
	 * shifted nano seconds. */
	s64 ntp_error;
	u32 ntp_error_shift;
	u32 ntp_err_mult;
	/* Flag used to avoid updating NTP twice with same second */
	u32 skip_second_overflow;
#ifdef CONFIG_DEBUG_TIMEKEEPING
	long last_warning;
	/*
	 * These simple flag variables are managed
	 * without locks, which is racy, but they are
	 * ok since we don't really care about being
	 * super precise about how many events were
	 * seen, just that a problem was observed.
	 */
	int underflow_seen;
	int overflow_seen;
#endif
};

#ifdef CONFIG_GENERIC_TIME_VSYSCALL

extern void update_vsyscall(struct timekeeper *tk);
extern void update_vsyscall_tz(void);

#else

static inline void update_vsyscall(struct timekeeper *tk) {}
static inline void update_vsyscall_tz(void) {}
#endif

#endif /* _LINUX_TIMEKEEPER_INTERNAL_H */
