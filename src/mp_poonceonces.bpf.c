/* Auto-generated from MP+poonceonces.litmus */
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile __u64 sync_flag[10000] = {0};
volatile __u32 count;
volatile __u32 sense;

/*
 * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *			       non-scalar types unchanged.
 */
/*
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */

#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))

#define smp_mb()						\
        ({							\
                volatile __u64 __val = 1;			\
		__val = __sync_fetch_and_add(&__val, 10);	\
        })

#define smp_load_acquire(p)					\
	({							\
		__unqual_scalar_typeof(*p) __val;		\
		__atomic_load(p, &__val, __ATOMIC_ACQUIRE);	\
		__val;						\
	})

#define smp_store_release(p, v)					\
	({							\
		__unqual_scalar_typeof(*p) __val = (v);		\
		__atomic_store(p, &__val, __ATOMIC_RELEASE);	\
	})

int barrier_wait(unsigned int id, unsigned int i)
{
	if (i >= 10000)
		return 0;

	if ((i % 2) == id) {
		WRITE_ONCE(sync_flag[i], 1);
		smp_mb();
	} else {
		for (int ii=0; ii<256; ii++) {
			if (READ_ONCE(sync_flag[i]) != 0) return 0;
		}
	}
	return 0;
}

static void bpf_sense_barrier(__u32 *local_sense, int t)
{
	*local_sense = !(*local_sense);

	__sync_fetch_and_add(&count, 1);

	if (__sync_fetch_and_add(&count, 0) == t) {
		// Last thread resets count and flips sense
		count = 0;
		sense = *local_sense;
	} else {
		for (int i = 0; i < 200; i++) {
			if (sense == *local_sense)
				break;
		}
	}
}

/*
 * * Result: Sometimes
 * *
 * * Can the counter-intuitive message-passing outcome be prevented with
 * * no ordering at all?
 * buf, 1);
 * WRITE_ONCE(*flag, 1);
 * }
 * 
 * P1(int *buf, int *flag)
 * {
 * int r0;
 * int r1;
 * 
 * r0 = READ_ONCE(*flag);
 * r1 = READ_ONCE(*buf);
 * }
 * 
 * exists (1:r0=1 /\ 1:r1=0) (* Bad outcome.
 */

struct {
    volatile __u64 buf[10000];
    volatile __u64 flag[10000];
    volatile __u64 r1[10000];  // For P1_r0
    volatile __u64 r2[10000];  // For P1_r1
} shared;

int num_threads = 2;
// Program for P0
SEC("raw_tp/test_prog1")
int handle_tp1(void *ctx)
{
	__u32 local_sense = 0;
	int i;

	bpf_sense_barrier(&local_sense, num_threads);
	smp_mb();
	bpf_for (i, 0, 10000) {
		barrier_wait(0, i);
		WRITE_ONCE(shared.buf[i], 1);
		WRITE_ONCE(shared.flag[i], 1);
	}
	smp_mb();
	return 0;
}

// Program for P1
SEC("raw_tp/test_prog2")
int handle_tp2(void *ctx)
{
	__u32 local_sense = 0;
	int i;

	bpf_sense_barrier(&local_sense, num_threads);
	smp_mb();
	bpf_for (i, 0, 10000) {
		barrier_wait(1, i);
		shared.r1[i] = READ_ONCE(shared.flag[i]);
		shared.r2[i] = READ_ONCE(shared.buf[i]);
	}
	smp_mb();
	return 0;
}
