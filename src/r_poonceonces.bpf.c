// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Auto-generated from R+poonceonces.litmus */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * * Result: Sometimes
 * *
 * * This is the unordered (thus lacking smp_mb()) version of one of the
 * * classic counterintuitive litmus tests that illustrates the effects of
 * * store propagation delays.
 */

// Place shared variables in the same cache line to increase contention
struct {
    volatile int x[1000];
    volatile int y[1000];
    volatile int r1[1000];  // For P1_r0
} shared;

volatile __u64 flag[1000] = {0};

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))

#define smp_mb() \
	({ \
 		volatile __u64 __val = 1; \
		__val = __sync_fetch_and_add(&__val, 10); \
	})

int barrier_wait(unsigned int id, unsigned int i)
{
 if (i >= 1000)
	 return 0;
 if ((i % 2) == id) {
    WRITE_ONCE(flag[i], 1);
    smp_mb();
  } else {
    #pragma unroll
    for (int ii=0; ii<256; ii++) {
      if (READ_ONCE(flag[i]) != 0) return 0;
    }
  }

 return 0;
}

// Program for P0
SEC("raw_tp/test_prog1")
int handle_tp1(void *ctx)
{
	smp_mb();
	for (int i=0; i<1000; i++) {
		barrier_wait(0, i);
		shared.x[i] = 1;
		shared.y[i] = 1;
	}
	smp_mb();
	return 0;
}

// Program for P1
SEC("raw_tp/test_prog2")
int handle_tp2(void *ctx)
{
	smp_mb();
	for (int i=0; i<1000; i++) {
		barrier_wait(1, i);
		shared.y[i] = 2;
		shared.r1[i] = shared.x[i];
	}
	smp_mb();
	return 0;
}
