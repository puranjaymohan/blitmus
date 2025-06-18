// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Auto-generated from IRIW+poonceonces+OnceOnce.litmus */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "iriw_poonceonces_onceonce.skel.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <bpf/bpf.h>
#include <getopt.h>
#include <time.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysinfo.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

struct test_config {
    int iterations;
    int cpu1;
    int cpu2;
    int cpu3;
    int cpu4;
    int verbose;
    bool random_cpus;
};

struct worker_args {
    int cpu;
    int prog_fd;
    struct iriw_poonceonces_onceonce_bpf *skel;
    pthread_barrier_t *barrier;  // Add barrier for synchronization
};

// Helper function to perform BPF_PROG_TEST_RUN on a specific CPU
static int run_bpf_on_cpu(int prog_fd, int cpu)
{
    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .flags = BPF_F_TEST_RUN_ON_CPU,
        .cpu = cpu,
    };
    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        fprintf(stderr, "Failed to run BPF program on CPU %d: %s\n", 
                cpu, strerror(errno));
        return err;
    }
    
    return 0;
}

// Function to get the number of available CPUs
int get_available_cpus(void) {
    cpu_set_t cpu_set;
    if (sched_getaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
        // Fallback to get_nprocs if sched_getaffinity fails
        return get_nprocs();
    }
    return CPU_COUNT(&cpu_set);
}

// Function to get all available CPU IDs
int get_available_cpu_ids(int *cpu_ids, int max_cpus) {
    cpu_set_t cpu_set;
    int count = 0;
    
    if (sched_getaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
        // Fallback to sequential CPU IDs if sched_getaffinity fails
        int num_cpus = get_nprocs();
        for (int i = 0; i < num_cpus && i < max_cpus; i++) {
            cpu_ids[i] = i;
            count++;
        }
        return count;
    }
    
    for (int i = 0; i < CPU_SETSIZE && count < max_cpus; i++) {
        if (CPU_ISSET(i, &cpu_set)) {
            cpu_ids[count++] = i;
        }
    }
    
    return count;
}

// Function to randomly select different CPUs
void select_random_cpus(int *cpus, int num_cpus) {
    int max_cpus = 1024;  // Maximum number of CPUs to consider
    int *cpu_ids = malloc(max_cpus * sizeof(int));
    if (!cpu_ids) {
        fprintf(stderr, "Failed to allocate memory for CPU IDs\n");
        return;
    }
    
    int available_cpus = get_available_cpu_ids(cpu_ids, max_cpus);
    if (available_cpus < num_cpus) {
        fprintf(stderr, "Not enough CPUs available (found %d, need %d)\n", available_cpus, num_cpus);
        free(cpu_ids);
        return;
    }
    
    // Seed the random number generator
    srand(time(NULL));
    
    // Select CPUs randomly without repetition
    int selected = 0;
    while (selected < num_cpus) {
        int idx = rand() % available_cpus;
        int cpu = cpu_ids[idx];
        
        // Check if this CPU is already selected
        bool already_selected = false;
        for (int i = 0; i < selected; i++) {
            if (cpus[i] == cpu) {
                already_selected = true;
                break;
            }
        }
        
        if (!already_selected) {
            cpus[selected++] = cpu;
        }
    }
    
    free(cpu_ids);
}

void *worker(void *arg)
{
    struct worker_args *args = (struct worker_args *)arg;
    int cpu = args->cpu;
    int prog_fd = args->prog_fd;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
        perror("sched_setaffinity");
        return NULL;
    }

    // Wait for all threads to reach this point before executing BPF program
    pthread_barrier_wait(args->barrier);
    
    // Run the BPF program on the specified CPU
    run_bpf_on_cpu(prog_fd, cpu);

    return NULL;
}

void reset_state(struct iriw_poonceonces_onceonce_bpf *skel) {
	memset(skel->bss, 0, sizeof(*skel->bss));
	memset(skel->bss->shared.x, 0, sizeof(int) * 1000);
	memset(skel->bss->shared.y, 0, sizeof(int) * 1000);
	memset(skel->bss->shared.r1, 0, sizeof(int) * 1000);
	memset(skel->bss->shared.r2, 0, sizeof(int) * 1000);
	memset(skel->bss->shared.r3, 0, sizeof(int) * 1000);
	memset(skel->bss->shared.r4, 0, sizeof(int) * 1000);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i, --iterations NUM   Number of test iterations (default: 1000000)\n");
    printf("  -c1, --cpu1 NUM       CPU ID for P0 thread (default: 0)\n");
    printf("  -c2, --cpu2 NUM       CPU ID for P1 thread (default: 1)\n");
    printf("  -c3, --cpu3 NUM       CPU ID for P2 thread (default: 2)\n");
    printf("  -c4, --cpu4 NUM       CPU ID for P3 thread (default: 3)\n");
    printf("  -d, --delay NUM        Delay factor to increase contention (default: 10000)\n");
    printf("  -r, --random-cpus      Randomly select CPUs for each iteration\n");
    printf("  -v, --verbose          Enable verbose output\n");
    printf("  -h, --help             Display this help message\n");
}

int main(int argc, char **argv)
{
	struct iriw_poonceonces_onceonce_bpf *skel;
	int err;
	struct test_config config = {
		.iterations = 1000000,
		.cpu1 = 0,
		.cpu2 = 1,
		.cpu3 = 2,
		.cpu4 = 3,
		.verbose = 0,
		.random_cpus = false
	};
	// Add counters for all possible states (16 states for 4 binary variables)
	unsigned long states[16] = {0};
	int matches = 0, non_matches = 0;
	// Thread variables
	pthread_t t0;
	pthread_t t1;
	pthread_t t2;
	pthread_t t3;
	struct timespec start_time, end_time;
	double elapsed_time;
	// Program file descriptors
	int prog1_fd;
	int prog2_fd;
	int prog3_fd;
	int prog4_fd;
	// Worker arguments
	struct worker_args args1;
	struct worker_args args2;
	struct worker_args args3;
	struct worker_args args4;
	pthread_barrier_t barrier;

	// Parse command line options
	static struct option long_options[] = {
		{"iterations", required_argument, 0, 'i'},
		{"cpu1", required_argument, 0, '1'},
		{"cpu2", required_argument, 0, '2'},
		{"cpu3", required_argument, 0, '3'},
		{"cpu4", required_argument, 0, '4'},
		{"delay", required_argument, 0, 'd'},
		{"random-cpus", no_argument, 0, 'r'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	int option_index = 0;
	char optstring[50] = "i:rvhd:1:2:3:4:";

	while ((opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {
		switch (opt) {
		case 'i':
			config.iterations = atoi(optarg);
			break;
		case '1':
			config.cpu1 = atoi(optarg);
			break;
		case '2':
			config.cpu2 = atoi(optarg);
			break;
		case '3':
			config.cpu3 = atoi(optarg);
			break;
		case '4':
			config.cpu4 = atoi(optarg);
			break;
		case 'r':
			config.random_cpus = true;
			break;
		case 'v':
			config.verbose = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = iriw_poonceonces_onceonce_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = iriw_poonceonces_onceonce_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Get program file descriptors */
	prog1_fd = bpf_program__fd(skel->progs.handle_tp1);
	prog2_fd = bpf_program__fd(skel->progs.handle_tp2);
	prog3_fd = bpf_program__fd(skel->progs.handle_tp3);
	prog4_fd = bpf_program__fd(skel->progs.handle_tp4);
	
	if (
prog1_fd < 0 || prog2_fd < 0 || prog3_fd < 0 || prog4_fd < 0
) {
		fprintf(stderr, "Failed to get program file descriptors\n");
		err = -1;
		goto cleanup;
	}

	printf("Starting litmus test with configuration:\n");
	printf("  Test: %s\n", "IRIW+poonceonces+OnceOnce");
	printf("  Iterations: %d\n", config.iterations);
	if (!config.random_cpus) {
		printf("  CPU1 (P0): %d\n", config.cpu1);
		printf("  CPU2 (P1): %d\n", config.cpu2);
		printf("  CPU3 (P2): %d\n", config.cpu3);
		printf("  CPU4 (P3): %d\n", config.cpu4);
	} else {
		printf("  Using random CPU sets for each iteration\n");
		printf("  Available CPUs: %d\n", get_available_cpus());
	}
	
	clock_gettime(CLOCK_MONOTONIC, &start_time);

	/* Initialize barrier for thread synchronization */
	if (pthread_barrier_init(&barrier, NULL, 4) != 0) {
		fprintf(stderr, "Failed to initialize barrier\n");
		err = -1;
		goto cleanup;
	}

	/* LOGIC */
	for (int i = 0; i < config.iterations; i++) {
		reset_state(skel);
		
		// Select random CPUs if enabled
		if (config.random_cpus) {
			int cpus[4];
			select_random_cpus(cpus, 4);
			config.cpu1 = cpus[0];
			config.cpu2 = cpus[1];
			config.cpu3 = cpus[2];
			config.cpu4 = cpus[3];
			if (config.verbose && i && i % 10000 == 0) {
				printf("\nUsing CPUs ");
				printf("%d ", config.cpu1);
				printf("%d ", config.cpu2);
				printf("%d ", config.cpu3);
				printf("%d ", config.cpu4);
				printf("\n");
			}
		}
		
		// Set up worker arguments
		args1.cpu = config.cpu1;
		args1.prog_fd = prog1_fd;
		args1.skel = skel;
		args1.barrier = &barrier;
		args2.cpu = config.cpu2;
		args2.prog_fd = prog2_fd;
		args2.skel = skel;
		args2.barrier = &barrier;
		args3.cpu = config.cpu3;
		args3.prog_fd = prog3_fd;
		args3.skel = skel;
		args3.barrier = &barrier;
		args4.cpu = config.cpu4;
		args4.prog_fd = prog4_fd;
		args4.skel = skel;
		args4.barrier = &barrier;

		// Create threads and run BPF programs on specific CPUs
		pthread_create(&t0, NULL, worker, &args1);
		pthread_create(&t1, NULL, worker, &args2);
		pthread_create(&t2, NULL, worker, &args3);
		pthread_create(&t3, NULL, worker, &args4);
		pthread_join(t0, NULL);
		pthread_join(t1, NULL);
		pthread_join(t2, NULL);
		pthread_join(t3, NULL);

		// Check results
		// Check results
		for (int ii=0; ii<1000; ii++) {
			// Get the values for this iteration
			int p1_r0 = skel->bss->shared.r1[ii];
			int p1_r1 = skel->bss->shared.r2[ii];
			int p3_r0 = skel->bss->shared.r3[ii];
			int p3_r1 = skel->bss->shared.r4[ii];
			
			// Calculate state index (treating the 4 variables as a 4-bit number)
			int state_idx = (p1_r0 << 3) | (p1_r1 << 2) | (p3_r0 << 1) | p3_r1;
			states[state_idx]++;
			
			// Check if this iteration matches the exists clause
			if (p1_r0 == 1 && p1_r1 == 0 && p3_r0 == 1 && p3_r1 == 0) {
				matches++;
			} else {
				non_matches++;
			}
		}
		// Print progress in verbose mode or every 100,000 iterations
		if (config.verbose && i && i % 10000 == 0) {
			printf("\rProgress: %d/%d iterations (%.1f%%) - Matches: %d (%.4f%%)", 
				i, config.iterations, (float)i/config.iterations*100,
				matches, (float)matches/(i*1000)*100);
			fflush(stdout);
		} else if (!config.verbose && i && i % 100000 == 0) {
			printf("\n[%d/%d] %.1f%% complete | ", 
				i, config.iterations, (float)i/config.iterations*100);
			
			// Show CPU configuration if using random CPUs
			if (config.random_cpus) {
				printf("CPUs: %d,%d,%d,%d | ", 
					config.cpu1, config.cpu2, config.cpu3, config.cpu4);
			}
			
			// Show match statistics
			printf("Matches: %d (%.4f%%)\n", matches, (float)matches/(i*1000)*100);
			
			// Show a visual indicator of whether matches were found
			if (matches > 0) {
				printf("  ► Weak memory behavior detected! (%d matches so far)\n", matches);
			}
		}
	}
	
	/* Destroy the barrier */
	pthread_barrier_destroy(&barrier);
	
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
		       (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

	// Get current time
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char time_str[26];
	strftime(time_str, 26, "%a %b %d %H:%M:%S %Z %Y", tm_info);

	// Print test header
	printf("Test IRIW+poonceonces+OnceOnce Allowed\n");
	
	// Count how many states have non-zero occurrences
	int active_states = 0;
	for (int i = 0; i < 16; i++) {
		if (states[i] > 0) active_states++;
	}
	
	// Print histogram header
	printf("Histogram (%d states)\n", active_states);
	
	// Print each state with its count
	const char* state_names[16] = {
		"1:r0=0; 1:r1=0; 3:r0=0; 3:r1=0;",
		"1:r0=0; 1:r1=0; 3:r0=0; 3:r1=1;",
		"1:r0=0; 1:r1=0; 3:r0=1; 3:r1=0;",
		"1:r0=0; 1:r1=0; 3:r0=1; 3:r1=1;",
		"1:r0=0; 1:r1=1; 3:r0=0; 3:r1=0;",
		"1:r0=0; 1:r1=1; 3:r0=0; 3:r1=1;",
		"1:r0=0; 1:r1=1; 3:r0=1; 3:r1=0;",
		"1:r0=0; 1:r1=1; 3:r0=1; 3:r1=1;",
		"1:r0=1; 1:r1=0; 3:r0=0; 3:r1=0;",
		"1:r0=1; 1:r1=0; 3:r0=0; 3:r1=1;",
		"1:r0=1; 1:r1=0; 3:r0=1; 3:r1=0;", // This is the one we're looking for
		"1:r0=1; 1:r1=0; 3:r0=1; 3:r1=1;",
		"1:r0=1; 1:r1=1; 3:r0=0; 3:r1=0;",
		"1:r0=1; 1:r1=1; 3:r0=0; 3:r1=1;",
		"1:r0=1; 1:r1=1; 3:r0=1; 3:r1=0;",
		"1:r0=1; 1:r1=1; 3:r0=1; 3:r1=1;"
	};
	
	for (int i = 0; i < 16; i++) {
		if (states[i] > 0) {
			// Mark the target state with an asterisk
			if (i == 10) { // 1:r0=1; 1:r1=0; 3:r0=1; 3:r1=0;
				printf("%-8lu *>%s\n", states[i], state_names[i]);
			} else {
				printf("%-8lu :>%s\n", states[i], state_names[i]);
			}
		}
	}
	
	// Print validation result
	printf("%s\n\n", matches > 0 ? "Ok" : "No");
	
	// Print witness counts
	printf("Witnesses\n");
	printf("Positive: %d, Negative: %d\n", matches, non_matches);
	printf("Condition exists (1:r0=1 /\\ 1:r1=0 /\\ 3:r0=1 /\\ 3:r1=0) is %s\n", 
		matches > 0 ? "validated" : "NOT validated");
	
	// Print observation summary
	const char* result_type = matches > 0 ? "Sometimes" : "Never";
	printf("Observation IRIW+poonceonces+OnceOnce %s %d %d\n", 
		result_type, matches, non_matches);
	printf("Time IRIW+poonceonces+OnceOnce %.2f\n\n", elapsed_time);
	
	// Print timestamp
	printf("%s\n", time_str);

cleanup:
	iriw_poonceonces_onceonce_bpf__destroy(skel);
	return -err;
}