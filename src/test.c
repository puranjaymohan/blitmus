// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Puranjay Mohan <puranjay@kernel.org> */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "test.skel.h"
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
    int verbose;
    bool random_cpus;
};

struct worker_args {
    int cpu;
    int prog_fd;
    struct test_bpf *skel;
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

// Function to randomly select two different CPUs
void select_random_cpus(int *cpu1, int *cpu2) {
    int max_cpus = 1024;  // Maximum number of CPUs to consider
    int *cpu_ids = malloc(max_cpus * sizeof(int));
    if (!cpu_ids) {
        fprintf(stderr, "Failed to allocate memory for CPU IDs\n");
        return;
    }
    
    int num_cpus = get_available_cpu_ids(cpu_ids, max_cpus);
    if (num_cpus < 2) {
        fprintf(stderr, "Not enough CPUs available (found %d)\n", num_cpus);
        free(cpu_ids);
        return;
    }
    
    // Seed the random number generator
    srand(time(NULL));
    
    // Select first CPU randomly
    int idx1 = rand() % num_cpus;
    *cpu1 = cpu_ids[idx1];
    
    // Select second CPU randomly (ensuring it's different from the first)
    int idx2;
    do {
        idx2 = rand() % num_cpus;
    } while (idx2 == idx1);
    
    *cpu2 = cpu_ids[idx2];
    
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

void reset_state(struct test_bpf *skel) {
	memset(skel->bss, 0, sizeof(*skel->bss));
	memset(skel->bss->shared.r1, 1, sizeof(int) * 1000);
	memset(skel->bss->shared.r2, 1, sizeof(int) * 1000);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i, --iterations NUM   Number of test iterations (default: 1000000)\n");
    printf("  -c, --cpu1 NUM         CPU ID for first thread (default: 0)\n");
    printf("  -C, --cpu2 NUM         CPU ID for second thread (default: 24)\n");
    printf("  -d, --delay NUM        Delay factor to increase contention (default: 10000)\n");
    printf("  -r, --random-cpus      Randomly select two CPUs for each iteration\n");
    printf("  -v, --verbose          Enable verbose output\n");
    printf("  -h, --help             Display this help message\n");
}

int main(int argc, char **argv)
{
	struct test_bpf *skel;
	int err;
	struct test_config config = {
		.iterations = 1000000,
		.cpu1 = 0,
		.cpu2 = 24,
		.verbose = 0,
		.random_cpus = false
	};
	int r1_1_r2_1 = 0, r1_1_r2_2 = 0, r1_2_r2_1 = 0, r1_2_r2_2 = 0;
	pthread_t t0, t1;
	struct timespec start_time, end_time;
	double elapsed_time;
	int prog1_fd, prog2_fd;
	struct worker_args args1, args2;
	pthread_barrier_t barrier;

	// Parse command line options
	static struct option long_options[] = {
		{"iterations", required_argument, 0, 'i'},
		{"cpu1", required_argument, 0, 'c'},
		{"cpu2", required_argument, 0, 'C'},
		{"delay", required_argument, 0, 'd'},
		{"random-cpus", no_argument, 0, 'r'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	int option_index = 0;

	while ((opt = getopt_long(argc, argv, "i:c:C:rvh", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'i':
			config.iterations = atoi(optarg);
			break;
		case 'c':
			config.cpu1 = atoi(optarg);
			break;
		case 'C':
			config.cpu2 = atoi(optarg);
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
	skel = test_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = test_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Get program file descriptors */
	prog1_fd = bpf_program__fd(skel->progs.handle_tp1);
	prog2_fd = bpf_program__fd(skel->progs.handle_tp2);
	
	if (prog1_fd < 0 || prog2_fd < 0) {
		fprintf(stderr, "Failed to get program file descriptors\n");
		err = -1;
		goto cleanup;
	}

	printf("Starting litmus test with configuration:\n");
	printf("  Iterations: %d\n", config.iterations);
	if (!config.random_cpus) {
		printf("  CPU1: %d\n", config.cpu1);
		printf("  CPU2: %d\n", config.cpu2);
	} else {
		printf("  Using random CPU pairs for each iteration\n");
		printf("  Available CPUs: %d\n", get_available_cpus());
	}
	
	clock_gettime(CLOCK_MONOTONIC, &start_time);

	/* Initialize barrier for thread synchronization */
	if (pthread_barrier_init(&barrier, NULL, 2) != 0) {
		fprintf(stderr, "Failed to initialize barrier\n");
		err = -1;
		goto cleanup;
	}

	/* LOGIC */
	for (int i = 0; i < config.iterations; i++) {
		reset_state(skel);
		
		// Select random CPUs if enabled
		if (config.random_cpus) {
			select_random_cpus(&config.cpu1, &config.cpu2);
			if (config.verbose && i && i % 10000 == 0) {
				printf("\nUsing CPUs %d and %d\n", config.cpu1, config.cpu2);
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

		// Create threads and run BPF programs on specific CPUs
		pthread_create(&t0, NULL, worker, &args1);
		pthread_create(&t1, NULL, worker, &args2);
		pthread_join(t0, NULL);
		pthread_join(t1, NULL);

		// Read state directly from global variables
		for (int ii=0; ii<1000; ii++) {
			int r1_val = skel->bss->shared.r1[ii];
			int r2_val = skel->bss->shared.r2[ii];

			// Count all possible outcomes
			if (r1_val == 0 && r2_val == 0) {
				r1_1_r2_1++;
			} else if (r1_val == 0 && r2_val == 1) {
				r1_1_r2_2++;
			} else if (r1_val == 1 && r2_val == 0) {
				r1_2_r2_1++;
			} else if (r1_val == 1 && r2_val == 1) {
				r1_2_r2_2++;
			} else {
				printf("Invalid state at: %d iteration (r1=%d, r2=%d)\n", i, r1_val, r2_val);
			}
		}
		// Print progress in verbose mode or every 100,000 iterations
		if (config.verbose && i && i % 10000 == 0) {
			printf("\rProgress: %d/%d iterations completed (%.1f%%)", 
				i, config.iterations, (float)i/config.iterations*100);
			fflush(stdout);
		} else if (!config.verbose && i && i % 100000 == 0) {
			printf("\nProgress: %d iterations completed (%.1f%%)\n", 
				i, (float)i/config.iterations*100);
			printf("Results till now:\n");
			printf("r1=0,r2=0: %d (%.2f%%)\n", r1_1_r2_1, (float)r1_1_r2_1/(i*10));
			printf("r1=0,r2=1: %d (%.2f%%)\n", r1_1_r2_2, (float)r1_1_r2_2/(i*10));
			printf("r1=1,r2=0: %d (%.2f%%)\n", r1_2_r2_1, (float)r1_2_r2_1/(i*10));
			printf("r1=1,r2=1: %d (%.2f%%)\n", r1_2_r2_2, (float)r1_2_r2_2/(i*10));
		}
	}
	
	/* Destroy the barrier */
	pthread_barrier_destroy(&barrier);
	
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	elapsed_time = (end_time.tv_sec - start_time.tv_sec) + 
		       (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

	printf("\n\nResults after %d iterations (completed in %.2f seconds):\n", 
		config.iterations, elapsed_time);
	printf("r1=0,r2=0: %d (%.2f%%)\n", r1_1_r2_1, (float)r1_1_r2_1/(config.iterations*10));
	printf("r1=0,r2=1: %d (%.2f%%)\n", r1_1_r2_2, (float)r1_1_r2_2/(config.iterations*10));
	printf("r1=1,r2=0: %d (%.2f%%)\n", r1_2_r2_1, (float)r1_2_r2_1/(config.iterations*10));
	printf("r1=1,r2=1: %d (%.2f%%)\n", r1_2_r2_2, (float)r1_2_r2_2/(config.iterations*10));

cleanup:
	test_bpf__destroy(skel);
	return -err;
}
