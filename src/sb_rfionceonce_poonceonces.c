// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Auto-generated from SB+rfionceonce+poonceonces.litmus */
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
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
#include <stdarg.h>
#include "uthash.h"

#define CONCAT(a, b) a##b
#define MAKE_FUNC(name, suffix) CONCAT(name, suffix)
#define STRUCT_NAME(name) struct CONCAT(name, _bpf)

#define BPF_OPEN(name)      MAKE_FUNC(name, _bpf__open)
#define BPF_LOAD(name)      MAKE_FUNC(name, _bpf__load)
#define BPF_DESTROY(name)   MAKE_FUNC(name, _bpf__destroy)

/*****/

#include "sb_rfionceonce_poonceonces.skel.h"
#define THREADS 2
#define TEST_NAME sb_rfionceonce_poonceonces
#define TEST_NAME_PRINT "SB+rfionceonce+poonceonces"
#define EXISTS_CLAUSE "0:r2=0 /\\ 1:r4=0"
#define INTERNAL_ITERATIONS 10000
#define NUM_KEYS 2

struct record {
        long long key[NUM_KEYS];
        unsigned long long count;
        bool target;
        UT_hash_handle hh;
};

const char *cond_vars_str[2] = {"0:r2", "1:r4"};

struct record *records = NULL;

bool expected = true;

void update_record(long long *key_values, bool target);

static void check_cond (STRUCT_NAME(TEST_NAME) *skel, unsigned long long *matches,
                        unsigned long long *non_matches, int c) {

	unsigned long long P0_r2 = skel->bss->shared.P0_r2[c];
	unsigned long long P1_r4 = skel->bss->shared.P1_r4[c];

        bool target = false;
        long long key_values[NUM_KEYS] = {0};


	key_values[0] = skel->bss->shared.P0_r2[c];
	key_values[1] = skel->bss->shared.P1_r4[c];

        // Check if this iteration matches the exists clause
        if (((P0_r2 == 0) && (P1_r4 == 0))) {
                *matches += 1;
                target = true;
        } else {
                *non_matches += 1;
        }
        update_record(key_values, target);
}

/*****/
void print_histogram() {
	struct record *r, *tmp;
	unsigned long long total = 0, num_states = 0;

	HASH_ITER(hh, records, r, tmp) {
        	total += r->count;
        	num_states++;
	}

	printf("Histogram (%llu states)\n", num_states);

	HASH_ITER(hh, records, r, tmp) {
        	printf("%-8llu %c>", r->count, r->target ? '*' : ':');
        	for (int i = 0; i < NUM_KEYS; i++) {
            		printf("%s=%lld; ", cond_vars_str[i], r->key[i]);
        	}
       		printf("\n");
    	}
}

void update_record(long long *key_values, bool target) {
        struct record *r = NULL;

        HASH_FIND(hh, records, key_values, sizeof(long long) * NUM_KEYS, r);
        if (!r) {
                r = malloc(sizeof(struct record));
                memcpy(r->key, key_values, sizeof(long long) * NUM_KEYS);
                r->count = 0;
                r->target = false;
                HASH_ADD(hh, records, key, sizeof(long long) * NUM_KEYS, r);
        }
        r->count += 1;
        r->target = target;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        if (level == LIBBPF_DEBUG)
                return 0;
        return vfprintf(stderr, format, args);
}

struct test_config {
        int iterations;
        int *cpus;
	bool aff;
        int verbose;
};

struct worker_args {
        int cpu;
        int prog_fd;
	bool aff;
        pthread_barrier_t *barrier;
};

static int run_bpf_on_cpu(int prog_fd, int cpu, bool aff)
{
        struct bpf_test_run_opts opts = {
                .sz = sizeof(struct bpf_test_run_opts),
        };

	if (aff) {
		opts.flags = BPF_F_TEST_RUN_ON_CPU;
		opts.cpu = cpu;
	}

        int err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err) {
                fprintf(stderr, "Failed to run BPF program on CPU %d: %s\n",
                        cpu, strerror(errno));
                return err;
        }

        return 0;
}

void *worker(void *arg)
{
        struct worker_args *args = (struct worker_args *)arg;
        int cpu = args->cpu;
        int prog_fd = args->prog_fd;
	bool aff = args->aff;

	if (aff) {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(cpu, &cpuset);

		if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
			perror("sched_setaffinity");
			return NULL;
		}
	}

        pthread_barrier_wait(args->barrier);

        // Run the BPF program on the specified CPU
        run_bpf_on_cpu(prog_fd, cpu, aff);

        return NULL;
}

void reset_state(STRUCT_NAME(TEST_NAME) *skel) {
        memset(skel->bss, 0, sizeof(*skel->bss));
}

void print_usage(const char *prog_name) {
        printf("Usage: %s [OPTIONS]\n", prog_name);
        printf("Options:\n");
        printf("  -i, --iterations NUM   Number of test iterations (default: 4100)\n");
        printf("  -v, --verbose          Enable verbose output\n");
        printf("  -a, --affinity         Pin threads to randomly selected cpus\n");
        printf("  -h, --help             Display this help message\n");
}

void select_random_cpus(int *cpus) {
        cpu_set_t available;
        int total_cpus = 0;
        int threads = THREADS;
        int *available_cpus;
        int i;

        CPU_ZERO(&available);
        if (sched_getaffinity(0, sizeof(available), &available) != 0) {
                perror("sched_getaffinity");
                exit(1);
        }

        /* Count available CPUs */
        for (i = 0; i < CPU_SETSIZE; i++) {
                if (CPU_ISSET(i, &available))
                        total_cpus++;
        }

        if (threads > total_cpus) {
                fprintf(stderr, "Not enough CPUs available (requested %d, available %d)\n", threads, total_cpus);
                exit(1);
        }

        /* Build list of available CPUs */
        available_cpus = malloc(sizeof(int) * total_cpus);
        if (!available_cpus) {
                perror("malloc");
                exit(1);
        }

        int idx = 0;
        for (i = 0; i < CPU_SETSIZE; i++) {
                if (CPU_ISSET(i, &available))
                        available_cpus[idx++] = i;
        }

        /* Shuffle using Fisher-Yates algorithm */
        srand(time(NULL));
        for (i = total_cpus - 1; i > 0; i--) {
                int j = rand() % (i + 1);
                int tmp = available_cpus[i];
                available_cpus[i] = available_cpus[j];
                available_cpus[j] = tmp;
        }

        /* Select first THREADS entries */
        for (i = 0; i < threads; i++) {
                cpus[i] = available_cpus[i];
        }

        free(available_cpus);
}

int main(int argc, char **argv)
{
        STRUCT_NAME(TEST_NAME) *skel;
        struct bpf_program *prog;
        int i = 0;
        int err;
        struct test_config config = {
                .iterations = 4100,
                .verbose = 0,
		.aff = 0
        };

        unsigned long long  matches = 0, non_matches = 0;

        pthread_t t[THREADS];

        struct timespec start_time, end_time;
        double elapsed_time;

        int prog_fds[THREADS];

        struct worker_args args[THREADS];

        pthread_barrier_t barrier;

        static struct option long_options[] = {
                {"iterations", required_argument, 0, 'i'},
                {"verbose", no_argument, 0, 'v'},
                {"affinity", no_argument, 0, 'a'},
                {"help", no_argument, 0, 'h'},
                {0, 0, 0, 0}
        };

        int opt;
        int option_index = 0;
        char optstring[50] = "i:vha";

        while ((opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {
                switch (opt) {
                case 'i':
                        config.iterations = atoi(optarg);
                        break;
                case 'v':
                        config.verbose = 1;
                        break;
		case 'a':
			config.aff = 1;
			break;
                case 'h':
                        print_usage(argv[0]);
                        return 0;
                default:
                        print_usage(argv[0]);
                        return 1;
                }
        }

	if (config.aff) {
		config.cpus = malloc(sizeof(int) * THREADS);
		select_random_cpus(config.cpus);
	}

        /* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);

        /* Open BPF application */
        skel = BPF_OPEN(TEST_NAME)();
        if (!skel) {
                fprintf(stderr, "Failed to open BPF skeleton\n");
                return 1;
        }

        /* Load & verify BPF programs */
        err = BPF_LOAD(TEST_NAME)(skel);
        if (err) {
                fprintf(stderr, "Failed to load and verify BPF skeleton\n");
                goto cleanup;
        }

        /* Get program file descriptors */
        bpf_object__for_each_program(prog, *skel->skeleton->obj) {
                prog_fds[i++] = bpf_program__fd(prog);
                if (prog_fds[i-1] < 0) {
                        fprintf(stderr, "Failed to get program file descriptors\n");
                        err = -1;
                        goto cleanup;
                }

        }

        printf("Starting litmus test with configuration:\n");
        printf("  Test: %s\n", TEST_NAME_PRINT);
        printf("  Iterations: %d\n", config.iterations);

        clock_gettime(CLOCK_MONOTONIC, &start_time);

        /* Initialize barrier for thread synchronization */
        if (pthread_barrier_init(&barrier, NULL, THREADS) != 0) {
                fprintf(stderr, "Failed to initialize barrier\n");
                err = -1;
                goto cleanup;
        }

        /* LOGIC */
        for (i = 0; i < config.iterations; i++) {
                reset_state(skel);

		if (config.aff)
			select_random_cpus(config.cpus);
                for (int thread = 0; thread < THREADS; thread++) {
			if (config.aff)
				args[thread].cpu = config.cpus[thread];
			args[thread].aff = config.aff;
                        args[thread].prog_fd = prog_fds[thread];
                        args[thread].barrier = &barrier;

                        pthread_create(&t[thread], NULL, worker, &args[thread]);
                }

                for (int thread = 0; thread < THREADS; thread++)
                        pthread_join(t[thread], NULL);

                // Check results
                for (int c = 0; c < INTERNAL_ITERATIONS; c++) {
                        // Get the values for this iteration
                        check_cond(skel, &matches, &non_matches, c);
                }

                if (config.verbose && i && i % (config.iterations / 10) == 0) {
                        printf("\rProgress: %d/%d iterations (%.1f%%) - Matches: %llu (%.4f%%)",
                                i, config.iterations, (float)i/config.iterations*100,
                                matches, ((float)matches/(i*INTERNAL_ITERATIONS))*100);
                        fflush(stdout);
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
        char time_str[25] = {0};
        strftime(time_str, 25, "%a %b %d %H:%M:%S %Z %Y", tm_info);

        // Print test header
        printf("\nTest %s Allowed\n", TEST_NAME_PRINT);

	print_histogram();

        // Print validation result
        printf("%s\n\n", matches > 0 ? "Ok" : "No");

        // Print witness counts
        printf("Witnesses\n");
        printf("Positive: %llu, Negative: %llu\n", matches, non_matches);
        printf("Condition exists (%s) is %s\n", EXISTS_CLAUSE,
                matches > 0 ? "validated" : "NOT validated");

        // Print observation summary
        const char* result_type = matches > 0 ? (matches ==
	(config.iterations * INTERNAL_ITERATIONS) ? "Always" : "Sometimes") : "Never";

        printf("Observation %s %s %llu %llu\n", TEST_NAME_PRINT,
                result_type, matches, non_matches);
        printf("Time %s %.2f\n\n", TEST_NAME_PRINT,elapsed_time);

        // Print timestamp
        printf("%s\n", time_str);

	err = !!matches && !expected;

cleanup:
        BPF_DESTROY(TEST_NAME)(skel);
        return err;
}

