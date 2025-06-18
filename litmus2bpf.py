#!/usr/bin/env python3
"""
Litmus Test to BPF Converter

This tool converts litmus tests to BPF programs that can run on real hardware
to detect weak memory model behavior.
"""

import os
import re
import sys
import argparse
from typing import Dict, List, Tuple, Set, Optional

class LitmusParser:
    """Parser for litmus test files"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.test_name = ""
        self.processes = []
        self.variables = set()
        self.registers = {}
        self.exists_clause = ""
        self.comments = []
        
    def parse(self) -> bool:
        """Parse the litmus test file"""
        try:
            with open(self.filename, 'r') as f:
                content = f.read()
                
            # Extract test name
            name_match = re.search(r'^C\s+(\S+)', content, re.MULTILINE)
            if name_match:
                self.test_name = name_match.group(1)
            
            # Extract comments
            comment_blocks = re.findall(r'\(\*.*?\*\)', content, re.DOTALL)
            for block in comment_blocks:
                self.comments.append(block.strip('(*').strip('*)').strip())
            
            # Extract processes
            process_blocks = re.findall(r'P\d+\s*\([^)]*\)\s*\{[^}]*\}', content, re.DOTALL)
            
            for block in process_blocks:
                process = {}
                
                # Extract process ID and parameters
                header_match = re.search(r'P(\d+)\s*\(([^)]*)\)', block)
                if header_match:
                    process['id'] = int(header_match.group(1))
                    params = header_match.group(2).strip()
                    process['params'] = [p.strip() for p in params.split(',')]
                    
                    # Extract variable names from parameters
                    for param in process['params']:
                        if '*' in param:
                            var_name = param.split('*')[1].strip()
                            self.variables.add(var_name)
                
                # Extract body
                body_match = re.search(r'\{([^}]*)\}', block, re.DOTALL)
                if body_match:
                    body = body_match.group(1).strip()
                    process['body'] = [line.strip() for line in body.split(';') if line.strip()]
                    
                    # Extract register declarations
                    reg_decls = [line for line in process['body'] if re.match(r'^\s*int\s+r\d+\s*$', line)]
                    process['registers'] = [re.search(r'int\s+(r\d+)', decl).group(1) for decl in reg_decls]
                    
                    # Extract operations (excluding register declarations)
                    process['operations'] = [line for line in process['body'] if not re.match(r'^\s*int\s+r\d+\s*$', line)]
                    
                    # Track registers for this process
                    self.registers[process['id']] = process['registers']
                
                self.processes.append(process)
            
            # Sort processes by ID
            self.processes.sort(key=lambda p: p['id'])
            
            # Extract exists clause
            exists_match = re.search(r'exists\s+\(([^)]*)\)', content)
            if exists_match:
                self.exists_clause = exists_match.group(1).strip()
                
            # Parse the exists clause to extract conditions
            self.parse_exists_clause()
            
            return True
            
        except Exception as e:
            print(f"Error parsing litmus test: {e}")
            return False
    
    def parse_exists_clause(self):
        """Parse the exists clause to extract conditions"""
        self.conditions = []
        if not self.exists_clause:
            return
            
        # Split by logical AND
        parts = re.split(r'\s*/\\\s*', self.exists_clause)
        for part in parts:
            # Extract process ID, register, and expected value
            match = re.search(r'(\d+):(\w+)=(\d+)', part)
            if match:
                proc_id = int(match.group(1))
                reg = match.group(2)
                value = int(match.group(3))
                self.conditions.append((proc_id, reg, value))

    def get_summary(self) -> str:
        """Return a summary of the parsed litmus test"""
        summary = []
        summary.append(f"Test Name: {self.test_name}")
        summary.append(f"Variables: {', '.join(sorted(self.variables))}")
        summary.append(f"Processes: {len(self.processes)}")
        
        for proc in self.processes:
            summary.append(f"  P{proc['id']}({', '.join(proc['params'])}):")
            for op in proc['operations']:
                summary.append(f"    {op}")
        
        if self.exists_clause:
            summary.append(f"Exists Clause: {self.exists_clause}")
            summary.append("Conditions:")
            for proc_id, reg, value in self.conditions:
                summary.append(f"  P{proc_id}:{reg}={value}")
        
        return "\n".join(summary)

class BPFGenerator:
    """Generator for BPF code from parsed litmus test"""
    
    def __init__(self, parser: LitmusParser):
        self.parser = parser
        self.max_processes = 8  # Maximum number of processes supported
        
    def generate_bpf_c(self) -> str:
        """Generate BPF C code"""
        if len(self.parser.processes) > self.max_processes:
            print(f"Warning: Only supporting up to {self.max_processes} processes, but test has {len(self.parser.processes)}")
        
        code = []
        code.append("// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause")
        code.append(f"/* Auto-generated from {os.path.basename(self.parser.filename)} */")
        code.append("#include <linux/bpf.h>")
        code.append("#include <bpf/bpf_helpers.h>")
        code.append("")
        code.append("char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";")
        code.append("")
        
        # Add comments from the original litmus test
        if self.parser.comments:
            code.append("/*")
            for comment in self.parser.comments:
                for line in comment.split('\n'):
                    code.append(f" * {line.strip()}")
            code.append(" */")
            code.append("")
        
        # Add shared variables
        code.append("// Place shared variables in the same cache line to increase contention")
        code.append("struct {")
        for var in sorted(self.parser.variables):
            code.append(f"    volatile int {var}[1000];")
        
        # Add registers for each process
        for proc_id, regs in self.parser.registers.items():
            for reg in regs:
                code.append(f"    volatile int P{proc_id}_{reg}[1000];")
        
        code.append("} shared;")
        code.append("")
        
        # Add synchronization flag
        code.append("volatile __u64 flag[1000] = {0};")
        code.append("")
        
        # Add helper macros
        code.append("#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))")
        code.append("")
        code.append("#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = (val))")
        code.append("")
        code.append("#define smp_mb() \\")
        code.append("\t({ \\")
        code.append(" \t\tvolatile __u64 __val = 1; \\")
        code.append("\t\t__val = __sync_fetch_and_add(&__val, 10); \\")
        code.append("\t})")
        code.append("")
        
        # Add barrier wait function
        code.append("int barrier_wait(unsigned int id, unsigned int i)")
        code.append("{")
        code.append(" if (i >= 1000)")
        code.append("\t return 0;")
        code.append(" if ((i % 2) == id) {")
        code.append("    WRITE_ONCE(flag[i], 1);")
        code.append("    smp_mb();")
        code.append("  } else {")
        code.append("    #pragma unroll")
        code.append("    for (int ii=0; ii<256; ii++) {")
        code.append("      if (READ_ONCE(flag[i]) != 0) return 0;")
        code.append("    }")
        code.append("  }")
        code.append("")
        code.append(" return 0;")
        code.append("}")
        code.append("")
        
        # Generate BPF programs for each process
        for proc in self.parser.processes[:self.max_processes]:
            proc_id = proc['id']
            code.append(f"// Program for P{proc_id}")
            code.append(f"SEC(\"raw_tp/test_prog{proc_id + 1}\")")
            code.append(f"int handle_tp{proc_id + 1}(void *ctx)")
            code.append("{")
            code.append("\tsmp_mb();")
            code.append("\tfor (int i=0; i<1000; i++) {")
            code.append(f"\t\tbarrier_wait({proc_id}, i);")
            
            # Convert operations
            for op in proc['operations']:
                bpf_op = self._convert_operation(op, proc_id)
                code.append(f"\t\t{bpf_op}")
            
            code.append("\t}")
            code.append("\tsmp_mb();")
            code.append("\treturn 0;")
            code.append("}")
            code.append("")
        
        return "\n".join(code)
    
    def _convert_operation(self, op: str, proc_id: int) -> str:
        """Convert a litmus test operation to BPF code"""
        # Handle WRITE_ONCE
        write_match = re.search(r'WRITE_ONCE\(\*(\w+),\s*(\d+)\)', op)
        if write_match:
            var = write_match.group(1)
            val = write_match.group(2)
            return f"shared.{var}[i] = {val};"
        
        # Handle READ_ONCE
        read_match = re.search(r'(\w+)\s*=\s*READ_ONCE\(\*(\w+)\)', op)
        if read_match:
            reg = read_match.group(1)
            var = read_match.group(2)
            return f"shared.P{proc_id}_{reg}[i] = shared.{var}[i];"
        
        # Default case - pass through (with a warning comment)
        return f"/* Unsupported operation: {op} */";
    def generate_user_c(self) -> str:
        """Generate user-space C code"""
        num_processes = len(self.parser.processes)
        
        code = []
        code.append("// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)")
        code.append(f"/* Auto-generated from {os.path.basename(self.parser.filename)} */")
        code.append("#define _GNU_SOURCE")
        code.append("#include <sched.h>")
        code.append("#include <stdio.h>")
        code.append("#include <unistd.h>")
        code.append("#include <sys/resource.h>")
        code.append("#include <bpf/libbpf.h>")
        code.append("#include \"test.skel.h\"")
        code.append("#include <stdlib.h>")
        code.append("#include <errno.h>")
        code.append("#include <unistd.h>")
        code.append("#include <pthread.h>")
        code.append("#include <sys/types.h>")
        code.append("#include <sys/time.h>")
        code.append("#include <bpf/bpf.h>")
        code.append("#include <getopt.h>")
        code.append("#include <time.h>")
        code.append("#include <linux/bpf.h>")
        code.append("#include <sys/syscall.h>")
        code.append("#include <string.h>")
        code.append("#include <stdbool.h>")
        code.append("#include <sys/sysinfo.h>")
        code.append("")
        
        # Add libbpf print function
        code.append("static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)")
        code.append("{")
        code.append("\tif (level == LIBBPF_DEBUG)")
        code.append("\t\treturn 0;")
        code.append("\treturn vfprintf(stderr, format, args);")
        code.append("}")
        code.append("")
        
        # Add test configuration struct
        code.append("struct test_config {")
        code.append("    int iterations;")
        for i in range(num_processes):
            code.append(f"    int cpu{i+1};")
        code.append("    int verbose;")
        code.append("    bool random_cpus;")
        code.append("};")
        code.append("")
        
        # Add worker arguments struct
        code.append("struct worker_args {")
        code.append("    int cpu;")
        code.append("    int prog_fd;")
        code.append("    struct test_bpf *skel;")
        code.append("    pthread_barrier_t *barrier;  // Add barrier for synchronization")
        code.append("};")
        code.append("")
        
        # Add helper functions
        code.append("// Helper function to perform BPF_PROG_TEST_RUN on a specific CPU")
        code.append("static int run_bpf_on_cpu(int prog_fd, int cpu)")
        code.append("{")
        code.append("    struct bpf_test_run_opts opts = {")
        code.append("        .sz = sizeof(struct bpf_test_run_opts),")
        code.append("        .flags = BPF_F_TEST_RUN_ON_CPU,")
        code.append("        .cpu = cpu,")
        code.append("    };")
        code.append("    ")
        code.append("    int err = bpf_prog_test_run_opts(prog_fd, &opts);")
        code.append("    if (err) {")
        code.append("        fprintf(stderr, \"Failed to run BPF program on CPU %d: %s\\n\", ")
        code.append("                cpu, strerror(errno));")
        code.append("        return err;")
        code.append("    }")
        code.append("    ")
        code.append("    return 0;")
        code.append("}")
        code.append("")
        
        # Add CPU selection functions
        code.append("// Function to get the number of available CPUs")
        code.append("int get_available_cpus(void) {")
        code.append("    cpu_set_t cpu_set;")
        code.append("    if (sched_getaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {")
        code.append("        // Fallback to get_nprocs if sched_getaffinity fails")
        code.append("        return get_nprocs();")
        code.append("    }")
        code.append("    return CPU_COUNT(&cpu_set);")
        code.append("}")
        code.append("")
        
        code.append("// Function to get all available CPU IDs")
        code.append("int get_available_cpu_ids(int *cpu_ids, int max_cpus) {")
        code.append("    cpu_set_t cpu_set;")
        code.append("    int count = 0;")
        code.append("    ")
        code.append("    if (sched_getaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {")
        code.append("        // Fallback to sequential CPU IDs if sched_getaffinity fails")
        code.append("        int num_cpus = get_nprocs();")
        code.append("        for (int i = 0; i < num_cpus && i < max_cpus; i++) {")
        code.append("            cpu_ids[i] = i;")
        code.append("            count++;")
        code.append("        }")
        code.append("        return count;")
        code.append("    }")
        code.append("    ")
        code.append("    for (int i = 0; i < CPU_SETSIZE && count < max_cpus; i++) {")
        code.append("        if (CPU_ISSET(i, &cpu_set)) {")
        code.append("            cpu_ids[count++] = i;")
        code.append("        }")
        code.append("    }")
        code.append("    ")
        code.append("    return count;")
        code.append("}")
        code.append("")
        
        # Add random CPU selection function
        code.append("// Function to randomly select different CPUs")
        code.append(f"void select_random_cpus(int *cpus, int num_cpus) {{")
        code.append("    int max_cpus = 1024;  // Maximum number of CPUs to consider")
        code.append("    int *cpu_ids = malloc(max_cpus * sizeof(int));")
        code.append("    if (!cpu_ids) {")
        code.append("        fprintf(stderr, \"Failed to allocate memory for CPU IDs\\n\");")
        code.append("        return;")
        code.append("    }")
        code.append("    ")
        code.append("    int available_cpus = get_available_cpu_ids(cpu_ids, max_cpus);")
        code.append("    if (available_cpus < num_cpus) {")
        code.append("        fprintf(stderr, \"Not enough CPUs available (found %d, need %d)\\n\", available_cpus, num_cpus);")
        code.append("        free(cpu_ids);")
        code.append("        return;")
        code.append("    }")
        code.append("    ")
        code.append("    // Seed the random number generator")
        code.append("    srand(time(NULL));")
        code.append("    ")
        code.append("    // Select CPUs randomly without repetition")
        code.append("    int selected = 0;")
        code.append("    while (selected < num_cpus) {")
        code.append("        int idx = rand() % available_cpus;")
        code.append("        int cpu = cpu_ids[idx];")
        code.append("        ")
        code.append("        // Check if this CPU is already selected")
        code.append("        bool already_selected = false;")
        code.append("        for (int i = 0; i < selected; i++) {")
        code.append("            if (cpus[i] == cpu) {")
        code.append("                already_selected = true;")
        code.append("                break;")
        code.append("            }")
        code.append("        }")
        code.append("        ")
        code.append("        if (!already_selected) {")
        code.append("            cpus[selected++] = cpu;")
        code.append("        }")
        code.append("    }")
        code.append("    ")
        code.append("    free(cpu_ids);")
        code.append("}")
        code.append("")
        
        # Add worker function
        code.append("void *worker(void *arg)")
        code.append("{")
        code.append("    struct worker_args *args = (struct worker_args *)arg;")
        code.append("    int cpu = args->cpu;")
        code.append("    int prog_fd = args->prog_fd;")
        code.append("")
        code.append("    cpu_set_t cpuset;")
        code.append("    CPU_ZERO(&cpuset);")
        code.append("    CPU_SET(cpu, &cpuset);")
        code.append("")
        code.append("    if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {")
        code.append("        perror(\"sched_setaffinity\");")
        code.append("        return NULL;")
        code.append("    }")
        code.append("")
        code.append("    // Wait for all threads to reach this point before executing BPF program")
        code.append("    pthread_barrier_wait(args->barrier);")
        code.append("    ")
        code.append("    // Run the BPF program on the specified CPU")
        code.append("    run_bpf_on_cpu(prog_fd, cpu);")
        code.append("")
        code.append("    return NULL;")
        code.append("}")
        code.append("")
        
        # Add reset state function
        code.append("void reset_state(struct test_bpf *skel) {")
        code.append("\tmemset(skel->bss, 0, sizeof(*skel->bss));")
        
        # Initialize all variables to 0
        for var in sorted(self.parser.variables):
            code.append(f"\tmemset(skel->bss->shared.{var}, 0, sizeof(int) * 1000);")
        
        # Initialize all registers to 0
        for proc_id, regs in self.parser.registers.items():
            for reg in regs:
                code.append(f"\tmemset(skel->bss->shared.P{proc_id}_{reg}, 0, sizeof(int) * 1000);")
        
        code.append("}")
        code.append("")
        
        # Add print usage function
        code.append("void print_usage(const char *prog_name) {")
        code.append("    printf(\"Usage: %s [OPTIONS]\\n\", prog_name);")
        code.append("    printf(\"Options:\\n\");")
        code.append("    printf(\"  -i, --iterations NUM   Number of test iterations (default: 1000000)\\n\");")
        
        for i in range(num_processes):
            code.append(f"    printf(\"  -c{i+1}, --cpu{i+1} NUM       CPU ID for P{i} thread (default: {i})\\n\");")
        
        code.append("    printf(\"  -d, --delay NUM        Delay factor to increase contention (default: 10000)\\n\");")
        code.append("    printf(\"  -r, --random-cpus      Randomly select CPUs for each iteration\\n\");")
        code.append("    printf(\"  -v, --verbose          Enable verbose output\\n\");")
        code.append("    printf(\"  -h, --help             Display this help message\\n\");")
        code.append("}")
        code.append("")
        
        # Add main function
        code.append("int main(int argc, char **argv)")
        code.append("{")
        code.append("\tstruct test_bpf *skel;")
        code.append("\tint err;")
        code.append("\tstruct test_config config = {")
        code.append("\t\t.iterations = 1000000,")
        
        # Set default CPU values
        for i in range(num_processes):
            code.append(f"\t\t.cpu{i+1} = {i},")
        
        code.append("\t\t.verbose = 0,")
        code.append("\t\t.random_cpus = false")
        code.append("\t};")
        
        # Add result counters based on the exists clause
        if self.parser.conditions:
            # Create a counter for each possible outcome
            code.append("\t// Result counters")
            code.append("\tint matches = 0, non_matches = 0;")
        
        # Add thread variables
        code.append("\t// Thread variables")
        for i in range(num_processes):
            code.append(f"\tpthread_t t{i};")
        
        code.append("\tstruct timespec start_time, end_time;")
        code.append("\tdouble elapsed_time;")
        
        # Add program file descriptors
        code.append("\t// Program file descriptors")
        for i in range(num_processes):
            code.append(f"\tint prog{i+1}_fd;")
        
        # Add worker args
        code.append("\t// Worker arguments")
        for i in range(num_processes):
            code.append(f"\tstruct worker_args args{i+1};")
        
        code.append("\tpthread_barrier_t barrier;")
        code.append("")
        
        # Add command line option parsing
        code.append("\t// Parse command line options")
        code.append("\tstatic struct option long_options[] = {")
        code.append("\t\t{\"iterations\", required_argument, 0, 'i'},")
        
        # Add CPU options
        for i in range(num_processes):
            code.append(f"\t\t{{\"cpu{i+1}\", required_argument, 0, 'c{i+1}'}},")
        
        code.append("\t\t{\"delay\", required_argument, 0, 'd'},")
        code.append("\t\t{\"random-cpus\", no_argument, 0, 'r'},")
        code.append("\t\t{\"verbose\", no_argument, 0, 'v'},")
        code.append("\t\t{\"help\", no_argument, 0, 'h'},")
        code.append("\t\t{0, 0, 0, 0}")
        code.append("\t};")
        code.append("")
        
        # Add option parsing loop
        code.append("\tint opt;")
        code.append("\tint option_index = 0;")
        code.append("\tchar optstring[50] = \"i:rvh\";")
        
        # Add CPU options to optstring
        for i in range(num_processes):
            code.append(f"\tstrcat(optstring, \"c{i+1}:\");")
        
        code.append("")
        code.append("\twhile ((opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1) {")
        code.append("\t\tswitch (opt) {")
        code.append("\t\tcase 'i':")
        code.append("\t\t\tconfig.iterations = atoi(optarg);")
        code.append("\t\t\tbreak;")
        
        # Add CPU option cases
        for i in range(num_processes):
            code.append(f"\t\tcase 'c{i+1}':")
            code.append(f"\t\t\tconfig.cpu{i+1} = atoi(optarg);")
            code.append("\t\t\tbreak;")
        
        code.append("\t\tcase 'r':")
        code.append("\t\t\tconfig.random_cpus = true;")
        code.append("\t\t\tbreak;")
        code.append("\t\tcase 'v':")
        code.append("\t\t\tconfig.verbose = 1;")
        code.append("\t\t\tbreak;")
        code.append("\t\tcase 'h':")
        code.append("\t\t\tprint_usage(argv[0]);")
        code.append("\t\t\treturn 0;")
        code.append("\t\tdefault:")
        code.append("\t\t\tprint_usage(argv[0]);")
        code.append("\t\t\treturn 1;")
        code.append("\t\t}")
        code.append("\t}")
        code.append("")
        
        # Add libbpf setup
        code.append("\t/* Set up libbpf errors and debug info callback */")
        code.append("\tlibbpf_set_print(libbpf_print_fn);")
        code.append("")
        code.append("\t/* Open BPF application */")
        code.append("\tskel = test_bpf__open();")
        code.append("\tif (!skel) {")
        code.append("\t\tfprintf(stderr, \"Failed to open BPF skeleton\\n\");")
        code.append("\t\treturn 1;")
        code.append("\t}")
        code.append("")
        code.append("\t/* Load & verify BPF programs */")
        code.append("\terr = test_bpf__load(skel);")
        code.append("\tif (err) {")
        code.append("\t\tfprintf(stderr, \"Failed to load and verify BPF skeleton\\n\");")
        code.append("\t\tgoto cleanup;")
        code.append("\t}")
        code.append("")
        
        # Get program file descriptors
        code.append("\t/* Get program file descriptors */")
        for i in range(num_processes):
            code.append(f"\tprog{i+1}_fd = bpf_program__fd(skel->progs.handle_tp{i+1});")
        
        # Check program file descriptors
        code.append("\t")
        code.append("\tif (")
        fd_checks = []
        for i in range(num_processes):
            fd_checks.append(f"prog{i+1}_fd < 0")
        code.append(" || ".join(fd_checks))
        code.append(") {")
        code.append("\t\tfprintf(stderr, \"Failed to get program file descriptors\\n\");")
        code.append("\t\terr = -1;")
        code.append("\t\tgoto cleanup;")
        code.append("\t}")
        code.append("")
        
        # Print configuration
        code.append("\tprintf(\"Starting litmus test with configuration:\\n\");")
        code.append("\tprintf(\"  Test: %s\\n\", \"" + self.parser.test_name + "\");")
        code.append("\tprintf(\"  Iterations: %d\\n\", config.iterations);")
        code.append("\tif (!config.random_cpus) {")
        for i in range(num_processes):
            code.append(f"\t\tprintf(\"  CPU{i+1} (P{i}): %d\\n\", config.cpu{i+1});")
        code.append("\t} else {")
        code.append("\t\tprintf(\"  Using random CPU sets for each iteration\\n\");")
        code.append("\t\tprintf(\"  Available CPUs: %d\\n\", get_available_cpus());")
        code.append("\t}")
        code.append("\t")
        
        # Start timing
        code.append("\tclock_gettime(CLOCK_MONOTONIC, &start_time);")
        code.append("")
        
        # Initialize barrier
        code.append("\t/* Initialize barrier for thread synchronization */")
        code.append(f"\tif (pthread_barrier_init(&barrier, NULL, {num_processes}) != 0) {{")
        code.append("\t\tfprintf(stderr, \"Failed to initialize barrier\\n\");")
        code.append("\t\terr = -1;")
        code.append("\t\tgoto cleanup;")
        code.append("\t}")
        code.append("")
        
        # Main test loop
        code.append("\t/* LOGIC */")
        code.append("\tfor (int i = 0; i < config.iterations; i++) {")
        code.append("\t\treset_state(skel);")
        code.append("\t\t")
        
        # Select random CPUs if enabled
        code.append("\t\t// Select random CPUs if enabled")
        code.append("\t\tif (config.random_cpus) {")
        code.append(f"\t\t\tint cpus[{num_processes}];")
        code.append(f"\t\t\tselect_random_cpus(cpus, {num_processes});")
        for i in range(num_processes):
            code.append(f"\t\t\tconfig.cpu{i+1} = cpus[{i}];")
        code.append("\t\t\tif (config.verbose && i && i % 10000 == 0) {")
        code.append("\t\t\t\tprintf(\"\\nUsing CPUs \");")
        for i in range(num_processes):
            code.append(f"\t\t\t\tprintf(\"%d \", config.cpu{i+1});")
        code.append("\t\t\t\tprintf(\"\\n\");")
        code.append("\t\t\t}")
        code.append("\t\t}")
        code.append("\t\t")
        
        # Set up worker arguments
        code.append("\t\t// Set up worker arguments")
        for i in range(num_processes):
            code.append(f"\t\targs{i+1}.cpu = config.cpu{i+1};")
            code.append(f"\t\targs{i+1}.prog_fd = prog{i+1}_fd;")
            code.append(f"\t\targs{i+1}.skel = skel;")
            code.append(f"\t\targs{i+1}.barrier = &barrier;")
        code.append("")
        
        # Create threads and run BPF programs
        code.append("\t\t// Create threads and run BPF programs on specific CPUs")
        for i in range(num_processes):
            code.append(f"\t\tpthread_create(&t{i}, NULL, worker, &args{i+1});")
        
        # Join threads
        for i in range(num_processes):
            code.append(f"\t\tpthread_join(t{i}, NULL);")
        code.append("")
        
        # Check results
        code.append("\t\t// Check results")
        code.append("\t\tfor (int ii=0; ii<1000; ii++) {")
        
        # Generate result checking code based on exists clause
        if self.parser.conditions:
            # Check if the conditions match
            code.append("\t\t\tbool match = true;")
            for proc_id, reg, value in self.parser.conditions:
                code.append(f"\t\t\tif (skel->bss->shared.P{proc_id}_{reg}[ii] != {value}) {{")
                code.append("\t\t\t\tmatch = false;")
                code.append("\t\t\t\tbreak;")
                code.append("\t\t\t}")
            code.append("\t\t\tif (match) {")
            code.append("\t\t\t\tmatches++;")
            code.append("\t\t\t} else {")
            code.append("\t\t\t\tnon_matches++;")
            code.append("\t\t\t}")
        
        code.append("\t\t}")
        
        # Print progress
        code.append("\t\t// Print progress in verbose mode or every 100,000 iterations")
        code.append("\t\tif (config.verbose && i && i % 10000 == 0) {")
        code.append("\t\t\tprintf(\"\\rProgress: %d/%d iterations completed (%.1f%%)\", ")
        code.append("\t\t\t\ti, config.iterations, (float)i/config.iterations*100);")
        code.append("\t\t\tfflush(stdout);")
        code.append("\t\t} else if (!config.verbose && i && i % 100000 == 0) {")
        code.append("\t\t\tprintf(\"\\nProgress: %d iterations completed (%.1f%%)\\n\", ")
        code.append("\t\t\t\ti, (float)i/config.iterations*100);")
        
        # Print intermediate results
        if self.parser.conditions:
            code.append("\t\t\tprintf(\"Results till now:\\n\");")
            code.append("\t\t\tprintf(\"Matches (");
            conditions = []
            for proc_id, reg, value in self.parser.conditions:
                conditions.append(f"{proc_id}:{reg}={value}")
            code.append(" /\\ ".join(conditions))
            code.append("): %d (%.2f%%)\\n\", matches, (float)matches/(i*1000)*100);")
            code.append("\t\t\tprintf(\"Non-matches: %d (%.2f%%)\\n\", non_matches, (float)non_matches/(i*1000)*100);")
        
        code.append("\t\t}")
        code.append("\t}")
        code.append("\t")
        
        # Destroy barrier
        code.append("\t/* Destroy the barrier */")
        code.append("\tpthread_barrier_destroy(&barrier);")
        code.append("\t")
        
        # Print final results
        code.append("\tclock_gettime(CLOCK_MONOTONIC, &end_time);")
        code.append("\telapsed_time = (end_time.tv_sec - start_time.tv_sec) + ")
        code.append("\t\t       (end_time.tv_nsec - start_time.tv_nsec) / 1e9;")
        code.append("")
        code.append("\tprintf(\"\\n\\nResults after %d iterations (completed in %.2f seconds):\\n\", ")
        code.append("\t\tconfig.iterations, elapsed_time);")
        
        if self.parser.conditions:
            code.append("\tprintf(\"Exists clause: (");
            code.append(" /\\ ".join(conditions))
            code.append(")\\n\");")
            code.append("\tprintf(\"Matches: %d (%.2f%%)\\n\", matches, (float)matches/(config.iterations*1000)*100);")
            code.append("\tprintf(\"Non-matches: %d (%.2f%%)\\n\", non_matches, (float)non_matches/(config.iterations*1000)*100);")
            code.append("\tprintf(\"Weak memory behavior %s\\n\", matches > 0 ? \"observed\" : \"not observed\");")
        
        # Cleanup and return
        code.append("")
        code.append("cleanup:")
        code.append("\ttest_bpf__destroy(skel);")
        code.append("\treturn -err;")
        code.append("}")
        
        return "\n".join(code)

def main():
    parser = argparse.ArgumentParser(description='Convert litmus tests to BPF programs')
    parser.add_argument('litmus_file', help='Path to the litmus test file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-n', '--name', help='Override test name for output files')
    
    args = parser.parse_args()
    
    # Parse the litmus test
    litmus_parser = LitmusParser(args.litmus_file)
    if not litmus_parser.parse():
        sys.exit(1)
    
    if args.verbose:
        print(litmus_parser.get_summary())
    
    # Generate BPF code
    generator = BPFGenerator(litmus_parser)
    bpf_code = generator.generate_bpf_c()
    
    # Ensure src directory exists
    src_dir = os.path.join('/local/home/pjy/code/blitmus', 'src')
    os.makedirs(src_dir, exist_ok=True)
    
    # Determine output file name
    test_name = args.name if args.name else litmus_parser.test_name.lower().replace('+', '_')
    
    # Write BPF code to file in src directory
    bpf_file = os.path.join(src_dir, f"{test_name}.bpf.c")
    with open(bpf_file, 'w') as f:
        f.write(bpf_code)
    
    print(f"Generated BPF code: {bpf_file}")
    
    # Generate user-space code
    user_code = generator.generate_user_c()
    user_file = os.path.join(src_dir, f"{test_name}.c")
    with open(user_file, 'w') as f:
        f.write(user_code)
    
    print(f"Generated user-space code: {user_file}")
    
    # Update the main Makefile to add the test name to APPS
    makefile_path = os.path.join('/local/home/pjy/code/blitmus', "Makefile")
    if os.path.exists(makefile_path):
        with open(makefile_path, 'r') as f:
            makefile_content = f.read()
        
        # Find the APPS line and update it
        if 'APPS =' in makefile_content:
            # Check if the test is already in APPS
            apps_line_pattern = r'APPS\s*=\s*(.*?)(?:\n|$)'
            apps_match = re.search(apps_line_pattern, makefile_content)
            if apps_match:
                apps_line = apps_match.group(0)
                apps_value = apps_match.group(1).strip()
                
                # Add the new test if it's not already there
                if test_name not in apps_value.split():
                    new_apps_line = f"APPS = {apps_value} {test_name}\n"
                    makefile_content = makefile_content.replace(apps_line, new_apps_line)
                    
                    with open(makefile_path, 'w') as f:
                        f.write(makefile_content)
                    
                    print(f"Updated Makefile: Added {test_name} to APPS")
                else:
                    print(f"Test {test_name} already in Makefile APPS")
        else:
            print("Warning: Could not find APPS line in Makefile")
    else:
        print("Warning: Makefile not found in the main directory")
    
    print(f"\nTo build the test:")
    print(f"  cd /local/home/pjy/code/blitmus")
    print(f"  make {test_name}")
    print(f"\nTo run the test:")
    print(f"  ./{test_name} [OPTIONS]")

if __name__ == "__main__":
    main()
    def generate_result_reporting(self, test_name, exists_clause):
        """Generate code for result reporting in the format requested"""
        # Count the number of registers used in the exists clause
        reg_count = 0
        for proc in self.parser.processes:
            reg_count += len(proc.get('registers', []))
        
        # Generate state names based on the registers
        state_names = []
        for i in range(2**reg_count):
            state_name = []
            bit_pos = reg_count - 1
            
            for proc_id, regs in self.parser.registers.items():
                for reg in regs:
                    val = (i >> bit_pos) & 1
                    state_name.append(f"{proc_id}:{reg}={val}")
                    bit_pos -= 1
            
            state_names.append("; ".join(state_name) + ";")
        
        # Find the target state index based on the exists clause
        target_state_idx = 0
        bit_pos = reg_count - 1
        for proc_id, reg, value in self.parser.conditions:
            if value == 1:
                target_state_idx |= (1 << bit_pos)
            bit_pos -= 1
        
        # Generate the exists clause string
        exists_parts = []
        for proc_id, reg, value in self.parser.conditions:
            exists_parts.append(f"{proc_id}:{reg}={value}")
        exists_str = " /\\ ".join(exists_parts)
        
        code = []
        code.append(f"""
	// Add counters for all possible states ({2**reg_count} states for {reg_count} binary variables)
	unsigned long states[{2**reg_count}] = {{0}};
	int matches = 0, non_matches = 0;
        """)
        
        # Generate result checking code
        code.append("""
		// Check results
		for (int ii=0; ii<1000; ii++) {
			// Get the values for this iteration""")
        
        # Generate code to get register values
        reg_idx = 1
        for proc_id, regs in self.parser.registers.items():
            for reg in regs:
                code.append(f"\t\t\tint p{proc_id}_{reg} = skel->bss->shared.r{reg_idx}[ii];")
                reg_idx += 1
        
        # Generate state index calculation
        code.append("\n\t\t\t// Calculate state index")
        code.append("\t\t\tint state_idx = 0;")
        bit_pos = reg_count - 1
        reg_idx = 1
        for proc_id, regs in self.parser.registers.items():
            for reg in regs:
                code.append(f"\t\t\tif (p{proc_id}_{reg}) state_idx |= (1 << {bit_pos});")
                bit_pos -= 1
                reg_idx += 1
        
        code.append("\t\t\tstates[state_idx]++;")
        
        # Generate condition check
        code.append("\n\t\t\t// Check if this iteration matches the exists clause")
        code.append("\t\t\tif (")
        conditions = []
        reg_idx = 1
        for proc_id, reg, value in self.parser.conditions:
            conditions.append(f"p{proc_id}_{reg} == {value}")
        code.append(" && ".join(conditions))
        code.append(") {")
        code.append("\t\t\t\tmatches++;")
        code.append("\t\t\t} else {")
        code.append("\t\t\t\tnon_matches++;")
        code.append("\t\t\t}")
        code.append("\t\t}")
        
        # Generate progress reporting
        code.append("""
		// Print progress in verbose mode or every 100,000 iterations
		if (config.verbose && i && i % 10000 == 0) {
			printf("\\rProgress: %d/%d iterations (%.1f%%) - Matches: %d (%.4f%%)", 
				i, config.iterations, (float)i/config.iterations*100,
				matches, (float)matches/(i*1000)*100);
			fflush(stdout);
		} else if (!config.verbose && i && i % 100000 == 0) {
			printf("\\n[%d/%d] %.1f%% complete | ", 
				i, config.iterations, (float)i/config.iterations*100);
			
			// Show CPU configuration if using random CPUs
			if (config.random_cpus) {
				printf("CPUs: ");
				for (int cpu_idx = 0; cpu_idx < %d; cpu_idx++) {
					printf("%%d", config.cpu[cpu_idx]);
					if (cpu_idx < %d - 1) printf(",");
				}
				printf(" | ");
			}
			
			// Show match statistics
			printf("Matches: %d (%.4f%%)", matches, (float)matches/(i*1000)*100);
			
			// Show a visual indicator of whether matches were found
			if (matches > 0) {
				printf("\\n  ► Weak memory behavior detected! (%d matches so far)", matches);
			}
			printf("\\n");
		}""" % (len(self.parser.processes), len(self.parser.processes)))
        
        # Generate final results output
        code.append(f"""
	// Get current time
	time_t now = time(NULL);
	struct tm *tm_info = localtime(&now);
	char time_str[26];
	strftime(time_str, 26, "%a %b %d %H:%M:%S %Z %Y", tm_info);

	// Print test header
	printf("Test {test_name} Allowed\\n");
	
	// Count how many states have non-zero occurrences
	int active_states = 0;
	for (int i = 0; i < {2**reg_count}; i++) {{
		if (states[i] > 0) active_states++;
	}}
	
	// Print histogram header
	printf("Histogram (%d states)\\n", active_states);
	
	// Print each state with its count
	const char* state_names[{2**reg_count}] = {{""")
        
        # Add state names
        for i, name in enumerate(state_names):
            if i < len(state_names) - 1:
                code.append(f'\t\t"{name}",')
            else:
                code.append(f'\t\t"{name}"')
        
        code.append("\t};")
        
        code.append(f"""
	for (int i = 0; i < {2**reg_count}; i++) {{
		if (states[i] > 0) {{
			// Mark the target state with an asterisk
			if (i == {target_state_idx}) {{
				printf("%-8lu *>%s\\n", states[i], state_names[i]);
			}} else {{
				printf("%-8lu :>%s\\n", states[i], state_names[i]);
			}}
		}}
	}}
	
	// Print validation result
	printf("%s\\n\\n", matches > 0 ? "Ok" : "No");
	
	// Print witness counts
	printf("Witnesses\\n");
	printf("Positive: %d, Negative: %d\\n", matches, non_matches);
	printf("Condition exists ({exists_str}) is %s\\n", 
		matches > 0 ? "validated" : "NOT validated");
	
	// Print observation summary
	const char* result_type = matches > 0 ? "Sometimes" : "Never";
	printf("Observation {test_name} %s %d %d\\n", 
		result_type, matches, non_matches);
	printf("Time {test_name} %.2f\\n\\n", elapsed_time);
	
	// Print timestamp
	printf("%s\\n", time_str);""")
        
        return "\n".join(code)
