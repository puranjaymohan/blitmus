# blitmus

A tool for converting litmus tests to BPF programs that can run memory consistency tests on real hardware.

## Overview

blitmus converts litmus tests (written in the standard litmus test format) into BPF programs that execute the same memory ordering patterns on actual hardware. This allows testing of weak memory model behavior using BPF's ability to run programs on specific CPUs.

The tool consists of:
- `litmus2bpf.py`: Python script that parses litmus test files and generates BPF programs
- Template files for generating userspace and BPF code
- Example litmus tests in the `litmus_tests/` directory

## Runner Script

```bash

sudo ./run.sh
System Information:
  CPU Architecture : aarch64
  Kernel Version   : 6.16.0-rc2+

Running tests...

  Running iriw_poonceonces_onceonce... ✓
  Running r_poonceonces... ✓
  Running sb_poonceonces... ✓
  Running sb_fencembonceonces... ✓
  Running mp_pooncerelease_poacquireonce... ✓
  Running mp_poonceonces... ✓
  Running dep_plain... ✓
  Running wrc_poonceonces_once... ✓
  Running wrc_pooncerelease_fencermbonceonce_once... ✓
  Running isa2_pooncerelease_poacquirerelease_poacquireonce... ✓
  Running isa2_poonceonces... ✓
  Running lb_poonceonces... ✓
  Running lb_fencembonceonce_ctrlonceonce... ✓
  Running lb_poacquireonce_pooncerelease... ✓
  Running corr_poonceonce_once... ✓
  Running corw_poonceonce_once... ✓
  Running cowr_poonceonce_once... ✓
  Running coww_poonceonce... ✓
  Running iriw_fencembonceonces_onceonce... ✓
  Running r_fencembonceonces... ✓
  Running s_fencewmbonceonce_poacquireonce... ✗ (exit code: 1)
  Running s_poonceonces... ✓
  Running z6_0_pooncerelease_poacquirerelease_fencembonceonce... ✓
  Running sb_rfionceonce_poonceonces... ✓

╔══════════════════════════════════════════════════════════════════════════════════════╗
║                             BPF Litmus Test Batch Runner                             ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
╔═══════════════════════════════════════╤══════════╤════════════╤════════════╤═════════╗
║ Test Name                             │ Result   │ Positive   │ Negative   │ Pos %   ║
╠═══════════════════════════════════════╪══════════╪════════════╪════════════╪═════════╣
║ IRIW+poonceonces+OnceOnce             │ ✓ OK     │         90 │   40999910 │   0.00% ║
║ R+poonceonces                         │ ✓ OK     │   25164300 │   15835700 │  61.38% ║
║ SB+poonceonces                        │ ✓ OK     │   33179289 │    7820711 │  80.93% ║
║ SB+fencembonceonces                   │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ MP+pooncerelease+poacquireonce        │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ MP+poonceonces                        │ ✓ OK     │    1097757 │   39902243 │   2.68% ║
║ dep+plain                             │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ WRC+poonceonces+Once                  │ ✓ OK     │         55 │   40999945 │   0.00% ║
║ WRC+pooncerelease+fencermbonceonc     │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ ISA2+pooncerelease+poacquirerelea     │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ ISA2+poonceonces                      │ ✓ OK     │      45266 │   40954734 │   0.11% ║
║ LB+poonceonces                        │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ LB+fencembonceonce+ctrlonceonce       │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ LB+poacquireonce+pooncerelease        │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ CoRR+poonceonce+Once                  │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ CoRW+poonceonce+Once                  │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ CoWR+poonceonce+Once                  │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ CoWW+poonceonce                       │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ IRIW+fencembonceonces+OnceOnce        │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ R+fencembonceonces                    │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ S+fencewmbonceonce+poacquireonce      │ ✗ FAILED │      13631 │   40986369 │   0.03% ║
║ S+poonceonces                         │ ✓ OK     │      19961 │   40980039 │   0.05% ║
║ Z6_0+pooncerelease+poacquirerelea     │ ✓ OK     │          0 │   41000000 │   0.00% ║
║ SB+rfionceonce+poonceonces            │ ✓ OK     │    1792533 │   39207467 │   4.37% ║
╚═══════════════════════════════════════╧══════════╧════════════╧════════════╧═════════╝

Summary:
  Total Tests: 24
  ✓ Passed:   23
  ✗ Failed:   1
  ⚠ Missing:  0

⚠ Some tests failed. Check individual logs in the logs/ directory for details.

```

## Litmus Test Format

Litmus tests describe concurrent memory access patterns to test memory consistency models. They typically include:
- Multiple processes (P0, P1, etc.) running on different CPUs
- Memory operations (reads/writes) with various ordering constraints
- An "exists" clause specifying outcomes that test weak memory behavior
- A comment inside (* *) with Result: Sometimes/Never/Always

Example litmus test (`SB+poonceonces.litmus`):
```
C SB+poonceonces

(*
 * Result: Sometimes
 *
 * This litmus test demonstrates that at least some ordering is required
 * to order the store-buffering pattern, where each process writes to the
 * variable that the preceding process reads.
 *)

P0(int *x, int *y)
{
    WRITE_ONCE(*x, 1);
    r0 = READ_ONCE(*y);
}

P1(int *x, int *y)
{
    WRITE_ONCE(*y, 1);
    r0 = READ_ONCE(*x);
}

exists (0:r0=0 /\ 1:r0=0)
```

## Usage

### Converting Litmus Tests

Convert a litmus test to BPF program:
```bash
./litmus2bpf.py litmus_tests/SB+poonceonces.litmus
```

This generates:
- `src/sb_poonceonces.bpf.c` - BPF program implementing the test
- `src/sb_poonceonces.c` - Userspace program to load and run the BPF program

### Building and Running

Build all generated programs:
```bash
make
```

Run a specific test:
```bash
./sb_poonceonces [options]
```

### Command Line Options

Generated test programs support these options:
- `-i, --iterations NUM`: Number of test iterations (default: 4100) [The code in the litmus test is executed NUM * 10000 times]
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Display help message

### Return code
If the comment in the Litmus Test says "Result: Never" and the condition in the exists clause is validated in any of the iterations then 1 is returned otherwise 0 is returned. So, a return code of 1 means invalid behaviour.

### Example

Running on Aarch64

```bash
$ sudo ./sb_poonceonces -i 2100
Starting litmus test with configuration:
    Test: SB+poonceonces
    Iterations: 2100
Test SB+poonceonces Allowed
Histogram (4 states)
18682053 *>0:r0=0; 1:r0=0;
1625972  :>0:r0=0; 1:r0=1;
691972   :>0:r0=1; 1:r0=0;
3        :>0:r0=1; 1:r0=1;
Ok

Witnesses
Positive: 18682053, Negative: 2317947
Condition exists (0:r0=0 /\ 1:r0=0) is validated
Observation SB+poonceonces Sometimes 18682053 2317947
Time SB+poonceonces 3.98

Mon Jun 23 20:06:24 UTC
```

Running on x86-64

```bash

$ sudo ./sb_poonceonces -i 2100
Starting litmus test with configuration:
  Test: SB+poonceonces
  Iterations: 2100
  CPU0 (P0): 0
  CPU1 (P1): 1
Test SB+poonceonces Allowed
Histogram (4 states)
41726    *>0:r0=0; 1:r0=0;
1266433  :>0:r0=0; 1:r0=1;
779337   :>0:r0=1; 1:r0=0;
12504    :>0:r0=1; 1:r0=1;
Ok

Witnesses
Positive: 41726, Negative: 2058274
Condition exists (0:r0=0 /\ 1:r0=0) is validated
Observation SB+poonceonces Sometimes 41726 2058274
Time SB+poonceonces 0.63

Tue Jun 24 11:27:13 UTC
```

## Example Litmus Tests

The `litmus_tests/` directory contains various memory ordering patterns:

- **Store Buffering (SB)**:
- **Message Passing (MP)**:
- **Load Buffering (LB)**:
- **Independent Reads of Independent Writes (IRIW)**:
- **Write-Read Causality (WRC)**:

## Implementation Details

The generated BPF programs use:
- `BPF_PROG_TEST_RUN` with `BPF_F_TEST_RUN_ON_CPU` to run on specific CPUs
- Shared memory maps for variables and synchronization
- pthread barriers for thread synchronization in userspace
- Statistical analysis of outcomes to detect weak memory behavior

## Building

Requirements:
- Linux kernel with BPF support [Tested with upstream]
- clang/LLVM [Tested with clang trunk]
- libbpf
- Python 3

Build dependencies are included as git submodules:
```bash
git submodule update --init --recursive
make
```

## TODO
- [ ] Improve the litmus2bpf.py to act as a full lexer -> parser
- [ ] Add more litmus tests to check BPF specific patters
- [ ] Add a script to auto-execute all tests and generate a report.
- [ ] Improve the overall userspace and bpf code templates

## License

Dual BSD/GPL
