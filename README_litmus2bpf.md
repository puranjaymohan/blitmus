# litmus2bpf - Litmus Test to BPF Converter

This tool converts litmus tests to BPF programs that can run on real hardware to detect weak memory model behavior.

## Overview

The `litmus2bpf.py` tool takes a litmus test file as input and generates:

1. A BPF program (`.bpf.c`) in the src/ directory that implements the litmus test
2. A user-space program (`.c`) in the src/ directory that loads and runs the BPF program on specific CPUs
3. Updates the main Makefile to add the test name to the APPS variable

## Usage

```
./litmus2bpf.py [OPTIONS] LITMUS_FILE
```

### Options

- `-v, --verbose`: Enable verbose output
- `-n, --name NAME`: Override test name for output files

### Example

```
./litmus2bpf.py -v /path/to/litmus/test.litmus
```

## How It Works

The tool performs the following steps:

1. Parses the litmus test file to extract:
   - Test name
   - Process definitions
   - Variables
   - Operations (READ_ONCE, WRITE_ONCE)
   - Exists clause (conditions to check)

2. Generates a BPF program that:
   - Defines shared variables in a struct
   - Creates a BPF program for each process in the litmus test
   - Implements the operations using shared memory
   - Uses barrier synchronization to coordinate execution

3. Generates a user-space program that:
   - Loads and runs the BPF programs on specific CPUs
   - Provides command-line options for configuration
   - Checks the results based on the exists clause
   - Reports statistics on weak memory behavior

4. Updates the main Makefile to include the new test in the APPS variable

## Building and Running

After generating the code:

```
cd /local/home/pjy/code/blitmus
make test_name
./test_name [OPTIONS]
```

### Runtime Options

- `-i, --iterations NUM`: Number of test iterations (default: 1000000)
- `-1, --cpu1 NUM`: CPU ID for first thread (default: 0)
- `-2, --cpu2 NUM`: CPU ID for second thread (default: 1)
- ... (and so on for each process)
- `-r, --random-cpus`: Randomly select CPUs for each iteration
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Display help message

## Result Format

The tool generates output in a format similar to the Linux kernel memory model tools:

```
Test TEST_NAME Allowed
Histogram (N states)
COUNT  :>1:r0=0; 1:r1=0; 3:r0=0; 3:r1=0;
COUNT  :>1:r0=0; 1:r1=0; 3:r0=0; 3:r1=1;
...
COUNT *>1:r0=1; 1:r1=0; 3:r0=1; 3:r1=0;  # Target state marked with *
...
Ok/No  # Whether the condition was validated

Witnesses
Positive: X, Negative: Y
Condition exists (1:r0=1 /\ 1:r1=0 /\ 3:r0=1 /\ 3:r1=0) is [NOT] validated
Observation TEST_NAME Sometimes/Never X Y
Time TEST_NAME N.NN

TIMESTAMP
```

## Limitations

- Currently supports only READ_ONCE and WRITE_ONCE operations
- Limited to simple memory access patterns
- Does not support complex control flow or loops in litmus tests

## Example

Converting the IRIW+poonceonces+OnceOnce.litmus test:

```
./litmus2bpf.py -v /path/to/IRIW+poonceonces+OnceOnce.litmus
```

This will generate:
- src/iriw_poonceonces_onceonce.bpf.c
- src/iriw_poonceonces_onceonce.c
- Update the Makefile to include iriw_poonceonces_onceonce in APPS

Then build and run:

```
make iriw_poonceonces_onceonce
./iriw_poonceonces_onceonce -i 1000000 -r -v
```
