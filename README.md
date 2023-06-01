# bpflitmus

A tool similar to klitmus that will convert BPF litmus tests to bpf
programs that will run the litmus test on real hardware.

## Overview

This tool implements a classic "store buffering" litmus test using BPF to detect weak memory model behavior on real hardware. The test creates two threads that run on different CPUs and perform memory operations in a specific order to test memory consistency.

The implementation uses BPF_PROG_TEST_RUN with the BPF_F_TEST_RUN_ON_CPU flag to ensure that BPF programs run on specific CPUs, providing more accurate testing of memory ordering behavior.

## Test Pattern

The test implements the following pattern:

Thread 1:
```
x = 2;
r1 = y;
```

Thread 2:
```
y = 2;
r2 = x;
```

In a sequentially consistent memory model, the outcome r1=1,r2=1 should be impossible. However, on hardware with relaxed memory ordering, this outcome can be observed.

## Usage

```
./test [OPTIONS]
```

### Options

- `-i, --iterations NUM`: Number of test iterations (default: 1000000)
- `-c, --cpu1 NUM`: CPU ID for first thread (default: 0)
- `-C, --cpu2 NUM`: CPU ID for second thread (default: 24)
- `-d, --delay NUM`: Delay factor to increase contention (default: 10000)
- `-r, --random-cpus`: Randomly select two CPUs for each iteration
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Display help message

### Example

```
./test -i 500000 -d 20000 -r -v
```

This runs the test with 500,000 iterations, with a delay factor of 20,000, using random CPU pairs for each iteration, and verbose output.

## Interpreting Results

The program will output the frequency of each possible outcome:

- r1=1,r2=1: Both threads see the old values (weak memory model behavior)
- r1=1,r2=2: Thread 1 sees old value, Thread 2 sees new value
- r1=2,r2=1: Thread 1 sees new value, Thread 2 sees old value
- r1=2,r2=2: Both threads see the new values

## Implementation Details

This implementation uses the BPF_PROG_TEST_RUN syscall with the BPF_F_TEST_RUN_ON_CPU flag to run BPF programs on specific CPUs. This approach provides more direct control over which CPU runs the BPF program compared to using tracepoints triggered by syscalls.

The test uses an initial delay controlled by the delay_factor parameter to create contention by ensuring both threads are likely to execute their critical sections at nearly the same time.

Thread synchronization is achieved using pthread barriers to ensure both threads start executing their BPF programs simultaneously, maximizing the chance of observing memory ordering effects.

When the random-cpus option is enabled, the program automatically detects available CPUs and randomly selects two different CPUs for each iteration, which helps in testing memory ordering behavior across different CPU pairs.

## Building

Build using the standard libbpf build process:

```
make
```

## License

Dual BSD/GPL
