#!/usr/bin/env python3
"""
Litmus Test to BPF Converter

This tool converts litmus tests to BPF programs that can run on real hardware
"""

import os
import re
import sys
import argparse

# Independent litmus instances per BPF program invocation ("slots").  One
# userspace round runs the litmus code NR_SLOTS times for a fast statistical
# sample.  Keep in sync with BLITMUS_SLOTS in template/bpf_header.
NR_SLOTS = 10000
# arena-recycle uses few slots per round (keeps the two processes aligned) and
# many more rounds; both are -D-overridable at build time.
RECYCLE_SLOTS = 128
# Default number of rounds (each runs the litmus code NR_SLOTS times).
DEFAULT_ITERATIONS = 4100
RECYCLE_ITERATIONS = 40000
# Histogram dimension per observed value.  Litmus outcomes are small integers
# (0/1/2); indices are clamped to this so an unexpected value can never index
# the states[] array out of bounds.  Kept small so many-condition tests stay
# cheap (states is HIST_DIM ** nr_conditions entries).
HIST_DIM = 8


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
        self.result_type = ""
        self.conditions = []           # [(proc_id, reg, value)]
        self.variable_conditions = []  # [(var, value)]
        self.array_sizes = {}          # {var: size} for variables used as v[expr]
        self.recycle_vars = []         # vars marked "blitmus: arena-recycle <var>"

    def parse(self) -> bool:
        """Parse the litmus test file"""
        try:
            with open(self.filename, 'r') as f:
                content = f.read()

            # Structural parsing (processes, exists) runs on a copy with C++
            # line comments removed, so a "// comment" between the parameter
            # list and the process body doesn't defeat the block regexes.
            # Name/Result/(* *) extraction still uses the raw content.
            code_content = re.sub(r'//[^\n]*', '', content)

            # Extract test name
            name_match = re.search(r'^C\s+(\S+)', content, re.MULTILINE)
            if name_match:
                self.test_name = name_match.group(1)

            # Extract comments and look for Result field
            comment_blocks = re.findall(r'\(\*.*?\*\)', content, re.DOTALL)
            for block in comment_blocks:
                comment_text = block.strip('(*').strip('*)').strip()
                self.comments.append(comment_text)

                # Look for Result: field in comments (case-sensitive)
                result_match = re.search(r'Result:\s*(\w+)', comment_text)
                if result_match:
                    self.result_type = result_match.group(1)

            process_blocks = re.findall(r'P\d+\s*\([^)]*\)\s*\{[^}]*\}', code_content, re.DOTALL)
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
                    process['body'] = [line.strip() for line in body.splitlines() if line.strip()]

                    # Extract register declarations
                    reg_decls = [line for line in process['body'] if re.match(r'^\s*int\s+r\d+\s*;$', line)]
                    process['registers'] = [re.search(r'int\s+(r\d+)', decl).group(1) for decl in reg_decls]

                    # Extract operations (excluding register declarations)
                    process['operations'] = [line for line in
                                             process['body'] if not
                                             re.match(r'^\s*int\s+r\d+\s*;$', line)]

                    # Track registers for this process
                    self.registers[process['id']] = process['registers']

                self.processes.append(process)

            # Sort processes by ID
            self.processes.sort(key=lambda p: p['id'])

            # Detect array variables (used as v[expr], e.g. a data-dependent
            # index for an address-dependency test).  Size = next power of two
            # above the largest literal index (>= 2).
            all_ops = ' '.join(op for proc in self.processes
                               for op in proc.get('operations', []))
            for v in self.variables:
                if not re.search(rf'\b{re.escape(v)}\s*\[', all_ops):
                    continue
                lits = re.findall(rf'\b{re.escape(v)}\s*\[\s*(\d+)\s*\]', all_ops)
                max_lit = max((int(x) for x in lits), default=1)
                size = 2
                while size <= max_lit:
                    size *= 2
                self.array_sizes[v] = size

            # "blitmus: arena-recycle <var>": <var> is recycled (see the backend).
            for c in self.comments:
                for m in re.finditer(r'blitmus:\s*arena-recycle\s+(\w+)', c):
                    if m.group(1) in self.variables and m.group(1) not in self.recycle_vars:
                        self.recycle_vars.append(m.group(1))

            # Extract exists clause
            exists_match = re.search(r'exists\s+\(([^)]*)\)', code_content)
            if exists_match:
                self.exists_clause = exists_match.group(1).strip()

            # Parse the exists clause to extract conditions
            self.parse_exists_clause()

            return True

        except OSError as e:
            print(f"blitmus: cannot read {self.filename}: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"blitmus: failed to parse {self.filename}: {e}", file=sys.stderr)
            return False

    def parse_exists_clause(self):
        """Parse the exists clause to extract conditions"""
        self.conditions = []
        self.variable_conditions = []  # For direct variable conditions like y=2
        if not self.exists_clause:
            return

        # Split by logical AND
        parts = re.split(r'\s*/\\\s*', self.exists_clause)
        for part in parts:
            part = part.strip()

            # Try to match process:register=value pattern
            proc_reg_match = re.search(r'(\d+):(\w+)=(\d+)', part)
            if proc_reg_match:
                proc_id = int(proc_reg_match.group(1))
                reg = proc_reg_match.group(2)
                value = int(proc_reg_match.group(3))
                self.conditions.append((proc_id, reg, value))
                continue

            # Try to match direct variable=value pattern
            var_match = re.search(r'(\w+)=(\d+)', part)
            if var_match:
                var = var_match.group(1)
                value = int(var_match.group(2))
                self.variable_conditions.append((var, value))
                continue

            print(f"Warning: Could not parse exists clause part: {part}")

    # Ordering primitives the BPF backend/template can actually lower.  BPF has
    # no instruction for a standalone read/write barrier, so smp_wmb()/smp_rmb()
    # (and RMW/RCU/lock primitives) are intentionally absent.
    SUPPORTED_CALLS = {
        'READ_ONCE', 'WRITE_ONCE',
        'smp_mb', 'smp_load_acquire', 'smp_store_release',
        'xchg', 'cmpxchg', 'atomic_fetch_add', 'atomic_add',
    }
    _CONTROL_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof'}

    def unsupported_primitives(self):
        """Return the primitives used by the test that the BPF backend cannot
        express (empty set means the test is fully supported)."""
        used = set()
        for proc in self.processes:
            for op in proc.get('operations', []):
                used.update(re.findall(r'\b([A-Za-z_]\w*)\s*\(', op))
        return used - self.SUPPORTED_CALLS - self._CONTROL_KEYWORDS

    def get_summary(self) -> str:
        """Return a summary of the parsed litmus test"""
        summary = []
        summary.append(f"Test Name: {self.test_name}")
        if self.result_type:
            summary.append(f"Result Type: {self.result_type}")
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
            for var, value in self.variable_conditions:
                summary.append(f"  {var}={value}")

        return "\n".join(summary)

class BPFGenerator:
    """Generator for BPF code from parsed litmus test"""

    def __init__(self, parser: LitmusParser, bpf_header_filename: str, user_header_filename: str, user_footer_filename: str):
        self.parser = parser
        self.max_processes = 8  # Maximum number of processes supported
        self.bpf_header_file = bpf_header_filename
        self.user_header_file = user_header_filename
        self.user_footer_file = user_footer_filename

    def _observed_regs(self):
        """Return the (proc_id, reg) pairs observed by the exists clause.

        These are klitmus's "finals": the only registers whose value has to
        leave the thread, so they are the only ones spilled to shared memory.
        """
        seen = []
        for proc_id, reg, _ in self.parser.conditions:
            if (proc_id, reg) not in seen:
                seen.append((proc_id, reg))
        return sorted(seen)

    def _process_registers(self, proc):
        """All register names a process needs as C locals.

        Includes registers that are explicitly declared (int rN;), any rN
        referenced by the body, and any observed by the exists clause, so we
        never leave a register undeclared regardless of how the test spells it.
        """
        regs = set(proc.get('registers', []))
        for op in proc.get('operations', []):
            regs.update(re.findall(r'\br\d+\b', op))
        for proc_id, reg, _ in self.parser.conditions:
            if proc_id == proc['id']:
                regs.add(reg)
        return sorted(regs, key=lambda r: int(r[1:]))

    def _rewrite_operation(self, op: str, backend: str = 'bss') -> str:
        """Retarget references to shared variables at this iteration's slot.

        The litmus body is otherwise emitted verbatim (klitmus keeps the C
        code untouched).  A shared variable v appears either dereferenced
        (*v, the object itself) or bare (v, its address, as passed to
        smp_store_release/smp_load_acquire); registers and everything else are
        left exactly as written so dependencies are carried in registers.

        backend selects where the shared memory lives:
          'bss'   -> shared.v[i]   (a per-slot array inside the bss struct)
          'arena' -> v[i]          (a per-slot arena global)
        """
        if not self.parser.variables:
            return op

        prefix = 'shared.' if backend == 'bss' else ''
        arrays = self.parser.array_sizes

        # Array variables first: v[expr] -> <prefix>v[i][(expr) & mask].  The
        # mask keeps a data-dependent index in bounds for the verifier while
        # preserving the dependency (the address still depends on expr).
        for v, size in arrays.items():
            op = re.sub(rf'\b{re.escape(v)}\s*\[\s*(.*?)\s*\]',
                        lambda m, v=v, size=size: f'{prefix}{v}[i][({m.group(1)}) & {size - 1}]',
                        op)

        # Scalar variables: "*v" -> <prefix>v[i]; a bare "v" -> its address.
        # A single left-to-right pass so emitted text is never rescanned.
        scalars = [v for v in self.parser.variables if v not in arrays]
        if scalars:
            var_alt = '|'.join(re.escape(v) for v in
                               sorted(scalars, key=len, reverse=True))
            pattern = re.compile(r'\*\s*(' + var_alt + r')\b|\b(' + var_alt + r')\b')

            def repl(m):
                if m.group(1) is not None:
                    return f'{prefix}{m.group(1)}[i]'
                return f'&{prefix}{m.group(2)}[i]'

            op = pattern.sub(repl, op)

        return op

    # Emitted before the shared-variable globals for the arena backend: the
    # arena map plus address-space-aware release/acquire.
    _ARENA_PREAMBLE = """\
struct {
\t__uint(type, BPF_MAP_TYPE_ARENA);
\t__uint(map_flags, BPF_F_MMAPABLE);
\t__uint(max_entries, 1024);
\t__ulong(map_extra, 0x1ull << 32);\t/* arm64 user vm start */
} arena SEC(".maps");
#define __arena __attribute__((address_space(1)))
#undef smp_store_release
#undef smp_load_acquire
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define smp_load_acquire(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)"""

    # arena-recycle backend: arena map (ARENA_PAGES, -D-overridable),
    # address-space-aware release/acquire, and the page alloc/free kfuncs.
    _RECYCLE_PREAMBLE = """\
#ifndef ARENA_PAGES
#define ARENA_PAGES 1024
#endif
struct {
\t__uint(type, BPF_MAP_TYPE_ARENA);
\t__uint(map_flags, BPF_F_MMAPABLE);
\t__uint(max_entries, ARENA_PAGES);
\t__ulong(map_extra, 0x1ull << 32);\t/* arm64 user vm start */
} arena SEC(".maps");
#define __arena __attribute__((address_space(1)))
#define NUMA_NO_NODE (-1)
#undef smp_store_release
#undef smp_load_acquire
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define smp_load_acquire(p)     __atomic_load_n((p), __ATOMIC_ACQUIRE)

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
\t\t\t\t    int node_id, __u64 flags) __ksym;
void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym;"""

    def _recycle_op_lines(self, op: str):
        """Expand one litmus operation for the arena-recycle backend.

        A recycled variable v is reached through a per-slot published pointer
        v_ptr[i] rather than a static arena global.  A write allocates a fresh
        page, writes through it, and publishes the pointer; a read loads the
        pointer and dereferences it (guarded, so an unpublished slot reads 0).
        Operations that touch no recycled variable are rewritten normally.
        """
        recycled = self.parser.recycle_vars
        arrays = self.parser.array_sizes

        touched = [v for v in recycled if re.search(rf'\b{re.escape(v)}\b', op)]
        if not touched:
            return [self._rewrite_operation(op, 'arena')]
        if len(touched) > 1:
            raise ValueError(f"operation touches >1 recycled var: {op!r}")

        v = touched[0]
        ptr, arr, size = f"{v}_p", f"{v}_ptr", arrays.get(v)
        alloc = (f"{ptr} = bpf_arena_alloc_pages(&arena, (void __arena *)0, 1, "
                 f"NUMA_NO_NODE, 0);")
        v_re = re.escape(v)

        # Scalar write: WRITE_ONCE(*v, VAL)
        m = re.fullmatch(rf'WRITE_ONCE\(\s*\*\s*{v_re}\s*,\s*(.+?)\s*\)\s*;?', op)
        if m and not size:
            return [alloc, f"if (!{ptr}) continue;",
                    f"WRITE_ONCE(*{ptr}, {m.group(1)});", f"{arr}[i] = {ptr};"]
        # Array write: WRITE_ONCE(v[idx], VAL)
        m = re.fullmatch(rf'WRITE_ONCE\(\s*{v_re}\s*\[\s*(.+?)\s*\]\s*,\s*(.+?)\s*\)\s*;?', op)
        if m and size:
            return [alloc, f"if (!{ptr}) continue;",
                    f"WRITE_ONCE({ptr}[({m.group(1)}) & {size - 1}], {m.group(2)});",
                    f"{arr}[i] = {ptr};"]
        # Scalar read: rN = READ_ONCE(*v)
        m = re.fullmatch(rf'(r\d+)\s*=\s*READ_ONCE\(\s*\*\s*{v_re}\s*\)\s*;?', op)
        if m and not size:
            return [f"{ptr} = {arr}[i];",
                    f"{m.group(1)} = {ptr} ? READ_ONCE(*{ptr}) : 0;"]
        # Array read: rN = READ_ONCE(v[idx])
        m = re.fullmatch(rf'(r\d+)\s*=\s*READ_ONCE\(\s*{v_re}\s*\[\s*(.+?)\s*\]\s*\)\s*;?', op)
        if m and size:
            return [f"{ptr} = {arr}[i];",
                    f"{m.group(1)} = {ptr} ? "
                    f"READ_ONCE({ptr}[({m.group(2)}) & {size - 1}]) : 0;"]

        raise ValueError(f"recycled var {v!r} used in unsupported form: {op!r}")

    def _proc_recycle_vars(self, proc):
        """Recycled variables referenced by a process's body."""
        return [v for v in self.parser.recycle_vars
                if any(re.search(rf'\b{re.escape(v)}\b', op)
                       for op in proc.get('operations', []))]

    def generate_bpf_c(self, backend: str = 'bss') -> str:
        """Generate the BPF program.

        backend='bss'     -> shared variables live in a bss struct (default).
        backend='arena'   -> shared variables are per-slot arena globals.
        backend='recycle' -> recycled variables live on per-slot pages allocated
                             and freed each round; other vars stay in the arena.
        Observed registers always spill to bss for readout.
        """
        if len(self.parser.processes) > self.max_processes:
            print(f"blitmus: {self.parser.test_name}: only {self.max_processes} "
                  f"processes supported, test has {len(self.parser.processes)}",
                  file=sys.stderr)

        # Registers observed by the exists clause (klitmus "finals").
        observed = self._observed_regs()

        backend_tag = {'arena': ' (arena backend)',
                       'recycle': ' (arena-recycle backend)'}.get(backend, '')
        code = [f"/* Auto-generated from {self.parser.test_name}.litmus{backend_tag} */"]
        # Default BLITMUS_SLOTS before bpf_header (its #ifndef picks it up); -D
        # still overrides.
        if backend == 'recycle':
            code.append("#ifndef BLITMUS_SLOTS")
            code.append(f"#define BLITMUS_SLOTS {RECYCLE_SLOTS}")
            code.append("#endif")
        with open(self.bpf_header_file, 'r') as f:
            code.append(f.read())

        # Carry the original litmus comment through for provenance.
        if self.parser.comments:
            code.append("/*")
            for comment in self.parser.comments:
                for line in comment.split('\n'):
                    code.append(f" * {line.strip()}")
            code.append(" */")
        code.append("")

        # Shared variables (the locations under test) and the write-back slots
        # for observed registers.  Unobserved registers never touch memory -
        # they stay in BPF registers, so data/address/control dependencies are
        # carried exactly as written.
        def var_dim(var):
            """Trailing array dimension: [SLOTS] for a scalar, [SLOTS][N] for
            an array variable used as v[expr]."""
            size = self.parser.array_sizes.get(var)
            return f"[BLITMUS_SLOTS][{size}]" if size else "[BLITMUS_SLOTS]"

        if backend == 'recycle':
            code.append(self._RECYCLE_PREAMBLE)
            for var in sorted(self.parser.variables):
                if var in self.parser.recycle_vars:
                    code.append(f"__u64 __arena * __arena {var}_ptr[BLITMUS_SLOTS];"
                                f"\t/* recycled {var}: per-slot published page */")
                else:
                    code.append(f"__u64 __arena {var}{var_dim(var)};")
            code.append("struct {")
            for proc_id, reg in observed:
                code.append(f"\tvolatile __u64 out_p{proc_id}_{reg}[BLITMUS_SLOTS];\t/* observed P{proc_id}:{reg} */")
            code.append("} shared;")
        elif backend == 'arena':
            code.append(self._ARENA_PREAMBLE)
            for var in sorted(self.parser.variables):
                code.append(f"__u64 __arena {var}{var_dim(var)};")
            code.append("struct {")
            for proc_id, reg in observed:
                code.append(f"\tvolatile __u64 out_p{proc_id}_{reg}[BLITMUS_SLOTS];\t/* observed P{proc_id}:{reg} */")
            code.append("} shared;")
        else:
            code.append("struct {")
            for var in sorted(self.parser.variables):
                code.append(f"\tvolatile __u64 {var}{var_dim(var)};")
            for proc_id, reg in observed:
                code.append(f"\tvolatile __u64 out_p{proc_id}_{reg}[BLITMUS_SLOTS];\t/* observed P{proc_id}:{reg} */")
            code.append("} shared;")
        code.append("")
        code.append(f"int num_threads = {len(self.parser.processes)};")

        # Generate BPF programs for each process
        for proc in self.parser.processes[:self.max_processes]:
            proc_id = proc['id']
            regs = self._process_registers(proc)
            spilled = [reg for (pid, reg) in observed if pid == proc_id]

            code.append(f"// Program for P{proc_id}")
            code.append(f"SEC(\"raw_tp/test_prog{proc_id + 1}\")")
            code.append(f"int handle_tp{proc_id + 1}(void *ctx)")
            code.append("{")
            code.append("\t__u32 local_sense = 0;")
            code.append("\tint i;")
            code.append("")
            code.append("\tbpf_sense_barrier(&local_sense, num_threads);")
            code.append("\tsmp_mb();")
            code.append("\tbpf_for (i, 0, BLITMUS_SLOTS) {")
            code.append(f"\t\tbarrier_wait({proc_id}, i);")

            # Litmus registers as C locals.  Initialised to 0 to satisfy the
            # verifier; 0 is also LKMM's initial register value, so a register
            # left unassigned on some path reads as the model expects.
            for reg in regs:
                code.append(f"\t\t__u64 {reg} = 0;")

            # Per-slot pointer locals for recycled variables this process touches.
            if backend == 'recycle':
                for v in self._proc_recycle_vars(proc):
                    code.append(f"\t\t__u64 __arena *{v}_p = 0;")

            # Compiler barrier delimiting the litmus body (cf. klitmus
            # dump_start/dump_end): stops the compiler from moving harness code
            # into the tested sequence.  It adds no hardware ordering.
            code.append("\t\tasm volatile(\"\" ::: \"memory\");")

            # Litmus body, verbatim except shared-variable references retargeted
            # at this iteration's memory slot.
            for op in proc['operations']:
                if backend == 'recycle':
                    for line in self._recycle_op_lines(op):
                        code.append(f"\t\t{line}")
                else:
                    code.append(f"\t\t{self._rewrite_operation(op, backend)}")

            code.append("\t\tasm volatile(\"\" ::: \"memory\");")

            # Spill observed registers to shared memory, once per iteration.
            for reg in spilled:
                code.append(f"\t\tshared.out_p{proc_id}_{reg}[i] = {reg};")

            code.append("\t}")
            code.append("\tsmp_mb();")
            code.append("\treturn 0;")
            code.append("}")
            code.append("")

        # reset(): run once per round by the harness before the processes.
        # Frees each recycled page and clears the arena vars (userspace resets
        # bss, not arena memory).
        if backend == 'recycle':
            code.append('SEC("raw_tp/reset")')
            code.append("int handle_reset(void *ctx)")
            code.append("{")
            code.append("\tint i;")
            code.append("\tbpf_for (i, 0, BLITMUS_SLOTS) {")
            for var in sorted(self.parser.variables):
                if var in self.parser.recycle_vars:
                    code.append(f"\t\tif ({var}_ptr[i])")
                    code.append(f"\t\t\tbpf_arena_free_pages(&arena, "
                                f"(void __arena *){var}_ptr[i], 1);")
                    code.append(f"\t\t{var}_ptr[i] = (void __arena *)0;")
                else:
                    size = self.parser.array_sizes.get(var)
                    if size:
                        code.append(f"\t\tfor (int k = 0; k < {size}; k++) "
                                    f"{var}[i][k] = 0;")
                    else:
                        code.append(f"\t\t{var}[i] = 0;")
            code.append("\t}")
            code.append("\treturn 0;")
            code.append("}")
            code.append("")

        return "\n".join(code)

    def generate_print_histogram(self, ordered_names):
        """Emit print_histogram(): a herd-style dump of every observed state.

        ordered_names is the list of condition names (e.g. p0_r0, var_x) in the
        same order as the states[] array dimensions.
        """
        n = len(ordered_names)
        code = []
        if n == 0:
            code.append("static void print_histogram(void) {}")
            code.append("")
            return code

        names_c = ', '.join(f'"{name}"' for name in ordered_names)
        code.append(f"static const char *var_names[] = {{{names_c}}};")
        code.append("")
        code.append("static void print_histogram(void)")
        code.append("{")
        code.append("\tunsigned long long total_states = 0;")

        def loops(body_lines):
            out = []
            for k in range(n):
                out.append('\t' * (k + 1) + f"for (int i{k} = 0; i{k} < HIST_DIM; i{k}++) {{")
            ind = '\t' * (n + 1)
            out.extend(ind + line for line in body_lines)
            for k in reversed(range(n)):
                out.append('\t' * (k + 1) + "}")
            return out

        idx = ''.join(f"[i{k}]" for k in range(n))
        code.extend(loops([f"if (states{idx} > 0) total_states++;"]))
        code.append('\tprintf("Histogram (%llu states)\\n", total_states);')

        body = [
            f"unsigned long long count = states{idx};",
            "if (!count) continue;",
            'printf("%-8llu %c>", count,',
            f"       &states{idx} == expected_state_p ? '*' : ':');",
            f"int vals[] = {{{', '.join(f'i{k}' for k in range(n))}}};",
            f"for (int k = 0; k < {n}; k++) {{",
            "\tconst char *name = var_names[k];",
            "\tint proc, reg;",
            '\tif (sscanf(name, "p%d_r%d", &proc, &reg) == 2)',
            '\t\tprintf("%d:r%d=%d; ", proc, reg, vals[k]);',
            '\telse if (!strncmp(name, "var_", 4))',
            '\t\tprintf("%s=%d; ", name + 4, vals[k]);',
            "}",
            'printf("\\n");',
        ]
        code.extend(loops(body))
        code.append("}")
        code.append("")
        return code

    def generate_user_c(self, name: str = None, print_name: str = None) -> str:
        """Generate the userspace loader/checker C code.

        name/print_name override the output/skeleton name and the printed test
        name, used to distinguish backend variants (e.g. sb_xchg vs
        sb_xchg_arena).  The userspace side is identical across backends: the
        observed registers always live in bss.
        """
        p = self.parser
        with open(self.user_header_file) as f:
            header = f.read()
        with open(self.user_footer_file) as f:
            footer = f.read()

        test_name = name or p.test_name.lower().replace('+', '_')
        print_name = print_name or p.test_name
        # Ordered list of (name, expected_value) for every exists condition.
        checks = [(f"p{pid}_{reg}", val) for pid, reg, val in p.conditions]
        checks += [(f"var_{var}", val) for var, val in p.variable_conditions]
        result_kind = {'Never': 'RESULT_NEVER',
                       'Always': 'RESULT_ALWAYS'}.get(p.result_type, 'RESULT_SOMETIMES')

        code = [f"/* Auto-generated from {p.test_name}.litmus */", header]
        clause = p.exists_clause.replace('\\', '\\\\')
        code += [
            f'#include "{test_name}.skel.h"',
            f"#define THREADS {len(p.processes)}",
            f"#define TEST_NAME {test_name}",
            f'#define TEST_NAME_PRINT "{print_name}"',
            f'#define EXISTS_CLAUSE "{clause}"',
            "#ifndef BLITMUS_SLOTS",
            f"#define BLITMUS_SLOTS {RECYCLE_SLOTS if p.recycle_vars else NR_SLOTS}",
            "#endif",
            f"#define DEFAULT_ITERATIONS "
            f"{RECYCLE_ITERATIONS if p.recycle_vars else DEFAULT_ITERATIONS}",
            f"#define HIST_DIM {HIST_DIM}",
            "/* Clamp a value to a valid histogram index (outcomes are small). */",
            "#define HIST_IDX(v) ((v) < HIST_DIM ? (int)(v) : HIST_DIM - 1)",
            "",
            "enum { RESULT_NEVER, RESULT_SOMETIMES, RESULT_ALWAYS };",
            f"static const int result_kind = {result_kind};",
            "",
        ]

        dims = "[HIST_DIM]" * len(checks) if checks else "[1]"
        code.append(f"static unsigned long long states{dims};")
        code.append("static unsigned long long *expected_state_p;")
        code.append("")

        # check_cond(): read this slot's observed values, tally the histogram,
        # and classify against the exists clause.
        code.append("static void check_cond(STRUCT_NAME(TEST_NAME) *skel,")
        code.append("\t\t       unsigned long long *matches,")
        code.append("\t\t       unsigned long long *non_matches, int c)")
        code.append("{")
        for pid, reg, _ in p.conditions:
            code.append(f"\tunsigned long long p{pid}_{reg} = skel->bss->shared.out_p{pid}_{reg}[c];")
        for var, _ in p.variable_conditions:
            code.append(f"\tunsigned long long var_{var} = skel->bss->shared.{var}[c];")
        if checks:
            hist_idx = ''.join(f"[HIST_IDX({name})]" for name, _ in checks)
            code.append(f"\tstates{hist_idx}++;")
            cond = " && ".join(f"{name} == {val}" for name, val in checks)
            code.append(f"\tif ({cond}) {{")
            code.append("\t\t(*matches)++;")
            code.append(f"\t\texpected_state_p = &states{hist_idx};")
            code.append("\t} else {")
            code.append("\t\t(*non_matches)++;")
            code.append("\t}")
        else:
            code.append("\t(void)skel; (void)c;")
            code.append("\t(*non_matches)++;")
        code.append("}")
        code.append("")

        code += self.generate_print_histogram([name for name, _ in checks])
        code.append(footer)
        return "\n".join(code)

def main():
    parser = argparse.ArgumentParser(description='Convert litmus tests to BPF programs')
    parser.add_argument('litmus_file', help='Path to the litmus test file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-n', '--name', help='Override test name for output files')

    bpf_header = os.path.join(f"{os.getcwd()}/template/", "bpf_header")
    user_header = os.path.join(f"{os.getcwd()}/template/", "user_header")
    user_footer = os.path.join(f"{os.getcwd()}/template/", "user_footer")

    args = parser.parse_args()

    # Parse the litmus test
    litmus_parser = LitmusParser(args.litmus_file)
    if not litmus_parser.parse():
        sys.exit(1)

    if args.verbose:
        print(litmus_parser.get_summary())

    # Skip tests using primitives the BPF backend cannot express (e.g.
    # smp_wmb()/smp_rmb()) instead of emitting code that will not build/load.
    # Exit 0 so `make regen_litmus` keeps processing the remaining tests.
    if not litmus_parser.processes:
        print(f"Skipping {args.litmus_file}: no processes parsed")
        sys.exit(0)

    unsupported = litmus_parser.unsupported_primitives()
    if unsupported:
        print(f"Skipping {litmus_parser.test_name}: unsupported primitive(s): "
              f"{', '.join(sorted(unsupported))}")
        sys.exit(0)

    generator = BPFGenerator(litmus_parser, bpf_header, user_header, user_footer)

    # Generated sources go under .output/gen/ (gitignored; regenerated by make).
    gen_dir = os.path.join(os.getcwd(), '.output', 'gen')
    os.makedirs(gen_dir, exist_ok=True)

    base_name = args.name if args.name else litmus_parser.test_name.lower().replace('+', '_')

    # Which backend variants to emit.  "arena-recycle" is exclusive (arena-only,
    # page-lifecycle probe); "arena" adds an arena variant alongside bss.  Both
    # read observed values back from bss, so they need register conditions.
    if litmus_parser.recycle_vars:
        if litmus_parser.variable_conditions:
            print(f"blitmus: {litmus_parser.test_name}: arena-recycle needs "
                  f"register conditions; skipping", file=sys.stderr)
            sys.exit(0)
        variants = [('recycle', base_name, litmus_parser.test_name)]
    else:
        variants = [('bss', base_name, litmus_parser.test_name)]
        if any(re.search(r'blitmus:\s*arena\b', c) for c in litmus_parser.comments):
            if litmus_parser.variable_conditions:
                print(f"blitmus: {litmus_parser.test_name}: arena backend needs "
                      f"register conditions; skipping arena variant", file=sys.stderr)
            else:
                variants.append(('arena', f"{base_name}_arena",
                                 f"{litmus_parser.test_name} (arena)"))

    for backend, name, print_name in variants:
        with open(os.path.join(gen_dir, f"{name}.bpf.c"), 'w') as f:
            f.write(generator.generate_bpf_c(backend))
        with open(os.path.join(gen_dir, f"{name}.c"), 'w') as f:
            f.write(generator.generate_user_c(name, print_name))
        print(f"Generated {backend} test: {name}")

if __name__ == "__main__":
    main()
