#!/usr/bin/env python3
"""
Litmus Test to BPF Converter

This tool converts litmus tests to BPF programs that can run on real hardware
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
            for var, value in getattr(self, 'variable_conditions', []):
                summary.append(f"  {var}={value}")

        return "\n".join(summary)

class BPFGenerator:
    """Generator for BPF code from parsed litmus test"""

    def __init__(self, parser: LitmusParser, bpf_header_filename: str, user_header_filename: str, user_footer_filename: str):
        self.parser = parser
        self.max_processes = 8  # Maximum number of processes supported
        self.reg_mapping = {}  # Will be populated during BPF generation
        self.bpf_header_file = bpf_header_filename
        self.user_header_file = user_header_filename
        self.user_footer_file = user_footer_filename

    def _create_register_mapping(self):
        """Create a mapping from (proc_id, reg) to sequential register numbers"""
        reg_counter = 1
        reg_mapping = {}
        for proc in self.parser.processes:
            proc_id = proc['id']
            for reg in proc.get('registers', []):
                reg_mapping[(proc_id, reg)] = reg_counter
                reg_counter += 1
        return reg_mapping

    def generate_bpf_c(self) -> str:
        """Generate BPF C code"""
        if len(self.parser.processes) > self.max_processes:
            print(f"Warning: Only supporting up to {self.max_processes} processes, but test has {len(self.parser.processes)}")

        # Create register mapping first
        self.reg_mapping = self._create_register_mapping()

        code = []
        code.append(f"/* Auto-generated from {self.parser.test_name}.litmus */")
        with open(self.bpf_header_file, 'r') as f:
                header_content = f.read()
        code.append(header_content)

        # Add comments from the original litmus test
        if self.parser.comments:
            code.append("/*")
            for comment in self.parser.comments:
                for line in comment.split('\n'):
                    code.append(f" * {line.strip()}")
            code.append(" */")
            code.append("")

        # Add shared variables
        code.append("struct {")
        for var in sorted(self.parser.variables):
            code.append(f"    volatile int {var}[1000];")

        # Add registers for each process - use sequential numbering
        for (proc_id, reg), reg_num in sorted(self.reg_mapping.items(), key=lambda item: item[1]):
                code.append(f"    volatile int r{reg_num}[1000];  // For P{proc_id}_{reg}")

        code.append("} shared;")
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
            return f"WRITE_ONCE(shared.{var}[i], {val});"

        # Handle READ_ONCE
        read_match = re.search(r'(\w+)\s*=\s*READ_ONCE\(\*(\w+)\)', op)
        if read_match:
            reg = read_match.group(1)
            var = read_match.group(2)
            # Use the sequential register mapping
            reg_num = self.reg_mapping.get((proc_id, reg), 0)
            return f"shared.r{reg_num}[i] = READ_ONCE(shared.{var}[i]);"

        smp_mb_match = re.match(r'\s*smp_mb\(\s*\)\s*;?', op)
        if smp_mb_match:
            return "smp_mb();"

        # Default case - pass through (with a warning comment)
        return f"/* Unsupported operation: {op} */";

    def generate_user_c(self) -> str:
        """Generate user-space C code"""
        num_processes = len(self.parser.processes)

        code = []
        code.append(f"/* Auto-generated from {self.parser.test_name}.litmus */")
        with open(self.user_header_file, 'r') as f:
                header_content = f.read()
        with open(self.user_footer_file, 'r') as f:
                footer_content = f.read()
        code.append(header_content)

        # Determine the skeleton header name
        test_name = self.parser.test_name.lower().replace('+', '_')
        code.append(f"#include \"{test_name}.skel.h\"")
        code.append(f"#define THREADS {len(self.parser.processes)}")
        code.append(f"#define TEST_NAME {test_name}")
        code.append(f"#define TEST_NAME_PRINT \"{self.parser.test_name}\"")
        clause = self.parser.exists_clause.replace('\\', '\\\\')
        code.append(f"#define EXISTS_CLAUSE \"{clause}\"")
        code.append("static void check_cond (STRUCT_NAME(TEST_NAME) *skel,")
        code.append("\t\t\tint *matches, int *non_matches, int c) {")

        # Generate result checking code based on exists clause
        if self.parser.conditions or getattr(self.parser, 'variable_conditions', []):
            # Generate code to get register values
            code.append("\t// Get the values for this iteration")
            reg_counter = 1
            reg_vars = []
            for proc in self.parser.processes:
                proc_id = proc['id']
                for reg in proc.get('registers', []):
                    var_name = f"p{proc_id}_{reg}"
                    code.append(f"\tint {var_name} = skel->bss->shared.r{reg_counter}[c];")
                    reg_vars.append(var_name)
                    reg_counter += 1

            # Generate code to get variable values (for variable conditions)
            var_vars = []
            for var, expected_value in getattr(self.parser, 'variable_conditions', []):
                var_name = f"var_{var}"
                code.append(f"\tint {var_name} = skel->bss->shared.{var}[c];")
                var_vars.append(var_name)

            # Generate condition check
            code.append("\t// Check if this iteration matches the exists clause")
            conditions = []

            # Add register conditions
            for proc in self.parser.processes:
                proc_id = proc['id']
                for reg in proc.get('registers', []):
                    # Find the expected value for this register
                    expected_value = None
                    for cond_proc_id, cond_reg, cond_value in self.parser.conditions:
                        if cond_proc_id == proc_id and cond_reg == reg:
                            expected_value = cond_value
                            break
                    if expected_value is not None:
                        conditions.append(f"p{proc_id}_{reg} == {expected_value}")

            # Add variable conditions
            for var, expected_value in getattr(self.parser, 'variable_conditions', []):
                    conditions.append(f"var_{var} == {expected_value}")

            if conditions:
                code.append("\tif (" + " && ".join(conditions) + ") {")
                code.append("\t\t\t*matches += 1;")
                code.append("\t} else {")
                code.append("\t\t\t*non_matches += 1;")
                code.append("\t}")

        code.append("}")
        code.append(footer_content)
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

    # Generate BPF code
    generator = BPFGenerator(litmus_parser, bpf_header, user_header, user_footer)
    bpf_code = generator.generate_bpf_c()

    src_dir = os.path.join(os.getcwd(), 'src')

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
    makefile_path = os.path.join(os.getcwd(), "Makefile")
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

    # Update .gitignore to add the test name if it doesn't exist
    gitignore_path = os.path.join(os.getcwd(), ".gitignore")
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()

        # Check if the test name is already in .gitignore
        gitignore_lines = gitignore_content.strip().split('\n') if gitignore_content.strip() else []
        if test_name not in gitignore_lines:
            # Append the test name to .gitignore
            with open(gitignore_path, 'a') as f:
                if gitignore_content and not gitignore_content.endswith('\n'):
                    f.write('\n')
                f.write(f"{test_name}\n")
            print(f"Updated .gitignore: Added {test_name}")
        else:
            print(f"Test {test_name} already in .gitignore")
    else:
        # Create .gitignore if it doesn't exist
        with open(gitignore_path, 'w') as f:
            f.write(f"{test_name}\n")
        print(f"Created .gitignore and added {test_name}")

    print(f"\nTo build the test:")
    print(f"  cd {os.getcwd()}")
    print(f"  make {test_name}")
    print(f"\nTo run the test:")
    print(f"  ./{test_name} [OPTIONS]")

if __name__ == "__main__":
    main()
