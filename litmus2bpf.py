#!/usr/bin/env python3

import os
import re
import argparse
from lark import Lark, Transformer
from jinja2 import Template
from collections import defaultdict

# ---------- Constants --------
VARIABLE_SIZE = 10000

# ---------- Grammar ----------
LITMUS_GRAMMAR = r"""
// Lexer Rules: order matters!
FFENCE.2: "smp_mb"
WFENCE.2: "smp_wmb"
RFENCE.2: "smp_rmb"
STORE_RELEASE.5: "smp_store_release"
LOAD_ACQUIRE.5: "smp_load_acquire"

EQUAL: "=="
NOTEQUAL: "!="
VAR_NAME: /[A-Za-z_][A-Za-z0-9_]*/
NAME: /[A-Za-z0-9_\+\-\.]+/
NUMBER: /-?[0-9]+/
PLUS: "+"
MINUS: "-"

// Grammar rules
start: test_name init_state? process+ exists_clause

test_name: "C" NAME
init_state: "{" (var_assign ";")* "}"
var_assign: VAR_NAME "=" NUMBER

process: "P" NUMBER "(" param_list ")" "{" statement* "}"
param_list: [param ("," param)*]
param: VAR_NAME "*" VAR_NAME

statement: decl
         | write_once
         | read_once
         | plain_store
         | plain_deref_store
         | plain_load
         | fence
         | store_release
         | load_acquire
         | imm_assign
         | arith_assign
         | if_stmt

decl: VAR_NAME VAR_NAME ("=" NUMBER)? ";"

write_once: "WRITE_ONCE" "(" "*" VAR_NAME "," NUMBER ")" ";"
read_once: VAR_NAME "=" "READ_ONCE" "(" "*" VAR_NAME ")" ";"

plain_store: "*" VAR_NAME "=" NUMBER ";"
plain_deref_store: "*" VAR_NAME "=" "*" VAR_NAME ";"
plain_load: "*" VAR_NAME "=" VAR_NAME ";"

imm_assign: VAR_NAME "=" NUMBER ";"
arith_assign: VAR_NAME "=" expr_rhs ";"
if_stmt: "if" "(" condition ")" if_body

if_body: "{" statement* "}" | statement

?expr_rhs: term ((PLUS | MINUS) term)*
term: VAR_NAME | NUMBER

condition: "*"? (VAR_NAME | VAR_NAME EQUAL NUMBER | VAR_NAME NOTEQUAL NUMBER)

fence: (FFENCE | WFENCE | RFENCE) "(" ")" ";"
store_release: STORE_RELEASE "(" VAR_NAME "," (NUMBER | VAR_NAME) ")" ";"
load_acquire: VAR_NAME "=" LOAD_ACQUIRE "(" VAR_NAME ")" ";"

exists_clause: "exists" "(" expr ")"
?expr: or_expr
?or_expr: and_expr ("\\/" and_expr)*
?and_expr: not_expr ("/\\" not_expr)*
?not_expr: "~" not_expr -> not_expr | atom
?atom: comparison | "(" expr ")"
comparison: thread_reg_eq | var_eq
thread_reg_eq: NUMBER ":" VAR_NAME "=" NUMBER
var_eq: VAR_NAME "=" NUMBER

%ignore /\s+/
"""

# ---------- AST ----------

class LitmusTest:  # root
    def __init__(self, name, processes, exists, init={}):
        self.name = name
        self.processes = processes
        self.exists = exists
        self.init = init
        self.variables = set()
        self.cond_variables = set()
        for process in processes:
            for x in process.params:
                self.variables.add(x[1])
            for stmt in process.statements:
                if isinstance(stmt, Decl):
                    self.variables.add(f"P{process.pid}_{stmt.reg}")
        self.parse_exists(exists)
        self.clause = self.render_exists_clause(exists)

    def parse_exists(self, exists):
        self.exists_c = self.parse_child(exists)

    def parse_child(self, child):
        exists_c = ""
        if isinstance(child, ThreadRegEq):
            self.cond_variables.add(f"P{child.tid}_{child.reg}")
            return f"(P{child.tid}_{child.reg} == {child.val})"
        elif isinstance(child, VarEq):
            self.cond_variables.add(f"{child.var}")
            return f"({child.var} == {child.val})"

        if isinstance(child, And):
            exists_c += " && ".join([self.parse_child(c) for c in child.children])
            return "(" + exists_c + ")"

        if isinstance(child, Or):
            exists_c += " || ".join([self.parse_child(c) for c in child.children])
            return "(" + exists_c + ")"

        if isinstance(child, Not):
            return "!" + self.parse_child(child.child)

    def render_exists_clause(self, expr):
        if isinstance(expr, Or):
            return r' \\/ '.join(f'{self.render_exists_clause(e)}' for e in expr.children)
        elif isinstance(expr, And):
            return r' /\\ '.join(f'{self.render_exists_clause(e)}' for e in expr.children)
        elif isinstance(expr, Not):
            return f'~{self.render_exists_clause(expr.child)}'
        elif isinstance(expr, ThreadRegEq):
            return f'{expr.tid}:{expr.reg}={expr.val}'
        elif isinstance(expr, VarEq):
            return f'{expr.var}={expr.val}'
        else:
            raise ValueError(f"Unknown expression type: {type(expr)}") 

class Process:
    def __init__(self, pid, params, statements):
        self.pid = pid; self.params = params; self.statements = statements
class Statement: pass
class Decl(Statement):
    def __init__(self, type_, reg, init_val=None): self.type, self.reg, self.init_val = type_, reg, init_val
class WriteOnce(Statement):
    def __init__(self, var, val): self.var, self.val = var, val
class ReadOnce(Statement):
    def __init__(self, reg, var): self.reg, self.var = reg, var
class PlainStore(Statement):
    def __init__(self, var, val): self.var, self.val = var, val
class PlainLoad(Statement):
    def __init__(self, reg, var): self.reg, self.var = reg, var
class ImmAssign(Statement):
    def __init__(self, reg, val): self.reg, self.val = reg, val
class ArithmeticAssign(Statement):
    def __init__(self, reg, expr_rhs): self.reg, self.expr_rhs = reg, expr_rhs
class IfStatement(Statement):
    def __init__(self, condition, body): self.condition, self.body = condition, body
class Fence(Statement):
    def __init__(self, fence): self.fence = fence
class StoreRelease(Statement):
    def __init__(self, var, val): self.var, self.val = var, val
class LoadAcquire(Statement):
    def __init__(self, reg, var): self.reg, self.var = reg, var
class UnhandledMacro(Statement):
    def __init__(self, text): self.text = text
class ExistsCondition: pass
class And(ExistsCondition):
    def __init__(self, children): self.children = children
class Or(ExistsCondition):
    def __init__(self, children): self.children = children
class Not(ExistsCondition):
    def __init__(self, child): self.child = child
class ThreadRegEq(ExistsCondition):
    def __init__(self, tid, reg, val): self.tid, self.reg, self.val = tid, reg, val
class VarEq(ExistsCondition):
    def __init__(self, var, val): self.var, self.val = var, val
class Condition: pass
class ConditionReg(Condition):
    def __init__(self, reg): self.reg = reg
class ConditionEq(Condition):
    def __init__(self, reg, val): self.reg, self.val = reg, val
class ConditionNeq(Condition):
    def __init__(self, reg, val): self.reg, self.val = reg, val

# ---------- Transformer ----------

class LitmusTransformer(Transformer):
    def start(self, items):
        # Extract known components
        test_name = items[0]

        # Possible init_state (check its type)
        if isinstance(items[1], dict):
            init_state = items[1]
            processes = items[2:-1]
        else:
            init_state = None  # or None if allowed
            processes = items[1:-1]

        exists = items[-1]
        return LitmusTest(
            name=test_name,
            init=init_state,
            processes=processes,
            exists=exists
        )
    def test_name(self, items): return str(items[0])
    def var_assign(self, items): return (str(items[0]), int(items[1]))
    def init_state(self, items): return dict(items)
    def process(self, items): return Process(int(items[0]), items[1], items[2:])
    def param_list(self, items):
        return [(str(x[0]), str(x[1])) for x in items]
    def param(self, items):
        return (str(items[0]), str(items[1]))
    def statement(self, items):
        return items[0]
    def comparison(self, items):
        return items[0]
    def decl(self, items):
        return Decl(str(items[0]), str(items[1]), int(items[2]) if len(items)>2 else None)
    def write_once(self, items): return WriteOnce(str(items[0]), int(items[1]))
    def read_once(self, items): return ReadOnce(str(items[0]), str(items[1]))
    def plain_store(self, items): return PlainStore(str(items[0]), int(items[1]))
    def plain_load(self, items): return PlainLoad(str(items[0]), str(items[1]))
    def plain_deref_store(self, items): return PlainLoad(str(items[0]), str(items[1]))
    def imm_assign(self, items): return ImmAssign(str(items[0]), int(items[1]))
    def arith_assign(self, items): return ArithmeticAssign(str(items[0]), items[1])
    def expr_rhs(self, items):
        return [items[0]] + [(str(items[i]), items[i+1]) for i in range(1, len(items), 2)]
    def term(self, items):
        return int(items[0]) if items[0].type=="NUMBER" else str(items[0])
    def if_stmt(self, items):
        return IfStatement(items[0], items[1] if isinstance(items[1], list) else [items[1]])
    def if_body(self, items): return items
    def condition(self, items):
        reg = str(items[0])
        if len(items)==1: return ConditionReg(reg)
        return ConditionEq(reg, int(items[2])) if items[1]=="==" else ConditionNeq(reg, int(items[2]))
    def fence(self, items): return Fence(items[0].value)
    def store_release(self, items):
        var = str(items[1])
        val = int(items[2]) if items[2].type == "NUMBER" else str(items[2])
        return StoreRelease(var, val)
    def load_acquire(self, items):
        reg = str(items[0])
        var = str(items[2])
        return LoadAcquire(reg, var)
    def macro(self, items): return UnhandledMacro(str(items[0]))
    def exists_clause(self, items): return items[0]
    def and_expr(self, items): return And(items)
    def or_expr(self, items): return Or(items)
    def not_expr(self, items): return Not(items[0])
    def thread_reg_eq(self, items): return ThreadRegEq(int(items[0]), str(items[1]), int(items[2]))
    def var_eq(self, items): return VarEq(str(items[0]), int(items[1]))

# ---------- Code generation ----------

def var_name(name, pid, params):
    if name in params:
        return name
    return f"P{pid}_" + name

def generate_bpf_stmt(stmt, pid, params):
    if isinstance(stmt, Decl):
        if stmt.init_val is not None:
            vname = var_name(stmt.reg, pid, params)
            return f"shared.{vname}[i]" + f" = {stmt.init_val};"
        else:
            return None
    if isinstance(stmt, WriteOnce):
        vname = var_name(stmt.var, pid, params)
        return f"WRITE_ONCE(shared.{vname}[i], {stmt.val});"
    if isinstance(stmt, ReadOnce):
        vname1 = var_name(stmt.reg, pid, params)
        vname2 = var_name(stmt.var, pid, params)
        return f"shared.{vname1}[i] = READ_ONCE(shared.{vname2}[i]);"
    if isinstance(stmt, PlainStore):
        vname = var_name(stmt.var, pid, params)
        return f"shared.{vname}[i] = {stmt.val};"
    if isinstance(stmt, PlainLoad):
        vname1 = var_name(stmt.reg, pid, params)
        vname2 = var_name(stmt.var, pid, params)
        return f"shared.{vname1}[i] = shared.{vname2}[i];"
    if isinstance(stmt, ImmAssign):
        vname = var_name(stmt.reg, pid, params)
        return f"shared.{vname}[i] = {stmt.val};"
    if isinstance(stmt, ArithmeticAssign):
        vname = var_name(stmt.reg, pid, params)
        return f"shared.{vname}[i] = {generate_expr_rhs(stmt.expr_rhs, pid, params)};"
    if isinstance(stmt, IfStatement):
        body = "\t\n".join(generate_bpf_stmt(s, pid, params) for s in stmt.body)
        name = var_name(stmt.condition.reg, pid, params)
        return f"if ({generate_if_condition(stmt.condition, name)}) {{\n\t\t\t{body}\n\t\t}}"
    if isinstance(stmt, Fence):
        return f"{stmt.fence}();"
    if isinstance(stmt, StoreRelease):
        vname1 = var_name(stmt.var, pid, params)
        if isinstance(stmt.val, int):
            vname2 = stmt.val
        else:
            vname2 = f"shared.{var_name(stmt.val, pid, params)}[i]"
        return f"smp_store_release(&shared.{vname1}[i], {vname2});"
    if isinstance(stmt, LoadAcquire):
        vname1 = var_name(stmt.reg, pid, params)
        vname2 = var_name(stmt.var, pid, params)
        return f"shared.{vname1}[i] = smp_load_acquire(&shared.{vname2}[i]);"
    print(stmt)
    return "// unhandled"

def generate_expr_rhs(expr, pid, params):
    if isinstance(expr[0], int):
        s = expr[0]
    else:
        s = f"shared.{var_name(expr[0], pid, params)}[i]"

    for op, right in expr[1:]:
        if isinstance(right, int):
            r = right
        else:
            r = f"shared.{var_name(right, pid, params)}[i]"
        s += f" {op} {r}"
    return s

def generate_if_condition(cond, name):
    if isinstance(cond, ConditionReg): return f"shared.{name}[i]"
    if isinstance(cond, ConditionEq): return f"shared.{name}[i] == {cond.val}"
    if isinstance(cond, ConditionNeq): return f"shared.{name}[i] != {cond.val}"
    return "UNKNOWN_COND"

def generate_bpf_c(litmus, bpf_header):

    bpf_header = bpf_header.replace('INTERNAL_ITERATIONS', str(VARIABLE_SIZE))
    bpf_code = f"""/* Auto-generated from {litmus.name}.litmus */
{bpf_header}
struct {{
"""
    for var in sorted(litmus.variables):
        bpf_code += f"\tvolatile __u64 {var}[{VARIABLE_SIZE}];\n"
    bpf_code += "} shared;\n\n"
    bpf_code += f"int num_threads = {len(litmus.processes)};\n"

    for proc in litmus.processes:
        proc_id = proc.pid
        param_names = [x[1] for x in proc.params]
        statements_code = "\n\t\t".join(
    		stmt for stmt in (generate_bpf_stmt(stmt, proc.pid, param_names) for stmt in proc.statements)
    		if stmt is not None
		)

        bpf_code += f"""\n// Program for P{proc_id}
SEC("raw_tp/test_prog{proc_id}")
int handle_tp{proc_id}(void *ctx)
{{
		__u32 local_sense = 0;
        int i;
        bpf_sense_barrier(&local_sense, num_threads);
        smp_mb();
        bpf_for (i, 0, {VARIABLE_SIZE}) {{
                barrier_wait({proc_id}, i);
                {statements_code}
        }}
        smp_mb();
        return 0;
}}
"""
    return bpf_code

def convert_var(v):
        if v.startswith("P") and "_" in v:
            p, reg = v[1:].split("_", 1)
            return f'{p}:{reg}'
        else:
            return v

def generate_user_c(litmus, user_header, user_footer, file_name):

    cond_vars = sorted(litmus.cond_variables)
    num_cond_vars = len (cond_vars)

    variables_code = "\n\t" + "\n\t".join(
    	[f"unsigned long long {var} = skel->bss->shared.{var}[c];" for var in cond_vars]
	)

    keys_code = "\n\t" + "\n\t".join(
    	[f"key_values[{i}] = skel->bss->shared.{var}[c];" for i, var in enumerate(cond_vars)]
	)

    entries = [f'"{convert_var(v)}"' for v in cond_vars]
    names_array = f'const char *cond_vars_str[{len(entries)}] = {{{", ".join(entries)}}};'

    user_code = f"""/* Auto-generated from {litmus.name}.litmus */
{user_header}
#include "{file_name}.skel.h"
#define THREADS {len(litmus.processes)}
#define TEST_NAME {file_name}
#define TEST_NAME_PRINT "{litmus.name}"
#define EXISTS_CLAUSE "{litmus.clause}"
#define INTERNAL_ITERATIONS {VARIABLE_SIZE}
#define NUM_KEYS {num_cond_vars}

struct record {{
        long long key[NUM_KEYS];
        unsigned long long count;
        bool target;
        UT_hash_handle hh;
}};

{names_array}

struct record *records = NULL;

bool expected = true;

void update_record(long long *key_values, bool target);

static void check_cond (STRUCT_NAME(TEST_NAME) *skel, unsigned long long *matches,
                        unsigned long long *non_matches, int c) {{
{variables_code}

        bool target = false;
        long long key_values[NUM_KEYS] = {{0}};

{keys_code}

        // Check if this iteration matches the exists clause
        if ({litmus.exists_c}) {{
                *matches += 1;
                target = true;
        }} else {{
                *non_matches += 1;
        }}
        update_record(key_values, target);
}}

{user_footer}
"""

    return user_code

# ---------- Main CLI ----------

def strip_comments(text):
    # Remove ML-style comments: (* ... *) including multiline
    # Only match when (* appears at start of line or after whitespace
    text = re.sub(r'(?<=\s)\(\*.*?\*\)|^\(\*.*?\*\)', '', text, flags=re.DOTALL | re.MULTILINE)

    # Remove C++-style comments: // ... (to end of line)
    text = re.sub(r'//.*?(?=\n|$)', '', text, flags=re.MULTILINE)

    # Remove locations [0:r1; 1:r3; x; y]
    text = re.sub(r'^locations.*$', '', text, flags=re.MULTILINE)

    return text

def parse_litmus(path):
    parser = Lark(LITMUS_GRAMMAR, parser="lalr", lexer="contextual", transformer=LitmusTransformer())
    tree = parser.parse(strip_comments(open(path).read()))
    return tree

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("litmus_file", help="Input litmus test file")
    parser.add_argument("out_dir", help="Output directory")
    args = parser.parse_args()

    litmus = parse_litmus(args.litmus_file)
    os.makedirs(args.out_dir, exist_ok=True)
    file_name = litmus.name.lower().replace('+', '_').replace('-','_')
    out_bpf_file = os.path.join(args.out_dir, file_name + ".bpf.c")
    out_user_file = os.path.join(args.out_dir, file_name + ".c")
    bpf_header_f = os.path.join(f"{os.getcwd()}/template/", "bpf_header")
    user_header_f = os.path.join(f"{os.getcwd()}/template/", "user_header")
    user_footer_f = os.path.join(f"{os.getcwd()}/template/", "user_footer")

    with open(bpf_header_f, 'r') as f:
        bpf_header = f.read()
    with open(user_header_f, 'r') as f:
        user_header = f.read()
    with open(user_footer_f, 'r') as f:
        user_footer = f.read()

    bpf_code = generate_bpf_c(litmus, bpf_header)
    user_code = generate_user_c(litmus, user_header, user_footer, file_name)

    with open(out_bpf_file, "w") as f:
        f.write("// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n")
        f.write(bpf_code)

    with open(out_user_file, "w") as f:
        f.write("// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause\n")
        f.write(user_code)

    print(f"Generated BPF C file: {out_bpf_file}")
    print(f"Generated Userspace C file: {out_user_file}")

if __name__ == "__main__":
    main()
