# MINIKRAN

[![License: AGPL-3.0-or-later OR Apache-2.0](https://img.shields.io/badge/license-AGPL--3.0--or--later%20OR%20Apache--2.0-blue.svg)](LICENSE.md)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Lean 4](https://img.shields.io/badge/Lean-4.34%2B-purple.svg)](https://leanprover.github.io/)
[![CLONE_GATE](https://img.shields.io/badge/CLONE__GATE-AES256-black.svg)]()

**MINIKRAN** is a language and runtime for sealed Workroom task orchestration.

Programs are written in `.mkr` files with MINIKRAN's own syntax. The runtime kernel enforces fail-closed authorization, epoch-locked task lifecycle, checkpoint recovery, and a cryptographically chained WORM ledger.

---

## The Language

MINIKRAN is **not a Rust library**. It is a language with its own syntax, lexer, parser, and interpreter. Programs look like this:

```minikran
-- hello.mkr
workroom "production-wr" {
    license  "lic-abc123"
    scope    "compute"
    node     "node-7"
    expires  9999
    key      0xdeadbeef
    sig      0xcafebabe
}

ceiling { cpu: 16, mem: 32, store: 100, power: 50 }

task compute-sum {
    id       1
    priority 2
    budget   { cpu: 4, mem: 8, store: 10, power: 5 }
    deadline 8000
    input    #sha256:aabbccdd
    code     #sha256:11223344
    verify   proof
    recover  restore
}

spawn    compute-sum at 10
schedule compute-sum -> node:7
dispatch compute-sum @ node:7
checkpoint compute-sum epoch:1 -> cp:100
verify   compute-sum ok
commit   compute-sum
```

---

## Run

```bash
cargo build --release

# Run a program
./target/release/minikran run examples/hello.mkr

# Run and print the WORM ledger
./target/release/minikran ledger examples/recovery.mkr

# Syntax check only
./target/release/minikran check examples/multi_task.mkr

# Dump token stream
./target/release/minikran lex examples/hello.mkr
```

---

## Language Reference

### Top-level statements

| Statement | Syntax | Effect |
|-----------|--------|--------|
| `workroom` | `workroom "id" { license: "..." scope: "..." node: "..." expires: N key: 0x... sig: 0x... }` | Authorize the kernel for a sealed workroom |
| `ceiling` | `ceiling { cpu: N mem: N store: N power: N }` | Set resource ceiling |
| `task` | `task name { id: N priority: N budget { ... } deadline: N input: #hash code: #hash }` | Declare a task |
| `spawn` | `spawn name at TICK` | Create task, validate, advance clock |
| `schedule` | `schedule name -> node:N` | Queue task on a node |
| `dispatch` | `dispatch name @ node:N` | Pop from queue, start running, return epoch |
| `checkpoint` | `checkpoint name epoch:N -> cp:ID` | Save checkpoint |
| `verify` | `verify name ok \| reject` | Accept or reject completed task |
| `commit` | `commit name` | Seal committed to WORM ledger |
| `abort` | `abort name` | Abort rejected task |
| `fault` | `fault name epoch:N` | Mark task faulted |
| `recover` | `recover name` | Begin recovery |
| `restore` | `restore name <- cp:ID` | Restore from checkpoint |
| `retry` | `retry name -> node:N` | Re-queue after restore |
| `suspend` | `suspend name epoch:N` | Suspend running task |
| `resume` | `resume name epoch:N` | Resume suspended task |

### Task lifecycle

```
Created → Validated → Queued → Running → Checkpointed → Verifying → Committed
                                   ↓                         ↓
                                 Fault                    Rejected → Aborted
                                   ↓
                              Recovering → Restored → Retrying → Queued
```

### Comments

```minikran
-- single line comment
```

---

## Repository Layout

```
minikran/
├── src/
│   ├── lib.rs           # Runtime kernel (task states, WORM ledger, budget, auth)
│   ├── lexer.rs         # Tokenizer for .mkr source
│   ├── parser.rs        # AST types + recursive descent parser
│   ├── interpreter.rs   # AST interpreter — drives the runtime kernel
│   └── main.rs          # CLI: minikran run|check|lex|ledger <file.mkr>
├── formal/
│   └── Minikran.lean    # Lean 4 state-transition model
├── examples/
│   ├── hello.mkr        # Happy path: spawn → commit
│   ├── recovery.mkr     # Fault → recover → restore → retry → commit
│   └── multi_task.mkr   # Three tasks: one committed, one rejected, one committed
├── FORMAL_STATUS.md
└── LICENSE.md
```

---

## Formal Model

`formal/Minikran.lean` is a Lean 4 state-transition specification:

```bash
lean formal/Minikran.lean
# LEAN_OK — no errors
```

---

## Tests

```bash
cargo test
# test fails_closed                      ... ok
# test verification_and_worm_commit      ... ok
# test recovery_requeues_from_a_bound_checkpoint ... ok
```
