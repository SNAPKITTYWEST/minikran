// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// CLONE_GATE:AES256:main_minikran_v1
//
// main.rs — MINIKRAN CLI
//
// Usage:
//   minikran run hello.mkr
//   minikran check hello.mkr      (parse only, no execute)
//   minikran lex hello.mkr        (dump tokens)
//   minikran ledger hello.mkr     (run + print WORM ledger)

mod lexer;
mod parser;
mod interpreter;

// re-export runtime types so interpreter can use them without super::
pub use crate::lib_impl::*;
mod lib_impl {
    pub use super::runtime::*;
}
mod runtime {
    include!("lib.rs");
}

use std::{fs, process};

fn usage() -> ! {
    eprintln!("Usage: minikran <run|check|lex|ledger> <file.mkr>");
    process::exit(1)
}

fn run_file(path: &str, execute: bool, dump_ledger: bool) -> Result<(), String> {
    let src = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {path}: {e}"))?;

    // Lex
    let mut lex = lexer::Lexer::new(&src);
    let tokens = lex.tokenize().map_err(|e| e.to_string())?;

    // Parse
    let mut parser = parser::Parser::new(tokens);
    let stmts = parser.parse_program().map_err(|e| e.to_string())?;
    println!("[minikran] parsed {} statements from '{path}'", stmts.len());

    if !execute { return Ok(()); }

    // Execute
    let mut interp = interpreter::Interpreter::new();
    interp.exec(&stmts).map_err(|e| e.to_string())?;

    if dump_ledger {
        if let Some(k) = interp.kernel() {
            println!("\n── WORM LEDGER ──────────────────────────────────");
            for ev in k.ledger.events() {
                println!("  seq:{:>4}  task:{:>4}  epoch:{:>3}  {:?} → {:?}  [{:?}]  seal:{:#018x}",
                    ev.sequence, ev.task_id, ev.epoch,
                    ev.from, ev.to, ev.kind, ev.seal);
            }
            println!("  chain valid: {}", k.ledger.valid_chain());
            println!("─────────────────────────────────────────────────");
        }
    }
    Ok(())
}

fn lex_file(path: &str) -> Result<(), String> {
    let src = fs::read_to_string(path).map_err(|e| format!("{e}"))?;
    let mut lex = lexer::Lexer::new(&src);
    let tokens = lex.tokenize().map_err(|e| e.to_string())?;
    for t in &tokens {
        println!("{:>4}:{:>3}  {:?}", t.span.line, t.span.col, t.tok);
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 { usage(); }
    let cmd  = args[1].as_str();
    let file = args[2].as_str();

    let result = match cmd {
        "run"    => run_file(file, true,  false),
        "check"  => run_file(file, false, false),
        "ledger" => run_file(file, true,  true),
        "lex"    => lex_file(file),
        _        => { eprintln!("unknown command '{cmd}'"); usage() }
    };

    if let Err(e) = result {
        eprintln!("[error] {e}");
        process::exit(1);
    }
}
