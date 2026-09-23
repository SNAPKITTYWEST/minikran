# MINIKRAN

Rust-only kernel for the Orbital Computing Stack task lifecycle.

The kernel implements `spawn`, `schedule`, `dispatch`, `suspend`, `resume`, `checkpoint`, `verify`, `commit`, `abort`, `fault`, `recover`, `restore`, and `retry`.

Execution is fail-closed. `Kernel::new` starts unauthorized; an application must supply a verifier for a complete, unexpired Workroom authorization record before it can spawn a task. No cryptographic implementation is supplied because no signed authorization record or trusted verification-key policy was provided.

`commit` is available only after a successful verification result and appends a commit event to the in-memory WORM-model ledger. It does not claim hardware-backed WORM persistence or cryptographic provenance.

## Checks

```powershell
cargo test
lean formal\Minikran.lean
```

The Lean file formally models the declared state transition relation. Its proof boundary is described in [FORMAL_STATUS.md](FORMAL_STATUS.md).

## License

This project is sealed under the supplied [RAW Workroom Sealed License](LICENSE.md). It is not initialized as a public Git repository and is not published to GitHub Pages.
