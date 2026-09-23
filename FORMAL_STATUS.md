# Formal status

`formal/Minikran.lean` is a Lean 4 model of the declared task-state transitions and is checked with `lean formal/Minikran.lean`.

It proves only facts about that model, including that a task has no direct `RUNNING → COMMITTED` transition. It does not prove the Rust implementation, cryptographic signature verification, WORM hardware, backend enforcement, or deployment configuration.

The Rust kernel therefore describes itself as **formally modeled**, not formally verified.
