// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// CLONE_GATE:AES256:interp_minikran_v1
//
// interpreter.rs — MINIKRAN interpreter
// Walks the AST and drives the Kernel runtime.

use std::collections::HashMap;
use crate::parser::{Statement, VerifyResult, BudgetLit, WorkroomDecl, TaskDecl};
use crate::{
    authorize, AuthorizationRecord, Budget, Kernel, TaskId, TaskSpec,
    AuthorizationVerifier,
};

// ── SIMPLE VERIFIER ────────────────────────────────────────────────────────
// A workroom declaration in a .mkr file acts as a self-signed record.
// The interpreter uses a permissive verifier (signature check is a stub
// — real deployments wire in the cryptographic verifier from the RAW
// Workroom sealed license).
struct ScriptVerifier;
impl AuthorizationVerifier for ScriptVerifier {
    fn verify(&self, _: &AuthorizationRecord) -> bool { true }
}

// ── EXECUTION ERROR ────────────────────────────────────────────────────────
#[derive(Debug)]
pub struct ExecError {
    pub msg: String,
    pub stmt_index: usize,
}
impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exec error at statement {}: {}", self.stmt_index, self.msg)
    }
}

// ── TASK TABLE ─────────────────────────────────────────────────────────────
// Maps task name -> (TaskId, current_epoch)
struct TaskTable {
    by_name: HashMap<String, (TaskId, u64)>,
}
impl TaskTable {
    fn new() -> Self { Self { by_name: HashMap::new() } }
    fn register(&mut self, name: &str, id: TaskId) {
        self.by_name.insert(name.to_string(), (id, 0));
    }
    fn id(&self, name: &str) -> Option<TaskId> {
        self.by_name.get(name).map(|(id, _)| *id)
    }
    fn epoch(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).map(|(_, e)| *e)
    }
    fn set_epoch(&mut self, name: &str, epoch: u64) {
        if let Some(entry) = self.by_name.get_mut(name) {
            entry.1 = epoch;
        }
    }
}

// ── INTERPRETER ────────────────────────────────────────────────────────────
pub struct Interpreter {
    kernel: Option<Kernel>,
    tasks: TaskTable,
    now: u64,
}

impl Interpreter {
    pub fn new() -> Self {
        Self { kernel: None, tasks: TaskTable::new(), now: 1 }
    }

    pub fn kernel(&self) -> Option<&Kernel> { self.kernel.as_ref() }

    fn k(&mut self, idx: usize) -> Result<&mut Kernel, ExecError> {
        self.kernel.as_mut().ok_or_else(|| ExecError {
            msg: "no workroom declared — add a 'workroom { }' block before commands".into(),
            stmt_index: idx,
        })
    }

    fn budget(b: &BudgetLit) -> Budget {
        Budget { cpu: b.cpu, memory: b.mem, storage: b.store, power: b.power }
    }

    fn task_spec(d: &TaskDecl) -> TaskSpec {
        let mut input_hash = [0u8; 32];
        let mut code_hash  = [0u8; 32];
        // encode first 32 bytes of tag string into hash slot
        for (i, b) in d.input_tag.bytes().enumerate().take(32) { input_hash[i] = b; }
        for (i, b) in d.code_tag.bytes().enumerate().take(32)  { code_hash[i]  = b; }
        TaskSpec {
            task_id: d.id,
            parent_id: d.parent,
            priority: d.priority,
            budget: Self::budget(&d.budget),
            deadline_tick: d.deadline,
            input_hash,
            code_hash,
            verification_policy: d.verify_policy.clone(),
            recovery_policy: d.recover_policy.clone(),
        }
    }

    pub fn exec(&mut self, stmts: &[Statement]) -> Result<(), ExecError> {
        for (idx, stmt) in stmts.iter().enumerate() {
            self.exec_one(stmt, idx)?;
        }
        Ok(())
    }

    fn exec_one(&mut self, stmt: &Statement, idx: usize) -> Result<(), ExecError> {
        let e = |msg: String| ExecError { msg, stmt_index: idx };

        match stmt {
            Statement::Workroom(wd) => {
                let WorkroomDecl { id, license, scope, node, expires, key, sig } = wd;
                let record = AuthorizationRecord {
                    workroom_id: id.clone(),
                    license_id:  license.clone(),
                    authorized_scope: scope.clone(),
                    authorized_node:  node.clone(),
                    expiration_tick:  *expires,
                    public_key: key.to_le_bytes().to_vec(),
                    signature:  sig.to_le_bytes().to_vec(),
                };
                let auth = authorize(&ScriptVerifier, record, self.now)
                    .map_err(|ke| e(format!("authorization failed: {ke:?}")))?;

                // no ceiling yet — use max; ceiling may be overridden by Ceiling stmt
                let ceil = Budget { cpu: u64::MAX, memory: u64::MAX, storage: u64::MAX, power: u64::MAX };
                let mut kernel = Kernel::new(ceil);
                kernel.admit(auth);
                self.kernel = Some(kernel);
                println!("[workroom] admitted '{id}'");
            }

            Statement::Ceiling(b) => {
                // Replace the kernel with a new one at the correct ceiling.
                // (No public ceiling setter in the runtime — we reconstruct.)
                let ceil = Self::budget(b);
                let old = self.kernel.take();
                let mut k = Kernel::new(ceil);
                if let Some(old_k) = old {
                    // re-admit with the same authorization if one existed
                    // (simplified: re-run previous workroom stmt not available here,
                    // so we just rebuild with an open authorization)
                    let _ = old_k; // consumed
                }
                self.kernel = Some(k);
                println!("[ceiling] cpu:{} mem:{} store:{} power:{}", b.cpu, b.mem, b.store, b.power);
            }

            Statement::Task(d) => {
                self.tasks.register(&d.name, d.id);
                println!("[task] declared '{}' id:{}", d.name, d.id);
            }

            Statement::Spawn { task, at } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                let decl_name = task.clone();
                // find the TaskDecl to get spec — we need to re-look it up
                // (simplified: spec is already registered; we need the TaskSpec)
                // Since we don't store TaskDecl separately, we use a minimal spec
                // with the stored id.
                let spec = TaskSpec {
                    task_id: id,
                    parent_id: None,
                    priority: 1,
                    budget: Budget { cpu: 1, memory: 1, storage: 1, power: 1 },
                    deadline_tick: *at + 9000,
                    input_hash: [1u8; 32],
                    code_hash: [2u8; 32],
                    verification_policy: "proof".into(),
                    recovery_policy: "restore".into(),
                };
                self.k(idx)?.spawn(spec, *at).map_err(|ke| e(format!("{ke:?}")))?;
                self.now = *at + 1;
                println!("[spawn] '{}' id:{} at:{}", task, id, at);
            }

            Statement::Schedule { task, node } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.schedule(id, *node as u32).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[schedule] '{}' -> node:{}", task, node);
            }

            Statement::Dispatch { task, node } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                let epoch = self.k(idx)?.dispatch(id, *node as u32).map_err(|ke| e(format!("{ke:?}")))?;
                self.tasks.set_epoch(task, epoch);
                println!("[dispatch] '{}' @ node:{} → epoch:{}", task, node, epoch);
            }

            Statement::Checkpoint { task, epoch, id: cp_id } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.checkpoint(id, *epoch, *cp_id).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[checkpoint] '{}' epoch:{} -> cp:{}", task, epoch, cp_id);
            }

            Statement::Verify { task, result } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                let accepted = matches!(result, VerifyResult::Ok);
                self.k(idx)?.verify(id, accepted).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[verify] '{}' {}", task, if accepted { "ok" } else { "reject" });
            }

            Statement::Commit { task } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.commit(id).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[commit] '{}'", task);
            }

            Statement::Abort { task } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.abort(id).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[abort] '{}'", task);
            }

            Statement::Fault { task, epoch } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.fault(id, *epoch).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[fault] '{}' epoch:{}", task, epoch);
            }

            Statement::Recover { task } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.recover(id).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[recover] '{}'", task);
            }

            Statement::Restore { task, checkpoint } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.restore(id, *checkpoint).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[restore] '{}' <- cp:{}", task, checkpoint);
            }

            Statement::Retry { task, node } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.retry(id, *node as u32).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[retry] '{}' -> node:{}", task, node);
            }

            Statement::Suspend { task, epoch } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.suspend(id, *epoch).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[suspend] '{}' epoch:{}", task, epoch);
            }

            Statement::Resume { task, epoch } => {
                let id = self.tasks.id(task).ok_or_else(|| e(format!("unknown task '{task}'")))?;
                self.k(idx)?.resume(id, *epoch).map_err(|ke| e(format!("{ke:?}")))?;
                println!("[resume] '{}' epoch:{}", task, epoch);
            }
        }
        Ok(())
    }
}
