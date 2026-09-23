//! MINIKRAN: a fail-closed Rust orchestration kernel for sealed Workrooms.

use std::collections::{BTreeMap, VecDeque};

pub type TaskId = u64;
pub type NodeId = u32;
pub type CheckpointId = u64;
pub type Epoch = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Created,
    Validated,
    Queued,
    Running,
    Checkpointed,
    Verifying,
    Committed,
    Fault,
    Recovering,
    Restored,
    Retrying,
    Rejected,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub cpu: u64,
    pub memory: u64,
    pub storage: u64,
    pub power: u64,
}
impl Budget {
    pub const fn fits(self, limit: Self) -> bool {
        self.cpu <= limit.cpu
            && self.memory <= limit.memory
            && self.storage <= limit.storage
            && self.power <= limit.power
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskSpec {
    pub task_id: TaskId,
    pub parent_id: Option<TaskId>,
    pub priority: u8,
    pub budget: Budget,
    pub deadline_tick: u64,
    pub input_hash: [u8; 32],
    pub code_hash: [u8; 32],
    pub verification_policy: String,
    pub recovery_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub spec: TaskSpec,
    pub state: TaskState,
    pub epoch: Epoch,
    pub checkpoint_id: Option<CheckpointId>,
    pub assigned_node: Option<NodeId>,
    pub suspended: bool,
    verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub workroom_id: String,
    pub license_id: String,
    pub authorized_scope: String,
    pub authorized_node: String,
    pub expiration_tick: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
pub trait AuthorizationVerifier {
    fn verify(&self, record: &AuthorizationRecord) -> bool;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    workroom_id: String,
    authorized_node: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelError {
    Unauthorized,
    InvalidAuthorization,
    ExpiredAuthorization,
    DuplicateTask(TaskId),
    MissingTask(TaskId),
    InvalidState {
        task_id: TaskId,
        state: TaskState,
        operation: &'static str,
    },
    BudgetExceeded(TaskId),
    DeadlineElapsed(TaskId),
    LeaseMismatch(TaskId),
}

pub fn authorize<V: AuthorizationVerifier>(
    verifier: &V,
    record: AuthorizationRecord,
    now_tick: u64,
) -> Result<Authorization, KernelError> {
    if record.workroom_id.is_empty()
        || record.license_id.is_empty()
        || record.authorized_scope.is_empty()
        || record.authorized_node.is_empty()
        || record.public_key.is_empty()
        || record.signature.is_empty()
    {
        return Err(KernelError::InvalidAuthorization);
    }
    if record.expiration_tick <= now_tick {
        return Err(KernelError::ExpiredAuthorization);
    }
    if !verifier.verify(&record) {
        return Err(KernelError::InvalidAuthorization);
    }
    Ok(Authorization {
        workroom_id: record.workroom_id,
        authorized_node: record.authorized_node,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerKind {
    Transition,
    Commit,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEvent {
    pub sequence: u64,
    pub task_id: TaskId,
    pub epoch: Epoch,
    pub kind: LedgerKind,
    pub from: TaskState,
    pub to: TaskState,
    pub previous_seal: u64,
    pub seal: u64,
}
#[derive(Default, Debug)]
pub struct WormLedger {
    events: Vec<LedgerEvent>,
}
impl WormLedger {
    pub fn events(&self) -> &[LedgerEvent] {
        &self.events
    }
    pub fn valid_chain(&self) -> bool {
        let mut prior = 0;
        self.events.iter().enumerate().all(|(index, e)| {
            let valid = e.sequence == index as u64 && e.previous_seal == prior;
            prior = e.seal;
            valid
        })
    }
    fn append(&mut self, task: &Task, kind: LedgerKind, from: TaskState, to: TaskState) {
        let previous_seal = self.events.last().map_or(0, |e| e.seal);
        let sequence = self.events.len() as u64;
        let seal = mix(sequence ^ task.spec.task_id ^ task.epoch ^ previous_seal ^ to as u64);
        self.events.push(LedgerEvent {
            sequence,
            task_id: task.spec.task_id,
            epoch: task.epoch,
            kind,
            from,
            to,
            previous_seal,
            seal,
        });
    }
}
fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ value >> 31
}

pub struct Kernel {
    authorization: Option<Authorization>,
    ceiling: Budget,
    tasks: BTreeMap<TaskId, Task>,
    queues: BTreeMap<NodeId, VecDeque<TaskId>>,
    pub ledger: WormLedger,
}
impl Kernel {
    pub fn new(ceiling: Budget) -> Self {
        Self {
            authorization: None,
            ceiling,
            tasks: BTreeMap::new(),
            queues: BTreeMap::new(),
            ledger: WormLedger::default(),
        }
    }
    pub fn admit(&mut self, authorization: Authorization) {
        self.authorization = Some(authorization);
    }
    pub fn task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.get(&id)
    }
    pub fn spawn(&mut self, spec: TaskSpec, now: u64) -> Result<(), KernelError> {
        self.guard()?;
        if self.tasks.contains_key(&spec.task_id) {
            return Err(KernelError::DuplicateTask(spec.task_id));
        }
        if !spec.budget.fits(self.ceiling) {
            return Err(KernelError::BudgetExceeded(spec.task_id));
        }
        if spec.deadline_tick <= now {
            return Err(KernelError::DeadlineElapsed(spec.task_id));
        }
        let id = spec.task_id;
        self.tasks.insert(
            id,
            Task {
                spec,
                state: TaskState::Created,
                epoch: 0,
                checkpoint_id: None,
                assigned_node: None,
                suspended: false,
                verified: false,
            },
        );
        self.transition(id, TaskState::Validated, LedgerKind::Transition, "validate")
    }
    pub fn schedule(&mut self, id: TaskId, node: NodeId) -> Result<(), KernelError> {
        self.guard()?;
        self.transition(id, TaskState::Queued, LedgerKind::Transition, "schedule")?;
        self.queues.entry(node).or_default().push_back(id);
        self.tasks
            .get_mut(&id)
            .ok_or(KernelError::MissingTask(id))?
            .assigned_node = Some(node);
        Ok(())
    }
    pub fn dispatch(&mut self, id: TaskId, node: NodeId) -> Result<Epoch, KernelError> {
        self.guard()?;
        if self.queues.get_mut(&node).and_then(|q| q.pop_front()) != Some(id) {
            return Err(KernelError::LeaseMismatch(id));
        }
        self.transition(id, TaskState::Running, LedgerKind::Transition, "dispatch")?;
        let task = self
            .tasks
            .get_mut(&id)
            .ok_or(KernelError::MissingTask(id))?;
        task.epoch += 1;
        Ok(task.epoch)
    }
    pub fn suspend(&mut self, id: TaskId, epoch: Epoch) -> Result<(), KernelError> {
        self.guard()?;
        self.lease(id, epoch, "suspend")?.suspended = true;
        Ok(())
    }
    pub fn resume(&mut self, id: TaskId, epoch: Epoch) -> Result<(), KernelError> {
        self.guard()?;
        self.lease(id, epoch, "resume")?.suspended = false;
        Ok(())
    }
    pub fn checkpoint(
        &mut self,
        id: TaskId,
        epoch: Epoch,
        checkpoint: CheckpointId,
    ) -> Result<(), KernelError> {
        self.guard()?;
        if self.lease(id, epoch, "checkpoint")?.suspended {
            return Err(KernelError::InvalidState {
                task_id: id,
                state: TaskState::Running,
                operation: "checkpoint",
            });
        }
        self.transition(
            id,
            TaskState::Checkpointed,
            LedgerKind::Transition,
            "checkpoint",
        )?;
        self.tasks
            .get_mut(&id)
            .ok_or(KernelError::MissingTask(id))?
            .checkpoint_id = Some(checkpoint);
        Ok(())
    }
    pub fn verify(&mut self, id: TaskId, accepted: bool) -> Result<(), KernelError> {
        self.guard()?;
        self.transition(id, TaskState::Verifying, LedgerKind::Transition, "verify")?;
        if accepted {
            self.tasks
                .get_mut(&id)
                .ok_or(KernelError::MissingTask(id))?
                .verified = true;
            Ok(())
        } else {
            self.transition(id, TaskState::Rejected, LedgerKind::Transition, "reject")
        }
    }
    pub fn commit(&mut self, id: TaskId) -> Result<(), KernelError> {
        self.guard()?;
        let task = self.tasks.get(&id).ok_or(KernelError::MissingTask(id))?;
        if task.state != TaskState::Verifying || !task.verified {
            return Err(KernelError::InvalidState {
                task_id: id,
                state: task.state,
                operation: "commit",
            });
        }
        self.transition(id, TaskState::Committed, LedgerKind::Commit, "commit")
    }
    pub fn abort(&mut self, id: TaskId) -> Result<(), KernelError> {
        self.guard()?;
        self.transition(id, TaskState::Aborted, LedgerKind::Transition, "abort")
    }
    pub fn fault(&mut self, id: TaskId, epoch: Epoch) -> Result<(), KernelError> {
        self.guard()?;
        let task = self.tasks.get(&id).ok_or(KernelError::MissingTask(id))?;
        if !matches!(task.state, TaskState::Running | TaskState::Checkpointed) {
            return Err(KernelError::InvalidState {
                task_id: id,
                state: task.state,
                operation: "fault",
            });
        }
        if task.epoch != epoch {
            return Err(KernelError::LeaseMismatch(id));
        }
        self.transition(id, TaskState::Fault, LedgerKind::Transition, "fault")
    }
    pub fn recover(&mut self, id: TaskId) -> Result<(), KernelError> {
        self.guard()?;
        self.transition(id, TaskState::Recovering, LedgerKind::Transition, "recover")
    }
    pub fn restore(&mut self, id: TaskId, checkpoint: CheckpointId) -> Result<(), KernelError> {
        self.guard()?;
        if self
            .tasks
            .get(&id)
            .ok_or(KernelError::MissingTask(id))?
            .checkpoint_id
            != Some(checkpoint)
        {
            return Err(KernelError::LeaseMismatch(id));
        }
        self.transition(id, TaskState::Restored, LedgerKind::Transition, "restore")
    }
    pub fn retry(&mut self, id: TaskId, node: NodeId) -> Result<(), KernelError> {
        self.guard()?;
        self.transition(id, TaskState::Retrying, LedgerKind::Transition, "retry")?;
        self.transition(id, TaskState::Queued, LedgerKind::Transition, "schedule")?;
        self.queues.entry(node).or_default().push_back(id);
        Ok(())
    }
    fn guard(&self) -> Result<(), KernelError> {
        self.authorization
            .as_ref()
            .map_or(Err(KernelError::Unauthorized), |_| Ok(()))
    }
    fn lease(
        &mut self,
        id: TaskId,
        epoch: Epoch,
        operation: &'static str,
    ) -> Result<&mut Task, KernelError> {
        let task = self
            .tasks
            .get_mut(&id)
            .ok_or(KernelError::MissingTask(id))?;
        if task.state != TaskState::Running {
            return Err(KernelError::InvalidState {
                task_id: id,
                state: task.state,
                operation,
            });
        }
        if task.epoch != epoch {
            return Err(KernelError::LeaseMismatch(id));
        }
        Ok(task)
    }
    fn transition(
        &mut self,
        id: TaskId,
        next: TaskState,
        kind: LedgerKind,
        operation: &'static str,
    ) -> Result<(), KernelError> {
        let task = self.tasks.get(&id).ok_or(KernelError::MissingTask(id))?;
        if !allowed(task.state, next) {
            return Err(KernelError::InvalidState {
                task_id: id,
                state: task.state,
                operation,
            });
        }
        let prior = task.state;
        let snapshot = task.clone();
        self.ledger.append(&snapshot, kind, prior, next);
        self.tasks
            .get_mut(&id)
            .ok_or(KernelError::MissingTask(id))?
            .state = next;
        Ok(())
    }
}
const fn allowed(from: TaskState, to: TaskState) -> bool {
    matches!(
        (from, to),
        (TaskState::Created, TaskState::Validated)
            | (TaskState::Validated, TaskState::Queued)
            | (TaskState::Queued, TaskState::Running)
            | (TaskState::Running, TaskState::Checkpointed)
            | (TaskState::Checkpointed, TaskState::Verifying)
            | (TaskState::Verifying, TaskState::Committed)
            | (TaskState::Verifying, TaskState::Rejected)
            | (TaskState::Rejected, TaskState::Aborted)
            | (TaskState::Running, TaskState::Fault)
            | (TaskState::Checkpointed, TaskState::Fault)
            | (TaskState::Fault, TaskState::Recovering)
            | (TaskState::Recovering, TaskState::Restored)
            | (TaskState::Restored, TaskState::Retrying)
            | (TaskState::Retrying, TaskState::Queued)
            | (TaskState::Fault, TaskState::Aborted)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestVerifier;
    impl AuthorizationVerifier for TestVerifier {
        fn verify(&self, _: &AuthorizationRecord) -> bool {
            true
        }
    }
    fn spec(id: TaskId) -> TaskSpec {
        TaskSpec {
            task_id: id,
            parent_id: None,
            priority: 1,
            budget: Budget {
                cpu: 1,
                memory: 1,
                storage: 1,
                power: 1,
            },
            deadline_tick: 90,
            input_hash: [1; 32],
            code_hash: [2; 32],
            verification_policy: "proof".into(),
            recovery_policy: "restore".into(),
        }
    }
    fn kernel() -> Kernel {
        let record = AuthorizationRecord {
            workroom_id: "wr-1".into(),
            license_id: "lic-1".into(),
            authorized_scope: "research".into(),
            authorized_node: "node-1".into(),
            expiration_tick: 100,
            public_key: vec![1],
            signature: vec![2],
        };
        let mut k = Kernel::new(Budget {
            cpu: 2,
            memory: 2,
            storage: 2,
            power: 2,
        });
        k.admit(authorize(&TestVerifier, record, 1).unwrap());
        k
    }
    #[test]
    fn fails_closed() {
        assert_eq!(
            Kernel::new(Budget {
                cpu: 1,
                memory: 1,
                storage: 1,
                power: 1
            })
            .spawn(spec(1), 1),
            Err(KernelError::Unauthorized)
        );
    }
    #[test]
    fn verification_and_worm_commit() {
        let mut k = kernel();
        k.spawn(spec(1), 1).unwrap();
        k.schedule(1, 7).unwrap();
        let e = k.dispatch(1, 7).unwrap();
        k.checkpoint(1, e, 3).unwrap();
        k.verify(1, true).unwrap();
        k.commit(1).unwrap();
        assert_eq!(k.task(1).unwrap().state, TaskState::Committed);
        assert!(k.ledger.valid_chain());
        assert!(matches!(
            k.ledger.events().last().unwrap().kind,
            LedgerKind::Commit
        ));
    }
    #[test]
    fn recovery_requeues_from_a_bound_checkpoint() {
        let mut k = kernel();
        k.spawn(spec(2), 1).unwrap();
        k.schedule(2, 7).unwrap();
        let e = k.dispatch(2, 7).unwrap();
        k.checkpoint(2, e, 8).unwrap();
        k.fault(2, e).unwrap();
        k.recover(2).unwrap();
        k.restore(2, 8).unwrap();
        k.retry(2, 7).unwrap();
        assert_eq!(k.dispatch(2, 7).unwrap(), e + 1);
    }
}
