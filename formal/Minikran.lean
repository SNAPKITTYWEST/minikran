/-! A checked model of MINIKRAN's stated task transitions. -/

inductive State where
  | created | validated | queued | running | checkpointed | verifying
  | committed | fault | recovering | restored | retrying | rejected | aborted
  deriving DecidableEq

inductive Step : State → State → Prop where
  | validate : Step .created .validated
  | schedule : Step .validated .queued
  | dispatch : Step .queued .running
  | checkpoint : Step .running .checkpointed
  | verify : Step .checkpointed .verifying
  | commit : Step .verifying .committed
  | reject : Step .verifying .rejected
  | abort_rejected : Step .rejected .aborted
  | fault : Step .running .fault
  | recover : Step .fault .recovering
  | restore : Step .recovering .restored
  | retry : Step .restored .retrying
  | requeue : Step .retrying .queued

theorem no_direct_commit : ¬ Step State.running State.committed := by
  intro h
  cases h

theorem commit_requires_verifying : Step State.verifying State.committed := Step.commit

theorem recovery_path_starts_from_fault : Step State.fault State.recovering := Step.recover
