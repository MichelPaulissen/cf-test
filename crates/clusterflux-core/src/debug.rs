use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ProcessId, TaskInstanceId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugParticipantKind {
    WasmTask,
    ControlledNativeCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugRuntimeState {
    Running,
    Frozen,
    Completed,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugParticipant {
    pub task: TaskInstanceId,
    pub name: String,
    pub kind: DebugParticipantKind,
    pub can_freeze: bool,
    pub state: DebugRuntimeState,
    pub stack_frames: Vec<String>,
    pub local_values: Vec<(String, String)>,
    pub task_args: Vec<(String, String)>,
    pub handles: Vec<(String, String)>,
    pub command_status: Option<String>,
    pub recent_output: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugStopReason {
    Breakpoint { task: TaskInstanceId, line: u32 },
    PauseRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadInspection {
    pub task: TaskInstanceId,
    pub name: String,
    pub stack_frames: Vec<String>,
    pub local_values: Vec<(String, String)>,
    pub task_args: Vec<(String, String)>,
    pub handles: Vec<(String, String)>,
    pub command_status: Option<String>,
    pub recent_output: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEpoch {
    pub process: ProcessId,
    pub epoch: u64,
    pub reason: DebugStopReason,
    participants: BTreeMap<TaskInstanceId, DebugParticipant>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugEpochError {
    #[error("no participant could freeze; `{task}` rejected the freeze request")]
    CannotFreeze { task: TaskInstanceId },
    #[error("participant `{0}` is not part of this debug epoch")]
    UnknownParticipant(TaskInstanceId),
    #[error("participant `{0}` did not acknowledge frozen state in this debug epoch")]
    ParticipantNotFrozen(TaskInstanceId),
}

impl DebugEpoch {
    pub fn all_stop(
        process: ProcessId,
        epoch: u64,
        reason: DebugStopReason,
        participants: Vec<DebugParticipant>,
    ) -> Result<Self, DebugEpochError> {
        let first_rejected = participants
            .iter()
            .find(|participant| {
                matches!(participant.state, DebugRuntimeState::Running) && !participant.can_freeze
            })
            .map(|participant| participant.task.clone());
        let participants: BTreeMap<_, _> = participants
            .into_iter()
            .map(|mut participant| {
                if matches!(participant.state, DebugRuntimeState::Running) {
                    participant.state = if participant.can_freeze {
                        DebugRuntimeState::Frozen
                    } else {
                        DebugRuntimeState::Failed(
                            "participant did not acknowledge frozen state before the debug deadline"
                                .to_owned(),
                        )
                    };
                }
                (participant.task.clone(), participant)
            })
            .collect();

        if !participants
            .values()
            .any(|participant| participant.state == DebugRuntimeState::Frozen)
        {
            return Err(DebugEpochError::CannotFreeze {
                task: first_rejected.unwrap_or_else(|| TaskInstanceId::from("debug-epoch")),
            });
        }

        Ok(Self {
            process,
            epoch,
            reason,
            participants,
        })
    }

    pub fn pause(
        process: ProcessId,
        epoch: u64,
        participants: Vec<DebugParticipant>,
    ) -> Result<Self, DebugEpochError> {
        Self::all_stop(process, epoch, DebugStopReason::PauseRequest, participants)
    }

    pub fn continue_all(&mut self) {
        for participant in self.participants.values_mut() {
            if participant.state == DebugRuntimeState::Frozen {
                participant.state = DebugRuntimeState::Running;
            }
        }
    }

    pub fn inspection(&self, task: &TaskInstanceId) -> Result<ThreadInspection, DebugEpochError> {
        let participant = self
            .participants
            .get(task)
            .ok_or_else(|| DebugEpochError::UnknownParticipant(task.clone()))?;
        if participant.state != DebugRuntimeState::Frozen {
            return Err(DebugEpochError::ParticipantNotFrozen(task.clone()));
        }
        Ok(ThreadInspection {
            task: participant.task.clone(),
            name: participant.name.clone(),
            stack_frames: participant.stack_frames.clone(),
            local_values: participant.local_values.clone(),
            task_args: participant.task_args.clone(),
            handles: participant.handles.clone(),
            command_status: participant.command_status.clone(),
            recent_output: participant.recent_output.clone(),
        })
    }

    pub fn participant_state(&self, task: &TaskInstanceId) -> Option<&DebugRuntimeState> {
        self.participants
            .get(task)
            .map(|participant| &participant.state)
    }

    pub fn thread_names(&self) -> Vec<String> {
        self.participants
            .values()
            .map(|participant| participant.name.clone())
            .collect()
    }

    pub fn all_threads_stopped(&self) -> bool {
        !self.participants.is_empty()
            && self
                .participants
                .values()
                .all(|participant| participant.state == DebugRuntimeState::Frozen)
    }

    pub fn partially_frozen(&self) -> bool {
        !self.all_threads_stopped()
            && self
                .participants
                .values()
                .any(|participant| participant.state == DebugRuntimeState::Frozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(task: &str, kind: DebugParticipantKind, can_freeze: bool) -> DebugParticipant {
        DebugParticipant {
            task: TaskInstanceId::from(task),
            name: task.to_owned(),
            kind,
            can_freeze,
            state: DebugRuntimeState::Running,
            stack_frames: vec![format!("{task}::run")],
            local_values: vec![("wasm_local_0".to_owned(), "I32(41)".to_owned())],
            task_args: vec![("target".to_owned(), "linux".to_owned())],
            handles: vec![("artifact".to_owned(), "artifact-1".to_owned())],
            command_status: Some("running".to_owned()),
            recent_output: vec!["building".to_owned()],
        }
    }

    #[test]
    fn breakpoint_creates_all_stop_debug_epoch_for_wasm_and_command_tasks() {
        let epoch = DebugEpoch::all_stop(
            ProcessId::from("process"),
            1,
            DebugStopReason::Breakpoint {
                task: TaskInstanceId::from("compile-linux"),
                line: 42,
            },
            vec![
                participant("main", DebugParticipantKind::WasmTask, true),
                participant(
                    "compile-linux",
                    DebugParticipantKind::ControlledNativeCommand,
                    true,
                ),
            ],
        )
        .unwrap();

        assert_eq!(
            epoch.participant_state(&TaskInstanceId::from("main")),
            Some(&DebugRuntimeState::Frozen)
        );
        assert_eq!(
            epoch.participant_state(&TaskInstanceId::from("compile-linux")),
            Some(&DebugRuntimeState::Frozen)
        );
    }

    #[test]
    fn debug_epoch_reports_failure_when_no_participant_can_freeze() {
        let error = DebugEpoch::pause(
            ProcessId::from("process"),
            1,
            vec![participant(
                "compile-linux",
                DebugParticipantKind::ControlledNativeCommand,
                false,
            )],
        )
        .unwrap_err();

        assert!(matches!(error, DebugEpochError::CannotFreeze { .. }));
    }

    #[test]
    fn debug_epoch_keeps_frozen_participants_when_another_participant_fails() {
        let epoch = DebugEpoch::pause(
            ProcessId::from("process"),
            1,
            vec![
                participant("main", DebugParticipantKind::WasmTask, true),
                participant(
                    "native",
                    DebugParticipantKind::ControlledNativeCommand,
                    false,
                ),
            ],
        )
        .unwrap();

        assert!(epoch.partially_frozen());
        assert!(!epoch.all_threads_stopped());
        assert!(matches!(
            epoch.participant_state(&TaskInstanceId::from("native")),
            Some(DebugRuntimeState::Failed(_))
        ));
        assert!(matches!(
            epoch.inspection(&TaskInstanceId::from("native")),
            Err(DebugEpochError::ParticipantNotFrozen(_))
        ));
    }

    #[test]
    fn continue_resumes_every_frozen_participant() {
        let mut epoch = DebugEpoch::pause(
            ProcessId::from("process"),
            1,
            vec![
                participant("main", DebugParticipantKind::WasmTask, true),
                participant("task", DebugParticipantKind::WasmTask, true),
            ],
        )
        .unwrap();

        epoch.continue_all();

        assert_eq!(
            epoch.participant_state(&TaskInstanceId::from("main")),
            Some(&DebugRuntimeState::Running)
        );
        assert_eq!(
            epoch.participant_state(&TaskInstanceId::from("task")),
            Some(&DebugRuntimeState::Running)
        );
    }

    #[test]
    fn inspection_exposes_stack_args_handles_command_status_and_output() {
        let epoch = DebugEpoch::pause(
            ProcessId::from("process"),
            1,
            vec![participant(
                "compile-linux",
                DebugParticipantKind::ControlledNativeCommand,
                true,
            )],
        )
        .unwrap();

        let inspection = epoch
            .inspection(&TaskInstanceId::from("compile-linux"))
            .unwrap();

        assert_eq!(inspection.stack_frames, vec!["compile-linux::run"]);
        assert_eq!(
            inspection.local_values[0],
            ("wasm_local_0".to_owned(), "I32(41)".to_owned())
        );
        assert_eq!(
            inspection.task_args[0],
            ("target".to_owned(), "linux".to_owned())
        );
        assert_eq!(
            inspection.handles[0],
            ("artifact".to_owned(), "artifact-1".to_owned())
        );
        assert_eq!(inspection.command_status, Some("running".to_owned()));
        assert_eq!(inspection.recent_output, vec!["building"]);
    }
}
