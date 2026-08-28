use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};

use crate::virtual_model::AdapterState;

use super::{
    client_user_request, coordinator_request, DebugEpochRecord, DebugEpochStatusRecord,
    TaskRestartRecord,
};

pub(super) fn coordinator_debug_epoch_request(
    state: &AdapterState,
    request: CoordinatorRequest,
) -> Result<CoordinatorResponse> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    coordinator_request(&coordinator, request)
}

pub(super) fn parse_debug_epoch_response(
    response: CoordinatorResponse,
) -> Result<DebugEpochRecord> {
    match response {
        CoordinatorResponse::DebugEpoch {
            epoch,
            command,
            affected_tasks,
            ..
        } => Ok(DebugEpochRecord {
            epoch,
            command,
            affected_tasks: affected_tasks.len(),
        }),
        _ => Err(anyhow!(
            "coordinator returned an unexpected debug epoch response"
        )),
    }
}

pub(super) fn wait_for_debug_epoch_state(
    state: &AdapterState,
    epoch: u64,
    frozen: bool,
) -> Result<DebugEpochStatusRecord> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let response = match coordinator_debug_epoch_request(
            state,
            client_user_request(
                state,
                CoordinatorRequest::InspectDebugEpoch {
                    tenant: state.tenant.to_string(),
                    project: state.project_id.to_string(),
                    actor_user: state.actor_user.to_string(),
                    process: state.process.to_string(),
                    epoch,
                },
            ),
        ) {
            Ok(response) => response,
            Err(error) if !frozen && debug_epoch_was_released(&error, state, epoch) => {
                return Ok(DebugEpochStatusRecord {
                    epoch,
                    command: "resume".to_owned(),
                    expected_tasks: 0,
                    acknowledgements: Vec::new(),
                    fully_frozen: false,
                    partially_frozen: false,
                    fully_resumed: true,
                    failed: false,
                    failure_messages: Vec::new(),
                });
            }
            Err(error) => return Err(error),
        };
        let status = parse_debug_epoch_status(response)?;
        if frozen && (status.fully_frozen || status.partially_frozen) {
            return Ok(status);
        }
        if status.failed {
            return Err(anyhow!(
                "debug epoch {epoch} participant failed: {}",
                status.failure_messages.join("; ")
            ));
        }
        if !frozen && status.fully_resumed {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "debug epoch {epoch} did not receive {}/{} signed participant acknowledgements for {} within 60 seconds",
                status.acknowledgements.len(),
                status.expected_tasks,
                if frozen { "frozen state" } else { "resumed state" }
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn debug_epoch_was_released(error: &anyhow::Error, state: &AdapterState, epoch: u64) -> bool {
    format!("{error:#}").contains(&format!(
        "debug epoch {epoch} is not active for {}",
        state.process
    ))
}

fn parse_debug_epoch_status(response: CoordinatorResponse) -> Result<DebugEpochStatusRecord> {
    match response {
        CoordinatorResponse::DebugEpochStatus {
            epoch,
            command,
            expected_tasks,
            acknowledgements,
            fully_frozen,
            partially_frozen,
            fully_resumed,
            failed,
            failure_messages,
            ..
        } => Ok(DebugEpochStatusRecord {
            epoch,
            command,
            expected_tasks: expected_tasks.len(),
            acknowledgements,
            fully_frozen,
            partially_frozen,
            fully_resumed,
            failed,
            failure_messages,
        }),
        _ => Err(anyhow!(
            "coordinator returned an unexpected debug epoch status response"
        )),
    }
}

pub(crate) fn parse_task_restart_response(
    response: CoordinatorResponse,
) -> Result<TaskRestartRecord> {
    match response {
        CoordinatorResponse::TaskRestart {
            accepted,
            restarted_task_instance,
            restarted_attempt_id,
            clean_boundary_available,
            requires_whole_process_restart,
            active_task,
            completed_event_observed,
            message,
            ..
        } => Ok(TaskRestartRecord {
            accepted,
            restarted_task_instance,
            restarted_attempt_id,
            clean_boundary_available,
            requires_whole_process_restart,
            active_task,
            completed_event_observed,
            message,
        }),
        _ => Err(anyhow!(
            "coordinator returned an unexpected task restart response"
        )),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::debug_epoch_was_released;
    use crate::virtual_model::AdapterState;

    #[test]
    fn accepts_epoch_release_after_an_accepted_resume() {
        let state = AdapterState {
            process: "vp-completed".into(),
            ..AdapterState::default()
        };

        assert!(debug_epoch_was_released(
            &anyhow!("coordinator protocol error: debug epoch 3 is not active for vp-completed"),
            &state,
            3,
        ));
        assert!(!debug_epoch_was_released(
            &anyhow!("coordinator protocol error: debug epoch 4 is not active for vp-completed"),
            &state,
            3,
        ));
        assert!(!debug_epoch_was_released(
            &anyhow!("coordinator protocol error: debug epoch 3 is not active for vp-other"),
            &state,
            3,
        ));
    }
}
