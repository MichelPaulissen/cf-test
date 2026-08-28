use std::collections::BTreeSet;

use clusterflux_core::SourceLocation;

use crate::CoordinatorServiceError;

use super::{DebugAcknowledgementState, DebugEpochRuntime};

pub(super) fn runtime_all_in_state(
    runtime: &DebugEpochRuntime,
    state: DebugAcknowledgementState,
) -> bool {
    !runtime.expected.is_empty()
        && runtime.expected.iter().all(|key| {
            runtime
                .acknowledgements
                .get(key)
                .is_some_and(|ack| ack.state == state)
        })
}

pub(super) fn validate_probe_symbols(
    probe_symbols: Vec<String>,
) -> Result<Vec<String>, CoordinatorServiceError> {
    if probe_symbols.len() > 128 {
        return Err(CoordinatorServiceError::Protocol(
            "debug breakpoint request exceeds 128 probe symbols".to_owned(),
        ));
    }
    let mut unique = BTreeSet::new();
    for symbol in probe_symbols {
        if symbol.trim().is_empty()
            || symbol.len() > 256
            || !symbol
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._:-/".contains(character))
        {
            return Err(CoordinatorServiceError::Protocol(
                "debug breakpoint probe symbol is invalid".to_owned(),
            ));
        }
        unique.insert(symbol);
    }
    Ok(unique.into_iter().collect())
}

pub(super) fn validate_debug_snapshot(
    stack_frames: &[String],
    local_values: &[(String, String)],
    task_args: &[(String, String)],
    handles: &[(String, String)],
    command_status: Option<&str>,
    recent_output: &[String],
    message: Option<&str>,
    current_source_location: Option<&SourceLocation>,
) -> Result<(), CoordinatorServiceError> {
    const MAX_ITEMS: usize = 128;
    const MAX_TEXT_BYTES: usize = 16 * 1024;
    if [
        stack_frames.len(),
        local_values.len(),
        task_args.len(),
        handles.len(),
        recent_output.len(),
    ]
    .into_iter()
    .any(|count| count > MAX_ITEMS)
    {
        return Err(CoordinatorServiceError::Protocol(
            "debug participant snapshot exceeds the 128-item field limit".to_owned(),
        ));
    }
    let text_bytes = stack_frames.iter().map(String::len).sum::<usize>()
        + local_values
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
        + task_args
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
        + handles
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
        + recent_output.iter().map(String::len).sum::<usize>()
        + command_status.map(str::len).unwrap_or(0)
        + message.map(str::len).unwrap_or(0)
        + current_source_location
            .map(|location| location.source_path.len() + location.probe_id.len() + 16)
            .unwrap_or(0);
    if text_bytes > MAX_TEXT_BYTES {
        return Err(CoordinatorServiceError::Protocol(format!(
            "debug participant snapshot is {text_bytes} bytes; maximum is {MAX_TEXT_BYTES}"
        )));
    }
    if current_source_location.is_some_and(|location| {
        location.source_path.is_empty()
            || location.source_path.len() > 512
            || location.source_path.starts_with('/')
            || location.source_path.split('/').any(|part| part == "..")
            || location.line == 0
            || location.column == Some(0)
            || location.probe_id.trim().is_empty()
            || location.probe_id.len() > 256
    }) {
        return Err(CoordinatorServiceError::Protocol(
            "debug participant source location is invalid".to_owned(),
        ));
    }
    Ok(())
}
