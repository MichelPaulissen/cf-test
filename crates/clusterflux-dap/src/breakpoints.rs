use std::collections::BTreeSet;
use std::fs;

use clusterflux_core::{
    discover_source_debug_probes, BundleDebugProbe, DebugRuntimeState, SourceLocation,
    TaskInstanceId,
};
use serde_json::{json, Value};

use crate::demo_backend::{LINUX_THREAD, MAIN_THREAD, PACKAGE_THREAD, WINDOWS_THREAD};
use crate::virtual_model::{AdapterState, VirtualThread};

pub(crate) fn request_thread<'a>(request: &Value, state: &'a AdapterState) -> &'a VirtualThread {
    let thread_id = request_thread_id(request).unwrap_or(MAIN_THREAD);
    state
        .threads
        .get(&thread_id)
        .unwrap_or_else(|| &state.threads[&MAIN_THREAD])
}

pub(crate) fn request_thread_id(request: &Value) -> Option<i64> {
    request
        .get("arguments")
        .and_then(|value| value.get("threadId"))
        .and_then(Value::as_i64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedBreakpoint {
    pub(crate) id: usize,
    pub(crate) line: i64,
    pub(crate) column: Option<i64>,
    pub(crate) verified: bool,
    pub(crate) message: String,
}

impl ResolvedBreakpoint {
    pub(crate) fn to_dap(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "verified": self.verified,
            "line": self.line,
            "message": self.message,
        });
        if let Some(column) = self.column {
            value["column"] = json!(column);
        }
        value
    }
}

pub(crate) fn load_bundle_debug_model(
    project: &str,
    fallback_source_path: &str,
) -> (BTreeSet<String>, Vec<BundleDebugProbe>) {
    let mut inventory = latest_compiled_source_inventory(project).unwrap_or_else(|| {
        BTreeSet::from([crate::source::repository_relative_source_path(
            project,
            fallback_source_path,
        )
        .unwrap_or_else(|| fallback_source_path.to_owned())])
    });
    let mut probes = Vec::new();
    for relative in &inventory {
        let path = crate::source::resolve_source_path(project, relative);
        let Ok(source) = fs::read_to_string(path) else {
            continue;
        };
        probes.extend(discover_source_debug_probes(relative, &source));
    }
    if let Some(sidecar) = latest_compiled_debug_sidecar(project) {
        let symbols = ["task_descriptors", "entrypoint_descriptors"]
            .into_iter()
            .flat_map(|field| {
                sidecar
                    .get(field)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(|descriptor| {
                Some((
                    (
                        descriptor.get("function")?.as_str()?.to_owned(),
                        descriptor.get("name")?.as_str()?.to_owned(),
                    ),
                    descriptor.get("probe_symbol")?.as_str()?.to_owned(),
                ))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for probe in &mut probes {
            if let Some(symbol) = symbols.get(&(probe.function.clone(), probe.task.to_string())) {
                probe.probe_symbol = symbol.clone();
            }
        }
    }
    inventory.retain(|path| path.starts_with(".clusterflux/") || path.starts_with("src/"));
    (inventory, probes)
}

fn latest_compiled_source_inventory(project: &str) -> Option<BTreeSet<String>> {
    let sidecar = latest_compiled_debug_sidecar(project)?;
    let paths = sidecar
        .get("source_inventory")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter(|path| {
            path.starts_with(".clusterflux/") && !path.contains("..") && !path.contains('\\')
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    (!paths.is_empty()).then_some(paths)
}

fn latest_compiled_debug_sidecar(project: &str) -> Option<Value> {
    let build_root = std::path::Path::new(project).join("target/clusterflux/build");
    let mut sidecars = fs::read_dir(build_root)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("debug-sidecar.json"))
        .filter(|path| path.is_file())
        .filter_map(|path| {
            let modified = fs::metadata(&path).ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect::<Vec<_>>();
    sidecars.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    let bytes = fs::read(&sidecars.first()?.1).ok()?;
    let sidecar: Value = serde_json::from_slice(&bytes).ok()?;
    if sidecar.get("format").and_then(Value::as_str) != Some("clusterflux-wasm-debug-v2") {
        return None;
    }
    Some(sidecar)
}

#[cfg(test)]
pub(crate) fn resolve_breakpoints(
    state: &mut AdapterState,
    requested_lines: Vec<i64>,
) -> Vec<ResolvedBreakpoint> {
    let resolved = requested_lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            let probe = debug_probe_for_line(state, line);
            let verified = probe.is_some()
                || (state.debug_probes.is_empty()
                    && source_function_name_at_line(state, line).is_some());
            let message = match probe {
                Some(probe) => format!(
                    "Mapped to Clusterflux debug probe {} for task {}",
                    probe.id, probe.task
                ),
                None if verified => "Mapped to Clusterflux virtual source location".to_owned(),
                None => "No Clusterflux debug probe metadata covers this source line".to_owned(),
            };
            ResolvedBreakpoint {
                id: index + 1,
                line,
                column: None,
                verified,
                message,
            }
        })
        .collect::<Vec<_>>();
    let source_path = state.source_path.clone();
    let locations = resolved
        .iter()
        .filter_map(|breakpoint| {
            let line = u32::try_from(breakpoint.line).ok()?;
            let probe = state.debug_probes.iter().find(|probe| {
                probe.source_path == source_path
                    && probe.line_start <= line
                    && line <= probe.line_end
            })?;
            Some(SourceLocation {
                source_path: source_path.clone(),
                line,
                column: None,
                probe_id: probe.probe_symbol.clone(),
            })
        })
        .collect();
    state.breakpoints_by_source.insert(source_path, locations);
    resolved
}

#[cfg(test)]
pub(crate) fn resolve_breakpoints_for_source(
    state: &mut AdapterState,
    requested_source_path: Option<&str>,
    requested_lines: Vec<i64>,
) -> Vec<ResolvedBreakpoint> {
    resolve_breakpoints_for_source_locations(
        state,
        requested_source_path,
        requested_lines
            .into_iter()
            .map(|line| (line, None))
            .collect(),
    )
}

pub(crate) fn resolve_breakpoints_for_source_locations(
    state: &mut AdapterState,
    requested_source_path: Option<&str>,
    requested_locations: Vec<(i64, Option<i64>)>,
) -> Vec<ResolvedBreakpoint> {
    if let Some(message) = state.source_mismatch.as_deref() {
        return unresolved_source_breakpoints(requested_locations, message);
    }
    let requested_source_path = requested_source_path.unwrap_or(&state.source_path);
    let Some(source_path) =
        crate::source::repository_relative_source_path(&state.project, requested_source_path)
    else {
        return unresolved_source_breakpoints(
            requested_locations,
            "Source path is outside the project",
        );
    };
    if !state.source_inventory.contains(&source_path) {
        return unresolved_source_breakpoints(
            requested_locations,
            "Source is not part of the compiled workflow source inventory",
        );
    }
    let resolved = requested_locations
        .into_iter()
        .enumerate()
        .map(|(index, (line, column))| {
            let probe = state.debug_probes.iter().find(|probe| {
                probe.source_path == source_path
                    && u32::try_from(line)
                        .is_ok_and(|line| probe.line_start <= line && line <= probe.line_end)
            });
            ResolvedBreakpoint {
                id: index + 1,
                line,
                column,
                verified: probe.is_some(),
                message: probe
                    .map(|probe| {
                        format!(
                            "Mapped to Clusterflux debug probe {} for task {}",
                            probe.id, probe.task
                        )
                    })
                    .unwrap_or_else(|| {
                        "No Clusterflux debug probe metadata covers this source line".to_owned()
                    }),
            }
        })
        .collect::<Vec<_>>();
    state.breakpoints_by_source.insert(
        source_path.clone(),
        resolved
            .iter()
            .filter_map(|breakpoint| {
                let line = u32::try_from(breakpoint.line).ok()?;
                let probe = state.debug_probes.iter().find(|probe| {
                    probe.source_path == source_path
                        && probe.line_start <= line
                        && line <= probe.line_end
                })?;
                Some(SourceLocation {
                    source_path: source_path.clone(),
                    line,
                    column: breakpoint
                        .column
                        .and_then(|column| u32::try_from(column).ok()),
                    probe_id: probe.probe_symbol.clone(),
                })
            })
            .collect(),
    );
    resolved
}

fn unresolved_source_breakpoints(
    requested_locations: Vec<(i64, Option<i64>)>,
    message: &str,
) -> Vec<ResolvedBreakpoint> {
    requested_locations
        .into_iter()
        .enumerate()
        .map(|(index, (line, column))| ResolvedBreakpoint {
            id: index + 1,
            line,
            column,
            verified: false,
            message: message.to_owned(),
        })
        .collect()
}

pub(crate) fn restart_requires_whole_process(request: &Value) -> bool {
    let Some(arguments) = request.get("arguments") else {
        return false;
    };

    arguments
        .get("requiresWholeProcessRestart")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || [
            "compatibility",
            "sourceCompatibility",
            "sourceEditCompatibility",
            "taskCompatibility",
        ]
        .iter()
        .filter_map(|field| arguments.get(field).and_then(Value::as_str))
        .any(is_incompatible_restart)
        || arguments
            .get("sourceEdit")
            .and_then(|value| value.get("compatibility"))
            .and_then(Value::as_str)
            .is_some_and(is_incompatible_restart)
}

fn is_incompatible_restart(value: &str) -> bool {
    value.eq_ignore_ascii_case("incompatible")
        || value.eq_ignore_ascii_case("whole-process")
        || value.eq_ignore_ascii_case("whole_process")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FreezeFailure {
    pub(crate) thread_id: i64,
    pub(crate) task: TaskInstanceId,
}

impl FreezeFailure {
    pub(crate) fn message(&self) -> String {
        format!(
            "debug all-stop failed: participant `{}` on thread {} could not freeze",
            self.task, self.thread_id
        )
    }
}

pub(crate) fn simulated_freeze_failure_thread(request: &Value) -> Option<i64> {
    request
        .get("arguments")
        .and_then(|arguments| arguments.get("simulateFreezeFailure"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then_some(PACKAGE_THREAD)
}

pub(crate) fn freeze_all(
    state: &mut AdapterState,
    stopped_thread: i64,
    forced_failure_thread: Option<i64>,
) -> Result<(), FreezeFailure> {
    let location = state
        .breakpoint_locations()
        .find(|location| thread_for_source_location(state, location) == stopped_thread)
        .or_else(|| state.breakpoint_locations().next())
        .cloned()
        .unwrap_or_else(|| SourceLocation {
            source_path: state.source_path.clone(),
            line: u32::try_from(state.threads[&stopped_thread].line).unwrap_or(1),
            column: None,
            probe_id: String::new(),
        });
    freeze_all_at_location(state, stopped_thread, location, forced_failure_thread)
}

pub(crate) fn freeze_all_at_location(
    state: &mut AdapterState,
    stopped_thread: i64,
    location: SourceLocation,
    forced_failure_thread: Option<i64>,
) -> Result<(), FreezeFailure> {
    if let Some(failure) = state.threads.values().find(|thread| {
        thread.state == DebugRuntimeState::Running
            && (!thread.freeze_supported || forced_failure_thread == Some(thread.id))
    }) {
        return Err(FreezeFailure {
            thread_id: failure.id,
            task: failure.task.clone(),
        });
    }

    state.epoch += 1;
    for thread in state.threads.values_mut() {
        if thread.state == DebugRuntimeState::Running {
            thread.state = DebugRuntimeState::Frozen;
        }
    }
    if let Some(thread) = state.threads.get_mut(&stopped_thread) {
        thread.line = i64::from(location.line);
        thread
            .recent_output
            .push(format!("debug epoch {} all-stop", state.epoch));
    }
    state.stopped_location = Some(location);
    Ok(())
}

pub(crate) fn stopped_thread_for_breakpoint(state: &AdapterState) -> i64 {
    if let Some(stopped_task) = state.stopped_task.as_ref() {
        if let Some(thread) = state
            .threads
            .values()
            .find(|thread| &thread.task == stopped_task)
        {
            return thread.id;
        }
    }
    state
        .breakpoint_locations()
        .next()
        .map(|location| thread_for_source_location(state, location))
        .unwrap_or(MAIN_THREAD)
}

pub(crate) fn position_confirmed_breakpoint_stop(state: &mut AdapterState, stopped_thread: i64) {
    let location = state
        .stopped_probe_symbol
        .as_deref()
        .and_then(|symbol| {
            let probe = state
                .debug_probes
                .iter()
                .find(|probe| probe.probe_symbol == symbol)?;
            state
                .breakpoint_locations()
                .find(|location| location.probe_id == probe.probe_symbol)
                .cloned()
        })
        .or_else(|| {
            state
                .breakpoint_locations()
                .find(|location| thread_for_source_location(state, location) == stopped_thread)
                .cloned()
        })
        .or_else(|| state.breakpoint_locations().next().cloned());
    if let (Some(location), Some(thread)) = (location, state.threads.get_mut(&stopped_thread)) {
        thread.line = i64::from(location.line);
        thread.recent_output.push(format!(
            "debug epoch {} confirmed frozen by all participants",
            state.epoch
        ));
        state.stopped_location = Some(location);
    }
}

pub(crate) fn next_breakpoint_after(
    state: &AdapterState,
    thread_id: i64,
) -> Option<(i64, SourceLocation)> {
    let current_line = state.threads.get(&thread_id)?.line;
    state
        .breakpoint_locations()
        .filter(|location| i64::from(location.line) > current_line)
        .min_by_key(|location| (&location.source_path, location.line))
        .cloned()
        .map(|location| (thread_for_source_location(state, &location), location))
}

fn thread_for_source_location(state: &AdapterState, location: &SourceLocation) -> i64 {
    if let Some(probe) = state
        .debug_probes
        .iter()
        .find(|probe| probe.probe_symbol == location.probe_id)
    {
        if state.runtime_backend == crate::virtual_model::RuntimeBackend::Simulated {
            let function = probe.function.to_ascii_lowercase();
            if function.contains("linux") {
                return LINUX_THREAD;
            }
            if function.contains("windows") {
                return WINDOWS_THREAD;
            }
            if function.contains("package") {
                return PACKAGE_THREAD;
            }
            return MAIN_THREAD;
        }
        return state
            .stopped_task
            .as_ref()
            .and_then(|task| {
                state
                    .threads
                    .values()
                    .find(|thread| &thread.task == task)
                    .map(|thread| thread.id)
            })
            .unwrap_or(MAIN_THREAD);
    }

    if let Some(function_name) = source_function_name_at_location(state, location) {
        let lower = function_name.to_ascii_lowercase();
        if lower.contains("linux") {
            return LINUX_THREAD;
        }
        if lower.contains("windows") {
            return WINDOWS_THREAD;
        }
        if lower.contains("package") {
            return PACKAGE_THREAD;
        }
        return MAIN_THREAD;
    }

    state
        .threads
        .values()
        .find(|thread| thread.line == i64::from(location.line))
        .map(|thread| thread.id)
        .unwrap_or(MAIN_THREAD)
}

fn source_function_name_at_location(
    state: &AdapterState,
    location: &SourceLocation,
) -> Option<String> {
    let source = fs::read_to_string(crate::source::resolve_source_path(
        &state.project,
        &location.source_path,
    ))
    .ok()?;
    function_name_at_line(&source, i64::from(location.line))
}

#[cfg(test)]
fn debug_probe_for_line(state: &AdapterState, line: i64) -> Option<&BundleDebugProbe> {
    let line = u32::try_from(line).ok()?;
    state
        .debug_probes
        .iter()
        .find(|probe| probe.line_start <= line && line <= probe.line_end)
}

#[cfg(test)]
pub(crate) fn source_function_name_at_line(state: &AdapterState, line: i64) -> Option<String> {
    let source = fs::read_to_string(crate::source::resolve_source_path(
        &state.project,
        &state.source_path,
    ))
    .ok()?;
    function_name_at_line(&source, line)
}

fn function_name_at_line(source: &str, line: i64) -> Option<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut index = usize::try_from(line).ok()?.saturating_sub(1);
    if index >= lines.len() {
        index = lines.len().saturating_sub(1);
    }
    lines[..=index]
        .iter()
        .rev()
        .find_map(|line| parse_rust_function_name(line))
}

pub(crate) fn parse_rust_function_name(line: &str) -> Option<String> {
    let start = line.find("fn ")? + 3;
    let rest = &line[start..];
    let name = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

pub(crate) fn step_thread(state: &mut AdapterState, thread_id: i64, description: &str) {
    state.epoch += 1;
    let resolved_thread = if state.threads.contains_key(&thread_id) {
        thread_id
    } else {
        LINUX_THREAD
    };
    if let Some(thread) = state.threads.get_mut(&resolved_thread) {
        thread.state = DebugRuntimeState::Frozen;
        thread.line += 1;
        thread
            .recent_output
            .push(format!("debug epoch {} {description}", state.epoch));
    }
}
