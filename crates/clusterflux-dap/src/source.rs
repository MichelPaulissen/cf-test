use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{json, Value};

use crate::virtual_model::{AdapterState, RuntimeBackend, VirtualThread};

pub(crate) fn infer_source_path(project: &str) -> String {
    if Path::new(project).join(".clusterflux/main.rs").is_file() {
        ".clusterflux/main.rs".to_owned()
    } else if Path::new(project).join("src/lib.rs").is_file() {
        "src/lib.rs".to_owned()
    } else if Path::new(project).join("src/main.rs").is_file() {
        "src/main.rs".to_owned()
    } else if Path::new(project).join("src/build.rs").is_file() {
        "src/build.rs".to_owned()
    } else {
        "src/main.rs".to_owned()
    }
}

pub(crate) fn source_name(source_path: &str) -> &str {
    Path::new(source_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(source_path)
}

pub(crate) fn stack_source_path(state: &AdapterState, thread: &VirtualThread) -> Option<String> {
    let source_path = state
        .stopped_location
        .as_ref()
        .filter(|_| state.stopped_task.as_ref() == Some(&thread.task))
        .or_else(|| {
            state
                .threads
                .get(&thread.id)
                .and_then(|thread| thread.current_source_location.as_ref())
        })
        .map(|location| location.source_path.as_str())
        .or_else(|| {
            (state.runtime_backend == RuntimeBackend::Simulated)
                .then_some(state.source_path.as_str())
        })?;
    Some(
        normalized_source_path(&state.project, source_path)
            .to_string_lossy()
            .into_owned(),
    )
}

pub(crate) fn repository_relative_source_path(project: &str, source_path: &str) -> Option<String> {
    let normalized = normalized_source_path(project, source_path);
    let project = normalized_source_path(project, ".");
    let relative = normalized.strip_prefix(project).ok()?;
    let value = relative.to_string_lossy().replace('\\', "/");
    (!value.is_empty()
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".."))
    .then_some(value)
}

pub(crate) fn source_response(state: &AdapterState, request: &Value) -> Result<Value> {
    let source_path = request
        .get("arguments")
        .and_then(|arguments| arguments.get("source"))
        .and_then(|source| source.get("path"))
        .and_then(Value::as_str)
        .unwrap_or(&state.source_path);
    let content = fs::read_to_string(resolve_source_path(&state.project, source_path))?;
    Ok(json!({
        "content": content,
        "mimeType": "text/x-rustsrc",
    }))
}

pub(crate) fn resolve_source_path(project: &str, source_path: &str) -> PathBuf {
    let path = Path::new(source_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        let direct = Path::new(project).join(path);
        if direct.exists() || path.starts_with(".clusterflux") {
            direct
        } else {
            let clusterflux_source = Path::new(project).join(".clusterflux").join(path);
            if clusterflux_source.exists() {
                clusterflux_source
            } else {
                direct
            }
        }
    }
}

fn normalized_source_path(project: &str, source_path: &str) -> PathBuf {
    let resolved = resolve_source_path(project, source_path);
    let absolute = if resolved.is_absolute() {
        resolved
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| Path::new(".").to_path_buf())
            .join(resolved)
    };
    absolute.canonicalize().unwrap_or(absolute)
}
