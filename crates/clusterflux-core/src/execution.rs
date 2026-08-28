use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ArtifactHandle, ArtifactId, Capability, Digest, EnvironmentRequirements, EnvironmentResource,
    NodeId, ProcessId, ProjectId, SourceLocation, TaskDefinitionId, TaskInstanceId, TenantId,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestRuntimeKind {
    Wasmtime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandBackendKind {
    LinuxRootlessPodman,
    WindowsContainerdNerdctl,
    WindowsCommandDev,
    StubbedWindowsSandbox,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandNetworkPolicy {
    Disabled,
    Enabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub working_directory: String,
    pub environment_variables: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub network: CommandNetworkPolicy,
    pub env: Option<EnvironmentResource>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandPlan {
    pub guest_runtime: GuestRuntimeKind,
    pub backend: CommandBackendKind,
    pub required_capability: Capability,
    pub user_attached_development_execution: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCommandPolicy {
    pub hosted_control_plane: bool,
    pub node_has_command_capability: bool,
}

impl NativeCommandPolicy {
    pub fn authorize(&self) -> Result<(), String> {
        if self.hosted_control_plane {
            return Err("hosted coordinator control plane cannot run native commands".to_owned());
        }
        if !self.node_has_command_capability {
            return Err("selected node or task lacks native command capability".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskBoundaryValue {
    SmallJson(serde_json::Value),
    Structured(StructuredTaskBoundary),
    SourceSnapshot(crate::Digest),
    Blob(crate::Digest),
    Artifact(ArtifactHandle),
    VfsManifest(crate::Digest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TaskBoundaryHandle {
    SourceSnapshot(crate::Digest),
    Blob(crate::Digest),
    Artifact(crate::ArtifactHandle),
    VfsManifest(crate::Digest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredTaskBoundary {
    pub value: serde_json::Value,
    pub handles: Vec<TaskBoundaryHandle>,
}

const TASK_HANDLE_PLACEHOLDER_KEY: &str = "$task_handle";

impl TaskBoundaryHandle {
    fn kind(&self) -> &'static str {
        match self {
            Self::SourceSnapshot(_) => "source_snapshot",
            Self::Blob(_) => "blob",
            Self::Artifact(_) => "artifact",
            Self::VfsManifest(_) => "vfs_manifest",
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::SourceSnapshot(digest) | Self::Blob(digest) | Self::VfsManifest(digest) => {
                if !digest.is_valid_sha256() {
                    return Err(format!("{} handle has an invalid digest", self.kind()));
                }
            }
            Self::Artifact(artifact) => {
                if artifact.id.as_str().trim().is_empty() || artifact.id.as_str().len() > 256 {
                    return Err("artifact handle has an invalid ID".to_owned());
                }
                if !artifact.digest.is_valid_sha256() {
                    return Err("artifact handle has an invalid digest".to_owned());
                }
            }
        }
        Ok(())
    }

    fn materialized_value(&self) -> serde_json::Value {
        match self {
            Self::SourceSnapshot(digest) | Self::Blob(digest) | Self::VfsManifest(digest) => {
                serde_json::json!({ "digest": digest })
            }
            Self::Artifact(artifact) => serde_json::json!({
                "id": artifact.id,
                "digest": artifact.digest,
                "size_bytes": artifact.size_bytes,
            }),
        }
    }
}

impl StructuredTaskBoundary {
    pub fn validate(&self) -> Result<(), String> {
        if self.handles.len() > 256 {
            return Err("structured task argument exceeds 256 handles".to_owned());
        }
        for handle in &self.handles {
            handle.validate()?;
        }
        let mut used = vec![false; self.handles.len()];
        validate_task_handle_placeholders(&self.value, &self.handles, &mut used)?;
        if let Some(index) = used.iter().position(|used| !used) {
            return Err(format!(
                "structured task argument contains unused handle-table entry {index}"
            ));
        }
        Ok(())
    }

    pub fn materialize(&self) -> Result<serde_json::Value, String> {
        self.validate()?;
        let mut value = self.value.clone();
        materialize_task_handle_placeholders(&mut value, &self.handles)?;
        Ok(value)
    }
}

fn validate_task_handle_placeholders(
    value: &serde_json::Value,
    handles: &[TaskBoundaryHandle],
    used: &mut [bool],
) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                validate_task_handle_placeholders(value, handles, used)?;
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(placeholder) = object.get(TASK_HANDLE_PLACEHOLDER_KEY) {
                if object.len() != 1 {
                    return Err("task handle placeholder must be the only object field".to_owned());
                }
                let placeholder = placeholder.as_object().ok_or_else(|| {
                    "task handle placeholder payload must be an object".to_owned()
                })?;
                if placeholder.len() != 2
                    || !placeholder.contains_key("index")
                    || !placeholder.contains_key("kind")
                {
                    return Err(
                        "task handle placeholder must contain exactly index and kind".to_owned(),
                    );
                }
                let index = placeholder["index"]
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                    .ok_or_else(|| "task handle placeholder index is invalid".to_owned())?;
                let kind = placeholder["kind"]
                    .as_str()
                    .ok_or_else(|| "task handle placeholder kind is invalid".to_owned())?;
                let handle = handles.get(index).ok_or_else(|| {
                    format!("task handle placeholder index {index} is out of range")
                })?;
                if handle.kind() != kind {
                    return Err(format!(
                        "task handle placeholder {index} expects kind {kind}, but the table contains {}",
                        handle.kind()
                    ));
                }
                if std::mem::replace(&mut used[index], true) {
                    return Err(format!(
                        "task handle placeholder index {index} is used more than once"
                    ));
                }
            } else {
                for value in object.values() {
                    validate_task_handle_placeholders(value, handles, used)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn materialize_task_handle_placeholders(
    value: &mut serde_json::Value,
    handles: &[TaskBoundaryHandle],
) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                materialize_task_handle_placeholders(value, handles)?;
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(placeholder) = object.get(TASK_HANDLE_PLACEHOLDER_KEY) {
                let index = placeholder
                    .get("index")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .ok_or_else(|| "validated task handle placeholder lost its index".to_owned())?;
                *value = handles
                    .get(index)
                    .ok_or_else(|| "validated task handle placeholder became invalid".to_owned())?
                    .materialized_value();
            } else {
                for value in object.values_mut() {
                    materialize_task_handle_placeholders(value, handles)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl TaskBoundaryValue {
    pub fn materialize(&self) -> Result<serde_json::Value, String> {
        match self {
            Self::SmallJson(value) => Ok(value.clone()),
            Self::Structured(structured) => structured.materialize(),
            Self::SourceSnapshot(digest) | Self::Blob(digest) | Self::VfsManifest(digest) => {
                TaskBoundaryHandle::SourceSnapshot(digest.clone()).validate()?;
                Ok(serde_json::json!({ "digest": digest }))
            }
            Self::Artifact(artifact) => {
                TaskBoundaryHandle::Artifact(artifact.clone()).validate()?;
                Ok(serde_json::json!({
                    "id": artifact.id,
                    "digest": artifact.digest,
                    "size_bytes": artifact.size_bytes,
                }))
            }
        }
    }

    pub fn required_artifacts(&self) -> Vec<ArtifactId> {
        match self {
            Self::Artifact(artifact) => vec![artifact.id.clone()],
            Self::Structured(structured) => structured
                .handles
                .iter()
                .filter_map(|handle| match handle {
                    TaskBoundaryHandle::Artifact(artifact) => Some(artifact.id.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Returns the authoritative artifact handles carried by this boundary value.
    /// Node-local warm-up uses the digest, rather than only the artifact ID, as
    /// its deduplication key.
    pub fn artifact_handles(&self) -> Vec<ArtifactHandle> {
        match self {
            Self::Artifact(artifact) => vec![artifact.clone()],
            Self::Structured(structured) => structured
                .handles
                .iter()
                .filter_map(|handle| match handle {
                    TaskBoundaryHandle::Artifact(artifact) => Some(artifact.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn source_snapshots(&self) -> Vec<Digest> {
        match self {
            Self::SourceSnapshot(snapshot) => vec![snapshot.clone()],
            Self::Structured(structured) => structured
                .handles
                .iter()
                .filter_map(|handle| match handle {
                    TaskBoundaryHandle::SourceSnapshot(snapshot) => Some(snapshot.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn rebind_source_snapshot(&mut self, replacement: &Digest) -> usize {
        match self {
            Self::SourceSnapshot(snapshot) => {
                *snapshot = replacement.clone();
                1
            }
            Self::Structured(structured) => structured
                .handles
                .iter_mut()
                .map(|handle| match handle {
                    TaskBoundaryHandle::SourceSnapshot(snapshot) => {
                        *snapshot = replacement.clone();
                        1
                    }
                    _ => 0,
                })
                .sum(),
            _ => 0,
        }
    }
}

pub const WASM_TASK_ABI_VERSION: u32 = 1;
pub const MAX_WASM_TASK_ENVELOPE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskStartRequest {
    pub abi_version: u32,
    pub task_definition: TaskDefinitionId,
    pub environment_id: Option<String>,
    pub args: Vec<TaskBoundaryValue>,
    /// Opaque project-secret names. Secret bytes never cross the Wasm boundary.
    #[serde(default)]
    pub requested_secrets: Vec<String>,
    #[serde(default)]
    pub failure_policy: TaskFailurePolicy,
}

impl WasmHostTaskStartRequest {
    pub fn validate(&self) -> Result<(), String> {
        WasmTaskInvocation {
            abi_version: self.abi_version,
            task_definition: self.task_definition.clone(),
            task_instance: TaskInstanceId::from("validation-only-instance"),
            args: self.args.clone(),
        }
        .validate()?;
        if self
            .environment_id
            .as_deref()
            .is_some_and(|environment| environment.trim().is_empty() || environment.len() > 128)
        {
            return Err("Wasm child task environment id is invalid".to_owned());
        }
        validate_secret_names(&self.requested_secrets)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskHandle {
    pub abi_version: u32,
    pub handle_id: u64,
    pub task_spec: TaskSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskJoinRequest {
    pub abi_version: u32,
    pub handle_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskJoinResult {
    pub abi_version: u32,
    pub task_instance: TaskInstanceId,
    pub result: TaskBoundaryValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostCommandRequest {
    pub abi_version: u32,
    pub program: String,
    pub args: Vec<String>,
    pub working_directory: String,
    pub environment_variables: BTreeMap<String, String>,
    /// Environment variable to opaque task-granted secret name.
    #[serde(default)]
    pub secret_environment_variables: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub network: CommandNetworkPolicy,
}

impl WasmHostCommandRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm command ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        if self.program.trim().is_empty() || self.program.len() > 4096 {
            return Err("Wasm command program is invalid".to_owned());
        }
        if self.args.len() > 1024 || self.args.iter().any(|arg| arg.len() > 16 * 1024) {
            return Err("Wasm command argument list exceeds ABI limits".to_owned());
        }
        validate_command_working_directory(&self.working_directory)?;
        if self.environment_variables.len() > 128 {
            return Err("Wasm command environment exceeds 128 variables".to_owned());
        }
        if self.secret_environment_variables.len() > 16
            || self.secret_environment_variables.keys().any(|name| {
                !valid_environment_name(name) || self.environment_variables.contains_key(name)
            })
        {
            return Err("Wasm command secret environment is invalid or too large".to_owned());
        }
        validate_secret_names(
            &self
                .secret_environment_variables
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )?;
        let environment_bytes =
            self.environment_variables
                .iter()
                .try_fold(0_usize, |total, (name, value)| {
                    if !valid_environment_name(name) || value.contains('\0') {
                        return Err(
                            "Wasm command environment contains an invalid variable".to_owned()
                        );
                    }
                    if name.len() > 128 || value.len() > 16 * 1024 {
                        return Err(
                            "Wasm command environment variable exceeds ABI limits".to_owned()
                        );
                    }
                    total
                        .checked_add(name.len() + value.len())
                        .ok_or_else(|| "Wasm command environment size overflowed".to_owned())
                })?;
        if environment_bytes > 32 * 1024 {
            return Err("Wasm command environment exceeds the 32 KiB limit".to_owned());
        }
        if !(1_000..=60 * 60 * 1_000).contains(&self.timeout_ms) {
            return Err("Wasm command timeout must be between 1 second and 1 hour".to_owned());
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_WASM_TASK_ENVELOPE_BYTES {
            return Err("Wasm command request exceeds the task ABI limit".to_owned());
        }
        Ok(())
    }
}

fn validate_command_working_directory(path: &str) -> Result<(), String> {
    let permitted_root = path == "/workspace"
        || path.starts_with("/workspace/")
        || path == "/clusterflux/output"
        || path.starts_with("/clusterflux/output/");
    if !permitted_root
        || path.len() > 4096
        || path.contains('\0')
        || path.contains('\\')
        || path.split('/').any(|component| component == "..")
    {
        return Err(
            "Wasm command working directory must stay under /workspace or /clusterflux/output"
                .to_owned(),
        );
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostCommandResult {
    pub abi_version: u32,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskControlRequest {
    pub abi_version: u32,
}

impl WasmHostTaskControlRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm task-control ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTaskControlResult {
    pub abi_version: u32,
    pub cancellation_requested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostDebugProbeRequest {
    pub abi_version: u32,
    pub symbol: String,
    #[serde(default)]
    pub source_location: Option<SourceLocation>,
}

impl WasmHostDebugProbeRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm debug-probe ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        if self.symbol.trim().is_empty()
            || self.symbol.len() > 256
            || !self
                .symbol
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._:-/".contains(character))
        {
            return Err("Wasm debug probe symbol is invalid".to_owned());
        }
        if self.source_location.as_ref().is_some_and(|location| {
            let bytes = location.source_path.as_bytes();
            let windows_absolute = bytes.get(1) == Some(&b':') && bytes.get(2) == Some(&b'/');
            location.probe_id != self.symbol
                || location.source_path.is_empty()
                || location.source_path.len() > 512
                || location.source_path.starts_with('/')
                || windows_absolute
                || location.source_path.split('/').any(|part| part == "..")
                || location.line == 0
                || location.column == Some(0)
        }) {
            return Err("Wasm debug probe source location is invalid".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostDebugProbeResult {
    pub abi_version: u32,
    pub breakpoint_matched: bool,
    pub debug_epoch: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostVfsRequest {
    pub abi_version: u32,
    pub operation: WasmHostVfsOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WasmHostVfsOperation {
    FlushOutput {
        relative_path: String,
    },
    MaterializeArtifact {
        artifact: ArtifactHandle,
        relative_path: String,
    },
    ReleaseArtifact {
        artifact: ArtifactHandle,
    },
}

impl WasmHostVfsRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm VFS ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        let relative_path = match &self.operation {
            WasmHostVfsOperation::FlushOutput { relative_path }
            | WasmHostVfsOperation::MaterializeArtifact { relative_path, .. } => {
                Some(relative_path)
            }
            WasmHostVfsOperation::ReleaseArtifact { .. } => None,
        };
        if let Some(relative_path) = relative_path {
            validate_task_relative_path(relative_path)?;
        }
        if let WasmHostVfsOperation::MaterializeArtifact { artifact, .. }
        | WasmHostVfsOperation::ReleaseArtifact { artifact } = &self.operation
        {
            if !artifact.digest.is_valid_sha256() {
                return Err("Wasm VFS artifact digest is invalid".to_owned());
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_WASM_TASK_ENVELOPE_BYTES {
            return Err("Wasm VFS request exceeds the task ABI limit".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostVfsResult {
    pub abi_version: u32,
    pub artifact: ArtifactHandle,
    pub relative_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostSourceSnapshotRequest {
    pub abi_version: u32,
}

impl WasmHostSourceSnapshotRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm source-snapshot ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostSourceSnapshotResult {
    pub abi_version: u32,
    pub snapshot: Digest,
}

fn validate_task_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || !component
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        })
    {
        return Err("Wasm VFS path must be a safe task-output-relative path".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmTaskInvocation {
    pub abi_version: u32,
    pub task_definition: TaskDefinitionId,
    pub task_instance: TaskInstanceId,
    pub args: Vec<TaskBoundaryValue>,
}

impl WasmTaskInvocation {
    pub fn new(
        task_definition: TaskDefinitionId,
        task_instance: TaskInstanceId,
        args: Vec<TaskBoundaryValue>,
    ) -> Self {
        Self {
            abi_version: WASM_TASK_ABI_VERSION,
            task_definition,
            task_instance,
            args,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm task ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        if self.task_definition.as_str().len() > 128 {
            return Err("Wasm task invocation has an invalid task-definition id".to_owned());
        }
        if self.task_instance.as_str().len() > 192 {
            return Err("Wasm task invocation has an invalid task-instance id".to_owned());
        }
        for argument in &self.args {
            argument.validate()?;
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_WASM_TASK_ENVELOPE_BYTES {
            return Err(format!(
                "Wasm task invocation is {} bytes; maximum is {}",
                encoded.len(),
                MAX_WASM_TASK_ENVELOPE_BYTES
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmTaskOutcome {
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmTaskResult {
    pub abi_version: u32,
    pub task_instance: TaskInstanceId,
    pub outcome: WasmTaskOutcome,
    pub result: Option<TaskBoundaryValue>,
    pub error: Option<String>,
}

impl WasmTaskResult {
    pub fn completed(task_instance: TaskInstanceId, result: TaskBoundaryValue) -> Self {
        Self {
            abi_version: WASM_TASK_ABI_VERSION,
            task_instance,
            outcome: WasmTaskOutcome::Completed,
            result: Some(result),
            error: None,
        }
    }

    pub fn failed(task_instance: TaskInstanceId, error: impl Into<String>) -> Self {
        Self {
            abi_version: WASM_TASK_ABI_VERSION,
            task_instance,
            outcome: WasmTaskOutcome::Failed,
            result: None,
            error: Some(error.into()),
        }
    }

    pub fn validate_for(&self, expected_instance: &TaskInstanceId) -> Result<(), String> {
        if self.abi_version != WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm task result ABI version {}; expected {}",
                self.abi_version, WASM_TASK_ABI_VERSION
            ));
        }
        if &self.task_instance != expected_instance {
            return Err(format!(
                "Wasm task result belongs to {} instead of {}",
                self.task_instance, expected_instance
            ));
        }
        match (&self.outcome, &self.result, &self.error) {
            (WasmTaskOutcome::Completed, Some(result), None) => result.validate(),
            (WasmTaskOutcome::Failed, None, Some(_)) => Ok(()),
            _ => Err("Wasm task result has inconsistent outcome fields".to_owned()),
        }
    }
}

impl TaskBoundaryValue {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::SmallJson(_) => Ok(()),
            Self::Structured(structured) => structured.validate(),
            Self::SourceSnapshot(digest) | Self::Blob(digest) | Self::VfsManifest(digest) => {
                TaskBoundaryHandle::SourceSnapshot(digest.clone()).validate()
            }
            Self::Artifact(artifact) => TaskBoundaryHandle::Artifact(artifact.clone()).validate(),
        }
    }

    pub fn reject_host_only(type_name: &str) -> Result<Self, String> {
        Err(format!(
            "task boundary value `{type_name}` is host-only; use small serialized data or handles"
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmExportAbi {
    EntrypointV1,
    TaskV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaskDispatch {
    CoordinatorNodeWasm {
        export: Option<String>,
        abi: WasmExportAbi,
    },
}

impl TaskDispatch {
    pub fn is_product_remote_dispatch(&self) -> bool {
        matches!(self, Self::CoordinatorNodeWasm { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub task_definition: TaskDefinitionId,
    pub task_instance: TaskInstanceId,
    pub dispatch: TaskDispatch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    pub environment: Option<EnvironmentRequirements>,
    pub environment_digest: Option<Digest>,
    pub required_capabilities: BTreeSet<Capability>,
    pub dependency_cache: Option<Digest>,
    pub source_snapshot: Option<Digest>,
    /// Public, immutable Git revision metadata used by a node to materialize a
    /// source handle it does not already have. It contains no credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<crate::RepositoryRevision>,
    pub required_artifacts: Vec<ArtifactId>,
    pub args: Vec<TaskBoundaryValue>,
    /// Opaque project-secret names authorized for this task. Values are never
    /// serialized into TaskSpec.
    #[serde(default)]
    pub requested_secrets: Vec<String>,
    pub vfs_epoch: u64,
    #[serde(default)]
    pub failure_policy: TaskFailurePolicy,
    pub bundle_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailurePolicy {
    #[default]
    FailFast,
    AwaitOperator,
}

impl TaskSpec {
    pub fn artifact_handles(&self) -> Vec<ArtifactHandle> {
        self.args
            .iter()
            .flat_map(TaskBoundaryValue::artifact_handles)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn product_mode_uses_remote_dispatch(&self) -> bool {
        self.dispatch.is_product_remote_dispatch()
    }

    pub fn derived_boundary_dependencies(
        &self,
    ) -> Result<(Option<Digest>, Vec<ArtifactId>), String> {
        for argument in &self.args {
            argument.validate()?;
        }
        let source_snapshots = self
            .args
            .iter()
            .flat_map(TaskBoundaryValue::source_snapshots)
            .collect::<BTreeSet<_>>();
        if source_snapshots.len() > 1 {
            return Err(
                "one task invocation cannot require multiple distinct source snapshots".to_owned(),
            );
        }
        let required_artifacts = self
            .args
            .iter()
            .flat_map(TaskBoundaryValue::required_artifacts)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok((source_snapshots.into_iter().next(), required_artifacts))
    }

    pub fn validate_boundary_authority(&self) -> Result<(), String> {
        validate_secret_names(&self.requested_secrets)?;
        let (source_snapshot, required_artifacts) = self.derived_boundary_dependencies()?;
        let process_source_context = matches!(
            self.dispatch,
            TaskDispatch::CoordinatorNodeWasm {
                abi: WasmExportAbi::EntrypointV1,
                ..
            }
        ) || (self
            .required_capabilities
            .contains(&Capability::SourceFilesystem)
            && source_snapshot.is_none());
        if !process_source_context && self.source_snapshot != source_snapshot {
            return Err(
                "task source dependency does not exactly match the canonical argument handle table"
                    .to_owned(),
            );
        }
        if let Some(revision) = &self.source_revision {
            revision.validate()?;
            if self.source_snapshot.as_ref() != Some(&revision.source_snapshot) {
                return Err(
                    "task Git revision does not match its canonical source handle".to_owned(),
                );
            }
        }
        if self.required_artifacts != required_artifacts {
            return Err(
                "task artifact dependencies do not exactly match the canonical argument handle table"
                    .to_owned(),
            );
        }
        Ok(())
    }

    pub fn rebind_source_snapshot(&mut self, replacement: Digest) -> Result<(), String> {
        self.validate_boundary_authority()?;
        if self.source_snapshot.is_none() {
            return Err("task has no SourceSnapshot argument handle to rebind".to_owned());
        }
        let rebound = self
            .args
            .iter_mut()
            .map(|argument| argument.rebind_source_snapshot(&replacement))
            .sum::<usize>();
        if rebound == 0 {
            return Err("task source dependency has no canonical argument handle".to_owned());
        }
        self.source_snapshot = Some(replacement);
        self.validate_boundary_authority()
    }
}

fn validate_secret_names(names: &[String]) -> Result<(), String> {
    if names.len() > 16 {
        return Err("task requests more than 16 secrets".to_owned());
    }
    let mut unique = BTreeSet::new();
    for name in names {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !unique.insert(name)
        {
            return Err("task secret name is invalid or duplicated".to_owned());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskJoinState {
    Pending,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskJoinResult {
    pub process: ProcessId,
    pub task_instance: TaskInstanceId,
    pub node: Option<NodeId>,
    pub state: TaskJoinState,
    pub result: Option<TaskBoundaryValue>,
    pub status_code: Option<i32>,
    pub remote_completion_observed: bool,
    pub message: String,
}

impl TaskJoinResult {
    pub fn pending(
        process: ProcessId,
        task_instance: TaskInstanceId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            process,
            task_instance,
            node: None,
            state: TaskJoinState::Pending,
            result: None,
            status_code: None,
            remote_completion_observed: false,
            message: message.into(),
        }
    }

    pub fn from_remote_completion(
        process: ProcessId,
        task_instance: TaskInstanceId,
        node: NodeId,
        state: TaskJoinState,
        result: Option<TaskBoundaryValue>,
        status_code: Option<i32>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            process,
            task_instance,
            node: Some(node),
            state,
            result,
            status_code,
            remote_completion_observed: true,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_control_plane_cannot_authorize_native_command() {
        let policy = NativeCommandPolicy {
            hosted_control_plane: true,
            node_has_command_capability: true,
        };

        assert!(policy
            .authorize()
            .unwrap_err()
            .contains("hosted coordinator"));
    }

    #[test]
    fn raw_pointer_style_task_argument_is_rejected() {
        let error = TaskBoundaryValue::reject_host_only("*const u8").unwrap_err();

        assert!(error.contains("host-only"));
    }

    #[test]
    fn structured_handle_placeholders_are_strict_and_table_authoritative() {
        let artifact = ArtifactHandle {
            id: ArtifactId::from("real.bin"),
            digest: Digest::sha256("real bytes"),
            size_bytes: 10,
        };
        let boundary = StructuredTaskBoundary {
            value: serde_json::json!({
                "label": "release",
                "artifact": { "$task_handle": { "index": 0, "kind": "artifact" } }
            }),
            handles: vec![TaskBoundaryHandle::Artifact(artifact.clone())],
        };

        boundary.validate().unwrap();
        assert_eq!(
            boundary.materialize().unwrap()["artifact"]["id"],
            "real.bin"
        );
        assert!(!boundary.value.to_string().contains("real.bin"));

        let mut wrong_kind = boundary.clone();
        wrong_kind.value["artifact"]["$task_handle"]["kind"] =
            serde_json::Value::String("blob".to_owned());
        assert!(wrong_kind.validate().unwrap_err().contains("expects kind"));

        let mut out_of_range = boundary.clone();
        out_of_range.value["artifact"]["$task_handle"]["index"] = serde_json::json!(1);
        assert!(out_of_range
            .validate()
            .unwrap_err()
            .contains("out of range"));

        let unused = StructuredTaskBoundary {
            value: serde_json::json!({ "label": "release" }),
            handles: boundary.handles.clone(),
        };
        assert!(unused.validate().unwrap_err().contains("unused"));

        let malformed = StructuredTaskBoundary {
            value: serde_json::json!({
                "$task_handle": { "index": 0, "kind": "artifact", "id": "forged.bin" }
            }),
            handles: boundary.handles,
        };
        assert!(malformed.validate().unwrap_err().contains("exactly"));
    }

    #[test]
    fn successful_wasm_result_validates_its_boundary_value() {
        let result = WasmTaskResult::completed(
            TaskInstanceId::from("task-1"),
            TaskBoundaryValue::Structured(StructuredTaskBoundary {
                value: serde_json::json!({
                    "$task_handle": { "index": 0, "kind": "artifact" }
                }),
                handles: vec![TaskBoundaryHandle::Artifact(ArtifactHandle {
                    id: ArtifactId::from("artifact.bin"),
                    digest: Digest::sha256("artifact"),
                    size_bytes: 8,
                })],
            }),
        );
        assert!(result.validate_for(&TaskInstanceId::from("task-1")).is_ok());

        let mut mismatched = result;
        let Some(TaskBoundaryValue::Structured(boundary)) = mismatched.result.as_mut() else {
            unreachable!();
        };
        boundary.value["$task_handle"]["kind"] = serde_json::json!("source_snapshot");
        assert!(mismatched
            .validate_for(&TaskInstanceId::from("task-1"))
            .unwrap_err()
            .contains("expects kind"));
    }

    #[test]
    fn task_dependencies_are_derived_only_from_boundary_handles() {
        let artifact = ArtifactHandle {
            id: ArtifactId::from("artifact.bin"),
            digest: Digest::sha256("artifact"),
            size_bytes: 8,
        };
        let source = Digest::sha256("source");
        let mut spec = TaskSpec {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            task_definition: TaskDefinitionId::from("compile"),
            task_instance: TaskInstanceId::from("compile-1"),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some("compile".to_owned()),
                abi: WasmExportAbi::TaskV1,
            },
            environment_id: None,
            environment: None,
            environment_digest: None,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: Some(source.clone()),
            source_revision: None,
            required_artifacts: vec![artifact.id.clone()],
            args: vec![
                TaskBoundaryValue::SourceSnapshot(source),
                TaskBoundaryValue::Artifact(artifact),
            ],
            requested_secrets: Vec::new(),
            vfs_epoch: 1,
            failure_policy: TaskFailurePolicy::FailFast,
            bundle_digest: Some(Digest::sha256("bundle")),
        };
        spec.validate_boundary_authority().unwrap();
        let replacement_source = Digest::sha256("replacement-source");
        spec.rebind_source_snapshot(replacement_source.clone())
            .unwrap();
        assert_eq!(spec.source_snapshot, Some(replacement_source.clone()));
        assert_eq!(spec.args[0].source_snapshots(), vec![replacement_source]);
        spec.required_artifacts = vec![ArtifactId::from("forged.bin")];
        assert!(spec
            .validate_boundary_authority()
            .unwrap_err()
            .contains("canonical argument handle table"));
    }

    #[test]
    fn process_entrypoint_and_source_preparation_can_bind_process_source() {
        let mut spec = TaskSpec {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            task_definition: TaskDefinitionId::from("build"),
            task_instance: TaskInstanceId::from("main"),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some("build".to_owned()),
                abi: WasmExportAbi::EntrypointV1,
            },
            environment_id: None,
            environment: None,
            environment_digest: None,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: Some(Digest::sha256("process-source")),
            source_revision: None,
            required_artifacts: Vec::new(),
            args: Vec::new(),
            requested_secrets: Vec::new(),
            vfs_epoch: 1,
            failure_policy: TaskFailurePolicy::FailFast,
            bundle_digest: Some(Digest::sha256("bundle")),
        };

        spec.validate_boundary_authority().unwrap();
        spec.dispatch = TaskDispatch::CoordinatorNodeWasm {
            export: Some("task".to_owned()),
            abi: WasmExportAbi::TaskV1,
        };
        assert!(spec.validate_boundary_authority().is_err());
        spec.required_capabilities
            .insert(Capability::SourceFilesystem);
        spec.validate_boundary_authority().unwrap();
    }

    #[test]
    fn product_task_spec_has_no_local_function_dispatch_variant() {
        let spec = TaskSpec {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            task_definition: TaskDefinitionId::from("compile-linux"),
            task_instance: TaskInstanceId::from("compile-linux-1"),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some("compile_linux".to_owned()),
                abi: WasmExportAbi::TaskV1,
            },
            environment_id: Some("linux".to_owned()),
            environment: None,
            environment_digest: None,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: None,
            source_snapshot: None,
            source_revision: None,
            required_artifacts: Vec::new(),
            args: vec![TaskBoundaryValue::SmallJson(serde_json::json!("src"))],
            requested_secrets: Vec::new(),
            vfs_epoch: 7,
            failure_policy: Default::default(),
            bundle_digest: Some(Digest::sha256("bundle")),
        };

        assert!(spec.product_mode_uses_remote_dispatch());
    }

    #[test]
    fn task_join_result_marks_remote_completion_as_observed() {
        let joined = TaskJoinResult::from_remote_completion(
            ProcessId::from("process"),
            TaskInstanceId::from("compile-linux-1"),
            NodeId::from("linux-a"),
            TaskJoinState::Completed,
            Some(TaskBoundaryValue::Artifact(ArtifactHandle {
                id: ArtifactId::from("app.tar.gz"),
                digest: Digest::sha256("artifact"),
                size_bytes: 8,
            })),
            Some(0),
            "completed from signed node event",
        );

        assert!(joined.remote_completion_observed);
        assert!(matches!(
            joined.result,
            Some(TaskBoundaryValue::Artifact(_))
        ));
    }

    #[test]
    fn structured_command_request_bounds_cwd_environment_timeout_and_network_policy() {
        let mut request = WasmHostCommandRequest {
            abi_version: WASM_TASK_ABI_VERSION,
            program: "cc".to_owned(),
            args: vec!["source.c".to_owned()],
            working_directory: "/workspace/crate".to_owned(),
            environment_variables: BTreeMap::from([
                ("BUILD_MODE".to_owned(), "release".to_owned()),
                ("SOURCE_DATE_EPOCH".to_owned(), "0".to_owned()),
            ]),
            secret_environment_variables: BTreeMap::new(),
            timeout_ms: 120_000,
            network: CommandNetworkPolicy::Disabled,
        };
        request.validate().unwrap();

        request.working_directory = "/workspace/../host".to_owned();
        assert!(request
            .validate()
            .unwrap_err()
            .contains("working directory"));
        request.working_directory = "/workspace".to_owned();
        request.environment_variables = BTreeMap::from([("BAD-NAME".to_owned(), "x".to_owned())]);
        assert!(request.validate().unwrap_err().contains("invalid variable"));
        request.environment_variables.clear();
        request.timeout_ms = 0;
        assert!(request.validate().unwrap_err().contains("timeout"));
    }

    #[test]
    fn debug_probe_rejects_host_absolute_source_locations() {
        for source_path in ["/checkout/main.rs", "C:/checkout/main.rs"] {
            let request = WasmHostDebugProbeRequest {
                abi_version: WASM_TASK_ABI_VERSION,
                symbol: "clusterflux.probe.task".to_owned(),
                source_location: Some(SourceLocation {
                    source_path: source_path.to_owned(),
                    line: 1,
                    column: None,
                    probe_id: "clusterflux.probe.task".to_owned(),
                }),
            };
            assert!(request.validate().is_err(), "accepted {source_path}");
        }
    }
}
