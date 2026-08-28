use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    Digest, EnvironmentResource, NormalizedWorkflowManifest, ProcessId, ProjectId, RepositoryId,
    RunId, TenantId, TriggerId, MAX_WORKFLOW_MANIFEST_BYTES,
};

pub const MAX_WORKFLOW_SOURCE_FILES: usize = 128;
pub const MAX_WORKFLOW_SOURCE_FILE_BYTES: usize = 128 * 1024;
pub const MAX_WORKFLOW_SOURCE_BYTES: usize = 512 * 1024;
pub const MAX_WORKFLOW_SOURCE_PATH_BYTES: usize = 512;
pub const MAX_COMPILER_DIAGNOSTIC_BYTES: usize = 64 * 1024;
pub const MAX_AUTOMATED_RUN_FAILURE_BYTES: usize = 4 * 1024;
pub const MAX_PUBLICATION_ASSETS: usize = 16;
pub const MAX_RAW_COMPILER_WASM_BYTES: usize = 10 * 1024 * 1024 + 512 * 1024;
pub const MAX_COMPILED_WORKFLOW_MODULE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMPILED_WORKFLOW_DEBUG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMPILED_WORKFLOW_METADATA_BYTES: usize = 512 * 1024;
pub const MAX_ENCODED_COMPILER_RESPONSE_BYTES: usize = 15 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgeKind {
    GitHub,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerEventKind {
    Push,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitTrigger {
    pub trigger_id: TriggerId,
    pub forge: ForgeKind,
    pub repository_id: RepositoryId,
    pub repository_url: String,
    pub commit_sha: String,
    pub git_ref: String,
    pub delivery_id: String,
    pub event_kind: TriggerEventKind,
    pub actor: Option<String>,
    pub trusted: bool,
    pub received_at: u64,
}

impl CommitTrigger {
    pub fn validate(&self) -> Result<(), String> {
        validate_public_clone_url(&self.repository_url)?;
        validate_commit_sha(&self.commit_sha)?;
        validate_bounded_text("Git ref", &self.git_ref, 512)?;
        let branch = self.git_ref.strip_prefix("refs/heads/");
        let tag = self.git_ref.strip_prefix("refs/tags/");
        if branch.or(tag).is_none_or(|name| name.is_empty()) {
            return Err("Git push ref must identify a branch or tag".to_owned());
        }
        validate_bounded_text("forge delivery ID", &self.delivery_id, 256)?;
        if let Some(actor) = &self.actor {
            validate_bounded_text("forge actor", actor, 256)?;
        }
        Ok(())
    }

    pub fn run_identity(&self, project: &ProjectId) -> Digest {
        Digest::from_parts([
            b"clusterflux-automated-run:v1".as_slice(),
            project.as_str().as_bytes(),
            self.repository_id.as_str().as_bytes(),
            self.commit_sha.as_bytes(),
            self.git_ref.as_bytes(),
            b"push".as_slice(),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSourceFile {
    pub path: String,
    pub mode: u32,
    pub digest: Digest,
    pub bytes: Vec<u8>,
}

impl WorkflowSourceFile {
    pub fn new(path: impl Into<String>, mode: u32, bytes: Vec<u8>) -> Result<Self, String> {
        let path = path.into();
        validate_workflow_source_path(&path)?;
        let maximum = if path == ".clusterflux/Cargo.toml" {
            MAX_WORKFLOW_MANIFEST_BYTES
        } else {
            MAX_WORKFLOW_SOURCE_FILE_BYTES
        };
        if bytes.len() > maximum {
            return Err(format!(
                "workflow source file `{path}` exceeds {maximum} bytes"
            ));
        }
        std::str::from_utf8(&bytes)
            .map_err(|_| format!("workflow source file `{path}` is not UTF-8"))?;
        let digest = Digest::sha256(&bytes);
        Ok(Self {
            path,
            mode,
            digest,
            bytes,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_workflow_source_path(&self.path)?;
        let maximum = if self.path == ".clusterflux/Cargo.toml" {
            MAX_WORKFLOW_MANIFEST_BYTES
        } else {
            MAX_WORKFLOW_SOURCE_FILE_BYTES
        };
        if self.bytes.len() > maximum {
            return Err(format!(
                "workflow source file `{}` exceeds {maximum} bytes",
                self.path,
            ));
        }
        std::str::from_utf8(&self.bytes)
            .map_err(|_| format!("workflow source file `{}` is not UTF-8", self.path))?;
        if self.digest != Digest::sha256(&self.bytes) {
            return Err(format!(
                "workflow source file `{}` digest does not match its bytes",
                self.path
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSource {
    pub trigger_id: TriggerId,
    pub repository_id: RepositoryId,
    pub commit_sha: String,
    pub tree_digest: Digest,
    pub manifest: NormalizedWorkflowManifest,
    pub files: Vec<WorkflowSourceFile>,
    #[serde(default)]
    pub environments: Vec<EnvironmentResource>,
}

impl WorkflowSource {
    pub fn new(
        trigger_id: TriggerId,
        repository_id: RepositoryId,
        commit_sha: impl Into<String>,
        files: Vec<WorkflowSourceFile>,
    ) -> Result<Self, String> {
        Self::new_with_environments(trigger_id, repository_id, commit_sha, files, Vec::new())
    }

    pub fn new_with_environments(
        trigger_id: TriggerId,
        repository_id: RepositoryId,
        commit_sha: impl Into<String>,
        mut files: Vec<WorkflowSourceFile>,
        mut environments: Vec<EnvironmentResource>,
    ) -> Result<Self, String> {
        let commit_sha = commit_sha.into();
        validate_commit_sha(&commit_sha)?;
        files.sort_by(|left, right| left.path.cmp(&right.path));
        validate_workflow_files(&files)?;
        validate_revision_environments(&mut environments)?;
        let manifest = normalized_manifest_from_files(&files)?;
        let tree_digest = workflow_tree_digest(&files, &manifest, &environments);
        Ok(Self {
            trigger_id,
            repository_id,
            commit_sha,
            tree_digest,
            manifest,
            files,
            environments,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_commit_sha(&self.commit_sha)?;
        validate_workflow_files(&self.files)?;
        let mut environments = self.environments.clone();
        validate_revision_environments(&mut environments)?;
        if environments != self.environments {
            return Err("workflow environments must be lexically ordered".to_owned());
        }
        let manifest = normalized_manifest_from_files(&self.files)?;
        if manifest != self.manifest {
            return Err("normalized workflow manifest does not match its source bytes".to_owned());
        }
        if self
            .files
            .windows(2)
            .any(|files| files[0].path >= files[1].path)
        {
            return Err("workflow source files must be unique and lexically ordered".to_owned());
        }
        let digest = workflow_tree_digest(&self.files, &self.manifest, &self.environments);
        if digest != self.tree_digest {
            return Err("workflow source tree digest does not match its files".to_owned());
        }
        Ok(())
    }

    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|file| file.bytes.len()).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRevision {
    pub repository_id: RepositoryId,
    pub clone_url: String,
    pub commit_sha: String,
    pub source_snapshot: Digest,
}

impl RepositoryRevision {
    pub fn validate(&self) -> Result<(), String> {
        validate_public_clone_url(&self.clone_url)?;
        validate_commit_sha(&self.commit_sha)?;
        if !self.source_snapshot.is_valid_sha256() {
            return Err("repository source snapshot is not a SHA-256 digest".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCompilerResourcePolicy {
    pub cpu_count: u16,
    pub memory_bytes: u64,
    pub wall_clock_seconds: u64,
    pub max_output_bytes: usize,
    pub max_diagnostic_bytes: usize,
}

impl Default for WorkflowCompilerResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_count: 1,
            memory_bytes: 1024 * 1024 * 1024,
            wall_clock_seconds: 120,
            max_output_bytes: 12 * 1024 * 1024,
            max_diagnostic_bytes: MAX_COMPILER_DIAGNOSTIC_BYTES,
        }
    }
}

impl WorkflowCompilerResourcePolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.cpu_count == 0
            || self.cpu_count > 8
            || self.memory_bytes < 128 * 1024 * 1024
            || self.memory_bytes > 16 * 1024 * 1024 * 1024
            || self.wall_clock_seconds == 0
            || self.wall_clock_seconds > 15 * 60
            || self.max_output_bytes == 0
            || self.max_output_bytes > 16 * 1024 * 1024
            || self.max_diagnostic_bytes == 0
            || self.max_diagnostic_bytes > MAX_COMPILER_DIAGNOSTIC_BYTES
        {
            return Err("workflow compiler resource policy exceeds bounded limits".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCompilationRequest {
    pub run_id: RunId,
    pub source: WorkflowSource,
    pub compiler_profile: String,
    pub compiler_image: Digest,
    pub compiler_sdk: Digest,
    pub rust_toolchain: String,
    pub resource_policy: WorkflowCompilerResourcePolicy,
}

impl WorkflowCompilationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.source.validate()?;
        validate_bounded_text("compiler profile", &self.compiler_profile, 128)?;
        if !self.compiler_image.is_valid_sha256() || !self.compiler_sdk.is_valid_sha256() {
            return Err("compiler image and SDK identities must be SHA-256 digests".to_owned());
        }
        validate_bounded_text("Rust toolchain", &self.rust_toolchain, 128)?;
        self.resource_policy.validate()
    }
}

pub fn workflow_compiler_profile_id(environment_digest: &Digest) -> String {
    let suffix = environment_digest
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or(environment_digest.as_str());
    format!("workflow-rust-{}", &suffix[..suffix.len().min(12)])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledWorkflowBundle {
    pub module_base64: String,
    pub bundle_digest: Digest,
    pub execution_module_digest: Digest,
    pub manifest_digest: Digest,
    pub source_tree_digest: Digest,
    pub sdk_abi_version: u32,
    pub default_entrypoint: String,
    pub entrypoints: Vec<String>,
    pub task_definitions: Vec<String>,
    pub environment_names: Vec<String>,
    pub environments: Vec<EnvironmentResource>,
    pub debug_metadata_base64: String,
    pub debug_sidecar_digest: Digest,
    pub path_remapping: Vec<(String, String)>,
    pub compiler_identity: crate::bundle::CompilerIdentity,
    pub source_paths: Vec<String>,
}

impl CompiledWorkflowBundle {
    pub fn validate_metadata(&self) -> Result<(), String> {
        crate::bundle::validate_compiler_identity(&self.compiler_identity)?;
        if !self.bundle_digest.is_valid_sha256()
            || !self.execution_module_digest.is_valid_sha256()
            || !self.manifest_digest.is_valid_sha256()
            || !self.source_tree_digest.is_valid_sha256()
            || !self.debug_sidecar_digest.is_valid_sha256()
        {
            return Err("compiled workflow digests must be SHA-256 digests".to_owned());
        }
        validate_bounded_text("default entrypoint", &self.default_entrypoint, 128)?;
        if self.entrypoints.is_empty()
            || self.entrypoints.len() > 64
            || self.task_definitions.len() > 256
            || self.environment_names.len() > 64
        {
            return Err("compiled workflow descriptor count exceeds limits".to_owned());
        }
        if self.source_paths.is_empty()
            || self.source_paths.len() > crate::MAX_WORKFLOW_SOURCE_FILES
            || self.source_paths.iter().any(|path| {
                path.is_empty()
                    || path.len() > 512
                    || path.starts_with('/')
                    || path
                        .split('/')
                        .any(|component| component == ".." || component.is_empty())
            })
        {
            return Err("compiled workflow source inventory is invalid".to_owned());
        }
        if self
            .source_paths
            .windows(2)
            .any(|paths| paths[0] >= paths[1])
        {
            return Err("compiled workflow source inventory is not sorted and unique".to_owned());
        }
        let mut environments = self.environments.clone();
        validate_revision_environments(&mut environments)?;
        if environments != self.environments
            || self.environment_names
                != environments
                    .iter()
                    .map(|environment| environment.name.clone())
                    .collect::<Vec<_>>()
        {
            return Err(
                "compiled workflow environment identities do not match their names".to_owned(),
            );
        }
        let mut unique = BTreeSet::new();
        for entrypoint in &self.entrypoints {
            validate_bounded_text("entrypoint", entrypoint, 128)?;
            if !unique.insert(entrypoint) {
                return Err("compiled workflow entrypoints are not unique".to_owned());
            }
        }
        if !unique.contains(&self.default_entrypoint) {
            return Err("default workflow entrypoint is not declared".to_owned());
        }
        unique.clear();
        for definition in &self.task_definitions {
            validate_bounded_text("task definition", definition, 128)?;
            if !unique.insert(definition) {
                return Err("compiled workflow task definitions are not unique".to_owned());
            }
        }
        unique.clear();
        for environment in &self.environment_names {
            validate_bounded_text("environment name", environment, 128)?;
            if !unique.insert(environment) {
                return Err("compiled workflow environment names are not unique".to_owned());
            }
        }
        if self.path_remapping.as_slice() != [("/workflow".to_owned(), ".clusterflux".to_owned())] {
            return Err("compiled workflow path remapping is not canonical".to_owned());
        }
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
        let encoded_limit = |bytes: usize| bytes.div_ceil(3).saturating_mul(4);
        if self.module_base64.len() > encoded_limit(MAX_COMPILED_WORKFLOW_MODULE_BYTES)
            || self.debug_metadata_base64.len() > encoded_limit(MAX_COMPILED_WORKFLOW_DEBUG_BYTES)
        {
            return Err("compiled workflow base64 artifacts exceed bounded limits".to_owned());
        }
        let module = BASE64_STANDARD
            .decode(&self.module_base64)
            .map_err(|_| "compiled workflow module is not valid base64".to_owned())?;
        let debug = BASE64_STANDARD
            .decode(&self.debug_metadata_base64)
            .map_err(|_| "compiled workflow debug sidecar is not valid base64".to_owned())?;
        if module.len() > MAX_COMPILED_WORKFLOW_MODULE_BYTES
            || debug.len() > MAX_COMPILED_WORKFLOW_DEBUG_BYTES
        {
            return Err("compiled workflow decoded artifacts exceed bounded limits".to_owned());
        }
        if Digest::sha256(&module) != self.execution_module_digest
            || Digest::sha256(&debug) != self.debug_sidecar_digest
        {
            return Err("compiled workflow artifact digest does not match its bytes".to_owned());
        }
        if serde_json::to_vec(self)
            .map_err(|error| format!("encode compiled workflow response: {error}"))?
            .len()
            > MAX_ENCODED_COMPILER_RESPONSE_BYTES
        {
            return Err("encoded compiled workflow response exceeds its bounded limit".to_owned());
        }
        let bundle_digest = Digest::from_parts([
            b"clusterflux-compiled-workflow:v2".as_slice(),
            self.execution_module_digest.as_str().as_bytes(),
            self.debug_sidecar_digest.as_str().as_bytes(),
            self.manifest_digest.as_str().as_bytes(),
            self.source_tree_digest.as_str().as_bytes(),
        ]);
        if bundle_digest != self.bundle_digest {
            return Err("compiled workflow bundle digest does not match its artifacts".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledWorkflowSummary {
    pub bundle_digest: Digest,
    pub execution_module_digest: Digest,
    pub manifest_digest: Digest,
    pub source_tree_digest: Digest,
    pub debug_sidecar_digest: Digest,
    pub sdk_abi_version: u32,
    pub default_entrypoint: String,
    pub entrypoints: Vec<String>,
    pub task_definitions: Vec<String>,
    pub environment_names: Vec<String>,
    pub environments: Vec<EnvironmentResource>,
    pub compiler_identity: crate::bundle::CompilerIdentity,
    pub source_paths: Vec<String>,
}

impl From<&CompiledWorkflowBundle> for CompiledWorkflowSummary {
    fn from(bundle: &CompiledWorkflowBundle) -> Self {
        Self {
            bundle_digest: bundle.bundle_digest.clone(),
            execution_module_digest: bundle.execution_module_digest.clone(),
            manifest_digest: bundle.manifest_digest.clone(),
            source_tree_digest: bundle.source_tree_digest.clone(),
            debug_sidecar_digest: bundle.debug_sidecar_digest.clone(),
            sdk_abi_version: bundle.sdk_abi_version,
            default_entrypoint: bundle.default_entrypoint.clone(),
            entrypoints: bundle.entrypoints.clone(),
            task_definitions: bundle.task_definitions.clone(),
            environment_names: bundle.environment_names.clone(),
            environments: bundle.environments.clone(),
            compiler_identity: bundle.compiler_identity.clone(),
            source_paths: bundle.source_paths.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCompilationResult {
    pub assignment_id: String,
    pub attempt_id: String,
    pub lease_epoch: u64,
    pub run_id: RunId,
    pub node: crate::NodeId,
    pub bundle: Option<CompiledWorkflowBundle>,
    pub compiler_transcript: String,
    pub failure_code: Option<String>,
    pub retryable: bool,
}

impl WorkflowCompilationResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.assignment_id.is_empty()
            || self.assignment_id.len() > 256
            || self.assignment_id.contains(char::is_whitespace)
            || self.attempt_id.is_empty()
            || self.attempt_id.len() > 256
            || self.attempt_id.contains(char::is_whitespace)
            || self.lease_epoch == 0
        {
            return Err("compiler result has an invalid assignment fence".to_owned());
        }
        if self.compiler_transcript.len() > MAX_COMPILER_DIAGNOSTIC_BYTES {
            return Err("compiler transcript exceeds its bounded limit".to_owned());
        }
        if let Some(bundle) = &self.bundle {
            bundle.validate_metadata()?;
            if self.failure_code.is_some() {
                return Err("successful compiler result contains a failure code".to_owned());
            }
        } else if self.failure_code.is_none() {
            return Err("failed compiler result omits its failure code".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomatedRunState {
    Accepted,
    LoadingSource,
    WaitingForCompilerNode,
    CompilingWorkflow,
    WaitingForProcessSlot,
    Launching,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl AutomatedRunState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomatedRunRecord {
    pub run_id: RunId,
    pub primary_trigger_id: TriggerId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub repository_id: RepositoryId,
    pub commit_sha: String,
    pub git_ref: String,
    pub trusted: bool,
    pub workflow_tree_digest: Option<Digest>,
    pub bundle_digest: Option<Digest>,
    pub state: AutomatedRunState,
    pub process_id: Option<ProcessId>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<String>,
    pub publication_tag: Option<String>,
    pub publication_url: Option<String>,
}

impl AutomatedRunRecord {
    pub fn validate(&self) -> Result<(), String> {
        validate_commit_sha(&self.commit_sha)?;
        validate_bounded_text("Git ref", &self.git_ref, 512)?;
        if self
            .failure_message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_AUTOMATED_RUN_FAILURE_BYTES)
        {
            return Err("automated run failure message exceeds its bounded limit".to_owned());
        }
        if self
            .waiting_reason
            .as_ref()
            .is_some_and(|reason| reason.len() > 256)
        {
            return Err("automated run waiting reason exceeds its bounded limit".to_owned());
        }
        if self.state.is_terminal() != self.ended_at.is_some() {
            return Err("automated run terminal state and end timestamp disagree".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryOutcome {
    Accepted,
    Deduplicated,
    Rejected,
}

/// Bounded, credential-free audit metadata for a hosted forge delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookDeliveryRecord {
    pub sequence: u64,
    pub binding_id: String,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub repository_id: RepositoryId,
    pub delivery_id: Option<String>,
    pub commit_sha: Option<String>,
    pub git_ref: Option<String>,
    pub outcome: WebhookDeliveryOutcome,
    pub run_id: Option<RunId>,
    pub reason_code: Option<String>,
    pub received_at: u64,
}

impl WebhookDeliveryRecord {
    pub fn validate(&self) -> Result<(), String> {
        validate_bounded_text("repository binding ID", &self.binding_id, 128)?;
        if let Some(delivery_id) = &self.delivery_id {
            validate_bounded_text("forge delivery ID", delivery_id, 256)?;
        }
        if let Some(commit_sha) = &self.commit_sha {
            validate_commit_sha(commit_sha)?;
        }
        if let Some(git_ref) = &self.git_ref {
            validate_bounded_text("Git ref", git_ref, 512)?;
        }
        if let Some(reason_code) = &self.reason_code {
            validate_bounded_text("webhook delivery reason code", reason_code, 128)?;
        }
        if self.outcome == WebhookDeliveryOutcome::Rejected && self.run_id.is_some() {
            return Err("rejected webhook delivery must not reference a run".to_owned());
        }
        if self.outcome != WebhookDeliveryOutcome::Rejected && self.run_id.is_none() {
            return Err("accepted webhook delivery must reference a run".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerContext {
    pub trigger_id: TriggerId,
    pub forge: ForgeKind,
    pub repository_id: RepositoryId,
    pub commit_sha: String,
    pub git_ref: String,
    pub event_kind: TriggerEventKind,
    pub trusted: bool,
    pub source_snapshot: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTriggerContextRequest {
    pub abi_version: u32,
}

impl WasmHostTriggerContextRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != crate::WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported trigger-context ABI version {}",
                self.abi_version
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmHostTriggerContextResult {
    pub abi_version: u32,
    pub context: TriggerContext,
}

impl TriggerContext {
    pub fn validate(&self) -> Result<(), String> {
        validate_commit_sha(&self.commit_sha)?;
        validate_bounded_text("Git ref", &self.git_ref, 512)?;
        if !self.source_snapshot.is_valid_sha256() {
            return Err("trigger source snapshot is not a SHA-256 digest".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationResult {
    pub tag: String,
    pub release_url: String,
    pub uploaded_asset_names: Vec<String>,
    pub published_at: u64,
}

impl PublicationResult {
    pub fn validate(&self) -> Result<(), String> {
        validate_bounded_text("publication tag", &self.tag, 256)?;
        validate_bounded_text("publication URL", &self.release_url, 2_048)?;
        if self.uploaded_asset_names.len() > MAX_PUBLICATION_ASSETS {
            return Err("publication asset count exceeds its bounded limit".to_owned());
        }
        for asset in &self.uploaded_asset_names {
            validate_bounded_text("publication asset name", asset, 256)?;
        }
        Ok(())
    }
}

pub fn validate_commit_sha(value: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("commit SHA must be exactly 40 lowercase hexadecimal characters".to_owned());
    }
    Ok(())
}

pub fn validate_public_clone_url(value: &str) -> Result<(), String> {
    validate_bounded_text("public clone URL", value, 2_048)?;
    if !value.starts_with("https://") || value.contains('@') {
        return Err("public clone URL must use HTTPS without credentials".to_owned());
    }
    Ok(())
}

fn validate_workflow_files(files: &[WorkflowSourceFile]) -> Result<(), String> {
    if files.is_empty() || files.len() > MAX_WORKFLOW_SOURCE_FILES {
        return Err(format!(
            "workflow source must contain 1 to {MAX_WORKFLOW_SOURCE_FILES} manifest/Rust files"
        ));
    }
    let mut total = 0_usize;
    let mut paths = BTreeSet::new();
    for file in files {
        file.validate()?;
        if !paths.insert(file.path.as_str()) {
            return Err(format!("duplicate workflow source path `{}`", file.path));
        }
        total = total.saturating_add(file.bytes.len());
    }
    if !paths.contains(".clusterflux/main.rs") {
        return Err("workflow source is missing .clusterflux/main.rs".to_owned());
    }
    if !paths.contains(".clusterflux/Cargo.toml") {
        return Err("workflow source is missing .clusterflux/Cargo.toml".to_owned());
    }
    if total > MAX_WORKFLOW_SOURCE_BYTES {
        return Err(format!(
            "workflow source exceeds {MAX_WORKFLOW_SOURCE_BYTES} total bytes"
        ));
    }
    Ok(())
}

fn normalized_manifest_from_files(
    files: &[WorkflowSourceFile],
) -> Result<NormalizedWorkflowManifest, String> {
    let manifest = files
        .iter()
        .find(|file| file.path == ".clusterflux/Cargo.toml")
        .ok_or_else(|| "workflow source is missing .clusterflux/Cargo.toml".to_owned())?;
    NormalizedWorkflowManifest::parse(&manifest.bytes).map_err(|error| error.to_string())
}

pub fn workflow_tree_identity(
    files: &[WorkflowSourceFile],
) -> Result<(NormalizedWorkflowManifest, Digest), String> {
    validate_workflow_files(files)?;
    let manifest = normalized_manifest_from_files(files)?;
    let digest = workflow_tree_digest(files, &manifest, &[]);
    Ok((manifest, digest))
}

fn workflow_tree_digest(
    files: &[WorkflowSourceFile],
    manifest: &NormalizedWorkflowManifest,
    environments: &[EnvironmentResource],
) -> Digest {
    let mut parts = Vec::with_capacity(1 + files.len() * 4);
    parts.push(b"clusterflux-workflow-source:v2".to_vec());
    parts.push(manifest.digest.as_str().as_bytes().to_vec());
    for file in files {
        if file.path == ".clusterflux/Cargo.toml" {
            continue;
        }
        parts.push(file.path.as_bytes().to_vec());
        parts.push(file.mode.to_be_bytes().to_vec());
        parts.push((file.bytes.len() as u64).to_be_bytes().to_vec());
        parts.push(file.digest.as_str().as_bytes().to_vec());
    }
    for environment in environments {
        parts.push(environment.name.as_bytes().to_vec());
        parts.push(
            environment
                .recipe_path
                .to_string_lossy()
                .as_bytes()
                .to_vec(),
        );
        parts.push(
            environment
                .context_path
                .to_string_lossy()
                .as_bytes()
                .to_vec(),
        );
        parts.push(environment.digest.as_str().as_bytes().to_vec());
    }
    Digest::from_parts(parts)
}

fn validate_revision_environments(
    environments: &mut Vec<EnvironmentResource>,
) -> Result<(), String> {
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    if environments.len() > 64 {
        return Err("workflow revision contains too many environments".to_owned());
    }
    let mut names = BTreeSet::new();
    for environment in environments {
        let recipe = environment.recipe_path.to_string_lossy();
        let context = environment.context_path.to_string_lossy();
        if environment.name.is_empty()
            || environment.name.len() > 128
            || !environment.digest.is_valid_sha256()
            || !names.insert(environment.name.clone())
            || !recipe.starts_with("envs/")
            || recipe.contains("..")
            || !context.starts_with("envs/")
            || context.contains("..")
        {
            return Err("workflow revision environment metadata is invalid".to_owned());
        }
        environment.validate_context_identity()?;
    }
    Ok(())
}

pub fn validate_workflow_source_path(path: &str) -> Result<(), String> {
    if path == ".clusterflux/Cargo.toml" {
        return Ok(());
    }
    if path.len() > MAX_WORKFLOW_SOURCE_PATH_BYTES
        || !path.starts_with(".clusterflux/")
        || !path.ends_with(".rs")
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.chars().any(char::is_control)
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(format!("invalid workflow source path `{path}`"));
    }
    Ok(())
}

fn validate_bounded_text(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} is empty, too large, or contains control characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha() -> String {
        "0123456789abcdef0123456789abcdef01234567".to_owned()
    }

    #[test]
    fn workflow_source_is_ordered_bounded_and_content_addressed() {
        let source = WorkflowSource::new(
            TriggerId::from("trigger-1"),
            RepositoryId::from("repository-1"),
            sha(),
            vec![
                WorkflowSourceFile::new(
                    ".clusterflux/Cargo.toml",
                    0o100644,
                    b"[package]\nname='test'\nversion='0.0.0'\nedition='2024'\npublish=false\n[lib]\npath='main.rs'\ncrate-type=['cdylib']\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0'}\n[workspace]\nresolver='3'\n"
                        .to_vec(),
                )
                .unwrap(),
                WorkflowSourceFile::new(
                    ".clusterflux/tasks.rs",
                    0o100644,
                    b"pub fn task() {}".to_vec(),
                )
                .unwrap(),
                WorkflowSourceFile::new(".clusterflux/main.rs", 0o100644, b"mod tasks;".to_vec())
                    .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(source.files[0].path, ".clusterflux/Cargo.toml");
        source.validate().unwrap();
    }

    #[test]
    fn trigger_run_identity_ignores_delivery_replays() {
        let trigger = CommitTrigger {
            trigger_id: TriggerId::from("trigger-1"),
            forge: ForgeKind::GitHub,
            repository_id: RepositoryId::from("repository-1"),
            repository_url: "https://github.com/example/repository.git".to_owned(),
            commit_sha: sha(),
            git_ref: "refs/heads/main".to_owned(),
            delivery_id: "delivery-1".to_owned(),
            event_kind: TriggerEventKind::Push,
            actor: Some("developer".to_owned()),
            trusted: true,
            received_at: 1,
        };
        trigger.validate().unwrap();
        let mut replay = trigger.clone();
        replay.delivery_id = "delivery-2".to_owned();
        assert_eq!(
            trigger.run_identity(&ProjectId::from("project")),
            replay.run_identity(&ProjectId::from("project"))
        );
    }

    #[test]
    fn default_compiler_output_budget_carries_the_bounded_debug_bundle() {
        let policy = WorkflowCompilerResourcePolicy::default();
        policy.validate().unwrap();
        assert_eq!(policy.max_output_bytes, 12 * 1024 * 1024);
        assert!(policy.max_output_bytes > MAX_COMPILED_WORKFLOW_DEBUG_BYTES);
    }

    #[test]
    fn publication_result_allows_pipeline_owned_metadata() {
        let publication = serde_json::from_value::<Option<PublicationResult>>(serde_json::json!({
            "tag": "build-0123456789ab",
            "release_url": "https://github.com/example/project/releases/tag/build-0123456789ab",
            "uploaded_asset_names": ["archive.tar.gz", "SHA256SUMS"],
            "published_at": 1,
            "nix_cache": {
                "attempted": true,
                "succeeded": false,
                "failure": "cache service unavailable"
            }
        }))
        .unwrap()
        .unwrap();

        publication.validate().unwrap();
        assert_eq!(publication.tag, "build-0123456789ab");
    }
}
