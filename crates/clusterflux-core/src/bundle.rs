use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use syn::parse::Parser;
use syn::{Expr, Item, Lit, Meta, Token};
use wasmparser::{Parser as WasmParser, Payload, Validator};

use crate::{
    CompiledWorkflowBundle, Digest, EnvironmentResource, SourceTransferPolicy, TaskDefinitionId,
    WASM_TASK_ABI_VERSION,
};

use crate::automation::{
    MAX_COMPILED_WORKFLOW_DEBUG_BYTES, MAX_COMPILED_WORKFLOW_METADATA_BYTES,
    MAX_COMPILED_WORKFLOW_MODULE_BYTES, MAX_RAW_COMPILER_WASM_BYTES,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompilerProfile {
    LocalCargo,
    HostedSandbox,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerIdentity {
    pub profile: CompilerProfile,
    pub rustc_version: String,
    pub rustc_commit: Option<String>,
    pub target: String,
    pub flags: Vec<String>,
    pub sdk_version: String,
    pub sdk_digest: Digest,
    #[serde(default)]
    pub trusted_dependencies: Vec<CompilerDependencyIdentity>,
    pub sandbox_image_digest: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerDependencyIdentity {
    pub package: String,
    pub version: String,
    pub features: Vec<String>,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledWorkflowInput {
    pub wasm_bytes: Vec<u8>,
    pub compiler_identity: CompilerIdentity,
    pub manifest_digest: Digest,
    pub source_identity: Digest,
    pub normalized_source_paths: Vec<String>,
    pub environments: Vec<EnvironmentResource>,
    pub requested_entrypoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedWorkflow {
    pub bundle: CompiledWorkflowBundle,
    pub execution_module: Vec<u8>,
    pub debug_sidecar: Vec<u8>,
    pub entrypoint_descriptors: Vec<Value>,
    pub task_descriptors: Vec<Value>,
    pub selected_entrypoint: Value,
}

/// Pure, shared authority for turning compiler output into Clusterflux artifacts.
///
/// Callers receive final bytes and metadata together and must not mutate either.
pub fn finalize_compiled_workflow(
    input: CompiledWorkflowInput,
) -> Result<FinalizedWorkflow, String> {
    if input.wasm_bytes.is_empty() || input.wasm_bytes.len() > MAX_RAW_COMPILER_WASM_BYTES {
        return Err("compiled Wasm module is empty or oversized".to_owned());
    }
    Validator::new()
        .validate_all(&input.wasm_bytes)
        .map_err(|error| format!("validate compiled Wasm: {error}"))?;

    validate_compiler_identity(&input.compiler_identity)?;
    let source_paths = normalize_source_inventory(input.normalized_source_paths)?;
    let environments = normalize_environments(input.environments)?;
    let mut module = input.wasm_bytes;
    let environment_manifest = serde_json::to_vec(&environments)
        .map_err(|error| format!("encode environment manifest: {error}"))?;
    if environment_manifest.len() > MAX_COMPILED_WORKFLOW_METADATA_BYTES {
        return Err("workflow environment metadata is oversized".to_owned());
    }
    append_custom_section(
        &mut module,
        "clusterflux.environments",
        &environment_manifest,
    );

    let entrypoint_descriptors = descriptor_records(&module, "clusterflux.entrypoints")?;
    let task_descriptors = descriptor_records(&module, "clusterflux.tasks")?;
    if entrypoint_descriptors.is_empty() {
        return Err(
            "workflow must declare at least one #[clusterflux::main] entrypoint".to_owned(),
        );
    }
    if task_descriptors.is_empty() {
        return Err("workflow must declare at least one #[clusterflux::task] task".to_owned());
    }
    let selected_entrypoint = select_entrypoint(
        &entrypoint_descriptors,
        input.requested_entrypoint.as_deref(),
    )?;
    let default_entrypoint = selected_entrypoint["name"]
        .as_str()
        .expect("validated entrypoint name")
        .to_owned();
    let entrypoints = descriptor_names(&entrypoint_descriptors, 64, "entrypoint")?;
    let task_definitions = descriptor_names(&task_descriptors, 256, "task")?;

    let (execution_module, debug_sidecar) = split_debug_artifacts(
        &module,
        &input.compiler_identity,
        &source_paths,
        &environments,
        &entrypoint_descriptors,
        &task_descriptors,
    )?;
    if execution_module.len() > MAX_COMPILED_WORKFLOW_MODULE_BYTES
        || debug_sidecar.len() > MAX_COMPILED_WORKFLOW_DEBUG_BYTES
    {
        return Err("workflow execution/debug artifacts exceed finalizer limits".to_owned());
    }
    let execution_module_digest = Digest::sha256(&execution_module);
    let debug_sidecar_digest = Digest::sha256(&debug_sidecar);
    let bundle_digest = Digest::from_parts([
        b"clusterflux-compiled-workflow:v2".as_slice(),
        execution_module_digest.as_str().as_bytes(),
        debug_sidecar_digest.as_str().as_bytes(),
        input.manifest_digest.as_str().as_bytes(),
        input.source_identity.as_str().as_bytes(),
    ]);
    let bundle = CompiledWorkflowBundle {
        module_base64: BASE64_STANDARD.encode(&execution_module),
        bundle_digest,
        execution_module_digest,
        manifest_digest: input.manifest_digest,
        source_tree_digest: input.source_identity,
        sdk_abi_version: WASM_TASK_ABI_VERSION,
        default_entrypoint,
        entrypoints,
        task_definitions,
        environment_names: environments.iter().map(|item| item.name.clone()).collect(),
        environments,
        debug_metadata_base64: BASE64_STANDARD.encode(&debug_sidecar),
        debug_sidecar_digest,
        path_remapping: vec![("/workflow".to_owned(), ".clusterflux".to_owned())],
        compiler_identity: input.compiler_identity,
        source_paths,
    };
    bundle.validate_metadata()?;
    Ok(FinalizedWorkflow {
        bundle,
        execution_module,
        debug_sidecar,
        entrypoint_descriptors,
        task_descriptors,
        selected_entrypoint,
    })
}

pub(crate) fn validate_compiler_identity(identity: &CompilerIdentity) -> Result<(), String> {
    if identity.rustc_version.is_empty()
        || identity.rustc_version.len() > 256
        || identity.target != "wasm32-unknown-unknown"
        || identity.flags.len() > 32
        || identity.sdk_version.is_empty()
        || identity.sdk_version.len() > 64
        || !identity.sdk_digest.is_valid_sha256()
        || identity.trusted_dependencies.len() > 8
        || identity
            .sandbox_image_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid_sha256())
    {
        return Err("compiler identity is missing or invalid".to_owned());
    }
    if identity.flags.iter().any(|flag| flag.len() > 256) {
        return Err("compiler identity contains an oversized flag".to_owned());
    }
    for dependency in &identity.trusted_dependencies {
        if dependency.package.is_empty()
            || dependency.package.len() > 64
            || dependency.version.is_empty()
            || dependency.version.len() > 64
            || dependency.features.len() > 16
            || dependency.features.iter().any(|feature| feature.len() > 64)
            || !dependency.digest.is_valid_sha256()
        {
            return Err("compiler trusted dependency identity is invalid".to_owned());
        }
    }
    Ok(())
}

fn normalize_source_inventory(mut paths: Vec<String>) -> Result<Vec<String>, String> {
    paths.sort();
    paths.dedup();
    if paths.is_empty() || paths.len() > crate::MAX_WORKFLOW_SOURCE_FILES {
        return Err("workflow source inventory is empty or oversized".to_owned());
    }
    if paths.iter().any(|path| {
        path.is_empty()
            || path.len() > 512
            || path.starts_with('/')
            || path
                .split('/')
                .any(|component| component == ".." || component.is_empty())
    }) {
        return Err("workflow source inventory contains a non-normalized path".to_owned());
    }
    Ok(paths)
}

fn normalize_environments(
    mut environments: Vec<EnvironmentResource>,
) -> Result<Vec<EnvironmentResource>, String> {
    environments.sort_by(|left, right| left.name.cmp(&right.name));
    if environments.len() > 64 {
        return Err("workflow references too many environments".to_owned());
    }
    let mut names = BTreeSet::new();
    for environment in &environments {
        if environment.name.is_empty()
            || environment.name.len() > 128
            || !environment.digest.is_valid_sha256()
            || !names.insert(environment.name.clone())
        {
            return Err("workflow environment manifest is invalid".to_owned());
        }
    }
    Ok(environments)
}

pub fn select_entrypoint(descriptors: &[Value], requested: Option<&str>) -> Result<Value, String> {
    let names = descriptor_names(descriptors, 64, "entrypoint")?;
    if let Some(requested) = requested {
        return descriptors
            .iter()
            .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(requested))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "workflow has no entrypoint `{requested}`; available entrypoints: {names:?}"
                )
            });
    }
    let explicit_defaults = descriptors
        .iter()
        .filter(|descriptor| descriptor.get("default").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    if explicit_defaults.len() > 1 {
        return Err("workflow declares more than one default entrypoint".to_owned());
    }
    if let Some(selected) = explicit_defaults.first() {
        return Ok((*selected).clone());
    }
    if let Some(main) = descriptors
        .iter()
        .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some("main"))
    {
        return Ok(main.clone());
    }
    if descriptors.len() == 1 {
        return Ok(descriptors[0].clone());
    }
    Err(format!(
        "workflow entrypoint is ambiguous; choose one explicitly from {names:?}"
    ))
}

pub fn descriptor_records(module: &[u8], section_name: &str) -> Result<Vec<Value>, String> {
    let mut records: Vec<Value> = Vec::new();
    for payload in WasmParser::new(0).parse_all(module) {
        let payload = payload.map_err(|error| format!("parse Wasm: {error}"))?;
        let Payload::CustomSection(section) = payload else {
            continue;
        };
        if section.name() != section_name {
            continue;
        }
        for record in section
            .data()
            .split(|byte| *byte == b'\n' || *byte == 0)
            .filter(|record| !record.is_empty())
        {
            records.push(
                serde_json::from_slice(record)
                    .map_err(|error| format!("invalid descriptor in {section_name}: {error}"))?,
            );
        }
    }
    records.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(records)
}

fn descriptor_names(records: &[Value], maximum: usize, kind: &str) -> Result<Vec<String>, String> {
    if records.len() > maximum {
        return Err(format!("workflow has too many {kind} descriptors"));
    }
    let mut names = BTreeSet::new();
    for record in records {
        let name = record
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .ok_or_else(|| format!("{kind} descriptor has no valid name"))?;
        if !names.insert(name.to_owned()) {
            return Err(format!("duplicate {kind} descriptor `{name}`"));
        }
    }
    Ok(names.into_iter().collect())
}

fn split_debug_artifacts(
    module: &[u8],
    compiler_identity: &CompilerIdentity,
    source_paths: &[String],
    environments: &[EnvironmentResource],
    entrypoint_descriptors: &[Value],
    task_descriptors: &[Value],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut execution = module
        .get(..8)
        .ok_or("compiled Wasm module has no header")?
        .to_vec();
    let mut sections = Vec::new();
    for payload in WasmParser::new(0).parse_all(module) {
        let payload = payload.map_err(|error| format!("parse Wasm debug metadata: {error}"))?;
        let Some((id, range)) = payload.as_section() else {
            continue;
        };
        if let Payload::CustomSection(section) = &payload {
            if section.name() == "name"
                || section.name().starts_with(".debug_")
                || section.name() == "sourceMappingURL"
                || section.name().starts_with("clusterflux.debug")
            {
                sections.push(json!({
                    "name": section.name(),
                    "data_base64": BASE64_STANDARD.encode(section.data()),
                }));
                continue;
            }
        }
        append_raw_section(&mut execution, id, &module[range]);
    }
    let probe_descriptors = descriptor_records(module, "clusterflux.probes")?;
    let sidecar = serde_json::to_vec(&json!({
        "format": "clusterflux-wasm-debug-v2",
        "compiler_identity": compiler_identity,
        "path_remapping": [{"from": "/workflow", "to": ".clusterflux"}],
        "source_inventory": source_paths,
        "environments": environments,
        "sections": sections,
        "task_descriptors": task_descriptors,
        "entrypoint_descriptors": entrypoint_descriptors,
        "probe_descriptors": probe_descriptors,
    }))
    .map_err(|error| format!("encode workflow debug sidecar: {error}"))?;
    if sidecar.len() > MAX_COMPILED_WORKFLOW_DEBUG_BYTES {
        return Err("workflow debug metadata is oversized".to_owned());
    }
    Ok((execution, sidecar))
}

fn append_custom_section(module: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut section = Vec::new();
    encode_unsigned_leb(name.len() as u64, &mut section);
    section.extend_from_slice(name.as_bytes());
    section.extend_from_slice(data);
    module.push(0);
    encode_unsigned_leb(section.len() as u64, module);
    module.extend_from_slice(&section);
}

fn append_raw_section(module: &mut Vec<u8>, id: u8, contents: &[u8]) {
    module.push(id);
    encode_unsigned_leb(contents.len() as u64, module);
    module.extend_from_slice(contents);
}

fn encode_unsigned_leb(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedInput {
    pub path: String,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleIdentityInputs {
    pub wasm_code: Digest,
    pub task_abi: Digest,
    pub entrypoints: Vec<String>,
    pub default_entrypoint: String,
    pub environments: Vec<EnvironmentResource>,
    pub source_provider_manifest: Digest,
    pub source_transfer_policy: SourceTransferPolicy,
    pub selected_inputs: Vec<SelectedInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMetadata {
    pub identity: Digest,
    pub wasm_code: Digest,
    pub task_metadata: BundleTaskMetadata,
    pub source_metadata: BundleSourceMetadata,
    pub debug_metadata: BundleDebugMetadata,
    pub large_input_policy: BundleLargeInputPolicy,
    pub restart_compatibility: BundleRestartCompatibility,
    pub environments: Vec<EnvironmentResource>,
    pub selected_inputs: Vec<SelectedInput>,
    pub embeds_full_container_images: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleTaskMetadata {
    pub task_abi: Digest,
    pub entrypoints: Vec<String>,
    pub default_entrypoint: String,
    pub authority: String,
    pub boundary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSourceMetadata {
    pub source_provider_manifest: Digest,
    pub transfer_policy: SourceTransferPolicy,
    pub selected_inputs: Vec<SelectedInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDebugMetadata {
    pub available: bool,
    pub source_level_breakpoints: bool,
    pub dap_virtual_process: bool,
    pub variables_pane_supported: bool,
    pub probes: Vec<BundleDebugProbe>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDebugProbe {
    pub id: String,
    #[serde(default)]
    pub probe_symbol: String,
    pub source_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub function: String,
    pub task: TaskDefinitionId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    pub source_path: String,
    pub line: u32,
    pub column: Option<u32>,
    pub probe_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleLargeInputPolicy {
    pub selected_inputs_are_content_digests: bool,
    pub selected_input_bytes_included: bool,
    pub full_repository_bytes_included: bool,
    pub silent_task_argument_serialization: bool,
    pub supported_handle_types: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRestartCompatibility {
    pub source_edits_can_restart_from_clean_task_boundary: bool,
    pub requires_clean_checkpoint_boundary: bool,
    pub compares_task_abi: Digest,
    pub compares_environment_digests: bool,
    pub compares_serialized_args: bool,
    pub discards_unflushed_task_local_changes: bool,
    pub incompatible_changes_require_whole_process_restart: bool,
}

impl BundleIdentityInputs {
    pub fn identity(&self) -> Digest {
        let mut parts = vec![
            b"bundle:v1".to_vec(),
            self.wasm_code.as_str().as_bytes().to_vec(),
            self.task_abi.as_str().as_bytes().to_vec(),
            self.source_provider_manifest.as_str().as_bytes().to_vec(),
            self.default_entrypoint.as_bytes().to_vec(),
            format!("{:?}", self.source_transfer_policy).into_bytes(),
        ];

        let mut entrypoints = self.entrypoints.clone();
        entrypoints.sort();
        for entrypoint in entrypoints {
            parts.push(entrypoint.into_bytes());
        }

        let mut environments = self.environments.clone();
        environments.sort_by(|left, right| left.name.cmp(&right.name));
        for environment in environments {
            parts.push(environment.name.as_bytes().to_vec());
            parts.push(format!("{:?}", environment.kind).into_bytes());
            parts.push(environment.digest.as_str().as_bytes().to_vec());
        }

        let mut inputs = self.selected_inputs.clone();
        inputs.sort_by(|left, right| left.path.cmp(&right.path));
        for input in inputs {
            parts.push(input.path.into_bytes());
            parts.push(input.digest.as_str().as_bytes().to_vec());
        }

        Digest::from_parts(parts)
    }

    pub fn inspectable_metadata(&self) -> BundleMetadata {
        let mut entrypoints = self.entrypoints.clone();
        entrypoints.sort();

        BundleMetadata {
            identity: self.identity(),
            wasm_code: self.wasm_code.clone(),
            task_metadata: BundleTaskMetadata {
                task_abi: self.task_abi.clone(),
                entrypoints,
                default_entrypoint: self.default_entrypoint.clone(),
                authority: "source_candidates".to_owned(),
                boundary: "approximate_pre_build_source_inspection".to_owned(),
            },
            source_metadata: BundleSourceMetadata {
                source_provider_manifest: self.source_provider_manifest.clone(),
                transfer_policy: self.source_transfer_policy.clone(),
                selected_inputs: self.selected_inputs.clone(),
            },
            debug_metadata: BundleDebugMetadata {
                available: true,
                source_level_breakpoints: true,
                dap_virtual_process: true,
                variables_pane_supported: true,
                probes: Vec::new(),
            },
            large_input_policy: BundleLargeInputPolicy {
                selected_inputs_are_content_digests: true,
                selected_input_bytes_included: false,
                full_repository_bytes_included: false,
                silent_task_argument_serialization: false,
                supported_handle_types: vec![
                    "SourceSnapshot".to_owned(),
                    "Blob".to_owned(),
                    "Artifact".to_owned(),
                    "VFS".to_owned(),
                ],
            },
            restart_compatibility: BundleRestartCompatibility {
                source_edits_can_restart_from_clean_task_boundary: true,
                requires_clean_checkpoint_boundary: true,
                compares_task_abi: self.task_abi.clone(),
                compares_environment_digests: true,
                compares_serialized_args: true,
                discards_unflushed_task_local_changes: true,
                incompatible_changes_require_whole_process_restart: true,
            },
            environments: self.environments.clone(),
            selected_inputs: self.selected_inputs.clone(),
            embeds_full_container_images: false,
        }
    }
}

pub fn discover_source_debug_probes(
    source_path: impl Into<String>,
    source: &str,
) -> Vec<BundleDebugProbe> {
    let source_path = source_path.into();
    let lines = source.lines().collect::<Vec<_>>();
    let function_starts = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            parse_rust_function_name(line).map(|function| (index, function))
        })
        .collect::<Vec<_>>();
    let Ok(file) = syn::parse_file(source) else {
        return Vec::new();
    };

    file.items
        .iter()
        .filter_map(|item| {
            let Item::Fn(function) = item else {
                return None;
            };
            let function_name = function.sig.ident.to_string();
            let task = clusterflux_probe_task(function)?;
            let (function_index, (line_index, _)) = function_starts
                .iter()
                .enumerate()
                .find(|(_, (_, candidate))| candidate == &function_name)?;
            let line_start = (*line_index + 1) as u32;
            let next_start = function_starts
                .get(function_index + 1)
                .map(|(next_index, _)| *next_index)
                .unwrap_or(lines.len());
            let line_end = next_start.max(*line_index + 1) as u32;
            Some(debug_probe(
                &source_path,
                line_start,
                line_end,
                &function_name,
                task,
            ))
        })
        .collect()
}

fn debug_probe(
    source_path: &str,
    line_start: u32,
    line_end: u32,
    function: &str,
    task: TaskDefinitionId,
) -> BundleDebugProbe {
    let id = Digest::from_parts([
        b"bundle-debug-probe:v1".as_slice(),
        source_path.as_bytes(),
        function.as_bytes(),
        task.as_str().as_bytes(),
        line_start.to_string().as_bytes(),
        line_end.to_string().as_bytes(),
    ])
    .as_str()
    .to_owned();
    BundleDebugProbe {
        id,
        probe_symbol: format!("clusterflux.probe.{function}"),
        source_path: source_path.to_owned(),
        line_start,
        line_end,
        function: function.to_owned(),
        task,
    }
}

fn parse_rust_function_name(line: &str) -> Option<String> {
    let start = line.find("fn ")? + 3;
    let rest = &line[start..];
    let name = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

fn clusterflux_probe_task(function: &syn::ItemFn) -> Option<TaskDefinitionId> {
    for attribute in &function.attrs {
        let mut segments = attribute.path().segments.iter();
        let Some(namespace) = segments.next() else {
            continue;
        };
        let Some(kind) = segments.next() else {
            continue;
        };
        if namespace.ident != "clusterflux" || segments.next().is_some() {
            continue;
        }
        let function_name = function.sig.ident.to_string();
        let default_name = match kind.ident.to_string().as_str() {
            "main" => function_name
                .strip_suffix("_main")
                .unwrap_or(&function_name)
                .to_owned(),
            "task" => function_name,
            _ => continue,
        };
        let declared_name = match &attribute.meta {
            Meta::List(list) => {
                let parser = syn::punctuated::Punctuated::<Meta, Token![,]>::parse_terminated;
                parser
                    .parse2(list.tokens.clone())
                    .ok()
                    .and_then(|items| {
                        items.into_iter().find_map(|item| {
                            let Meta::NameValue(name_value) = item else {
                                return None;
                            };
                            if !name_value.path.is_ident("name") {
                                return None;
                            }
                            let Expr::Lit(value) = name_value.value else {
                                return None;
                            };
                            let Lit::Str(value) = value.lit else {
                                return None;
                            };
                            Some(value.value())
                        })
                    })
                    .unwrap_or(default_name)
            }
            _ => default_name,
        };
        return Some(TaskDefinitionId::new(declared_name));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{EnvironmentKind, EnvironmentRequirements};

    use super::*;

    fn env(digest: &str) -> EnvironmentResource {
        EnvironmentResource {
            name: "linux".to_owned(),
            kind: EnvironmentKind::Containerfile,
            recipe_path: PathBuf::from("envs/linux/Containerfile"),
            context_path: PathBuf::from("envs/linux"),
            context_manifest: Vec::new(),
            context_manifest_digest: Digest::from_parts([b"environment-context:v1"]),
            digest: Digest::sha256(digest),
            requirements: EnvironmentRequirements::linux_container(),
        }
    }

    fn compiler(profile: CompilerProfile) -> CompilerIdentity {
        CompilerIdentity {
            profile,
            rustc_version: "1.88.0".to_owned(),
            rustc_commit: Some("0123456789abcdef".to_owned()),
            target: "wasm32-unknown-unknown".to_owned(),
            flags: vec!["-Copt-level=1".to_owned()],
            sdk_version: "0.2.0".to_owned(),
            sdk_digest: Digest::sha256("sdk"),
            trusted_dependencies: Vec::new(),
            sandbox_image_digest: None,
        }
    }

    fn descriptor_module(entrypoints: &[Value]) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        for entrypoint in entrypoints {
            let mut record = serde_json::to_vec(entrypoint).unwrap();
            record.push(0);
            append_custom_section(&mut module, "clusterflux.entrypoints", &record);
        }
        let mut task = serde_json::to_vec(&json!({
            "name": "task",
            "required_capabilities": []
        }))
        .unwrap();
        task.push(0);
        append_custom_section(&mut module, "clusterflux.tasks", &task);
        module
    }

    #[test]
    fn shared_finalizer_attaches_environments_splits_debug_and_selects_one_authority() {
        let finalized = finalize_compiled_workflow(CompiledWorkflowInput {
            wasm_bytes: descriptor_module(&[
                json!({"name": "build", "default": true}),
                json!({"name": "main", "default": false}),
            ]),
            compiler_identity: compiler(CompilerProfile::LocalCargo),
            manifest_digest: Digest::sha256("manifest"),
            source_identity: Digest::sha256("source"),
            normalized_source_paths: vec![".clusterflux/main.rs".to_owned()],
            environments: vec![env("recipe")],
            requested_entrypoint: None,
        })
        .unwrap();

        assert_eq!(finalized.bundle.default_entrypoint, "build");
        assert_eq!(finalized.bundle.environment_names, ["linux"]);
        let attached_environment = WasmParser::new(0)
            .parse_all(&finalized.execution_module)
            .filter_map(Result::ok)
            .find_map(|payload| match payload {
                Payload::CustomSection(section) if section.name() == "clusterflux.environments" => {
                    Some(section.data().to_vec())
                }
                _ => None,
            })
            .expect("finalizer attached environment authority");
        let attached: Vec<EnvironmentResource> =
            serde_json::from_slice(&attached_environment).unwrap();
        assert_eq!(attached[0].name, "linux");
        let sidecar: Value = serde_json::from_slice(&finalized.debug_sidecar).unwrap();
        assert_eq!(sidecar["format"], "clusterflux-wasm-debug-v2");
        assert_eq!(sidecar["source_inventory"][0], ".clusterflux/main.rs");
        assert_eq!(sidecar["environments"][0]["name"], "linux");
    }

    #[test]
    fn entrypoint_rule_rejects_ambiguity_and_honors_explicit_request() {
        let descriptors = vec![json!({"name": "build"}), json!({"name": "test"})];
        assert!(select_entrypoint(&descriptors, None)
            .unwrap_err()
            .contains("ambiguous"));
        assert_eq!(
            select_entrypoint(&descriptors, Some("test")).unwrap()["name"],
            "test"
        );
    }

    #[test]
    fn shared_finalizer_rejects_duplicate_compiled_entrypoint_descriptors() {
        let error = finalize_compiled_workflow(CompiledWorkflowInput {
            wasm_bytes: descriptor_module(&[json!({"name": "build"}), json!({"name": "build"})]),
            compiler_identity: compiler(CompilerProfile::LocalCargo),
            manifest_digest: Digest::sha256("manifest"),
            source_identity: Digest::sha256("source"),
            normalized_source_paths: vec![".clusterflux/main.rs".to_owned()],
            environments: Vec::new(),
            requested_entrypoint: None,
        })
        .unwrap_err();
        assert!(error.contains("duplicate entrypoint descriptor `build`"));
    }

    #[test]
    fn raw_debug_bearing_output_is_split_before_final_limits() {
        let mut module = descriptor_module(&[json!({"name": "main"})]);
        append_custom_section(&mut module, "execution-padding", &vec![0_u8; 2_500 * 1024]);
        append_custom_section(&mut module, ".debug_info", &vec![7_u8; 3 * 1024 * 1024]);
        assert!(module.len() > 4 * 1024 * 1024);

        let finalized = finalize_compiled_workflow(CompiledWorkflowInput {
            wasm_bytes: module,
            compiler_identity: compiler(CompilerProfile::HostedSandbox),
            manifest_digest: Digest::sha256("manifest"),
            source_identity: Digest::sha256("source"),
            normalized_source_paths: vec![".clusterflux/main.rs".to_owned()],
            environments: Vec::new(),
            requested_entrypoint: None,
        })
        .unwrap();

        assert!(finalized.execution_module.len() < MAX_COMPILED_WORKFLOW_MODULE_BYTES);
        assert!(finalized.debug_sidecar.len() < MAX_COMPILED_WORKFLOW_DEBUG_BYTES);
    }

    #[test]
    fn raw_execution_and_debug_limits_are_independent() {
        let input = |wasm_bytes| CompiledWorkflowInput {
            wasm_bytes,
            compiler_identity: compiler(CompilerProfile::HostedSandbox),
            manifest_digest: Digest::sha256("manifest"),
            source_identity: Digest::sha256("source"),
            normalized_source_paths: vec![".clusterflux/main.rs".to_owned()],
            environments: Vec::new(),
            requested_entrypoint: None,
        };
        assert!(
            finalize_compiled_workflow(input(vec![0; MAX_RAW_COMPILER_WASM_BYTES + 1]))
                .unwrap_err()
                .contains("oversized")
        );

        let mut execution = descriptor_module(&[json!({"name": "main"})]);
        append_custom_section(
            &mut execution,
            "execution-padding",
            &vec![0; MAX_COMPILED_WORKFLOW_MODULE_BYTES],
        );
        assert!(finalize_compiled_workflow(input(execution))
            .unwrap_err()
            .contains("execution/debug artifacts"));

        let mut debug = descriptor_module(&[json!({"name": "main"})]);
        append_custom_section(&mut debug, ".debug_info", &vec![0; 7 * 1024 * 1024]);
        assert!(finalize_compiled_workflow(input(debug))
            .unwrap_err()
            .contains("debug metadata"));
    }

    #[test]
    fn local_and_hosted_profiles_share_bundle_schema_and_descriptor_semantics() {
        let finish = |profile| {
            finalize_compiled_workflow(CompiledWorkflowInput {
                wasm_bytes: descriptor_module(&[json!({"name": "main"})]),
                compiler_identity: compiler(profile),
                manifest_digest: Digest::sha256("manifest"),
                source_identity: Digest::sha256("source"),
                normalized_source_paths: vec![".clusterflux/main.rs".to_owned()],
                environments: vec![env("recipe")],
                requested_entrypoint: None,
            })
            .unwrap()
        };
        let local = finish(CompilerProfile::LocalCargo);
        let hosted = finish(CompilerProfile::HostedSandbox);
        let keys = |bundle: &CompiledWorkflowBundle| {
            serde_json::to_value(bundle)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(keys(&local.bundle), keys(&hosted.bundle));
        assert_eq!(local.bundle.entrypoints, hosted.bundle.entrypoints);
        assert_eq!(
            local.bundle.task_definitions,
            hosted.bundle.task_definitions
        );
        assert_eq!(
            local.bundle.environment_names,
            hosted.bundle.environment_names
        );
        assert_eq!(
            local.bundle.execution_module_digest,
            hosted.bundle.execution_module_digest
        );
        assert_ne!(local.bundle.bundle_digest, hosted.bundle.bundle_digest);
    }

    #[test]
    fn bundle_identity_changes_when_environment_recipe_changes() {
        let base = BundleIdentityInputs {
            wasm_code: Digest::sha256("wasm"),
            task_abi: Digest::sha256("abi"),
            entrypoints: vec!["build".to_owned()],
            default_entrypoint: "build".to_owned(),
            environments: vec![env("recipe-a")],
            source_provider_manifest: Digest::sha256("source"),
            source_transfer_policy: SourceTransferPolicy::local_first_snapshot_chunks(),
            selected_inputs: vec![],
        };
        let mut changed = base.clone();
        changed.environments = vec![env("recipe-b")];

        assert_ne!(base.identity(), changed.identity());
    }

    #[test]
    fn bundle_metadata_is_inspectable_and_does_not_vendor_images_by_default() {
        let inputs = BundleIdentityInputs {
            wasm_code: Digest::sha256("wasm"),
            task_abi: Digest::sha256("abi"),
            entrypoints: vec!["build".to_owned(), "test".to_owned()],
            default_entrypoint: "build".to_owned(),
            environments: vec![env("recipe")],
            source_provider_manifest: Digest::sha256("source"),
            source_transfer_policy: SourceTransferPolicy::local_first_snapshot_chunks(),
            selected_inputs: vec![SelectedInput {
                path: "inputs/config.json".to_owned(),
                digest: Digest::sha256("config"),
            }],
        };

        let metadata = inputs.inspectable_metadata();

        assert!(metadata.wasm_code.as_str().starts_with("sha256:"));
        assert_eq!(metadata.task_metadata.default_entrypoint, "build");
        assert!(metadata
            .task_metadata
            .entrypoints
            .contains(&"test".to_owned()));
        assert!(metadata.debug_metadata.dap_virtual_process);
        assert!(
            metadata
                .source_metadata
                .transfer_policy
                .local_source_bytes_remain_node_local
        );
        assert!(
            metadata
                .large_input_policy
                .selected_inputs_are_content_digests
        );
        assert!(!metadata.large_input_policy.selected_input_bytes_included);
        assert!(!metadata.large_input_policy.full_repository_bytes_included);
        assert!(
            !metadata
                .large_input_policy
                .silent_task_argument_serialization
        );
        assert!(metadata
            .large_input_policy
            .supported_handle_types
            .contains(&"Artifact".to_owned()));
        assert!(
            metadata
                .restart_compatibility
                .source_edits_can_restart_from_clean_task_boundary
        );
        assert!(
            metadata
                .restart_compatibility
                .requires_clean_checkpoint_boundary
        );
        assert_eq!(
            metadata.restart_compatibility.compares_task_abi,
            inputs.task_abi
        );
        assert!(
            metadata
                .restart_compatibility
                .incompatible_changes_require_whole_process_restart
        );
        assert_eq!(metadata.environments.len(), 1);
        assert!(!metadata.embeds_full_container_images);
    }

    #[test]
    fn source_debug_probe_metadata_maps_function_ranges_to_tasks() {
        let probes = discover_source_debug_probes(
            "src/build.rs",
            r#"#[clusterflux::main]
fn build_main() {
    let linux = compile_linux();
}

#[clusterflux::task]
fn compile_linux() {
    println!("linux");
}

fn helper_without_runtime_probe() {}

#[clusterflux::task(name = "release")]
fn package_release() {
    println!("package");
}
"#,
        );

        assert_eq!(probes.len(), 3);
        assert_eq!(probes[0].source_path, "src/build.rs");
        assert_eq!(probes[0].function, "build_main");
        assert_eq!(probes[0].task, TaskDefinitionId::from("build"));
        assert_eq!(probes[0].line_start, 2);
        assert_eq!(probes[0].line_end, 6);
        assert_eq!(probes[1].function, "compile_linux");
        assert_eq!(probes[1].task, TaskDefinitionId::from("compile_linux"));
        assert_eq!(probes[2].function, "package_release");
        assert_eq!(probes[2].task, TaskDefinitionId::from("release"));
        assert!(probes.iter().all(|probe| probe.id.starts_with("sha256:")));

        let duplicate_name_elsewhere = discover_source_debug_probes(
            "src/other.rs",
            "#[clusterflux::task]\nfn compile_linux() {}\n",
        );
        assert_ne!(probes[1].id, duplicate_name_elsewhere[0].id);
    }
}
