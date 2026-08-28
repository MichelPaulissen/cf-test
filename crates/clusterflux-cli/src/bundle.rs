use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clusterflux_core::{
    diagnose_environment_references, discover_source_debug_probes, BundleDebugProbe,
    BundleIdentityInputs, BundleMetadata, Digest, EnvironmentReference, ProjectModel,
    SelectedInput, SourceProviderKind, SourceProviderManifest,
};
use clusterflux_source::detect_source_provider;
use serde::Serialize;

use crate::BundleInspectArgs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct BundleInspection {
    pub(crate) project: PathBuf,
    pub(crate) default_source_providers: Vec<SourceProviderKind>,
    pub(crate) source_provider_manifest: SourceProviderManifest,
    pub(crate) source_provider_statuses: Vec<SourceProviderStatus>,
    pub(crate) environment_diagnostics: Vec<EnvironmentDiagnosticReport>,
    pub(crate) pre_schedule_diagnostics: Vec<CliDiagnostic>,
    pub(crate) metadata: BundleMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SourceProviderStatus {
    pub(crate) provider: String,
    pub(crate) status: String,
    pub(crate) active: bool,
    pub(crate) reason: String,
    pub(crate) coordinator_checkout_required: bool,
    pub(crate) coordinator_receives_source_bytes_by_default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EnvironmentDiagnosticReport {
    pub(crate) path: String,
    pub(crate) reference: EnvironmentReference,
    pub(crate) message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CliDiagnostic {
    pub(crate) severity: String,
    pub(crate) category: String,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) next_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceProviderSelection {
    active_provider: SourceProviderKind,
    statuses: Vec<SourceProviderStatus>,
}

pub(crate) fn discovered_environment_names(inspection: Option<&BundleInspection>) -> Vec<String> {
    inspection
        .map(|inspection| {
            inspection
                .metadata
                .environments
                .iter()
                .map(|environment| environment.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn bundle_inspection(args: BundleInspectArgs, cwd: PathBuf) -> Result<BundleInspection> {
    let project = args.project.unwrap_or(cwd);
    let provider_selection = source_provider_selection(
        &project,
        args.source_provider.as_deref(),
        &args.disabled_source_providers,
    )?;
    let project = project
        .canonicalize()
        .context("resolve local Clusterflux project root")?;
    let model = ProjectModel::discover_without_config(&project)
        .map_err(anyhow::Error::msg)
        .context("inspect local .clusterflux Cargo project")?;
    let selected_inputs = local_selected_inputs(&project, &model)?;
    let debug_probes = discover_debug_probes(&project, &selected_inputs)?;
    let source_provider_manifest = source_provider_manifest(&provider_selection.active_provider);
    source_provider_manifest.validate_public_mvp()?;
    let environment_diagnostics =
        environment_diagnostics_for_inputs(&project, &selected_inputs, &model.environments)?;
    let identity_inputs = BundleIdentityInputs {
        wasm_code: wasm_source_proxy_digest(&selected_inputs),
        task_abi: task_abi_digest(&model),
        entrypoints: model.entrypoints.keys().cloned().collect(),
        default_entrypoint: model.default_entrypoint.clone(),
        environments: model.environments.clone(),
        source_provider_manifest: source_provider_manifest.digest.clone(),
        source_transfer_policy: source_provider_manifest.transfer_policy.clone(),
        selected_inputs,
    };
    let mut metadata = identity_inputs.inspectable_metadata();
    metadata.debug_metadata.probes = debug_probes;
    let pre_schedule_diagnostics = pre_schedule_diagnostics(
        &provider_selection.statuses,
        &environment_diagnostics,
        &model.environments,
    );

    Ok(BundleInspection {
        project,
        default_source_providers: vec![SourceProviderKind::Filesystem, SourceProviderKind::Git],
        source_provider_manifest,
        source_provider_statuses: provider_selection.statuses,
        environment_diagnostics,
        pre_schedule_diagnostics,
        metadata,
    })
}

fn local_selected_inputs(project: &Path, model: &ProjectModel) -> Result<Vec<SelectedInput>> {
    let workflow_root = project.join(".clusterflux");
    let mut pending = vec![workflow_root.clone()];
    let mut selected = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("read local workflow directory {}", directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let relative = path.strip_prefix(project)?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            if relative != ".clusterflux/Cargo.toml" && !relative.ends_with(".rs") {
                continue;
            }
            let digest = if relative == ".clusterflux/Cargo.toml" {
                model.manifest_digest.clone()
            } else {
                Digest::sha256(std::fs::read(&path)?)
            };
            selected.push(SelectedInput {
                path: relative,
                digest,
            });
        }
    }
    selected.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(selected)
}

fn source_provider_selection(
    project: &Path,
    requested_provider: Option<&str>,
    disabled_providers: &[String],
) -> Result<SourceProviderSelection> {
    let detected_provider = detect_source_provider(project)
        .map_err(anyhow::Error::msg)
        .context("detect source provider for project checkout")?;
    let has_git_checkout = detected_provider == SourceProviderKind::Git;
    let disabled = disabled_providers
        .iter()
        .map(|provider| provider.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let requested = requested_provider.map(source_provider_kind_from_id);
    let active_provider = requested.clone().unwrap_or_else(|| {
        if !disabled.contains(detected_provider.provider_id()) {
            detected_provider
        } else {
            SourceProviderKind::Filesystem
        }
    });
    let active_provider_id = active_provider.provider_id().to_owned();
    let mut statuses = vec![
        builtin_source_provider_status(
            SourceProviderKind::Filesystem,
            true,
            disabled.contains("filesystem"),
            active_provider_id == "filesystem",
        ),
        builtin_source_provider_status(
            SourceProviderKind::Git,
            has_git_checkout,
            disabled.contains("git"),
            active_provider_id == "git",
        ),
        SourceProviderStatus {
            provider: "custom".to_owned(),
            status: "disabled".to_owned(),
            active: false,
            reason: "no custom source-provider module was configured for this project".to_owned(),
            coordinator_checkout_required: false,
            coordinator_receives_source_bytes_by_default: false,
        },
    ];

    if let Some(SourceProviderKind::Custom(provider)) = requested {
        statuses.push(SourceProviderStatus {
            provider,
            status: "unsupported".to_owned(),
            active: true,
            reason: "custom source-provider modules must be supplied by public plugin/API code before use".to_owned(),
            coordinator_checkout_required: false,
            coordinator_receives_source_bytes_by_default: false,
        });
    }

    Ok(SourceProviderSelection {
        active_provider,
        statuses,
    })
}

fn source_provider_kind_from_id(provider: &str) -> SourceProviderKind {
    match provider.trim().to_ascii_lowercase().as_str() {
        "filesystem" => SourceProviderKind::Filesystem,
        "git" => SourceProviderKind::Git,
        other => SourceProviderKind::Custom(other.to_owned()),
    }
}

fn builtin_source_provider_status(
    kind: SourceProviderKind,
    available: bool,
    disabled: bool,
    active: bool,
) -> SourceProviderStatus {
    let provider = kind.provider_id().to_owned();
    let (status, reason) = if disabled {
        (
            "disabled",
            format!("source provider `{provider}` was disabled by CLI override"),
        )
    } else if available {
        (
            "enabled",
            format!("source provider `{provider}` is available in this checkout"),
        )
    } else {
        (
            "missing",
            format!("source provider `{provider}` is not available for this checkout"),
        )
    };
    SourceProviderStatus {
        provider,
        status: status.to_owned(),
        active,
        reason,
        coordinator_checkout_required: false,
        coordinator_receives_source_bytes_by_default: false,
    }
}

fn source_provider_manifest(kind: &SourceProviderKind) -> SourceProviderManifest {
    SourceProviderManifest::local_first(
        kind.clone(),
        "default source provider manifest; snapshot creation can be scheduled as a node task",
    )
}

fn environment_diagnostics_for_inputs(
    project: &Path,
    selected_inputs: &[SelectedInput],
    environments: &[clusterflux_core::EnvironmentResource],
) -> Result<Vec<EnvironmentDiagnosticReport>> {
    let mut diagnostics = Vec::new();
    for input in selected_inputs {
        if !input.path.ends_with(".rs") {
            continue;
        }
        let source = std::fs::read_to_string(project.join(&input.path))
            .with_context(|| format!("failed to read {}", project.join(&input.path).display()))?;
        diagnostics.extend(
            diagnose_environment_references(&source, environments)
                .into_iter()
                .map(|diagnostic| EnvironmentDiagnosticReport {
                    path: input.path.clone(),
                    reference: diagnostic.reference,
                    message: diagnostic.message,
                }),
        );
    }
    Ok(diagnostics)
}

fn discover_debug_probes(
    project: &Path,
    selected_inputs: &[SelectedInput],
) -> Result<Vec<BundleDebugProbe>> {
    let mut probes = Vec::new();
    for input in selected_inputs {
        if !input.path.ends_with(".rs") {
            continue;
        }
        let source = std::fs::read_to_string(project.join(&input.path))
            .with_context(|| format!("failed to read {}", project.join(&input.path).display()))?;
        probes.extend(discover_source_debug_probes(&input.path, &source));
    }
    Ok(probes)
}

fn pre_schedule_diagnostics(
    source_provider_statuses: &[SourceProviderStatus],
    environment_diagnostics: &[EnvironmentDiagnosticReport],
    environments: &[clusterflux_core::EnvironmentResource],
) -> Vec<CliDiagnostic> {
    let mut diagnostics = Vec::new();
    diagnostics.extend(
        environment_diagnostics
            .iter()
            .map(|diagnostic| CliDiagnostic {
                severity: "error".to_owned(),
                category: "environment".to_owned(),
                code: "missing_environment".to_owned(),
                message: format!("{} at {}", diagnostic.message, diagnostic.path),
                next_actions: vec![
                    "create the missing envs/<name>/Containerfile or envs/<name>/Dockerfile"
                        .to_owned(),
                    "rerun clusterflux inspect".to_owned(),
                ],
            }),
    );

    diagnostics.extend(
        source_provider_statuses
            .iter()
            .filter(|status| {
                status.active
                    && matches!(
                        status.status.as_str(),
                        "missing" | "disabled" | "unsupported"
                    )
            })
            .map(|status| CliDiagnostic {
                severity: "error".to_owned(),
                category: "source_provider".to_owned(),
                code: format!("source_provider_{}", status.status),
                message: format!(
                    "active source provider `{}` is {}: {}",
                    status.provider, status.status, status.reason
                ),
                next_actions: vec![
                    "choose an available source provider with --source-provider".to_owned(),
                    "rerun clusterflux inspect --json".to_owned(),
                ],
            }),
    );

    for environment in environments {
        if environment.requirements.capabilities.is_empty() {
            continue;
        }
        let mut capabilities = environment
            .requirements
            .capabilities
            .iter()
            .map(|capability| format!("{capability:?}"))
            .collect::<Vec<_>>();
        capabilities.sort();
        diagnostics.push(CliDiagnostic {
            severity: "info".to_owned(),
            category: "capability".to_owned(),
            code: "environment_capability_requirements".to_owned(),
            message: format!(
                "environment `{}` requires node capabilities: {}",
                environment.name,
                capabilities.join(", ")
            ),
            next_actions: vec![
                "attach a node that reports these capabilities before scheduling work".to_owned(),
            ],
        });
    }

    diagnostics
}

fn wasm_source_proxy_digest(selected_inputs: &[SelectedInput]) -> Digest {
    let mut parts = vec![b"wasm-source-proxy:v1".to_vec()];
    for input in selected_inputs {
        parts.push(input.path.as_bytes().to_vec());
        parts.push(input.digest.as_str().as_bytes().to_vec());
    }
    Digest::from_parts(parts)
}

pub(crate) fn task_abi_digest(model: &ProjectModel) -> Digest {
    let mut parts = vec![b"task-abi:v1".to_vec()];
    for entrypoint in model.entrypoints.values() {
        parts.push(entrypoint.name.as_bytes().to_vec());
        parts.push(entrypoint.function.as_bytes().to_vec());
    }
    Digest::from_parts(parts)
}
