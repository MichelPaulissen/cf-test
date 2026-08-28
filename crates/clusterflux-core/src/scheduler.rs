use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ArtifactConnectivityFacts, ArtifactId, ArtifactRelayPolicy, Capability, ClusterfluxPathKind,
    Digest, EnvironmentRequirements, NodeCapabilities, NodeId, ProjectId, TenantId,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub id: NodeId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub capabilities: NodeCapabilities,
    pub cached_environments: BTreeSet<Digest>,
    pub dependency_caches: BTreeSet<Digest>,
    pub source_snapshots: BTreeSet<Digest>,
    pub artifact_locations: BTreeSet<ArtifactId>,
    pub artifact_connectivity: ArtifactConnectivityFacts,
    pub online: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRequest {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub environment: Option<EnvironmentRequirements>,
    pub environment_digest: Option<Digest>,
    #[serde(default)]
    pub environment_cache_required: bool,
    pub required_capabilities: BTreeSet<Capability>,
    pub dependency_cache: Option<Digest>,
    pub source_snapshot: Option<Digest>,
    pub required_artifacts: BTreeSet<ArtifactId>,
    pub quota_available: bool,
    pub policy_allowed: bool,
    pub prefer_node: Option<NodeId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub node: NodeId,
    pub score: i64,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("no capable node for placement: {message}")]
pub struct PlacementError {
    pub message: String,
}

pub trait Scheduler {
    fn place(
        &self,
        nodes: &[NodeDescriptor],
        request: &PlacementRequest,
    ) -> Result<Placement, PlacementError>;
}

#[derive(Clone, Debug, Default)]
pub struct DefaultScheduler;

impl Scheduler for DefaultScheduler {
    fn place(
        &self,
        nodes: &[NodeDescriptor],
        request: &PlacementRequest,
    ) -> Result<Placement, PlacementError> {
        let mut scored = Vec::new();
        let mut rejection_counts = BTreeMap::<String, usize>::new();

        for node in nodes {
            match compatibility(node, request) {
                Ok(mut placement) => {
                    locality_score(node, request, &mut placement);
                    scored.push(placement);
                }
                Err(reasons) => {
                    for reason in reasons {
                        *rejection_counts.entry(reason).or_default() += 1;
                    }
                }
            }
        }

        scored
            .into_iter()
            .max_by_key(|placement| placement.score)
            .ok_or_else(|| PlacementError {
                message: rejection_counts
                    .into_iter()
                    .map(|(reason, count)| format!("{reason} ({count} node(s))"))
                    .collect::<Vec<_>>()
                    .join("; "),
            })
    }
}

fn compatibility(
    node: &NodeDescriptor,
    request: &PlacementRequest,
) -> Result<Placement, Vec<String>> {
    let mut reasons = Vec::new();
    if !node.online {
        reasons.push("node offline".to_owned());
    }
    if node.tenant != request.tenant {
        reasons.push("tenant mismatch".to_owned());
    }
    if node.project != request.project {
        reasons.push("project mismatch".to_owned());
    }
    if !request.quota_available {
        reasons.push("quota unavailable for placement".to_owned());
    }
    if !request.policy_allowed {
        reasons.push("policy denied placement".to_owned());
    }
    if node.capabilities.work_policy == crate::NodeWorkPolicy::SystemTasksOnly {
        reasons.push("system-tasks-only node does not execute process tasks".to_owned());
    }
    for capability in &request.required_capabilities {
        if !node.capabilities.capabilities.contains(capability) {
            reasons.push(format!("missing capability {capability:?}"));
        }
    }
    if let Some(environment) = &request.environment {
        if let Some(required_os) = &environment.os {
            if &node.capabilities.os != required_os {
                reasons.push(format!("environment requires os {required_os:?}"));
            }
        }
        if let Some(required_arch) = &environment.arch {
            if &node.capabilities.arch != required_arch {
                reasons.push(format!("environment requires arch {required_arch}"));
            }
        }
        for capability in &environment.capabilities {
            if !node.capabilities.capabilities.contains(capability) {
                reasons.push(format!("environment requires capability {capability:?}"));
            }
        }
    }
    if request.environment_cache_required {
        match request.environment_digest.as_ref() {
            Some(digest) if !node.cached_environments.contains(digest) => {
                reasons.push(format!(
                    "required named environment cache {digest} is unavailable"
                ));
            }
            None => reasons.push("required named environment cache digest is missing".to_owned()),
            Some(_) => {}
        }
    }
    let source_snapshot_missing = request
        .source_snapshot
        .as_ref()
        .is_some_and(|digest| !node.source_snapshots.contains(digest));
    if source_snapshot_missing {
        // Snapshot-only tasks have no immutable repository revision to clone and
        // Clusterflux has no source-snapshot peer transfer protocol.  A generic
        // Git capability or artifact endpoint therefore cannot make the exact
        // source available.  Callers omit this placement constraint only when
        // the task carries a validated immutable source revision.
        reasons.push("required source snapshot is not local to this node".to_owned());
    }
    let missing_artifacts = request
        .required_artifacts
        .iter()
        .filter(|artifact| !node.artifact_locations.contains(*artifact))
        .count();
    if missing_artifacts > 0 && !node.artifact_connectivity.endpoint_advertised {
        reasons.push(format!(
            "{missing_artifacts} required artifact(s) unavailable and peer data-plane endpoint unavailable"
        ));
    }

    if reasons.is_empty() {
        Ok(Placement {
            node: node.id.clone(),
            score: 0,
            reasons: Vec::new(),
        })
    } else {
        Err(reasons)
    }
}

fn locality_score(node: &NodeDescriptor, request: &PlacementRequest, placement: &mut Placement) {
    if request.prefer_node.as_ref() == Some(&node.id) {
        placement.score += 100;
        placement.reasons.push("preferred node".to_owned());
    }
    if request
        .environment_digest
        .as_ref()
        .is_some_and(|digest| node.cached_environments.contains(digest))
    {
        placement.score += 50;
        placement.reasons.push("warm environment cache".to_owned());
    }
    if request
        .source_snapshot
        .as_ref()
        .is_some_and(|digest| node.source_snapshots.contains(digest))
    {
        placement.score += 40;
        placement
            .reasons
            .push("source snapshot already local".to_owned());
    }
    if request
        .dependency_cache
        .as_ref()
        .is_some_and(|digest| node.dependency_caches.contains(digest))
    {
        placement.score += 30;
        placement.reasons.push("warm dependency cache".to_owned());
    }
    let artifact_hits = request
        .required_artifacts
        .iter()
        .filter(|artifact| node.artifact_locations.contains(*artifact))
        .count() as i64;
    if artifact_hits > 0 {
        placement.score += 10 * artifact_hits;
        placement.reasons.push(format!(
            "{artifact_hits} required artifact(s) already local"
        ));
    }
    let missing_artifacts = request
        .required_artifacts
        .len()
        .saturating_sub(artifact_hits as usize);
    if missing_artifacts > 0 && node.artifact_connectivity.endpoint_advertised {
        match node.artifact_connectivity.recent_path {
            ClusterfluxPathKind::Local => {
                placement.score += 10;
                placement
                    .reasons
                    .push("recent local artifact cache hit".to_owned());
            }
            ClusterfluxPathKind::Direct => {
                placement.score += 5;
                placement
                    .reasons
                    .push("recent direct artifact path".to_owned());
            }
            ClusterfluxPathKind::Relayed
                if node.artifact_connectivity.relay_policy
                    == ArtifactRelayPolicy::RelayFallbackAllowed =>
            {
                placement.score -= 10;
                placement
                    .reasons
                    .push("artifact transfer may use configured self-hosted relay".to_owned());
            }
            ClusterfluxPathKind::Relayed | ClusterfluxPathKind::Unknown => {}
        }
        if node.artifact_connectivity.recent_direct_failure {
            placement.score -= 20;
            placement
                .reasons
                .push("recent direct artifact path failure".to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EnvironmentBackend, Os};

    use super::*;

    fn node(id: &str, cached_source: bool) -> NodeDescriptor {
        let source = Digest::sha256("source");
        NodeDescriptor {
            id: NodeId::from(id),
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            capabilities: NodeCapabilities {
                os: Os::Linux,
                arch: "x86_64".to_owned(),
                capabilities: BTreeSet::from([
                    Capability::Command,
                    Capability::Containers,
                    Capability::RootlessPodman,
                ]),
                environment_backends: BTreeSet::from([EnvironmentBackend::Container]),
                source_providers: BTreeSet::from(["filesystem".to_owned()]),
                work_policy: crate::NodeWorkPolicy::Normal,
                system_bundles: Vec::new(),
            },
            cached_environments: BTreeSet::from([Digest::sha256("env")]),
            dependency_caches: if cached_source {
                BTreeSet::from([Digest::sha256("deps")])
            } else {
                BTreeSet::new()
            },
            source_snapshots: if cached_source {
                BTreeSet::from([source])
            } else {
                BTreeSet::new()
            },
            artifact_locations: BTreeSet::new(),
            artifact_connectivity: ArtifactConnectivityFacts {
                endpoint_advertised: true,
                ..ArtifactConnectivityFacts::default()
            },
            online: true,
        }
    }

    #[test]
    fn scheduler_prefers_warm_source_and_environment() {
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: Some(EnvironmentRequirements::linux_container()),
            environment_digest: Some(Digest::sha256("env")),
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: Some(Digest::sha256("deps")),
            source_snapshot: Some(Digest::sha256("source")),
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let placement = DefaultScheduler
            .place(&[node("cold", false), node("warm", true)], &request)
            .unwrap();

        assert_eq!(placement.node, NodeId::from("warm"));
        assert!(placement
            .reasons
            .iter()
            .any(|reason| reason.contains("source")));
        assert!(placement
            .reasons
            .iter()
            .any(|reason| reason.contains("dependency")));
    }

    #[test]
    fn scheduler_excludes_system_tasks_only_node_from_process_tasks() {
        let mut compiler = node("compiler", false);
        compiler.capabilities.capabilities.clear();
        compiler.capabilities.work_policy = crate::NodeWorkPolicy::SystemTasksOnly;
        compiler.capabilities.environment_backends.clear();
        compiler.capabilities.source_providers.clear();
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let placement = DefaultScheduler
            .place(&[compiler, node("runtime", false)], &request)
            .unwrap();

        assert_eq!(placement.node, NodeId::from("runtime"));
    }

    #[test]
    fn scheduler_requires_requested_named_environment_cache() {
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: Some(Digest::sha256("missing-environment")),
            environment_cache_required: true,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let error = DefaultScheduler
            .place(&[node("uncached", false)], &request)
            .unwrap_err();

        assert!(error.message.contains("named environment cache"));
    }

    #[test]
    fn scheduler_failure_names_missing_constraint() {
        let mut request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::WindowsCommandDev]),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };
        request.required_capabilities.insert(Capability::Command);

        let error = DefaultScheduler
            .place(&[node("linux", false)], &request)
            .unwrap_err();

        assert!(error.message.contains("WindowsCommandDev"));
    }

    #[test]
    fn scheduler_failure_names_environment_constraint() {
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: Some(EnvironmentRequirements::windows_command_dev()),
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let error = DefaultScheduler
            .place(&[node("linux", false)], &request)
            .unwrap_err();

        assert!(error.message.contains("environment requires os Windows"));
        assert!(error
            .message
            .contains("environment requires capability WindowsCommandDev"));
    }

    #[test]
    fn scheduler_requires_snapshot_locality_without_an_immutable_revision() {
        let mut unrelated_checkout = node("unrelated-checkout", false);
        unrelated_checkout
            .capabilities
            .capabilities
            .insert(Capability::SourceGit);
        let mut disconnected = node("disconnected", false);
        disconnected.artifact_connectivity.endpoint_advertised = false;
        let mut local = node("local", true);
        local.artifact_connectivity.endpoint_advertised = false;
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: None,
            source_snapshot: Some(Digest::sha256("source")),
            required_artifacts: BTreeSet::new(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let placement = DefaultScheduler
            .place(&[disconnected, local], &request)
            .unwrap();
        assert_eq!(placement.node, NodeId::from("local"));

        let error = DefaultScheduler
            .place(&[unrelated_checkout], &request)
            .unwrap_err();
        assert!(error
            .message
            .contains("required source snapshot is not local to this node"));

        let mut disconnected = node("disconnected", false);
        disconnected.artifact_connectivity.endpoint_advertised = false;
        let error = DefaultScheduler
            .place(&[disconnected], &request)
            .unwrap_err();

        assert!(error
            .message
            .contains("required source snapshot is not local to this node"));
    }

    #[test]
    fn scheduler_failure_names_required_artifact_transfer_constraint() {
        let mut disconnected = node("disconnected", true);
        disconnected.artifact_connectivity.endpoint_advertised = false;
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::from([ArtifactId::from("cache")]),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let error = DefaultScheduler
            .place(&[disconnected], &request)
            .unwrap_err();

        assert!(error.message.contains(
            "1 required artifact(s) unavailable and peer data-plane endpoint unavailable"
        ));
    }

    #[test]
    fn scheduler_prefers_recent_direct_artifact_paths_without_rejecting_unknown_paths() {
        let mut direct = node("direct", true);
        direct.artifact_connectivity.recent_path = ClusterfluxPathKind::Direct;
        let unknown = node("unknown", true);
        let request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::from([ArtifactId::from("remote-artifact")]),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };

        let placement = DefaultScheduler
            .place(&[unknown, direct], &request)
            .unwrap();
        assert_eq!(placement.node, NodeId::from("direct"));
        assert!(placement
            .reasons
            .iter()
            .any(|reason| reason == "recent direct artifact path"));
    }

    #[test]
    fn scheduler_failure_names_quota_and_policy_constraints() {
        let mut request = PlacementRequest {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: BTreeSet::from([Capability::Command]),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: BTreeSet::new(),
            quota_available: false,
            policy_allowed: true,
            prefer_node: None,
        };

        let error = DefaultScheduler
            .place(&[node("linux", false)], &request)
            .unwrap_err();

        assert!(error.message.contains("quota unavailable for placement"));

        request.quota_available = true;
        request.policy_allowed = false;
        let error = DefaultScheduler
            .place(&[node("linux", false)], &request)
            .unwrap_err();

        assert!(error.message.contains("policy denied placement"));
    }
}
