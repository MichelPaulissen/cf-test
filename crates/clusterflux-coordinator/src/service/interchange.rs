use std::collections::BTreeSet;

use clusterflux_core::{
    generate_opaque_token, ArtifactAssignmentRole, ArtifactAssignmentState,
    ArtifactConnectivityFacts, ArtifactDataPlanePolicy, ArtifactHoldReason, ArtifactId,
    ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferErrorCode,
    ArtifactTransferLease, ArtifactTransferPhase, ArtifactTransferRecord, ArtifactTransferState,
    AuthorizedPeerEndpoint, ClusterfluxDeploymentMode, ClusterfluxPathKind,
    IrohEndpointAdvertisement, IrohRelayConfiguration, NodeId, ProcessId, ProjectId, TenantId,
};

use crate::{CoordinatorError, NodeScopeKey};

use super::interchange_registry::{InterchangeArtifactEffect, InterchangeProgress};
use super::{CoordinatorResponse, CoordinatorService, CoordinatorServiceError};

const DEFAULT_ENDPOINT_ADVERTISEMENT_TTL_SECONDS: u64 = 60;
const ENDPOINT_ADVERTISEMENT_CLOCK_SKEW_SECONDS: u64 = 5;
const DEFAULT_TRANSFER_LEASE_TTL_SECONDS: u64 = 120;
const MAX_INTERCHANGE_TRANSFERS: usize = 4_096;
const DEFAULT_ACTIVE_TRANSFER_LEASE_TTL_SECONDS: u64 = 10 * 60;
const DEFAULT_NO_PROGRESS_TIMEOUT_SECONDS: u64 = 5 * 60;
const MAX_ACTIVE_TRANSFER_LEASE_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_NO_PROGRESS_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_ABSOLUTE_TRANSFER_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_TRANSFER_CREATIONS_PER_TENANT_NODE_MINUTE: usize = 1_000_000;
const MAX_PARTIAL_BYTES_PER_NODE_PROJECT: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_DIRECT_PATH_DEADLINE_MS: u64 = 10 * 60 * 1_000;
const ASSIGNMENT_ACK_RECOVERY_SECONDS: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorArtifactInterchangeConfiguration {
    pub deployment_mode: ClusterfluxDeploymentMode,
    pub relay: IrohRelayConfiguration,
    pub artifact_relay_policy: ArtifactRelayPolicy,
    pub generation: u64,
    pub endpoint_advertisement_ttl_seconds: u64,
    pub transfer_lease_ttl_seconds: u64,
    pub active_transfer_lease_ttl_seconds: u64,
    pub no_progress_timeout_seconds: u64,
    pub absolute_transfer_max_seconds: Option<u64>,
    pub max_active_transfers_per_tenant: usize,
    pub max_active_transfers_per_project: usize,
    pub max_active_transfers_per_process: usize,
    pub max_provider_leases_per_node: usize,
    pub max_receiver_leases_per_node: usize,
    pub max_transfer_creations_per_tenant_node_minute: usize,
    pub max_partial_bytes_per_node_project: u64,
    pub direct_path_deadline_ms: u64,
    pub direct_path_grace_period_ms: u64,
}

impl Default for CoordinatorArtifactInterchangeConfiguration {
    fn default() -> Self {
        Self {
            deployment_mode: ClusterfluxDeploymentMode::SelfHosted,
            relay: IrohRelayConfiguration::Disabled,
            artifact_relay_policy: ArtifactRelayPolicy::DirectRequired,
            generation: 1,
            endpoint_advertisement_ttl_seconds: DEFAULT_ENDPOINT_ADVERTISEMENT_TTL_SECONDS,
            transfer_lease_ttl_seconds: DEFAULT_TRANSFER_LEASE_TTL_SECONDS,
            active_transfer_lease_ttl_seconds: DEFAULT_ACTIVE_TRANSFER_LEASE_TTL_SECONDS,
            no_progress_timeout_seconds: DEFAULT_NO_PROGRESS_TIMEOUT_SECONDS,
            absolute_transfer_max_seconds: None,
            max_active_transfers_per_tenant: 128,
            max_active_transfers_per_project: 64,
            max_active_transfers_per_process: 32,
            max_provider_leases_per_node: 64,
            max_receiver_leases_per_node: 64,
            max_transfer_creations_per_tenant_node_minute: 120,
            max_partial_bytes_per_node_project: 64 * 1024 * 1024 * 1024,
            direct_path_deadline_ms: 20_000,
            direct_path_grace_period_ms: 2_000,
        }
    }
}

impl CoordinatorArtifactInterchangeConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if self.generation == 0
            || self.endpoint_advertisement_ttl_seconds == 0
            || self.endpoint_advertisement_ttl_seconds > 10 * 60
            || self.transfer_lease_ttl_seconds == 0
            || self.transfer_lease_ttl_seconds > 15 * 60
            || self.active_transfer_lease_ttl_seconds == 0
            || self.active_transfer_lease_ttl_seconds > MAX_ACTIVE_TRANSFER_LEASE_TTL_SECONDS
            || self.no_progress_timeout_seconds == 0
            || self.no_progress_timeout_seconds > MAX_NO_PROGRESS_TIMEOUT_SECONDS
            || self.no_progress_timeout_seconds < self.active_transfer_lease_ttl_seconds / 4
            || self.absolute_transfer_max_seconds.is_some_and(|maximum| {
                maximum < self.active_transfer_lease_ttl_seconds
                    || maximum > MAX_ABSOLUTE_TRANSFER_SECONDS
            })
            || self.max_active_transfers_per_tenant == 0
            || self.max_active_transfers_per_tenant > MAX_INTERCHANGE_TRANSFERS
            || self.max_active_transfers_per_project == 0
            || self.max_active_transfers_per_project > MAX_INTERCHANGE_TRANSFERS
            || self.max_active_transfers_per_process == 0
            || self.max_active_transfers_per_process > MAX_INTERCHANGE_TRANSFERS
            || self.max_provider_leases_per_node == 0
            || self.max_provider_leases_per_node > MAX_INTERCHANGE_TRANSFERS
            || self.max_receiver_leases_per_node == 0
            || self.max_receiver_leases_per_node > MAX_INTERCHANGE_TRANSFERS
            || self.max_transfer_creations_per_tenant_node_minute == 0
            || self.max_transfer_creations_per_tenant_node_minute
                > MAX_TRANSFER_CREATIONS_PER_TENANT_NODE_MINUTE
            || self.max_partial_bytes_per_node_project == 0
            || self.max_partial_bytes_per_node_project > MAX_PARTIAL_BYTES_PER_NODE_PROJECT
            || self.direct_path_deadline_ms == 0
            || self.direct_path_deadline_ms > MAX_DIRECT_PATH_DEADLINE_MS
            || self.direct_path_grace_period_ms > self.direct_path_deadline_ms
        {
            return Err(
                "artifact interchange policy contains an invalid generation or bound".to_owned(),
            );
        }
        if self.deployment_mode == ClusterfluxDeploymentMode::HostedPublic {
            if self.artifact_relay_policy != ArtifactRelayPolicy::DirectRequired {
                return Err("hosted public artifact transfers must require direct paths".to_owned());
            }
            if matches!(self.relay, IrohRelayConfiguration::Disabled) {
                return Err(
                    "hosted public NAT traversal requires a Clusterflux assist relay".to_owned(),
                );
            }
        }
        if self.deployment_mode == ClusterfluxDeploymentMode::LocalOffline
            && !matches!(self.relay, IrohRelayConfiguration::Disabled)
        {
            return Err("local/offline artifact interchange must disable relays".to_owned());
        }
        if matches!(self.relay, IrohRelayConfiguration::Disabled)
            && self.artifact_relay_policy == ArtifactRelayPolicy::RelayFallbackAllowed
        {
            return Err(
                "artifact relay fallback cannot be enabled without a configured relay".to_owned(),
            );
        }
        if let IrohRelayConfiguration::Custom(relays) = &self.relay {
            if relays.is_empty() || relays.len() > clusterflux_core::MAX_ENDPOINT_RELAY_URLS {
                return Err("artifact interchange relay list is empty or too large".to_owned());
            }
            let mut urls = BTreeSet::new();
            for relay in relays {
                if relay.url.is_empty()
                    || relay.url.len() > clusterflux_core::MAX_RELAY_URL_BYTES
                    || relay_url_is_forbidden_or_invalid(&relay.url, self.deployment_mode)
                    || !urls.insert(&relay.url)
                {
                    return Err(
                        "artifact interchange relay URL is invalid or duplicated".to_owned()
                    );
                }
            }
        }
        Ok(())
    }

    fn node_policy(&self) -> ArtifactDataPlanePolicy {
        ArtifactDataPlanePolicy {
            relay: self.relay.clone(),
            artifact_relay_policy: self.artifact_relay_policy,
            generation: self.generation,
            endpoint_advertisement_ttl_seconds: self.endpoint_advertisement_ttl_seconds,
            direct_path_deadline_ms: self.direct_path_deadline_ms,
            direct_path_grace_period_ms: self.direct_path_grace_period_ms,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct InterchangeTransfer {
    pub(super) record: ArtifactTransferRecord,
    pub(super) destination_authorization: ArtifactTransferAuthorization,
    pub(super) provider_authorization: ArtifactTransferAuthorization,
    pub(super) destination_assignment: ArtifactAssignmentState,
    pub(super) provider_assignment: ArtifactAssignmentState,
    pub(super) destination_acknowledged_at: Option<u64>,
    pub(super) provider_acknowledged_at: Option<u64>,
    pub(super) metered_body_bytes: u64,
}

impl CoordinatorService {
    pub fn authorize_relay_endpoint(
        &mut self,
        endpoint_id: &str,
    ) -> Result<bool, CoordinatorServiceError> {
        Ok(self.authorized_relay_endpoint_scope(endpoint_id)?.is_some())
    }

    pub fn authorized_relay_endpoint_scope(
        &mut self,
        endpoint_id: &str,
    ) -> Result<Option<NodeScopeKey>, CoordinatorServiceError> {
        self.expire_interchange_state()?;
        if !matches!(
            self.artifact_interchange_configuration.relay,
            IrohRelayConfiguration::Custom(_)
        ) {
            return Ok(None);
        }
        let Some(scope) = self.node_registry.endpoint_scope(endpoint_id) else {
            return Ok(None);
        };
        let active_need = self.interchange_registry.transfers().any(|transfer| {
            !transfer.record.state.terminal()
                && transfer.record.expires_at >= self.current_epoch_seconds().unwrap_or_default()
                && transfer.record.tenant == scope.tenant
                && transfer.record.project == scope.project
                && (transfer.record.source_node == scope.node
                    || transfer.record.destination_node == scope.node)
        });
        Ok((active_need
            && self.node_is_live(scope)
            && self
                .coordinator
                .node_identity(&scope.tenant, &scope.project, &scope.node)
                .is_some())
        .then_some(scope.clone()))
    }

    pub(super) fn artifact_connectivity_facts(
        &self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
    ) -> ArtifactConnectivityFacts {
        let recent = self
            .interchange_registry
            .transfers()
            .filter(|transfer| {
                transfer.record.tenant == scope.tenant
                    && transfer.record.project == scope.project
                    && (transfer.record.source_node == scope.node
                        || transfer.record.destination_node == scope.node)
            })
            .max_by_key(|transfer| transfer.record.updated_at);
        ArtifactConnectivityFacts {
            endpoint_advertised: self
                .node_registry
                .has_active_advertisement(scope, now_epoch_seconds),
            recent_path: recent
                .map(|transfer| transfer.record.path_kind)
                .unwrap_or(ClusterfluxPathKind::Unknown),
            recent_direct_failure: recent.is_some_and(|transfer| {
                matches!(
                    transfer.record.failure_code,
                    Some(ArtifactTransferErrorCode::DirectPathTimeout)
                )
            }),
            relay_policy: self
                .artifact_interchange_configuration
                .artifact_relay_policy,
        }
    }

    pub fn configure_artifact_interchange(
        &mut self,
        configuration: CoordinatorArtifactInterchangeConfiguration,
    ) -> Result<(), CoordinatorServiceError> {
        configuration
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        if configuration.generation <= self.artifact_interchange_configuration.generation {
            return Err(CoordinatorServiceError::Protocol(
                "artifact interchange policy generation must increase".to_owned(),
            ));
        }
        self.artifact_interchange_configuration = configuration;
        self.node_registry.clear_advertisements();
        Ok(())
    }

    pub(super) fn handle_get_artifact_data_plane_policy(
        &mut self,
        tenant: String,
        project: String,
        node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        Ok(CoordinatorResponse::ArtifactDataPlanePolicy {
            policy: self.artifact_interchange_configuration.node_policy(),
        })
    }

    pub(super) fn handle_report_iroh_endpoint_advertisement(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        advertisement: IrohEndpointAdvertisement,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        self.expire_interchange_state()?;
        advertisement
            .validate_bounds()
            .map_err(CoordinatorServiceError::Protocol)?;
        if advertisement.tenant != scope.tenant
            || advertisement.project != scope.project
            || advertisement.node != scope.node
        {
            return Err(CoordinatorError::Unauthorized(
                "Iroh endpoint advertisement is outside the signed node scope".to_owned(),
            )
            .into());
        }
        if advertisement.relay_configuration_generation
            != self.artifact_interchange_configuration.generation
        {
            return Err(CoordinatorServiceError::Protocol(
                "Iroh endpoint advertisement uses a stale relay policy generation".to_owned(),
            ));
        }
        let now = self.current_epoch_seconds()?;
        let maximum_expiry = now.saturating_add(
            self.artifact_interchange_configuration
                .endpoint_advertisement_ttl_seconds,
        );
        if advertisement.expires_at <= now
            || advertisement.expires_at
                > maximum_expiry.saturating_add(ENDPOINT_ADVERTISEMENT_CLOCK_SKEW_SECONDS)
        {
            return Err(CoordinatorServiceError::Protocol(
                "Iroh endpoint advertisement expiry is outside the coordinator policy".to_owned(),
            ));
        }
        self.validate_advertised_relays(&advertisement)?;
        match self
            .node_registry
            .register_advertisement(scope, advertisement.clone())
        {
            Ok(()) => {}
            Err(super::EndpointAdvertisementError::BoundToAnotherScope) => {
                return Err(CoordinatorError::Unauthorized(
                    "Iroh EndpointId is already bound to another active node scope".to_owned(),
                )
                .into());
            }
            Err(super::EndpointAdvertisementError::IdentityChanged) => {
                return Err(CoordinatorError::Unauthorized(
                    "Iroh EndpointId changed without a node identity rotation".to_owned(),
                )
                .into());
            }
            Err(super::EndpointAdvertisementError::StaleGeneration) => {
                return Err(CoordinatorServiceError::Protocol(
                    "Iroh endpoint advertisement generation is stale".to_owned(),
                ));
            }
        }
        Ok(CoordinatorResponse::IrohEndpointAdvertisementAccepted {
            endpoint_id: advertisement.endpoint_id,
            generation: advertisement.generation,
            expires_at: advertisement.expires_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_request_artifact_interchange(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        artifact: String,
        offset: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let destination_scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&destination_scope)?;
        self.expire_interchange_state()?;
        if !self.node_is_live(&destination_scope) {
            return Err(CoordinatorServiceError::Protocol(
                ArtifactTransferErrorCode::DestinationNodeOffline
                    .as_str()
                    .to_owned(),
            ));
        }
        let process = ProcessId::try_new(process)
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?;
        let artifact = ArtifactId::try_new(artifact)
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?;
        if self.process_registry.is_cancelled(&(
            destination_scope.tenant.clone(),
            destination_scope.project.clone(),
            process.clone(),
        )) {
            return Err(CoordinatorServiceError::Protocol(
                ArtifactTransferErrorCode::TransferCancelled
                    .as_str()
                    .to_owned(),
            ));
        }
        let metadata = self
            .artifact_registry
            .metadata(
                &destination_scope.tenant,
                &destination_scope.project,
                &artifact,
            )
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    ArtifactTransferErrorCode::NoArtifactLocation
                        .as_str()
                        .to_owned(),
                )
            })?;
        if metadata.process != process {
            return Err(CoordinatorError::Unauthorized(
                "artifact transfer process does not own the requested artifact".to_owned(),
            )
            .into());
        }
        // A transfer is coordinator work on behalf of a concrete retention need.
        // Once process/task/transfer/download/checkpoint/explicit holds are gone,
        // a late receiver poll must not resurrect the released artifact.
        if self
            .artifact_registry
            .holds(
                &destination_scope.tenant,
                &destination_scope.project,
                &artifact,
            )
            .is_empty()
        {
            return Err(CoordinatorServiceError::Protocol(
                "artifact_released".to_owned(),
            ));
        }
        if offset > metadata.size {
            return Err(CoordinatorServiceError::Protocol(
                ArtifactTransferErrorCode::RangeInvalid.as_str().to_owned(),
            ));
        }
        let now = self.current_epoch_seconds()?;
        if metadata.retaining_nodes.contains(&destination_scope.node) {
            let transfer_id = generate_opaque_token("artifact_local")
                .map_err(CoordinatorServiceError::Protocol)?;
            return Ok(CoordinatorResponse::ArtifactTransferAuthorization {
                authorization: None,
                transfer: Some(ArtifactTransferRecord {
                    transfer_id,
                    tenant: destination_scope.tenant,
                    project: destination_scope.project,
                    process,
                    artifact,
                    source_node: destination_scope.node.clone(),
                    destination_node: destination_scope.node,
                    bytes_completed: metadata.size,
                    path_kind: ClusterfluxPathKind::Local,
                    state: ArtifactTransferState::Completed,
                    created_at: now,
                    updated_at: now,
                    expires_at: now,
                    stream_ticket_expires_at: now,
                    last_progress_at: now,
                    total_bytes: metadata.size,
                    phase: ArtifactTransferPhase::Complete,
                    failure_code: None,
                    attempt_count: 0,
                }),
            });
        }
        let destination_advertisement = self.active_advertisement(&destination_scope)?.clone();
        if let Some((authorization, transfer)) = self.interchange_registry.renew(
            &destination_scope.tenant,
            &destination_scope.project,
            &process,
            &artifact,
            &destination_scope.node,
            now,
            self.artifact_interchange_configuration
                .transfer_lease_ttl_seconds,
            self.artifact_interchange_configuration
                .active_transfer_lease_ttl_seconds,
            self.artifact_interchange_configuration
                .absolute_transfer_max_seconds,
        ) {
            return Ok(CoordinatorResponse::ArtifactTransferAuthorization {
                authorization: Some(Box::new(authorization)),
                transfer: Some(transfer),
            });
        }

        let previous_attempts = self
            .interchange_registry
            .transfers()
            .filter(|transfer| {
                transfer.record.tenant == destination_scope.tenant
                    && transfer.record.project == destination_scope.project
                    && transfer.record.process == process
                    && transfer.record.artifact == artifact
                    && transfer.record.destination_node == destination_scope.node
            })
            .collect::<Vec<_>>();
        let attempted_sources = previous_attempts
            .iter()
            .filter(|transfer| {
                transfer.record.state.terminal()
                    && transfer.record.failure_code.is_some_and(|code| {
                        matches!(
                            code.retry_class(),
                            clusterflux_core::ArtifactTransferRetryClass::TryAnotherSource
                                | clusterflux_core::ArtifactTransferRetryClass::PermanentSourceInvalidation
                        )
                    })
            })
            .map(|transfer| transfer.record.source_node.clone())
            .collect::<BTreeSet<_>>();
        let attempt_count = previous_attempts
            .iter()
            .map(|transfer| transfer.record.attempt_count)
            .max()
            .unwrap_or_default()
            .saturating_add(1);

        self.enforce_interchange_admission(
            &destination_scope.tenant,
            &destination_scope.project,
            &process,
            &destination_scope.node,
            metadata.size.saturating_sub(offset),
            now,
        )?;

        let source_scope = metadata
            .retaining_nodes
            .iter()
            .filter(|source| **source != destination_scope.node)
            .filter(|source| !attempted_sources.contains(*source))
            .map(|source| {
                NodeScopeKey::from_refs(
                    &destination_scope.tenant,
                    &destination_scope.project,
                    source,
                )
            })
            .find(|scope| {
                self.node_is_live(scope)
                    && self.node_registry.has_active_advertisement(
                        scope,
                        self.current_epoch_seconds().unwrap_or_default(),
                    )
            })
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    ArtifactTransferErrorCode::EndpointAdvertisementMissing
                        .as_str()
                        .to_owned(),
                )
            })?;
        let provider_active = self
            .interchange_registry
            .transfers()
            .filter(|transfer| {
                !transfer.record.state.terminal()
                    && transfer.record.tenant == source_scope.tenant
                    && transfer.record.project == source_scope.project
                    && transfer.record.source_node == source_scope.node
            })
            .count();
        if provider_active
            >= self
                .artifact_interchange_configuration
                .max_provider_leases_per_node
        {
            return Err(temporary_capacity("provider node lease capacity"));
        }
        let source_advertisement = self.active_advertisement(&source_scope)?.clone();
        let stream_ticket_expires_at = now.saturating_add(
            self.artifact_interchange_configuration
                .transfer_lease_ttl_seconds,
        );
        let expires_at = now.saturating_add(
            self.artifact_interchange_configuration
                .active_transfer_lease_ttl_seconds,
        );
        let transfer_id = generate_opaque_token("artifact_interchange")
            .map_err(CoordinatorServiceError::Protocol)?;
        let nonce = generate_opaque_token("artifact_interchange_nonce")
            .map_err(CoordinatorServiceError::Protocol)?;
        let mut transfer_secret = [0_u8; 32];
        getrandom::fill(&mut transfer_secret).map_err(|error| {
            CoordinatorServiceError::Protocol(format!("generate artifact transfer secret: {error}"))
        })?;
        let lease = ArtifactTransferLease {
            transfer_id: transfer_id.clone(),
            tenant: destination_scope.tenant.clone(),
            project: destination_scope.project.clone(),
            process: process.clone(),
            artifact: artifact.clone(),
            digest: metadata.digest.clone(),
            size_bytes: metadata.size,
            source_node: source_scope.node.clone(),
            source_endpoint_id: source_advertisement.endpoint_id.clone(),
            destination_node: destination_scope.node.clone(),
            destination_endpoint_id: destination_advertisement.endpoint_id.clone(),
            allowed_offset: offset,
            maximum_bytes: metadata.size.saturating_sub(offset),
            relay_policy: self
                .artifact_interchange_configuration
                .artifact_relay_policy,
            direct_path_deadline_ms: self
                .artifact_interchange_configuration
                .direct_path_deadline_ms,
            expires_at: stream_ticket_expires_at,
            active_lease_expires_at: expires_at,
            nonce,
        };
        let destination_authorization = ArtifactTransferAuthorization {
            lease: lease.clone(),
            transfer_secret,
            peer: authorized_peer(&source_advertisement),
        };
        let provider_authorization = ArtifactTransferAuthorization {
            lease,
            transfer_secret,
            peer: authorized_peer(&destination_advertisement),
        };
        let record = ArtifactTransferRecord {
            transfer_id: transfer_id.clone(),
            tenant: destination_scope.tenant,
            project: destination_scope.project,
            process,
            artifact,
            source_node: source_scope.node,
            destination_node: destination_scope.node,
            bytes_completed: offset,
            path_kind: ClusterfluxPathKind::Unknown,
            state: ArtifactTransferState::SourceSelected,
            created_at: now,
            updated_at: now,
            expires_at,
            stream_ticket_expires_at,
            last_progress_at: now,
            total_bytes: metadata.size,
            phase: ArtifactTransferPhase::Queued,
            failure_code: None,
            attempt_count,
        };
        if self
            .interchange_registry
            .create(
                transfer_id,
                InterchangeTransfer {
                    record: record.clone(),
                    destination_authorization: destination_authorization.clone(),
                    provider_authorization,
                    destination_assignment: ArtifactAssignmentState::Offered,
                    provider_assignment: ArtifactAssignmentState::Offered,
                    destination_acknowledged_at: None,
                    provider_acknowledged_at: None,
                    metered_body_bytes: 0,
                },
                MAX_INTERCHANGE_TRANSFERS,
            )
            .is_err()
        {
            return Err(CoordinatorServiceError::Protocol(
                ArtifactTransferErrorCode::CapacityUnavailable
                    .as_str()
                    .to_owned(),
            ));
        }
        let _ = self.artifact_registry.add_hold(
            &record.tenant,
            &record.project,
            &record.artifact,
            ArtifactHoldReason::ActiveTransfer {
                transfer_id: record.transfer_id.clone(),
            },
            now,
        );
        Ok(CoordinatorResponse::ArtifactTransferAuthorization {
            authorization: Some(Box::new(destination_authorization)),
            transfer: Some(record),
        })
    }

    pub(super) fn handle_poll_artifact_provider_assignment(
        &mut self,
        tenant: String,
        project: String,
        node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        self.expire_interchange_state()?;
        let now = self.current_epoch_seconds()?;
        let (retired_transfer_ids, authorization) = self
            .interchange_registry
            .poll_provider_assignment(&scope, now, ASSIGNMENT_ACK_RECOVERY_SECONDS);
        let authorization = authorization.map(Box::new);
        Ok(CoordinatorResponse::ArtifactProviderAssignment {
            authorization,
            retired_transfer_ids,
        })
    }

    pub(super) fn handle_poll_artifact_receiver_assignment(
        &mut self,
        tenant: String,
        project: String,
        node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        self.expire_interchange_state()?;
        let now = self.current_epoch_seconds()?;
        let authorization = self
            .interchange_registry
            .poll_receiver_assignment(&scope, now, ASSIGNMENT_ACK_RECOVERY_SECONDS)
            .map(Box::new);
        Ok(CoordinatorResponse::ArtifactReceiverAssignment { authorization })
    }

    pub(super) fn handle_acknowledge_artifact_assignment(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        transfer_id: String,
        role: ArtifactAssignmentRole,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        self.expire_interchange_state()?;
        let now = self.current_epoch_seconds()?;
        let state =
            match self
                .interchange_registry
                .acknowledge_assignment(&scope, &transfer_id, role, now)
            {
                Ok(state) => state,
                Err(super::AssignmentAcknowledgementError::UnknownTransfer) => {
                    return Err(CoordinatorServiceError::Protocol(
                        "unknown artifact transfer".to_owned(),
                    ));
                }
                Err(super::AssignmentAcknowledgementError::OutsideScope) => {
                    return Err(CoordinatorError::Unauthorized(
                        "artifact assignment acknowledgement is outside the signed node scope"
                            .to_owned(),
                    )
                    .into());
                }
                Err(super::AssignmentAcknowledgementError::RoleMismatch) => {
                    return Err(CoordinatorError::Unauthorized(
                        "artifact assignment role does not match the signed node".to_owned(),
                    )
                    .into());
                }
            };
        Ok(CoordinatorResponse::ArtifactAssignmentAcknowledged {
            transfer_id,
            role,
            state,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_report_artifact_interchange(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        transfer_id: String,
        state: ArtifactTransferState,
        bytes_completed: u64,
        path_kind: ClusterfluxPathKind,
        failure_code: Option<ArtifactTransferErrorCode>,
        verified_digest: Option<clusterflux_core::Digest>,
        verified_size: Option<u64>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = parse_node_scope(tenant, project, node)?;
        self.authorize_interchange_node(&scope)?;
        self.expire_interchange_state()?;
        let now = self.current_epoch_seconds()?;
        let progress = {
            let artifact_registry = &mut self.artifact_registry;
            self.interchange_registry.report_progress(
                &scope,
                &transfer_id,
                state,
                bytes_completed,
                path_kind,
                failure_code,
                verified_digest,
                verified_size,
                now,
                self.artifact_interchange_configuration
                    .active_transfer_lease_ttl_seconds,
                self.artifact_interchange_configuration
                    .transfer_lease_ttl_seconds,
                self.artifact_interchange_configuration
                    .absolute_transfer_max_seconds,
                |effect| match effect {
                    InterchangeArtifactEffect::RecordVerifiedLocation {
                        tenant,
                        project,
                        artifact,
                        node,
                        digest,
                        size,
                    } => artifact_registry
                        .record_verified_retaining_location(
                            &tenant, &project, &artifact, &node, &digest, size,
                        )
                        .map_err(|error| CoordinatorServiceError::Protocol(error.to_string())),
                    InterchangeArtifactEffect::RemoveMissingSource {
                        tenant,
                        project,
                        artifact,
                        node,
                    } => {
                        artifact_registry
                            .remove_retaining_location(&tenant, &project, &artifact, &node);
                        Ok(())
                    }
                },
            )?
        };
        let InterchangeProgress {
            record,
            authorization,
            terminal_hold,
        } = progress;
        if let Some((tenant, project, artifact, reason)) = terminal_hold {
            self.artifact_registry
                .remove_hold(&tenant, &project, &artifact, &reason);
        }
        Ok(CoordinatorResponse::ArtifactTransferProgressAccepted {
            transfer: record,
            authorization,
        })
    }

    pub(super) fn cancel_artifact_interchanges_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        now: u64,
    ) -> usize {
        let (cancelled, released_holds) = self
            .interchange_registry
            .cancel_process(tenant, project, process, now);
        for (tenant, project, artifact, reason) in released_holds {
            self.artifact_registry
                .remove_hold(&tenant, &project, &artifact, &reason);
        }
        cancelled
    }

    fn authorize_interchange_node(
        &self,
        scope: &NodeScopeKey,
    ) -> Result<(), CoordinatorServiceError> {
        self.coordinator
            .node_identity(&scope.tenant, &scope.project, &scope.node)
            .ok_or(CoordinatorError::UnknownNode)?;
        Ok(())
    }

    fn active_advertisement(
        &self,
        scope: &NodeScopeKey,
    ) -> Result<&IrohEndpointAdvertisement, CoordinatorServiceError> {
        let now = self.current_epoch_seconds()?;
        self.node_registry
            .advertisement(scope)
            .filter(|advertisement| advertisement.expires_at > now)
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    ArtifactTransferErrorCode::EndpointAdvertisementMissing
                        .as_str()
                        .to_owned(),
                )
            })
    }

    fn validate_advertised_relays(
        &self,
        advertisement: &IrohEndpointAdvertisement,
    ) -> Result<(), CoordinatorServiceError> {
        let allowed = match &self.artifact_interchange_configuration.relay {
            IrohRelayConfiguration::Disabled => Vec::new(),
            IrohRelayConfiguration::Custom(relays) => relays
                .iter()
                .map(|relay| relay.url.as_str())
                .collect::<Vec<_>>(),
        };
        if advertisement
            .relay_urls
            .iter()
            .any(|url| !allowed.iter().any(|allowed| relay_urls_match(allowed, url)))
        {
            return Err(CoordinatorError::Unauthorized(
                "Iroh endpoint advertised a relay outside coordinator policy".to_owned(),
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn expire_interchange_state(&mut self) -> Result<(), CoordinatorServiceError> {
        let now = self.current_epoch_seconds()?;
        self.node_registry
            .expire_advertisements(now, self.node_stale_after_seconds);
        let no_progress_timeout = self
            .artifact_interchange_configuration
            .no_progress_timeout_seconds;
        let absolute_max = self
            .artifact_interchange_configuration
            .absolute_transfer_max_seconds;
        let released_holds =
            self.interchange_registry
                .expire(now, no_progress_timeout, absolute_max, 10 * 60);
        for (tenant, project, artifact, reason) in released_holds {
            self.artifact_registry
                .remove_hold(&tenant, &project, &artifact, &reason);
        }
        Ok(())
    }

    fn enforce_interchange_admission(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        destination_node: &NodeId,
        requested_partial_bytes: u64,
        now: u64,
    ) -> Result<(), CoordinatorServiceError> {
        let active = self
            .interchange_registry
            .transfers()
            .filter(|transfer| !transfer.record.state.terminal())
            .collect::<Vec<_>>();
        if active
            .iter()
            .filter(|transfer| &transfer.record.tenant == tenant)
            .count()
            >= self
                .artifact_interchange_configuration
                .max_active_transfers_per_tenant
        {
            return Err(temporary_capacity("tenant active-transfer capacity"));
        }
        if active
            .iter()
            .filter(|transfer| {
                &transfer.record.tenant == tenant && &transfer.record.project == project
            })
            .count()
            >= self
                .artifact_interchange_configuration
                .max_active_transfers_per_project
        {
            return Err(temporary_capacity("project active-transfer capacity"));
        }
        if active
            .iter()
            .filter(|transfer| {
                &transfer.record.tenant == tenant
                    && &transfer.record.project == project
                    && &transfer.record.process == process
            })
            .count()
            >= self
                .artifact_interchange_configuration
                .max_active_transfers_per_process
        {
            return Err(temporary_capacity("process active-transfer capacity"));
        }
        let receiver_transfers = active.iter().filter(|transfer| {
            &transfer.record.tenant == tenant
                && &transfer.record.project == project
                && &transfer.record.destination_node == destination_node
        });
        let receiver_count = receiver_transfers.clone().count();
        if receiver_count
            >= self
                .artifact_interchange_configuration
                .max_receiver_leases_per_node
        {
            return Err(temporary_capacity("receiver node lease capacity"));
        }
        let partial_bytes = receiver_transfers.fold(0_u64, |total, transfer| {
            total.saturating_add(
                transfer
                    .record
                    .total_bytes
                    .saturating_sub(transfer.record.bytes_completed),
            )
        });
        if partial_bytes.saturating_add(requested_partial_bytes)
            > self
                .artifact_interchange_configuration
                .max_partial_bytes_per_node_project
        {
            return Err(temporary_capacity("node/project partial-byte capacity"));
        }
        let recent_creations = self
            .interchange_registry
            .transfers()
            .filter(|transfer| {
                &transfer.record.tenant == tenant
                    && &transfer.record.destination_node == destination_node
                    && transfer.record.created_at >= now.saturating_sub(60)
            })
            .count();
        if recent_creations
            >= self
                .artifact_interchange_configuration
                .max_transfer_creations_per_tenant_node_minute
        {
            return Err(temporary_capacity("tenant/node transfer creation rate"));
        }
        Ok(())
    }
}

fn relay_urls_match(configured: &str, advertised: &str) -> bool {
    configured == advertised
        || configured.strip_suffix('/') == Some(advertised)
        || advertised.strip_suffix('/') == Some(configured)
}

fn temporary_capacity(scope: &str) -> CoordinatorServiceError {
    CoordinatorServiceError::Protocol(format!(
        "{}: {scope} is temporarily full; retry with backoff",
        ArtifactTransferErrorCode::CapacityUnavailable.as_str()
    ))
}

fn parse_node_scope(
    tenant: String,
    project: String,
    node: String,
) -> Result<NodeScopeKey, CoordinatorServiceError> {
    Ok(NodeScopeKey::new(
        TenantId::try_new(tenant)
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?,
        ProjectId::try_new(project)
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?,
        NodeId::try_new(node)
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?,
    ))
}

fn authorized_peer(advertisement: &IrohEndpointAdvertisement) -> AuthorizedPeerEndpoint {
    AuthorizedPeerEndpoint {
        node: advertisement.node.clone(),
        endpoint_id: advertisement.endpoint_id.clone(),
        generation: advertisement.generation,
        direct_addresses: advertisement.direct_addresses.clone(),
        relay_urls: advertisement.relay_urls.clone(),
    }
}

fn relay_url_is_forbidden_or_invalid(
    value: &str,
    deployment_mode: ClusterfluxDeploymentMode,
) -> bool {
    if value.contains('?') || value.contains('#') {
        return true;
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return true;
    };
    if !matches!(scheme, "http" | "https") || remainder.is_empty() {
        return true;
    }
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return true;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
    .trim_end_matches('.')
    .to_ascii_lowercase();
    let loopback =
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.");
    (scheme == "http" && (deployment_mode == ClusterfluxDeploymentMode::HostedPublic || !loopback))
        || (deployment_mode == ClusterfluxDeploymentMode::HostedPublic && scheme != "https")
        || host.is_empty()
        || ["iroh.link", "iroh.computer", "n0.computer"]
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_policy_accepts_iroh_root_slash_canonicalization_only() {
        assert!(relay_urls_match(
            "https://relay.clusterflux.example",
            "https://relay.clusterflux.example/"
        ));
        assert!(relay_urls_match(
            "https://relay.clusterflux.example/",
            "https://relay.clusterflux.example"
        ));
        assert!(!relay_urls_match(
            "https://relay.clusterflux.example",
            "https://relay.clusterflux.example/other"
        ));
    }

    #[test]
    fn interchange_configuration_rejects_effectively_unbounded_limits() {
        let fields: [fn(&mut CoordinatorArtifactInterchangeConfiguration); 5] = [
            |configuration: &mut CoordinatorArtifactInterchangeConfiguration| {
                configuration.active_transfer_lease_ttl_seconds = u64::MAX;
            },
            |configuration: &mut CoordinatorArtifactInterchangeConfiguration| {
                configuration.no_progress_timeout_seconds = u64::MAX;
            },
            |configuration: &mut CoordinatorArtifactInterchangeConfiguration| {
                configuration.absolute_transfer_max_seconds = Some(u64::MAX);
            },
            |configuration: &mut CoordinatorArtifactInterchangeConfiguration| {
                configuration.max_partial_bytes_per_node_project = u64::MAX;
            },
            |configuration: &mut CoordinatorArtifactInterchangeConfiguration| {
                configuration.direct_path_deadline_ms = u64::MAX;
            },
        ];
        for mutate in fields {
            let mut configuration = CoordinatorArtifactInterchangeConfiguration::default();
            mutate(&mut configuration);
            assert!(configuration.validate().is_err());
        }

        let configuration = CoordinatorArtifactInterchangeConfiguration {
            max_active_transfers_per_tenant: usize::MAX,
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(configuration.validate().is_err());
    }

    #[test]
    fn hosted_policy_requires_clusterflux_assist_and_direct_artifact_paths() {
        let mut configuration = CoordinatorArtifactInterchangeConfiguration {
            deployment_mode: ClusterfluxDeploymentMode::HostedPublic,
            artifact_relay_policy: ArtifactRelayPolicy::DirectRequired,
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(configuration.validate().is_err());
        configuration.relay =
            IrohRelayConfiguration::Custom(vec![clusterflux_core::ClusterfluxRelayConfig {
                url: "https://relay.clusterflux.example".to_owned(),
                access_token: None,
            }]);
        assert!(configuration.validate().is_ok());
        configuration.artifact_relay_policy = ArtifactRelayPolicy::RelayFallbackAllowed;
        assert!(configuration.validate().is_err());
    }

    #[test]
    fn coordinator_rejects_iroh_public_relay_domains() {
        let configuration = CoordinatorArtifactInterchangeConfiguration {
            relay: IrohRelayConfiguration::Custom(vec![clusterflux_core::ClusterfluxRelayConfig {
                url: "https://use1-1.relay.iroh.link".to_owned(),
                access_token: None,
            }]),
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(configuration.validate().is_err());
    }

    #[test]
    fn self_hosted_relay_fallback_requires_an_operator_owned_relay() {
        let relay =
            IrohRelayConfiguration::Custom(vec![clusterflux_core::ClusterfluxRelayConfig {
                url: "https://relay.self-hosted.example".to_owned(),
                access_token: Some("deployment-token".to_owned()),
            }]);
        let configuration = CoordinatorArtifactInterchangeConfiguration {
            deployment_mode: ClusterfluxDeploymentMode::SelfHosted,
            relay,
            artifact_relay_policy: ArtifactRelayPolicy::RelayFallbackAllowed,
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(configuration.validate().is_ok());

        let direct_only_without_relay = CoordinatorArtifactInterchangeConfiguration {
            deployment_mode: ClusterfluxDeploymentMode::SelfHosted,
            relay: IrohRelayConfiguration::Disabled,
            artifact_relay_policy: ArtifactRelayPolicy::DirectRequired,
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(direct_only_without_relay.validate().is_ok());

        let invalid_fallback_without_relay = CoordinatorArtifactInterchangeConfiguration {
            artifact_relay_policy: ArtifactRelayPolicy::RelayFallbackAllowed,
            ..direct_only_without_relay
        };
        assert!(invalid_fallback_without_relay.validate().is_err());
    }

    #[test]
    fn local_offline_mode_rejects_even_custom_relays() {
        let configuration = CoordinatorArtifactInterchangeConfiguration {
            deployment_mode: ClusterfluxDeploymentMode::LocalOffline,
            relay: IrohRelayConfiguration::Custom(vec![clusterflux_core::ClusterfluxRelayConfig {
                url: "http://127.0.0.1:3340".to_owned(),
                access_token: None,
            }]),
            artifact_relay_policy: ArtifactRelayPolicy::DirectRequired,
            ..CoordinatorArtifactInterchangeConfiguration::default()
        };
        assert!(configuration.validate().is_err());
    }
}
