use std::collections::BTreeMap;

use clusterflux_core::{
    ArtifactAssignmentRole, ArtifactAssignmentState, ArtifactHoldReason, ArtifactId,
    ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferErrorCode,
    ArtifactTransferPhase, ArtifactTransferRecord, ArtifactTransferState, ClusterfluxPathKind,
    Digest, NodeId, ProcessId, ProjectId, TenantId,
};

use crate::{CoordinatorError, NodeScopeKey};

use super::interchange::InterchangeTransfer;
use super::CoordinatorServiceError;

pub(super) type ReleasedTransferHold = (TenantId, ProjectId, ArtifactId, ArtifactHoldReason);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AssignmentAcknowledgementError {
    UnknownTransfer,
    OutsideScope,
    RoleMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferAdmissionError {
    CapacityUnavailable,
}

pub(super) enum InterchangeArtifactEffect {
    RecordVerifiedLocation {
        tenant: TenantId,
        project: ProjectId,
        artifact: ArtifactId,
        node: NodeId,
        digest: Digest,
        size: u64,
    },
    RemoveMissingSource {
        tenant: TenantId,
        project: ProjectId,
        artifact: ArtifactId,
        node: NodeId,
    },
}

pub(super) struct InterchangeProgress {
    pub(super) record: ArtifactTransferRecord,
    pub(super) authorization: Option<Box<ArtifactTransferAuthorization>>,
    pub(super) terminal_hold: Option<ReleasedTransferHold>,
}

/// Owns all in-memory transfer lifecycle state and aggregate byte meters.
/// Admission, expiry, and terminal cleanup are kept here so callers cannot
/// bypass the global transfer ceiling or leave active-transfer holds orphaned.
#[derive(Default)]
pub(super) struct InterchangeRegistry {
    transfers: BTreeMap<String, InterchangeTransfer>,
    direct_body_bytes: u64,
    relayed_body_bytes: u64,
    unknown_path_body_bytes: u64,
}

impl InterchangeRegistry {
    pub(super) fn transfers(&self) -> impl Iterator<Item = &InterchangeTransfer> {
        self.transfers.values()
    }

    #[cfg(test)]
    pub(super) fn transfer(&self, transfer_id: &str) -> Option<&InterchangeTransfer> {
        self.transfers.get(transfer_id)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.transfers.len()
    }

    pub(super) fn metrics(&self) -> (u64, u64, u64) {
        (
            self.direct_body_bytes,
            self.relayed_body_bytes,
            self.unknown_path_body_bytes,
        )
    }

    pub(super) fn create(
        &mut self,
        transfer_id: String,
        transfer: InterchangeTransfer,
        capacity: usize,
    ) -> Result<(), TransferAdmissionError> {
        self.prune_terminal_to_fit(capacity);
        if self.transfers.len() >= capacity {
            return Err(TransferAdmissionError::CapacityUnavailable);
        }
        self.transfers.insert(transfer_id, transfer);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn report_progress(
        &mut self,
        scope: &NodeScopeKey,
        transfer_id: &str,
        state: ArtifactTransferState,
        bytes_completed: u64,
        path_kind: ClusterfluxPathKind,
        failure_code: Option<ArtifactTransferErrorCode>,
        verified_digest: Option<Digest>,
        verified_size: Option<u64>,
        now: u64,
        active_lease_ttl_seconds: u64,
        transfer_ticket_ttl_seconds: u64,
        absolute_transfer_max_seconds: Option<u64>,
        mut apply_artifact_effect: impl FnMut(
            InterchangeArtifactEffect,
        ) -> Result<(), CoordinatorServiceError>,
    ) -> Result<InterchangeProgress, CoordinatorServiceError> {
        let (progress, newly_metered) = {
            let transfer = self.transfers.get_mut(transfer_id).ok_or_else(|| {
                CoordinatorServiceError::Protocol("unknown artifact transfer".to_owned())
            })?;
            if transfer.record.tenant != scope.tenant
                || transfer.record.project != scope.project
                || (transfer.record.source_node != scope.node
                    && transfer.record.destination_node != scope.node)
            {
                return Err(CoordinatorError::Unauthorized(
                    "artifact transfer report is outside the signed node scope".to_owned(),
                )
                .into());
            }
            if transfer.record.state.terminal() {
                if transfer.record.state == state
                    && transfer.record.bytes_completed == bytes_completed
                    && transfer.record.path_kind == path_kind
                    && transfer.record.failure_code == failure_code
                {
                    return Ok(InterchangeProgress {
                        record: transfer.record.clone(),
                        authorization: None,
                        terminal_hold: None,
                    });
                }
                let stable_code = match transfer.record.state {
                    ArtifactTransferState::Cancelled => {
                        ArtifactTransferErrorCode::TransferCancelled.as_str()
                    }
                    ArtifactTransferState::Expired => {
                        ArtifactTransferErrorCode::TransferLeaseExpired.as_str()
                    }
                    ArtifactTransferState::Failed => transfer
                        .record
                        .failure_code
                        .map(ArtifactTransferErrorCode::as_str)
                        .unwrap_or("artifact_transfer_failed"),
                    ArtifactTransferState::Completed => "artifact_transfer_completed",
                    _ => unreachable!("terminal state matched above"),
                };
                return Err(CoordinatorServiceError::Protocol(stable_code.to_owned()));
            }
            if bytes_completed < transfer.record.bytes_completed
                || bytes_completed > transfer.destination_authorization.lease.size_bytes
            {
                return Err(CoordinatorServiceError::Protocol(
                    "artifact transfer byte progress is invalid".to_owned(),
                ));
            }
            let made_progress = bytes_completed > transfer.record.bytes_completed;
            // Provider assignments are deliberately redeliverable after a node or
            // coordinator control-session restart. Re-registering an already-ready
            // provider renews its pin and stream ticket; it must not move a receiver-
            // advanced transfer backwards from Transferring/Verifying to Connecting.
            let provider_ready_refresh = scope.node == transfer.record.source_node
                && state == ArtifactTransferState::Connecting
                && matches!(
                    transfer.record.state,
                    ArtifactTransferState::Connecting
                        | ArtifactTransferState::WaitingForDirect
                        | ArtifactTransferState::Transferring
                        | ArtifactTransferState::Verifying
                );
            if !provider_ready_refresh && !transfer.record.state.permits_transition_to(state) {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "artifact transfer lifecycle cannot move from {:?} to {:?}",
                    transfer.record.state, state
                )));
            }
            if scope.node == transfer.record.source_node
                && matches!(
                    state,
                    ArtifactTransferState::Connecting
                        | ArtifactTransferState::WaitingForDirect
                        | ArtifactTransferState::Transferring
                )
            {
                transfer.provider_assignment = ArtifactAssignmentState::Ready;
                // A ready notification is the point at which a useful stream ticket
                // begins. Redeliver the renewed receiver authorization immediately.
                transfer.destination_assignment = ArtifactAssignmentState::Offered;
                transfer.destination_acknowledged_at = None;
            }
            if scope.node == transfer.record.destination_node
                && matches!(
                    state,
                    ArtifactTransferState::Transferring
                        | ArtifactTransferState::Verifying
                        | ArtifactTransferState::Completed
                )
            {
                transfer.destination_assignment = ArtifactAssignmentState::Ready;
            }
            if transfer.destination_authorization.lease.relay_policy
                == ArtifactRelayPolicy::DirectRequired
                && bytes_completed > transfer.destination_authorization.lease.allowed_offset
                && !matches!(
                    path_kind,
                    ClusterfluxPathKind::Direct | ClusterfluxPathKind::Local
                )
            {
                transfer.record.state = ArtifactTransferState::Failed;
                transfer.record.failure_code = Some(ArtifactTransferErrorCode::RelayPathForbidden);
                transfer.record.updated_at = now;
                return Err(CoordinatorServiceError::Protocol(
                    ArtifactTransferErrorCode::RelayPathForbidden
                        .as_str()
                        .to_owned(),
                ));
            }
            if state == ArtifactTransferState::Completed {
                if scope.node != transfer.record.destination_node
                    || bytes_completed != transfer.destination_authorization.lease.size_bytes
                    || verified_digest.as_ref()
                        != Some(&transfer.destination_authorization.lease.digest)
                    || verified_size != Some(transfer.destination_authorization.lease.size_bytes)
                    || failure_code.is_some()
                {
                    return Err(CoordinatorServiceError::Protocol(
                        "artifact completion lacks exact destination verification proof".to_owned(),
                    ));
                }
                apply_artifact_effect(InterchangeArtifactEffect::RecordVerifiedLocation {
                    tenant: transfer.record.tenant.clone(),
                    project: transfer.record.project.clone(),
                    artifact: transfer.record.artifact.clone(),
                    node: transfer.record.destination_node.clone(),
                    digest: transfer.destination_authorization.lease.digest.clone(),
                    size: transfer.destination_authorization.lease.size_bytes,
                })?;
            } else if state.terminal() && failure_code.is_none() {
                return Err(CoordinatorServiceError::Protocol(
                    "terminal artifact transfer failure requires a stable failure code".to_owned(),
                ));
            }
            if failure_code == Some(ArtifactTransferErrorCode::ArtifactMissingAtSource) {
                if state != ArtifactTransferState::Failed
                    || scope.node != transfer.record.source_node
                {
                    return Err(CoordinatorError::Unauthorized(
                        "only the selected source may report that retained artifact bytes are missing"
                            .to_owned(),
                    )
                    .into());
                }
                apply_artifact_effect(InterchangeArtifactEffect::RemoveMissingSource {
                    tenant: transfer.record.tenant.clone(),
                    project: transfer.record.project.clone(),
                    artifact: transfer.record.artifact.clone(),
                    node: transfer.record.source_node.clone(),
                })?;
            }
            let body_bytes = if path_kind == ClusterfluxPathKind::Local {
                0
            } else {
                bytes_completed
                    .saturating_sub(transfer.destination_authorization.lease.allowed_offset)
            };
            let newly_metered = body_bytes.saturating_sub(transfer.metered_body_bytes);
            transfer.metered_body_bytes = transfer.metered_body_bytes.max(body_bytes);
            let recorded_state = if provider_ready_refresh {
                transfer.record.state
            } else {
                state
            };
            transfer.record.state = recorded_state;
            transfer.record.bytes_completed = bytes_completed;
            transfer.record.path_kind = path_kind;
            transfer.record.failure_code = failure_code;
            transfer.record.updated_at = now;
            transfer.record.phase = match recorded_state {
                ArtifactTransferState::Requested
                | ArtifactTransferState::SourceSelected
                | ArtifactTransferState::Retrying => ArtifactTransferPhase::Queued,
                ArtifactTransferState::Connecting => ArtifactTransferPhase::Connecting,
                ArtifactTransferState::WaitingForDirect => ArtifactTransferPhase::WaitingForDirect,
                ArtifactTransferState::Transferring => ArtifactTransferPhase::Transferring,
                ArtifactTransferState::Verifying => ArtifactTransferPhase::Verifying,
                ArtifactTransferState::Completed
                | ArtifactTransferState::Failed
                | ArtifactTransferState::Cancelled
                | ArtifactTransferState::Expired => ArtifactTransferPhase::Complete,
            };
            let valid_wait = matches!(
                state,
                ArtifactTransferState::Connecting
                    | ArtifactTransferState::WaitingForDirect
                    | ArtifactTransferState::Verifying
            );
            let mut renewed_active_lease = false;
            if !recorded_state.terminal() && (made_progress || valid_wait) {
                transfer.record.last_progress_at = now;
                let renewed = now.saturating_add(active_lease_ttl_seconds);
                let renewed = absolute_transfer_max_seconds
                    .map(|maximum| renewed.min(transfer.record.created_at.saturating_add(maximum)))
                    .unwrap_or(renewed);
                transfer.record.expires_at = renewed;
                transfer
                    .destination_authorization
                    .lease
                    .active_lease_expires_at = renewed;
                transfer
                    .provider_authorization
                    .lease
                    .active_lease_expires_at = renewed;
                renewed_active_lease = true;
            }
            if scope.node == transfer.record.source_node
                && state == ArtifactTransferState::Connecting
                && !recorded_state.terminal()
            {
                let ticket_expiry = now
                    .saturating_add(transfer_ticket_ttl_seconds)
                    .min(transfer.record.expires_at);
                transfer.record.stream_ticket_expires_at = ticket_expiry;
                transfer.destination_authorization.lease.expires_at = ticket_expiry;
                transfer.provider_authorization.lease.expires_at = ticket_expiry;
            }
            if renewed_active_lease {
                // Refresh the other participant through its normal assignment poll.
                // The reporting participant receives its authorization in this reply.
                if scope.node == transfer.record.destination_node {
                    transfer.provider_assignment = ArtifactAssignmentState::Offered;
                    transfer.provider_acknowledged_at = None;
                } else {
                    transfer.destination_assignment = ArtifactAssignmentState::Offered;
                    transfer.destination_acknowledged_at = None;
                }
            }
            let terminal_hold = recorded_state.terminal().then(|| {
                (
                    transfer.record.tenant.clone(),
                    transfer.record.project.clone(),
                    transfer.record.artifact.clone(),
                    ArtifactHoldReason::ActiveTransfer {
                        transfer_id: transfer.record.transfer_id.clone(),
                    },
                )
            });
            let authorization = (!recorded_state.terminal())
                .then(|| {
                    if scope.node == transfer.record.source_node {
                        transfer.provider_authorization.clone()
                    } else {
                        transfer.destination_authorization.clone()
                    }
                })
                .map(Box::new);
            (
                InterchangeProgress {
                    record: transfer.record.clone(),
                    authorization,
                    terminal_hold,
                },
                newly_metered,
            )
        };
        self.meter_body_bytes(path_kind, newly_metered);
        Ok(progress)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn renew(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        artifact: &ArtifactId,
        destination_node: &NodeId,
        now_epoch_seconds: u64,
        ticket_ttl_seconds: u64,
        active_ttl_seconds: u64,
        absolute_max_seconds: Option<u64>,
    ) -> Option<(ArtifactTransferAuthorization, ArtifactTransferRecord)> {
        let transfer = self.transfers.values_mut().find(|transfer| {
            transfer.record.expires_at >= now_epoch_seconds
                && !transfer.record.state.terminal()
                && &transfer.record.tenant == tenant
                && &transfer.record.project == project
                && &transfer.record.process == process
                && &transfer.record.artifact == artifact
                && &transfer.record.destination_node == destination_node
        })?;
        let active_expiry = now_epoch_seconds.saturating_add(active_ttl_seconds);
        let active_expiry = absolute_max_seconds
            .map(|maximum| active_expiry.min(transfer.record.created_at.saturating_add(maximum)))
            .unwrap_or(active_expiry);
        let ticket_expiry = now_epoch_seconds
            .saturating_add(ticket_ttl_seconds)
            .min(active_expiry);
        transfer.record.stream_ticket_expires_at = ticket_expiry;
        transfer.destination_authorization.lease.expires_at = ticket_expiry;
        transfer.provider_authorization.lease.expires_at = ticket_expiry;
        if matches!(
            transfer.record.state,
            ArtifactTransferState::Requested
                | ArtifactTransferState::SourceSelected
                | ArtifactTransferState::Connecting
                | ArtifactTransferState::WaitingForDirect
                | ArtifactTransferState::Retrying
        ) {
            transfer.record.last_progress_at = now_epoch_seconds;
            transfer.record.expires_at = active_expiry;
            transfer
                .destination_authorization
                .lease
                .active_lease_expires_at = active_expiry;
            transfer
                .provider_authorization
                .lease
                .active_lease_expires_at = active_expiry;
        }
        Some((
            transfer.destination_authorization.clone(),
            transfer.record.clone(),
        ))
    }

    pub(super) fn poll_provider_assignment(
        &mut self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
        acknowledgement_recovery_seconds: u64,
    ) -> (Vec<String>, Option<ArtifactTransferAuthorization>) {
        let retired_transfer_ids = self
            .transfers
            .values()
            .filter(|transfer| {
                transfer.record.tenant == scope.tenant
                    && transfer.record.project == scope.project
                    && transfer.record.source_node == scope.node
                    && transfer.record.state.terminal()
            })
            .map(|transfer| transfer.record.transfer_id.clone())
            .collect();
        let assignment = self.transfers.values_mut().find(|transfer| {
            transfer.record.tenant == scope.tenant
                && transfer.record.project == scope.project
                && transfer.record.source_node == scope.node
                && (transfer.provider_assignment == ArtifactAssignmentState::Offered
                    || (transfer.provider_assignment == ArtifactAssignmentState::Acknowledged
                        && transfer
                            .provider_acknowledged_at
                            .unwrap_or(0)
                            .saturating_add(acknowledgement_recovery_seconds)
                            < now_epoch_seconds))
                && !transfer.record.state.terminal()
                && transfer.record.expires_at >= now_epoch_seconds
        });
        let authorization = assignment.map(|transfer| {
            if transfer.provider_assignment == ArtifactAssignmentState::Acknowledged {
                transfer.provider_assignment = ArtifactAssignmentState::Offered;
                transfer.provider_acknowledged_at = None;
            }
            transfer.provider_authorization.clone()
        });
        (retired_transfer_ids, authorization)
    }

    pub(super) fn poll_receiver_assignment(
        &mut self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
        acknowledgement_recovery_seconds: u64,
    ) -> Option<ArtifactTransferAuthorization> {
        self.transfers.values_mut().find_map(|transfer| {
            ((transfer.destination_assignment == ArtifactAssignmentState::Offered
                || (transfer.destination_assignment == ArtifactAssignmentState::Acknowledged
                    && transfer
                        .destination_acknowledged_at
                        .unwrap_or(0)
                        .saturating_add(acknowledgement_recovery_seconds)
                        < now_epoch_seconds))
                && !transfer.record.state.terminal()
                && transfer.record.destination_node == scope.node
                && transfer.record.tenant == scope.tenant
                && transfer.record.project == scope.project
                && transfer.record.expires_at >= now_epoch_seconds)
                .then(|| {
                    if transfer.destination_assignment == ArtifactAssignmentState::Acknowledged {
                        transfer.destination_assignment = ArtifactAssignmentState::Offered;
                        transfer.destination_acknowledged_at = None;
                    }
                    transfer.destination_authorization.clone()
                })
        })
    }

    pub(super) fn acknowledge_assignment(
        &mut self,
        scope: &NodeScopeKey,
        transfer_id: &str,
        role: ArtifactAssignmentRole,
        now_epoch_seconds: u64,
    ) -> Result<ArtifactAssignmentState, AssignmentAcknowledgementError> {
        let transfer = self
            .transfers
            .get_mut(transfer_id)
            .ok_or(AssignmentAcknowledgementError::UnknownTransfer)?;
        if transfer.record.tenant != scope.tenant || transfer.record.project != scope.project {
            return Err(AssignmentAcknowledgementError::OutsideScope);
        }
        let (state, acknowledged_at) = match role {
            ArtifactAssignmentRole::Provider if transfer.record.source_node == scope.node => (
                &mut transfer.provider_assignment,
                &mut transfer.provider_acknowledged_at,
            ),
            ArtifactAssignmentRole::Receiver if transfer.record.destination_node == scope.node => (
                &mut transfer.destination_assignment,
                &mut transfer.destination_acknowledged_at,
            ),
            _ => return Err(AssignmentAcknowledgementError::RoleMismatch),
        };
        if matches!(
            *state,
            ArtifactAssignmentState::Offered | ArtifactAssignmentState::Acknowledged
        ) {
            *state = ArtifactAssignmentState::Acknowledged;
            *acknowledged_at = Some(now_epoch_seconds);
        }
        Ok(*state)
    }

    pub(super) fn meter_body_bytes(&mut self, path_kind: ClusterfluxPathKind, bytes: u64) {
        match path_kind {
            ClusterfluxPathKind::Local => {}
            ClusterfluxPathKind::Direct => {
                self.direct_body_bytes = self.direct_body_bytes.saturating_add(bytes);
            }
            ClusterfluxPathKind::Relayed => {
                self.relayed_body_bytes = self.relayed_body_bytes.saturating_add(bytes);
            }
            ClusterfluxPathKind::Unknown => {
                self.unknown_path_body_bytes = self.unknown_path_body_bytes.saturating_add(bytes);
            }
        }
    }

    pub(super) fn cancel_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        now_epoch_seconds: u64,
    ) -> (usize, Vec<ReleasedTransferHold>) {
        let mut released_holds = Vec::new();
        for transfer in self.transfers.values_mut().filter(|transfer| {
            !transfer.record.state.terminal()
                && &transfer.record.tenant == tenant
                && &transfer.record.project == project
                && &transfer.record.process == process
        }) {
            transfer.record.state = ArtifactTransferState::Cancelled;
            transfer.record.failure_code = Some(ArtifactTransferErrorCode::TransferCancelled);
            transfer.record.updated_at = now_epoch_seconds;
            transfer.record.phase = ArtifactTransferPhase::Complete;
            released_holds.push(active_hold(transfer));
        }
        (released_holds.len(), released_holds)
    }

    pub(super) fn cancel_node_for_hard_drain(
        &mut self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
    ) -> Vec<(ArtifactId, String)> {
        let mut released = Vec::new();
        for transfer in self
            .transfers
            .values_mut()
            .filter(|transfer| transfer_matches_active_node(transfer, scope))
        {
            transfer.record.state = ArtifactTransferState::Cancelled;
            transfer.record.failure_code = Some(ArtifactTransferErrorCode::TransferCancelled);
            transfer.record.updated_at = now_epoch_seconds;
            transfer.record.phase = ArtifactTransferPhase::Complete;
            released.push((
                transfer.record.artifact.clone(),
                transfer.record.transfer_id.clone(),
            ));
        }
        released
    }

    pub(super) fn fail_node(&mut self, scope: &NodeScopeKey, now_epoch_seconds: u64) {
        for transfer in self
            .transfers
            .values_mut()
            .filter(|transfer| transfer_matches_active_node(transfer, scope))
        {
            transfer.record.state = ArtifactTransferState::Failed;
            transfer.record.failure_code = Some(if transfer.record.source_node == scope.node {
                ArtifactTransferErrorCode::SourceNodeOffline
            } else {
                ArtifactTransferErrorCode::DestinationNodeOffline
            });
            transfer.record.updated_at = now_epoch_seconds;
            transfer.record.phase = ArtifactTransferPhase::Complete;
        }
    }

    pub(super) fn expire(
        &mut self,
        now_epoch_seconds: u64,
        no_progress_timeout_seconds: u64,
        absolute_transfer_max_seconds: Option<u64>,
        terminal_retention_seconds: u64,
    ) -> Vec<ReleasedTransferHold> {
        let mut released_holds = Vec::new();
        for transfer in self.transfers.values_mut() {
            let no_progress_expired = transfer
                .record
                .last_progress_at
                .saturating_add(no_progress_timeout_seconds)
                < now_epoch_seconds;
            let absolute_expired = absolute_transfer_max_seconds.is_some_and(|maximum| {
                transfer.record.created_at.saturating_add(maximum) < now_epoch_seconds
            });
            if !transfer.record.state.terminal()
                && (transfer.record.expires_at < now_epoch_seconds
                    || no_progress_expired
                    || absolute_expired)
            {
                transfer.record.state = ArtifactTransferState::Expired;
                transfer.record.failure_code =
                    Some(ArtifactTransferErrorCode::TransferLeaseExpired);
                transfer.record.updated_at = now_epoch_seconds;
                transfer.record.phase = ArtifactTransferPhase::Complete;
                released_holds.push(active_hold(transfer));
            }
        }
        self.transfers.retain(|_, transfer| {
            !transfer.record.state.terminal()
                || transfer
                    .record
                    .updated_at
                    .saturating_add(terminal_retention_seconds)
                    >= now_epoch_seconds
        });
        released_holds
    }

    fn prune_terminal_to_fit(&mut self, capacity: usize) {
        while self.transfers.len() >= capacity {
            let oldest = self
                .transfers
                .iter()
                .filter(|(_, transfer)| transfer.record.state.terminal())
                .min_by_key(|(_, transfer)| transfer.record.updated_at)
                .map(|(id, _)| id.clone());
            let Some(oldest) = oldest else {
                break;
            };
            self.transfers.remove(&oldest);
        }
    }
}

fn active_hold(transfer: &InterchangeTransfer) -> ReleasedTransferHold {
    (
        transfer.record.tenant.clone(),
        transfer.record.project.clone(),
        transfer.record.artifact.clone(),
        ArtifactHoldReason::ActiveTransfer {
            transfer_id: transfer.record.transfer_id.clone(),
        },
    )
}

fn transfer_matches_active_node(transfer: &InterchangeTransfer, scope: &NodeScopeKey) -> bool {
    !transfer.record.state.terminal()
        && transfer.record.tenant == scope.tenant
        && transfer.record.project == scope.project
        && (transfer.record.source_node == scope.node
            || transfer.record.destination_node == scope.node)
}
