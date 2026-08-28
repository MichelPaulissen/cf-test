use std::collections::BTreeMap;

use clusterflux_core::{
    Digest, EnrollmentGrant, IrohEndpointAdvertisement, NodeDescriptor, NodeDrainStatus,
    NodeLifecycleState, ProjectId, TenantId,
};

use crate::NodeScopeKey;

use super::keys::EnrollmentGrantKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SourceSnapshotAdmissionError {
    MissingDescriptor,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EndpointAdvertisementError {
    BoundToAnotherScope,
    IdentityChanged,
    StaleGeneration,
}

/// Owns coordinator-local node discovery, liveness, drain, enrollment, and
/// endpoint state. All maps are private so cleanup and bounded admission cannot
/// be bypassed by sibling request handlers.
#[derive(Default)]
pub(super) struct NodeRegistry {
    descriptors: BTreeMap<NodeScopeKey, NodeDescriptor>,
    drain_statuses: BTreeMap<NodeScopeKey, NodeDrainStatus>,
    last_seen_epoch_seconds: BTreeMap<NodeScopeKey, u64>,
    enrollment_grants: BTreeMap<EnrollmentGrantKey, EnrollmentGrant>,
    iroh_endpoint_advertisements: BTreeMap<NodeScopeKey, IrohEndpointAdvertisement>,
    iroh_endpoint_bindings: BTreeMap<String, NodeScopeKey>,
}

impl NodeRegistry {
    pub(super) fn descriptor(&self, scope: &NodeScopeKey) -> Option<&NodeDescriptor> {
        self.descriptors.get(scope)
    }

    pub(super) fn descriptors(&self) -> impl Iterator<Item = (&NodeScopeKey, &NodeDescriptor)> {
        self.descriptors.iter()
    }

    #[cfg(test)]
    pub(super) fn contains_node(&self, scope: &NodeScopeKey) -> bool {
        self.descriptors.contains_key(scope)
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    pub(super) fn reported_count(&self) -> usize {
        self.descriptors.len()
    }

    pub(super) fn live_count(&self, now_epoch_seconds: u64, stale_after_seconds: u64) -> usize {
        self.descriptors
            .keys()
            .filter(|scope| self.is_live(scope, now_epoch_seconds, stale_after_seconds))
            .count()
    }

    pub(super) fn record_descriptor(&mut self, scope: NodeScopeKey, descriptor: NodeDescriptor) {
        self.descriptors.insert(scope, descriptor);
    }

    pub(super) fn descriptor_count_for_project(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> usize {
        self.descriptors
            .values()
            .filter(|descriptor| &descriptor.tenant == tenant && &descriptor.project == project)
            .count()
    }

    pub(super) fn record_source_snapshot(
        &mut self,
        scope: &NodeScopeKey,
        source_snapshot: Digest,
        capacity: usize,
    ) -> Result<(), SourceSnapshotAdmissionError> {
        let descriptor = self
            .descriptors
            .get_mut(scope)
            .ok_or(SourceSnapshotAdmissionError::MissingDescriptor)?;
        if !descriptor.source_snapshots.contains(&source_snapshot)
            && descriptor.source_snapshots.len() >= capacity
        {
            return Err(SourceSnapshotAdmissionError::Capacity);
        }
        descriptor.source_snapshots.insert(source_snapshot);
        Ok(())
    }

    pub(super) fn is_live(
        &self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
        stale_after_seconds: u64,
    ) -> bool {
        self.last_seen_epoch_seconds
            .get(scope)
            .is_some_and(|last_seen| {
                now_epoch_seconds.saturating_sub(*last_seen) <= stale_after_seconds
            })
    }

    pub(super) fn mark_seen(&mut self, scope: &NodeScopeKey, seen_at_epoch_seconds: u64) {
        if self
            .drain_statuses
            .get(scope)
            .is_some_and(|status| status.state == NodeLifecycleState::Released && !status.ephemeral)
        {
            self.drain_statuses.remove(scope);
        }
        self.last_seen_epoch_seconds
            .insert(scope.clone(), seen_at_epoch_seconds);
        if let Some(descriptor) = self.descriptors.get_mut(scope) {
            descriptor.online = true;
        }
    }

    pub(super) fn last_seen(&self, scope: &NodeScopeKey) -> Option<u64> {
        self.last_seen_epoch_seconds.get(scope).copied()
    }

    pub(super) fn live_descriptors(
        &self,
        now_epoch_seconds: u64,
        stale_after_seconds: u64,
    ) -> Vec<NodeDescriptor> {
        self.descriptors
            .values()
            .cloned()
            .map(|mut descriptor| {
                let scope = NodeScopeKey::from_refs(
                    &descriptor.tenant,
                    &descriptor.project,
                    &descriptor.id,
                );
                descriptor.online = self.is_live(&scope, now_epoch_seconds, stale_after_seconds)
                    && self
                        .drain_statuses
                        .get(&scope)
                        .is_none_or(|status| status.state == NodeLifecycleState::Active);
                descriptor
            })
            .collect()
    }

    pub(super) fn begin_drain(
        &mut self,
        scope: &NodeScopeKey,
        ephemeral: bool,
        provider_deadline_epoch_seconds: Option<u64>,
        soft_drain_deadline_epoch_seconds: Option<u64>,
        hard_drain_deadline_epoch_seconds: Option<u64>,
    ) {
        let status = self
            .drain_statuses
            .entry(scope.clone())
            .or_insert_with(|| NodeDrainStatus::active(scope.node.clone()));
        status.ephemeral |= ephemeral;
        if let Some(deadline) =
            hard_drain_deadline_epoch_seconds.or(provider_deadline_epoch_seconds)
        {
            status.provider_deadline_epoch_seconds = Some(deadline);
            status.hard_drain_deadline_epoch_seconds = Some(deadline);
        }
        if soft_drain_deadline_epoch_seconds.is_some() {
            status.soft_drain_deadline_epoch_seconds = soft_drain_deadline_epoch_seconds;
        }
        status.state = match status.state {
            NodeLifecycleState::Active | NodeLifecycleState::Draining => {
                NodeLifecycleState::Draining
            }
            NodeLifecycleState::ReadyToRelease => NodeLifecycleState::ReadyToRelease,
            NodeLifecycleState::Released => NodeLifecycleState::Released,
        };
    }

    pub(super) fn drain_status(&self, scope: &NodeScopeKey) -> Option<&NodeDrainStatus> {
        self.drain_statuses.get(scope)
    }

    pub(super) fn drain_status_or_active(&self, scope: &NodeScopeKey) -> NodeDrainStatus {
        self.drain_statuses
            .get(scope)
            .cloned()
            .unwrap_or_else(|| NodeDrainStatus::active(scope.node.clone()))
    }

    pub(super) fn record_drain_status(&mut self, scope: NodeScopeKey, status: NodeDrainStatus) {
        self.drain_statuses.insert(scope, status);
    }

    pub(super) fn drain_scopes(&self) -> Vec<NodeScopeKey> {
        self.drain_statuses.keys().cloned().collect()
    }

    pub(super) fn accepts_new_work(&self, scope: &NodeScopeKey) -> bool {
        self.drain_statuses
            .get(scope)
            .is_none_or(|status| status.state == NodeLifecycleState::Active)
    }

    pub(super) fn mark_released(&mut self, scope: &NodeScopeKey) {
        if let Some(descriptor) = self.descriptors.get_mut(scope) {
            descriptor.artifact_locations.clear();
            descriptor.online = false;
        }
        self.remove_endpoint(scope);
    }

    pub(super) fn remove_node(&mut self, scope: &NodeScopeKey) -> bool {
        let descriptor_removed = self.descriptors.remove(scope).is_some();
        self.drain_statuses.remove(scope);
        self.last_seen_epoch_seconds.remove(scope);
        self.remove_endpoint(scope);
        descriptor_removed
    }

    pub(super) fn prune_enrollment_grants(&mut self, now_epoch_seconds: u64) {
        self.enrollment_grants.retain(|_, grant| {
            !grant.consumed && grant.expires_at_epoch_seconds >= now_epoch_seconds
        });
    }

    pub(super) fn enrollment_grant_count(&self, tenant: &TenantId, project: &ProjectId) -> usize {
        self.enrollment_grants
            .values()
            .filter(|grant| &grant.tenant == tenant && &grant.project == project)
            .count()
    }

    pub(super) fn insert_enrollment_grant(
        &mut self,
        key: EnrollmentGrantKey,
        grant: EnrollmentGrant,
    ) {
        self.enrollment_grants.insert(key, grant);
    }

    pub(super) fn exchange_enrollment_grant<T, E>(
        &mut self,
        key: &EnrollmentGrantKey,
        exchange: impl FnOnce(&mut EnrollmentGrant) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        let Some(grant) = self.enrollment_grants.get_mut(key) else {
            return Ok(None);
        };
        let exchanged = exchange(grant)?;
        self.enrollment_grants.remove(key);
        Ok(Some(exchanged))
    }

    pub(super) fn endpoint_scope(&self, endpoint_id: &str) -> Option<&NodeScopeKey> {
        self.iroh_endpoint_bindings.get(endpoint_id)
    }

    pub(super) fn advertisement(&self, scope: &NodeScopeKey) -> Option<&IrohEndpointAdvertisement> {
        self.iroh_endpoint_advertisements.get(scope)
    }

    pub(super) fn has_active_advertisement(
        &self,
        scope: &NodeScopeKey,
        now_epoch_seconds: u64,
    ) -> bool {
        self.advertisement(scope)
            .is_some_and(|advertisement| advertisement.expires_at > now_epoch_seconds)
    }

    pub(super) fn register_advertisement(
        &mut self,
        scope: NodeScopeKey,
        advertisement: IrohEndpointAdvertisement,
    ) -> Result<(), EndpointAdvertisementError> {
        if self
            .iroh_endpoint_bindings
            .get(&advertisement.endpoint_id)
            .is_some_and(|bound_scope| bound_scope != &scope)
        {
            return Err(EndpointAdvertisementError::BoundToAnotherScope);
        }
        if let Some(current) = self.iroh_endpoint_advertisements.get(&scope) {
            if current.endpoint_id != advertisement.endpoint_id {
                return Err(EndpointAdvertisementError::IdentityChanged);
            }
            if advertisement.generation < current.generation {
                return Err(EndpointAdvertisementError::StaleGeneration);
            }
        }
        self.iroh_endpoint_bindings
            .insert(advertisement.endpoint_id.clone(), scope.clone());
        self.iroh_endpoint_advertisements
            .insert(scope, advertisement);
        Ok(())
    }

    pub(super) fn clear_advertisements(&mut self) {
        self.iroh_endpoint_advertisements.clear();
        self.iroh_endpoint_bindings.clear();
    }

    pub(super) fn expire_advertisements(
        &mut self,
        now_epoch_seconds: u64,
        stale_after_seconds: u64,
    ) {
        let expired_scopes = self
            .iroh_endpoint_advertisements
            .iter()
            .filter(|(scope, advertisement)| {
                advertisement.expires_at <= now_epoch_seconds
                    || !self.is_live(scope, now_epoch_seconds, stale_after_seconds)
            })
            .map(|(scope, _)| scope.clone())
            .collect::<Vec<_>>();
        for scope in expired_scopes {
            self.remove_endpoint(&scope);
        }
    }

    fn remove_endpoint(&mut self, scope: &NodeScopeKey) {
        if let Some(advertisement) = self.iroh_endpoint_advertisements.remove(scope) {
            self.iroh_endpoint_bindings
                .remove(&advertisement.endpoint_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{NodeDrainStatus, NodeId, NodeLifecycleState, ProjectId, TenantId};

    use super::{NodeRegistry, NodeScopeKey};

    fn released_status(node: &NodeId, ephemeral: bool) -> NodeDrainStatus {
        let mut status = NodeDrainStatus::active(node.clone());
        status.state = NodeLifecycleState::Released;
        status.ephemeral = ephemeral;
        status
    }

    #[test]
    fn signed_liveness_reactivates_a_released_persistent_node() {
        let scope = NodeScopeKey::new(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("persistent"),
        );
        let mut registry = NodeRegistry::default();
        registry.record_drain_status(scope.clone(), released_status(&scope.node, false));

        registry.mark_seen(&scope, 42);

        assert!(registry.accepts_new_work(&scope));
        assert_eq!(registry.last_seen(&scope), Some(42));
    }

    #[test]
    fn signed_liveness_does_not_reactivate_a_released_ephemeral_node() {
        let scope = NodeScopeKey::new(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("ephemeral"),
        );
        let mut registry = NodeRegistry::default();
        registry.record_drain_status(scope.clone(), released_status(&scope.node, true));

        registry.mark_seen(&scope, 42);

        assert!(!registry.accepts_new_work(&scope));
        assert_eq!(registry.last_seen(&scope), Some(42));
    }
}
