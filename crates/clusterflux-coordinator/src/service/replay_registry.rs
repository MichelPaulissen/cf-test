use std::collections::BTreeMap;

use clusterflux_core::{AgentId, ProjectId, TenantId};

use crate::NodeScopeKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReplayAdmissionError {
    Duplicate,
    Capacity,
}

/// Owns bounded, expiring replay windows. Agent and node admission is scoped to
/// its full authority tuple, while the single configured admin authority has a
/// separate global ceiling; node revocation synchronously clears its nonce set.
#[derive(Default)]
pub(super) struct ReplayRegistry {
    agent_nonces: BTreeMap<(TenantId, ProjectId, AgentId, String), u64>,
    node_nonces: BTreeMap<(NodeScopeKey, String), u64>,
    admin_nonces: BTreeMap<String, u64>,
}

impl ReplayRegistry {
    pub(super) fn admit_admin(
        &mut self,
        nonce: String,
        issued_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
        window_seconds: u64,
        capacity: usize,
    ) -> Result<(), ReplayAdmissionError> {
        self.admin_nonces
            .retain(|_, issued_at| now_epoch_seconds <= issued_at.saturating_add(window_seconds));
        if self.admin_nonces.contains_key(&nonce) {
            return Err(ReplayAdmissionError::Duplicate);
        }
        if self.admin_nonces.len() >= capacity {
            return Err(ReplayAdmissionError::Capacity);
        }
        self.admin_nonces.insert(nonce, issued_at_epoch_seconds);
        Ok(())
    }

    pub(super) fn prepare_agent(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        agent: &AgentId,
        nonce: &str,
        now_epoch_seconds: u64,
        window_seconds: u64,
    ) -> Result<(), ReplayAdmissionError> {
        self.agent_nonces
            .retain(|_, issued_at| now_epoch_seconds <= issued_at.saturating_add(window_seconds));
        let replay_key = (
            tenant.clone(),
            project.clone(),
            agent.clone(),
            nonce.to_owned(),
        );
        if self.agent_nonces.contains_key(&replay_key) {
            return Err(ReplayAdmissionError::Duplicate);
        }
        Ok(())
    }

    pub(super) fn commit_agent(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        agent: AgentId,
        nonce: String,
        issued_at_epoch_seconds: u64,
        capacity_per_authority: usize,
    ) -> Result<(), ReplayAdmissionError> {
        let retained = self
            .agent_nonces
            .keys()
            .filter(|(retained_tenant, retained_project, retained_agent, _)| {
                retained_tenant == &tenant
                    && retained_project == &project
                    && retained_agent == &agent
            })
            .count();
        if retained >= capacity_per_authority {
            return Err(ReplayAdmissionError::Capacity);
        }
        self.agent_nonces
            .insert((tenant, project, agent, nonce), issued_at_epoch_seconds);
        Ok(())
    }

    pub(super) fn prepare_node(
        &mut self,
        scope: &NodeScopeKey,
        nonce: &str,
        now_epoch_seconds: u64,
        window_seconds: u64,
    ) -> Result<(), ReplayAdmissionError> {
        self.node_nonces.retain(|_, accepted_at| {
            now_epoch_seconds <= accepted_at.saturating_add(window_seconds)
        });
        if self
            .node_nonces
            .contains_key(&(scope.clone(), nonce.to_owned()))
        {
            return Err(ReplayAdmissionError::Duplicate);
        }
        Ok(())
    }

    pub(super) fn commit_node(
        &mut self,
        scope: NodeScopeKey,
        nonce: String,
        accepted_at_epoch_seconds: u64,
        capacity_per_authority: usize,
    ) -> Result<(), ReplayAdmissionError> {
        let retained = self
            .node_nonces
            .keys()
            .filter(|(retained_scope, _)| retained_scope == &scope)
            .count();
        if retained >= capacity_per_authority {
            return Err(ReplayAdmissionError::Capacity);
        }
        self.node_nonces
            .insert((scope, nonce), accepted_at_epoch_seconds);
        Ok(())
    }

    pub(super) fn clear_node(&mut self, scope: &NodeScopeKey) {
        self.node_nonces
            .retain(|(retained_scope, _), _| retained_scope != scope);
    }

    #[cfg(test)]
    pub(super) fn seed_node(
        &mut self,
        scope: NodeScopeKey,
        nonce: String,
        accepted_at_epoch_seconds: u64,
    ) {
        self.node_nonces
            .insert((scope, nonce), accepted_at_epoch_seconds);
    }

    #[cfg(test)]
    pub(super) fn node_count(&self, scope: &NodeScopeKey) -> usize {
        self.node_nonces
            .keys()
            .filter(|(retained_scope, _)| retained_scope == scope)
            .count()
    }

    #[cfg(test)]
    pub(super) fn contains_node(&self, scope: &NodeScopeKey, nonce: &str) -> bool {
        self.node_nonces
            .contains_key(&(scope.clone(), nonce.to_owned()))
    }
}
