use std::collections::{BTreeMap, BTreeSet};

use clusterflux_core::{
    Actor, AuthContext, Authorization, CredentialKind, Digest, EnrollmentError, EnrollmentGrant,
    NodeCredential, NodeId, ProcessId, ProjectId, SourceProviderKind, TenantId, UserId,
};
use thiserror::Error;

mod agents;
pub mod durable;
pub mod postgres_store;
pub mod service;
mod sessions;
pub use durable::{
    AcceptedCommitTriggerRecord, AccountPolicyState, ActiveAssignmentRecord, AgentPublicKeyRecord,
    AssignmentKind, AssignmentMutationRecord, AssignmentMutationResponse, AssignmentState,
    AutomatedRunStageRecord, AutomationDurableState, CliSessionRecord, CredentialRecord,
    DurableState, DurableStore, EncryptedProjectSecretRecord, FallibleDurableStore,
    HostedAdminAuditRecord, HostedAdminDurableState, InMemoryDurableStore, NodeIdentityRecord,
    NodeScopeKey, ProjectEnvironmentRecord, ProjectPermissionRecord, ProjectRecord,
    SecretAuditRecord, ServicePolicyRecord, SourceProviderConfigRecord, TenantQuotaOverrideRecord,
    TenantQuotaOverrideValues, TenantRecord, TerminalAssignmentRecord, UserRecord,
};
pub use postgres_store::{
    PostgresDurableStore, PostgresStoreError, PostgresTable, POSTGRES_DURABLE_TABLES,
};
pub use service::{
    AdmissionQuotaLimits, CoordinatorAdmission, CoordinatorArtifactInterchangeConfiguration,
    CoordinatorMainRuntimeConfiguration, CoordinatorRequest, CoordinatorResponse,
    CoordinatorService, CoordinatorServiceError, CoordinatorServiceStartupConfiguration,
    DebugAcknowledgementState, DebugAuditEvent, DebugParticipantAcknowledgement,
    HostedAccountMutationResult, HostedTenantAdminStatus, SourcePreparationDisposition,
    SourcePreparationStatus, TaskAssignment, TaskAttemptSnapshot, TaskAttemptState,
    TaskCancellationTarget, TaskCompletionEvent, TaskExecutor, TaskFailureResolution,
    TaskTerminalState, MAX_COORDINATOR_MAINS,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveProcess {
    pub id: ProcessId,
    pub launch_attempt: Option<clusterflux_core::LaunchAttemptId>,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub connected_nodes: BTreeSet<NodeId>,
    pub coordinator_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct Coordinator {
    durable: DurableState,
    active_processes: BTreeMap<(TenantId, ProjectId, ProcessId), ActiveProcess>,
    coordinator_epoch: u64,
}

const MAX_TENANT_QUOTA_OVERRIDES: usize = 100_000;
const MAX_HOSTED_ADMIN_AUDIT_RECORDS: usize = 10_000;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoordinatorError {
    #[error("node identity is not enrolled")]
    UnknownNode,
    #[error("node enrollment failed: {0:?}")]
    Enrollment(EnrollmentError),
    #[error("stale virtual process state from coordinator epoch {stale_epoch}; current epoch is {current_epoch}")]
    StaleProcessEpoch {
        stale_epoch: u64,
        current_epoch: u64,
    },
    #[error("unauthorized coordinator action: {0}")]
    Unauthorized(String),
}

impl Coordinator {
    pub(crate) fn durable_state(&self) -> &DurableState {
        &self.durable
    }

    pub(crate) fn durable_state_mut(&mut self) -> &mut DurableState {
        &mut self.durable
    }

    pub fn boot(store: &impl DurableStore, coordinator_epoch: u64) -> Self {
        Self {
            durable: store.load(),
            active_processes: BTreeMap::new(),
            coordinator_epoch,
        }
    }

    pub fn try_boot<S: FallibleDurableStore>(
        store: &mut S,
        coordinator_epoch: u64,
    ) -> Result<Self, S::Error> {
        Ok(Self {
            durable: store.load_state()?,
            active_processes: BTreeMap::new(),
            coordinator_epoch,
        })
    }

    pub fn persist(&self, store: &mut impl DurableStore) {
        store.save(self.durable.clone());
    }

    pub fn try_persist<S: FallibleDurableStore>(&self, store: &mut S) -> Result<(), S::Error> {
        store.save_state(&self.durable)
    }

    pub fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }

    pub fn upsert_tenant(&mut self, id: TenantId) {
        self.durable.tenants.insert(id.clone(), TenantRecord { id });
    }

    pub fn upsert_user(&mut self, tenant: TenantId, id: UserId, credential_kind: CredentialKind) {
        self.durable.users.insert(
            id.clone(),
            UserRecord {
                id,
                tenant,
                credential_kind,
            },
        );
    }

    pub fn upsert_project(&mut self, tenant: TenantId, id: ProjectId, name: impl Into<String>) {
        self.durable.projects.insert(
            id.clone(),
            ProjectRecord {
                id,
                tenant,
                name: name.into(),
            },
        );
    }

    pub fn enroll_node(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        node: NodeId,
        public_key: impl Into<String>,
        enrollment_scope: impl Into<String>,
    ) {
        let key = NodeScopeKey::new(tenant.clone(), project.clone(), node.clone());
        self.durable.node_identities.insert(
            key,
            NodeIdentityRecord {
                id: node,
                tenant,
                project,
                public_key: public_key.into(),
                enrollment_scope: enrollment_scope.into(),
                last_seen_epoch_seconds: None,
            },
        );
    }

    pub fn create_node_enrollment_grant(
        &self,
        tenant: TenantId,
        project: ProjectId,
        grant_id: impl Into<String>,
        scope: impl Into<String>,
        expires_at_epoch_seconds: u64,
    ) -> EnrollmentGrant {
        EnrollmentGrant {
            tenant,
            project,
            grant_id: grant_id.into(),
            scope: scope.into(),
            expires_at_epoch_seconds,
            consumed: false,
        }
    }

    pub fn exchange_node_enrollment_grant(
        &mut self,
        grant: &mut EnrollmentGrant,
        node: NodeId,
        public_key: &str,
        requested_scope: &str,
        now_epoch_seconds: u64,
    ) -> Result<NodeCredential, CoordinatorError> {
        let credential = grant
            .exchange_for_node_identity(
                node.clone(),
                public_key,
                requested_scope,
                now_epoch_seconds,
            )
            .map_err(CoordinatorError::Enrollment)?;
        self.enroll_node(
            credential.tenant.clone(),
            credential.project.clone(),
            node.clone(),
            public_key,
            credential.scope.clone(),
        );
        let subject =
            NodeScopeKey::new(credential.tenant.clone(), credential.project.clone(), node)
                .credential_subject();
        self.durable.credentials.insert(
            subject.clone(),
            CredentialRecord {
                subject,
                tenant: credential.tenant.clone(),
                project: Some(credential.project.clone()),
                kind: credential.credential_kind.clone(),
                public_key_fingerprint: Some(credential.public_key_fingerprint.clone()),
            },
        );
        Ok(credential)
    }

    pub fn upsert_source_provider_config(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        provider: SourceProviderKind,
        manifest_digest: Digest,
    ) {
        let provider_key = format!("{provider:?}");
        self.durable.source_provider_configs.insert(
            (tenant.clone(), project.clone(), provider_key),
            SourceProviderConfigRecord {
                tenant,
                project,
                provider,
                manifest_digest,
            },
        );
    }

    pub fn upsert_service_policy_record(
        &mut self,
        tenant: TenantId,
        name: impl Into<String>,
        digest: Digest,
    ) {
        let name = name.into();
        self.durable.service_policy_records.insert(
            (tenant.clone(), name.clone()),
            ServicePolicyRecord {
                tenant,
                name,
                digest,
            },
        );
    }

    pub fn suspend_tenant(&mut self, tenant: TenantId, actor: UserId) -> ServicePolicyRecord {
        self.upsert_tenant(tenant.clone());
        let name = "tenant:suspended".to_owned();
        let digest = Digest::from_parts([
            b"tenant-suspension:v1".as_slice(),
            tenant.as_str().as_bytes(),
            actor.as_str().as_bytes(),
        ]);
        self.upsert_service_policy_record(tenant.clone(), name.clone(), digest);
        self.service_policy_record(&tenant, &name)
            .expect("tenant suspension record was just inserted")
            .clone()
    }

    pub fn resume_tenant(&mut self, tenant: &TenantId) -> bool {
        self.durable
            .service_policy_records
            .remove(&(tenant.clone(), "tenant:suspended".to_owned()))
            .is_some()
    }

    pub fn tenant_quota_override(&self, tenant: &TenantId) -> Option<&TenantQuotaOverrideRecord> {
        self.durable.hosted_admin.tenant_quota_overrides.get(tenant)
    }

    pub fn replace_tenant_quota_override(
        &mut self,
        tenant: TenantId,
        values: Option<TenantQuotaOverrideValues>,
        operator: UserId,
        action: impl Into<String>,
        occurred_at_epoch_seconds: u64,
    ) -> Result<HostedAdminAuditRecord, String> {
        let old_quota_override = self
            .tenant_quota_override(&tenant)
            .map(|record| record.values.clone());
        let values = values.filter(|values| !values.is_empty());
        if values.is_some()
            && old_quota_override.is_none()
            && self.durable.hosted_admin.tenant_quota_overrides.len() >= MAX_TENANT_QUOTA_OVERRIDES
        {
            return Err("hosted tenant quota override capacity is full".to_owned());
        }
        match values.clone() {
            Some(values) => {
                self.upsert_tenant(tenant.clone());
                self.durable.hosted_admin.tenant_quota_overrides.insert(
                    tenant.clone(),
                    TenantQuotaOverrideRecord {
                        tenant: tenant.clone(),
                        values,
                        updated_at_epoch_seconds: occurred_at_epoch_seconds,
                        operator: operator.clone(),
                    },
                );
            }
            None => {
                self.durable
                    .hosted_admin
                    .tenant_quota_overrides
                    .remove(&tenant);
            }
        }
        Ok(self.record_hosted_admin_audit(
            tenant,
            action,
            old_quota_override,
            values,
            operator,
            occurred_at_epoch_seconds,
        ))
    }

    pub fn record_hosted_admin_audit(
        &mut self,
        tenant: TenantId,
        action: impl Into<String>,
        old_quota_override: Option<TenantQuotaOverrideValues>,
        new_quota_override: Option<TenantQuotaOverrideValues>,
        operator: UserId,
        occurred_at_epoch_seconds: u64,
    ) -> HostedAdminAuditRecord {
        let sequence = self.durable.hosted_admin.next_audit_sequence;
        self.durable.hosted_admin.next_audit_sequence = sequence.saturating_add(1);
        let record = HostedAdminAuditRecord {
            sequence,
            tenant,
            action: action.into(),
            old_quota_override,
            new_quota_override,
            operator,
            occurred_at_epoch_seconds,
        };
        while self.durable.hosted_admin.audit.len() >= MAX_HOSTED_ADMIN_AUDIT_RECORDS {
            self.durable.hosted_admin.audit.pop_front();
        }
        self.durable.hosted_admin.audit.push_back(record.clone());
        record
    }

    pub fn tenant_suspended(&self, tenant: &TenantId) -> bool {
        self.service_policy_record(tenant, "tenant:suspended")
            .is_some()
    }

    pub fn tenant_disabled(&self, tenant: &TenantId) -> bool {
        self.service_policy_record(tenant, "tenant:disabled")
            .is_some()
    }

    pub fn tenant_deleted(&self, tenant: &TenantId) -> bool {
        self.service_policy_record(tenant, "tenant:deleted")
            .is_some()
    }

    pub fn tenant_manual_review(&self, tenant: &TenantId) -> bool {
        self.service_policy_record(tenant, "tenant:manual_review")
            .is_some()
    }

    pub fn account_policy_state(&self, tenant: &TenantId) -> AccountPolicyState {
        let suspended = self.tenant_suspended(tenant);
        let disabled = self.tenant_disabled(tenant);
        let deleted = self.tenant_deleted(tenant);
        let manual_review = self.tenant_manual_review(tenant);
        let account_status = if deleted {
            "deleted"
        } else if disabled {
            "disabled"
        } else if suspended {
            "suspended"
        } else if manual_review {
            "manual_review"
        } else {
            "active"
        }
        .to_owned();
        let sanitized_reason = match account_status.as_str() {
            "deleted" => Some("account or tenant is no longer active".to_owned()),
            "disabled" => Some("account or tenant is disabled by hosted policy".to_owned()),
            "suspended" => Some("account or tenant is suspended by hosted policy".to_owned()),
            "manual_review" => Some("account or tenant is pending hosted review".to_owned()),
            _ => None,
        };
        let next_actions = if account_status == "active" {
            Vec::new()
        } else {
            vec![
                "clusterflux auth status --json".to_owned(),
                "contact the hosted operator or use a self-hosted coordinator".to_owned(),
            ]
        };
        AccountPolicyState {
            account_status,
            suspended,
            disabled,
            deleted,
            manual_review,
            sanitized_reason,
            next_actions,
        }
    }

    pub fn ensure_tenant_active(&self, tenant: &TenantId) -> Result<(), CoordinatorError> {
        let account_state = self.account_policy_state(tenant);
        if account_state.account_status != "active" {
            return Err(CoordinatorError::Unauthorized(format!(
                "tenant is {} by admin controls",
                account_state.account_status
            )));
        }
        Ok(())
    }

    pub fn start_process(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        id: ProcessId,
    ) -> ActiveProcess {
        self.start_process_for_launch_attempt(tenant, project, id, None)
    }

    pub fn start_process_for_launch_attempt(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        id: ProcessId,
        launch_attempt: Option<clusterflux_core::LaunchAttemptId>,
    ) -> ActiveProcess {
        let process = ActiveProcess {
            id: id.clone(),
            launch_attempt,
            tenant,
            project,
            connected_nodes: BTreeSet::new(),
            coordinator_epoch: self.coordinator_epoch,
        };
        self.active_processes.insert(
            (process.tenant.clone(), process.project.clone(), id),
            process.clone(),
        );
        process
    }

    pub fn authorize_node_for_process(
        &self,
        node: &NodeId,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<(), CoordinatorError> {
        if !self
            .durable
            .node_identities
            .contains_key(&NodeScopeKey::from_refs(tenant, project, node))
        {
            return Err(CoordinatorError::UnknownNode);
        }
        if !self
            .active_processes
            .contains_key(&(tenant.clone(), project.clone(), process.clone()))
        {
            return Err(CoordinatorError::Unauthorized(
                "virtual process is not active in coordinator memory".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn reconnect_node(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
        process: Option<(&ProcessId, u64)>,
    ) -> Result<(), CoordinatorError> {
        if !self
            .durable
            .node_identities
            .contains_key(&NodeScopeKey::from_refs(tenant, project, node))
        {
            return Err(CoordinatorError::UnknownNode);
        }

        if let Some((process_id, stale_epoch)) = process {
            if stale_epoch != self.coordinator_epoch {
                return Err(CoordinatorError::StaleProcessEpoch {
                    stale_epoch,
                    current_epoch: self.coordinator_epoch,
                });
            }
            let key = (tenant.clone(), project.clone(), process_id.clone());
            if let Some(active) = self.active_processes.get_mut(&key) {
                active.connected_nodes.insert(node.clone());
            }
        }

        Ok(())
    }

    pub fn revoke_node_credential(
        &mut self,
        context: &AuthContext,
        node: &NodeId,
    ) -> Result<NodeIdentityRecord, CoordinatorError> {
        let identity = self
            .durable
            .node_identities
            .get(&NodeScopeKey::from_refs(
                &context.tenant,
                &context.project,
                node,
            ))
            .ok_or(CoordinatorError::UnknownNode)?
            .clone();
        if !matches!(context.actor, Actor::User(_)) {
            return Err(CoordinatorError::Unauthorized(
                "node credential revocation requires a user identity".to_owned(),
            ));
        }
        let key = NodeScopeKey::from_refs(&context.tenant, &context.project, node);
        self.durable.node_identities.remove(&key);
        self.durable.credentials.remove(&key.credential_subject());
        for active in self
            .active_processes
            .values_mut()
            .filter(|active| active.tenant == context.tenant && active.project == context.project)
        {
            active.connected_nodes.remove(&key.node);
        }
        Ok(identity)
    }

    pub fn list_projects(&self, context: &AuthContext) -> Vec<ProjectRecord> {
        self.durable
            .projects
            .values()
            .filter(|project| project.tenant == context.tenant)
            .cloned()
            .collect()
    }

    pub fn authorize_debug_attach(
        &self,
        context: &AuthContext,
        process: &ProcessId,
    ) -> Authorization {
        let Some(active) = self.active_process(&context.tenant, &context.project, process) else {
            return Authorization::deny("virtual process is not active in this tenant or project");
        };
        let Actor::User(user) = &context.actor else {
            return Authorization::deny("debug attach requires a user identity");
        };
        let permission = self.durable.project_permissions.get(&(
            active.tenant.clone(),
            active.project.clone(),
            user.clone(),
        ));
        if !permission.is_some_and(|permission| permission.can_debug) {
            return Authorization::deny("debug attach requires explicit project permission");
        }
        Authorization::allow("debug attach authorized for project")
    }

    pub fn project(&self, id: &ProjectId) -> Option<&ProjectRecord> {
        self.durable.projects.get(id)
    }

    pub fn project_count_for_tenant(&self, tenant: &TenantId) -> usize {
        self.durable
            .projects
            .values()
            .filter(|project| &project.tenant == tenant)
            .count()
    }

    pub fn active_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        id: &ProcessId,
    ) -> Option<&ActiveProcess> {
        self.active_processes
            .get(&(tenant.clone(), project.clone(), id.clone()))
    }

    pub fn active_process_for_project(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> Option<&ActiveProcess> {
        self.active_processes
            .values()
            .find(|active| &active.tenant == tenant && &active.project == project)
    }

    pub fn active_processes_for_project(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> Vec<ActiveProcess> {
        self.active_processes
            .values()
            .filter(|active| &active.tenant == tenant && &active.project == project)
            .cloned()
            .collect()
    }

    pub fn active_process_exists_outside_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        id: &ProcessId,
    ) -> bool {
        self.active_processes.values().any(|active| {
            active.id == *id && (active.tenant != *tenant || active.project != *project)
        })
    }

    pub fn abort_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<ActiveProcess, CoordinatorError> {
        let key = (tenant.clone(), project.clone(), process.clone());
        let active = self.active_processes.get(&key).ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "process abort requires an active virtual process".to_owned(),
            )
        })?;
        debug_assert_eq!(&active.tenant, tenant);
        debug_assert_eq!(&active.project, project);
        Ok(self
            .active_processes
            .remove(&key)
            .expect("active process was checked immediately before removal"))
    }

    pub fn abort_process_for_launch_attempt(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        launch_attempt: &clusterflux_core::LaunchAttemptId,
    ) -> Result<ActiveProcess, CoordinatorError> {
        let key = (tenant.clone(), project.clone(), process.clone());
        let active = self.active_processes.get(&key).ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "launch rollback requires an active virtual process".to_owned(),
            )
        })?;
        if active.launch_attempt.as_ref() != Some(launch_attempt) {
            return Err(CoordinatorError::Unauthorized(format!(
                "launch rollback denied: attempt {} does not own process {}",
                launch_attempt.as_str(),
                process.as_str()
            )));
        }
        Ok(self
            .active_processes
            .remove(&key)
            .expect("active process was checked immediately before removal"))
    }

    pub fn active_process_count(&self) -> usize {
        self.active_processes.len()
    }

    pub fn active_process_count_for_tenant(&self, tenant: &TenantId) -> usize {
        self.active_processes
            .values()
            .filter(|process| &process.tenant == tenant)
            .count()
    }

    pub fn active_process_scopes_for_tenant(
        &self,
        tenant: &TenantId,
    ) -> Vec<(ProjectId, ProcessId)> {
        self.active_processes
            .values()
            .filter(|process| &process.tenant == tenant)
            .map(|process| (process.project.clone(), process.id.clone()))
            .collect()
    }

    pub fn tenant_count(&self) -> usize {
        self.durable.tenants.len()
    }

    pub fn user_count(&self) -> usize {
        self.durable.users.len()
    }

    pub fn project_count(&self) -> usize {
        self.durable.projects.len()
    }

    pub fn node_identity_count(&self) -> usize {
        self.durable.node_identities.len()
    }

    pub fn node_identity(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        id: &NodeId,
    ) -> Option<&NodeIdentityRecord> {
        self.durable
            .node_identities
            .get(&NodeScopeKey::from_refs(tenant, project, id))
    }

    pub fn node_identity_count_for_tenant(&self, tenant: &TenantId) -> usize {
        self.durable
            .node_identities
            .values()
            .filter(|node| &node.tenant == tenant)
            .count()
    }

    pub fn mark_node_identity_seen(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
        seen_at_epoch_seconds: u64,
    ) {
        if let Some(identity) = self
            .durable
            .node_identities
            .get_mut(&NodeScopeKey::from_refs(tenant, project, node))
        {
            identity.last_seen_epoch_seconds = Some(
                identity
                    .last_seen_epoch_seconds
                    .unwrap_or_default()
                    .max(seen_at_epoch_seconds),
            );
        }
    }

    pub fn source_provider_config(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        provider: &str,
    ) -> Option<&SourceProviderConfigRecord> {
        self.durable.source_provider_configs.get(&(
            tenant.clone(),
            project.clone(),
            provider.to_owned(),
        ))
    }

    pub fn service_policy_record(
        &self,
        tenant: &TenantId,
        name: &str,
    ) -> Option<&ServicePolicyRecord> {
        self.durable
            .service_policy_records
            .get(&(tenant.clone(), name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use clusterflux_core::AgentId;

    use super::*;

    #[test]
    fn coordinator_restart_preserves_project_but_not_live_processes() {
        let mut store = InMemoryDurableStore::default();
        let mut first = Coordinator::boot(&store, 1);
        first.upsert_tenant(TenantId::from("tenant"));
        first.upsert_user(
            TenantId::from("tenant"),
            UserId::from("user"),
            CredentialKind::CliDeviceSession,
        );
        first.upsert_project(TenantId::from("tenant"), ProjectId::from("project"), "demo");
        first.upsert_source_provider_config(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            SourceProviderKind::Git,
            Digest::sha256("git-manifest"),
        );
        first.upsert_service_policy_record(
            TenantId::from("tenant"),
            "community tier",
            Digest::sha256("policy"),
        );
        let mut grant = first.create_node_enrollment_grant(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "grant",
            "node:attach",
            100,
        );
        first
            .exchange_node_enrollment_grant(
                &mut grant,
                NodeId::from("node"),
                "public-key",
                "node:attach",
                99,
            )
            .unwrap();
        first.start_process(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            ProcessId::from("process"),
        );
        first.persist(&mut store);

        let mut restarted = Coordinator::boot(&store, 2);

        assert!(restarted
            .durable
            .tenants
            .contains_key(&TenantId::from("tenant")));
        assert!(restarted.durable.users.contains_key(&UserId::from("user")));
        assert!(restarted.project(&ProjectId::from("project")).is_some());
        assert!(restarted
            .node_identity(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
            )
            .is_some());
        let node_subject = NodeScopeKey::new(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
        )
        .credential_subject();
        assert_eq!(
            restarted
                .durable
                .credentials
                .get(&node_subject)
                .map(|credential| &credential.kind),
            Some(&CredentialKind::NodeCredential)
        );
        assert!(restarted
            .source_provider_config(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                "Git"
            )
            .is_some());
        assert!(restarted
            .service_policy_record(&TenantId::from("tenant"), "community tier")
            .is_some());
        assert_eq!(restarted.active_process_count(), 0);

        let process = ProcessId::from("process-rerun");
        let rerun = restarted.start_process(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            process.clone(),
        );
        assert_eq!(rerun.coordinator_epoch, 2);
        restarted
            .reconnect_node(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
                Some((&process, 2)),
            )
            .unwrap();
        assert!(restarted
            .active_process(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &process,
            )
            .unwrap()
            .connected_nodes
            .contains(&NodeId::from("node")));
    }

    #[test]
    fn duplicate_node_ids_use_distinct_durable_identities_and_credential_subjects() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        let node = NodeId::from("shared-node");
        let scopes = [
            (TenantId::from("tenant-a"), ProjectId::from("project-a")),
            (TenantId::from("tenant-b"), ProjectId::from("project-b")),
            (TenantId::from("tenant-a"), ProjectId::from("project-c")),
        ];
        for (index, (tenant, project)) in scopes.iter().enumerate() {
            let mut grant = coordinator.create_node_enrollment_grant(
                tenant.clone(),
                project.clone(),
                format!("grant-{index}"),
                "node:attach",
                100,
            );
            coordinator
                .exchange_node_enrollment_grant(
                    &mut grant,
                    node.clone(),
                    &format!("public-key-{index}"),
                    "node:attach",
                    99,
                )
                .unwrap();
        }

        let scope_a = NodeScopeKey::from_refs(&scopes[0].0, &scopes[0].1, &node);
        let scope_b = NodeScopeKey::from_refs(&scopes[1].0, &scopes[1].1, &node);
        let scope_c = NodeScopeKey::from_refs(&scopes[2].0, &scopes[2].1, &node);
        assert_ne!(scope_a.credential_subject(), scope_b.credential_subject());
        assert_ne!(scope_a.credential_subject(), scope_c.credential_subject());
        assert_eq!(
            coordinator.node_identity(&scope_a.tenant, &scope_a.project, &scope_a.node),
            coordinator.durable.node_identities.get(&scope_a)
        );
        assert_eq!(
            coordinator.node_identity(&scope_b.tenant, &scope_b.project, &scope_b.node),
            coordinator.durable.node_identities.get(&scope_b)
        );
        assert_eq!(
            coordinator.node_identity(&scope_c.tenant, &scope_c.project, &scope_c.node),
            coordinator.durable.node_identities.get(&scope_c)
        );
        assert!(coordinator
            .durable
            .credentials
            .contains_key(&scope_a.credential_subject()));
        assert!(coordinator
            .durable
            .credentials
            .contains_key(&scope_b.credential_subject()));
        assert!(coordinator
            .durable
            .credentials
            .contains_key(&scope_c.credential_subject()));
        assert_eq!(coordinator.durable.node_identities.len(), 3);
        assert_eq!(coordinator.durable.credentials.len(), 3);
    }

    #[test]
    fn identical_process_ids_are_isolated_by_tenant_and_project() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        let process = ProcessId::from("vp-current");
        let tenant_a = TenantId::from("tenant-a");
        let project_a = ProjectId::from("project-a");
        let tenant_b = TenantId::from("tenant-b");
        let project_b = ProjectId::from("project-b");

        coordinator.start_process(tenant_a.clone(), project_a.clone(), process.clone());
        coordinator.start_process(tenant_b.clone(), project_b.clone(), process.clone());

        assert_eq!(coordinator.active_process_count(), 2);
        assert!(coordinator
            .active_process(&tenant_a, &project_a, &process)
            .is_some());
        assert!(coordinator
            .active_process(&tenant_b, &project_b, &process)
            .is_some());
        coordinator
            .abort_process(&tenant_a, &project_a, &process)
            .unwrap();
        assert!(coordinator
            .active_process(&tenant_a, &project_a, &process)
            .is_none());
        assert!(coordinator
            .active_process(&tenant_b, &project_b, &process)
            .is_some());
    }

    #[test]
    fn node_reconnect_rejects_stale_process_epoch_after_restart() {
        let mut store = InMemoryDurableStore::default();
        let mut first = Coordinator::boot(&store, 1);
        first.upsert_tenant(TenantId::from("tenant"));
        first.upsert_project(TenantId::from("tenant"), ProjectId::from("project"), "demo");
        first.enroll_node(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
            "public-key",
            "node",
        );
        first.persist(&mut store);

        let mut restarted = Coordinator::boot(&store, 2);
        restarted
            .reconnect_node(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
                None,
            )
            .unwrap();

        let error = restarted
            .reconnect_node(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
                Some((&ProcessId::from("process"), 1)),
            )
            .unwrap_err();

        assert!(matches!(error, CoordinatorError::StaleProcessEpoch { .. }));
    }

    #[test]
    fn node_enrollment_grant_becomes_persistent_node_identity() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        let mut grant = coordinator.create_node_enrollment_grant(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "grant",
            "node:attach",
            100,
        );

        let credential = coordinator
            .exchange_node_enrollment_grant(
                &mut grant,
                NodeId::from("node"),
                "public-key",
                "node:attach",
                99,
            )
            .unwrap();

        assert_eq!(credential.credential_kind, CredentialKind::NodeCredential);
        assert!(coordinator
            .node_identity(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
            )
            .is_some());
    }

    #[test]
    fn node_credential_revocation_is_project_scoped_and_removes_identity() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        coordinator.enroll_node(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
            "public-key",
            "node:attach",
        );
        let node_subject = NodeScopeKey::new(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
        )
        .credential_subject();
        coordinator.durable.credentials.insert(
            node_subject.clone(),
            CredentialRecord {
                subject: node_subject.clone(),
                tenant: TenantId::from("tenant"),
                project: Some(ProjectId::from("project")),
                kind: CredentialKind::NodeCredential,
                public_key_fingerprint: Some(Digest::sha256("public-key")),
            },
        );
        coordinator.start_process(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            ProcessId::from("process"),
        );
        coordinator
            .reconnect_node(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
                Some((&ProcessId::from("process"), 1)),
            )
            .unwrap();

        let foreign = coordinator
            .revoke_node_credential(
                &AuthContext {
                    tenant: TenantId::from("other"),
                    project: ProjectId::from("project"),
                    actor: Actor::User(UserId::from("user")),
                },
                &NodeId::from("node"),
            )
            .unwrap_err();
        assert!(matches!(foreign, CoordinatorError::UnknownNode));

        let revoked = coordinator
            .revoke_node_credential(
                &AuthContext {
                    tenant: TenantId::from("tenant"),
                    project: ProjectId::from("project"),
                    actor: Actor::User(UserId::from("user")),
                },
                &NodeId::from("node"),
            )
            .unwrap();
        assert_eq!(revoked.id, NodeId::from("node"));
        assert!(coordinator
            .node_identity(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
            )
            .is_none());
        assert!(!coordinator.durable.credentials.contains_key(&node_subject));
        assert!(!coordinator
            .active_process(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &ProcessId::from("process"),
            )
            .unwrap()
            .connected_nodes
            .contains(&NodeId::from("node")));
    }

    #[test]
    fn project_listing_is_filtered_by_tenant() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        coordinator.upsert_project(
            TenantId::from("tenant-a"),
            ProjectId::from("project-a"),
            "a",
        );
        coordinator.upsert_project(
            TenantId::from("tenant-b"),
            ProjectId::from("project-b"),
            "b",
        );

        let projects = coordinator.list_projects(&AuthContext {
            tenant: TenantId::from("tenant-a"),
            project: ProjectId::from("project-a"),
            actor: Actor::User(UserId::from("user-a")),
        });

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, ProjectId::from("project-a"));
    }

    #[test]
    fn tenant_suspension_is_durable_admin_policy_state() {
        let mut store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        let record =
            coordinator.suspend_tenant(TenantId::from("tenant"), UserId::from("admin-user"));

        assert_eq!(record.tenant, TenantId::from("tenant"));
        assert_eq!(record.name, "tenant:suspended");
        assert!(coordinator.tenant_suspended(&TenantId::from("tenant")));
        assert!(coordinator
            .ensure_tenant_active(&TenantId::from("tenant"))
            .unwrap_err()
            .to_string()
            .contains("suspended"));

        coordinator.persist(&mut store);
        let restarted = Coordinator::boot(&store, 2);
        assert!(restarted.tenant_suspended(&TenantId::from("tenant")));
    }

    #[test]
    fn account_policy_state_summarizes_sensitive_admin_records_safely() {
        let tenant = TenantId::from("tenant");
        let mut coordinator = Coordinator::boot(&InMemoryDurableStore::default(), 1);

        let active = coordinator.account_policy_state(&tenant);
        assert_eq!(active.account_status, "active");
        assert!(active.sanitized_reason.is_none());
        assert!(active.next_actions.is_empty());

        coordinator.upsert_service_policy_record(
            tenant.clone(),
            "tenant:manual_review",
            Digest::from_parts([b"manual-review".as_slice()]),
        );
        let manual_review = coordinator.account_policy_state(&tenant);
        assert_eq!(manual_review.account_status, "manual_review");
        assert!(manual_review.manual_review);
        assert_eq!(
            manual_review.sanitized_reason.as_deref(),
            Some("account or tenant is pending hosted review")
        );

        coordinator.upsert_service_policy_record(
            tenant.clone(),
            "tenant:disabled",
            Digest::from_parts([b"disabled".as_slice()]),
        );
        let disabled = coordinator.account_policy_state(&tenant);
        assert_eq!(disabled.account_status, "disabled");
        assert!(disabled.disabled);
        assert!(disabled.manual_review);
        assert_eq!(
            disabled.sanitized_reason.as_deref(),
            Some("account or tenant is disabled by hosted policy")
        );

        coordinator.upsert_service_policy_record(
            tenant.clone(),
            "tenant:deleted",
            Digest::from_parts([b"deleted".as_slice()]),
        );
        let deleted = coordinator.account_policy_state(&tenant);
        assert_eq!(deleted.account_status, "deleted");
        assert!(deleted.deleted);
        assert!(deleted.disabled);
        assert!(deleted.manual_review);
        assert_eq!(
            deleted.sanitized_reason.as_deref(),
            Some("account or tenant is no longer active")
        );
        assert!(deleted
            .next_actions
            .iter()
            .any(|action| action.contains("hosted operator")));
    }

    #[test]
    fn hosted_account_and_quota_policy_survive_restart_and_resume_is_reversible() {
        let mut store = InMemoryDurableStore::default();
        let tenant = TenantId::from("tenant");
        let operator = UserId::from("hosted-admin");
        let mut first = Coordinator::boot(&store, 1);
        first.upsert_project(tenant.clone(), ProjectId::from("project"), "Project");
        first.issue_cli_session(
            tenant.clone(),
            ProjectId::from("project"),
            UserId::from("user"),
            "session-secret",
            None,
        );
        first
            .replace_tenant_quota_override(
                tenant.clone(),
                Some(TenantQuotaOverrideValues {
                    max_projects: Some(1_000),
                    max_nodes: Some(32),
                    max_active_processes: Some(8),
                }),
                operator.clone(),
                "quota_set",
                10,
            )
            .unwrap();
        first.suspend_tenant(tenant.clone(), operator.clone());
        assert_eq!(first.revoke_cli_sessions_for_tenant(&tenant), 1);
        first.record_hosted_admin_audit(
            tenant.clone(),
            "account_suspend",
            None,
            None,
            operator.clone(),
            11,
        );
        first.persist(&mut store);

        let mut restarted = Coordinator::boot(&store, 2);
        assert!(restarted.tenant_suspended(&tenant));
        assert_eq!(
            restarted
                .tenant_quota_override(&tenant)
                .unwrap()
                .values
                .max_projects,
            Some(1_000)
        );
        assert!(restarted
            .authenticate_cli_session_for_status("session-secret")
            .unwrap_err()
            .to_string()
            .contains("revoked"));
        assert_eq!(restarted.durable.hosted_admin.audit.len(), 2);

        assert!(restarted.resume_tenant(&tenant));
        assert!(!restarted.resume_tenant(&tenant));
        restarted.record_hosted_admin_audit(
            tenant.clone(),
            "account_resume",
            None,
            None,
            operator,
            12,
        );
        restarted.persist(&mut store);
        let resumed = Coordinator::boot(&store, 3);
        assert_eq!(
            resumed.account_policy_state(&tenant).account_status,
            "active"
        );
        assert!(resumed
            .authenticate_cli_session_for_status("session-secret")
            .unwrap_err()
            .to_string()
            .contains("revoked"));
        assert!(resumed.project(&ProjectId::from("project")).is_some());
    }

    #[test]
    fn agent_public_keys_are_project_user_scoped_and_restart_durable() {
        let mut store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        coordinator.upsert_tenant(TenantId::from("tenant"));
        coordinator.upsert_user(
            TenantId::from("tenant"),
            UserId::from("user"),
            CredentialKind::CliDeviceSession,
        );
        coordinator.upsert_project(TenantId::from("tenant"), ProjectId::from("project"), "demo");

        let registered = coordinator.register_agent_public_key(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("user"),
            AgentId::from("agent-ci"),
            "agent-key-v1",
        );
        assert_eq!(registered.version, 1);
        assert!(!registered.revoked);
        assert!(!registered.human_account_creation_privilege);
        assert_eq!(registered.scopes, vec!["project:read", "project:run"]);

        let rotated = coordinator.register_agent_public_key(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("user"),
            AgentId::from("agent-ci"),
            "agent-key-v2",
        );
        assert_eq!(rotated.version, 2);
        assert_eq!(rotated.public_key, "agent-key-v2");

        coordinator.persist(&mut store);
        let mut restarted = Coordinator::boot(&store, 2);
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let listed = restarted.list_agent_public_keys(&context);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent, AgentId::from("agent-ci"));
        assert_eq!(listed[0].version, 2);

        let foreign_user_context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("other-user")),
        };
        assert!(restarted
            .list_agent_public_keys(&foreign_user_context)
            .is_empty());

        let foreign_project_context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("other-project"),
            actor: Actor::User(UserId::from("user")),
        };
        assert!(restarted
            .list_agent_public_keys(&foreign_project_context)
            .is_empty());

        let revoked = restarted
            .revoke_agent_public_key(&context, &AgentId::from("agent-ci"))
            .unwrap();
        assert!(revoked.revoked);
        assert!(!restarted
            .durable
            .credentials
            .contains_key("agent:tenant:project:agent-ci"));
    }

    #[test]
    fn node_cannot_claim_process_outside_authorized_scope() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        coordinator.enroll_node(
            TenantId::from("tenant-a"),
            ProjectId::from("project-a"),
            NodeId::from("node-a"),
            "public-key",
            "node",
        );
        coordinator.start_process(
            TenantId::from("tenant-b"),
            ProjectId::from("project-b"),
            ProcessId::from("process-b"),
        );

        let error = coordinator
            .authorize_node_for_process(
                &NodeId::from("node-a"),
                &TenantId::from("tenant-b"),
                &ProjectId::from("project-b"),
                &ProcessId::from("process-b"),
            )
            .unwrap_err();

        assert!(matches!(error, CoordinatorError::UnknownNode));
    }

    #[test]
    fn debug_attach_requires_explicit_project_permission() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        coordinator.start_process(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            ProcessId::from("process"),
        );
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };

        let denied = coordinator.authorize_debug_attach(&context, &ProcessId::from("process"));
        coordinator.grant_project_debug(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("user"),
        );
        let allowed = coordinator.authorize_debug_attach(&context, &ProcessId::from("process"));

        assert!(!denied.allowed);
        assert!(denied.reason.contains("explicit project permission"));
        assert!(allowed.allowed);
    }
}
