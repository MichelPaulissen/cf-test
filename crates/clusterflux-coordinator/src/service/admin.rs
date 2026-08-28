use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    admin_request_proof_from_token_digest, CredentialKind, Digest, TenantId, UserId,
};
use serde::{Deserialize, Serialize};

use crate::CoordinatorError;
use crate::{
    AccountPolicyState, HostedAdminAuditRecord, TenantQuotaOverrideRecord,
    TenantQuotaOverrideValues,
};

use super::{
    AdmissionQuotaLimits, CoordinatorResponse, CoordinatorService, CoordinatorServiceError,
};

const ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedTenantAdminStatus {
    pub tenant: TenantId,
    pub account: AccountPolicyState,
    pub default_quota: AdmissionQuotaLimits,
    pub quota_override: Option<TenantQuotaOverrideRecord>,
    pub effective_quota: AdmissionQuotaLimits,
    pub projects_current: u64,
    pub node_identities_current: u64,
    pub active_processes_current: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedAccountMutationResult {
    pub status: HostedTenantAdminStatus,
    pub audit: HostedAdminAuditRecord,
    pub revoked_sessions: u64,
    pub aborted_processes: u64,
}

impl CoordinatorService {
    pub fn hosted_tenant_admin_status(&self, tenant: &TenantId) -> HostedTenantAdminStatus {
        let quota_override = self.coordinator.tenant_quota_override(tenant).cloned();
        let default_quota = self.quota.default_admission_limits();
        let effective_quota = self
            .quota
            .effective_admission_limits(quota_override.as_ref().map(|record| &record.values));
        HostedTenantAdminStatus {
            tenant: tenant.clone(),
            account: self.coordinator.account_policy_state(tenant),
            default_quota,
            quota_override,
            effective_quota,
            projects_current: u64::try_from(self.coordinator.project_count_for_tenant(tenant))
                .unwrap_or(u64::MAX),
            node_identities_current: u64::try_from(
                self.coordinator.node_identity_count_for_tenant(tenant),
            )
            .unwrap_or(u64::MAX),
            active_processes_current: u64::try_from(
                self.coordinator.active_process_count_for_tenant(tenant),
            )
            .unwrap_or(u64::MAX),
        }
    }

    pub fn hosted_account_policy_state(&self, tenant: &TenantId) -> AccountPolicyState {
        self.coordinator.account_policy_state(tenant)
    }

    pub fn configure_hosted_tenant_quota(
        &mut self,
        tenant: TenantId,
        values: Option<TenantQuotaOverrideValues>,
        operator: UserId,
        action: impl Into<String>,
        occurred_at_epoch_seconds: u64,
        safety_ceiling: u64,
    ) -> Result<HostedTenantAdminStatus, CoordinatorServiceError> {
        if safety_ceiling == 0 {
            return Err(CoordinatorServiceError::Protocol(
                "hosted quota safety ceiling must be positive".to_owned(),
            ));
        }
        if let Some(values) = values.as_ref() {
            for (name, value) in [
                ("max_projects", values.max_projects),
                ("max_nodes", values.max_nodes),
                ("max_active_processes", values.max_active_processes),
            ] {
                if value.is_some_and(|value| value == 0 || value > safety_ceiling) {
                    return Err(CoordinatorServiceError::Protocol(format!(
                        "{name} must be positive and no greater than the hosted safety ceiling of {safety_ceiling}"
                    )));
                }
            }
        }
        self.coordinator
            .replace_tenant_quota_override(
                tenant.clone(),
                values,
                operator,
                action,
                occurred_at_epoch_seconds,
            )
            .map_err(CoordinatorServiceError::Protocol)?;
        self.persist_durable_state()?;
        Ok(self.hosted_tenant_admin_status(&tenant))
    }

    pub fn suspend_hosted_account(
        &mut self,
        tenant: TenantId,
        operator: UserId,
        occurred_at_epoch_seconds: u64,
    ) -> Result<HostedAccountMutationResult, CoordinatorServiceError> {
        self.coordinator
            .suspend_tenant(tenant.clone(), operator.clone());
        let revoked_sessions = self.coordinator.revoke_cli_sessions_for_tenant(&tenant);
        let audit = self.coordinator.record_hosted_admin_audit(
            tenant.clone(),
            "account_suspend",
            None,
            None,
            operator,
            occurred_at_epoch_seconds,
        );
        self.persist_durable_state()?;

        let automated_runs = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| record.run.tenant == tenant && !record.run.state.is_terminal())
            .map(|record| record.run.run_id.clone())
            .collect::<Vec<_>>();
        for run in automated_runs {
            self.cancel_automated_run(&run)?;
        }

        let process_scopes = self.coordinator.active_process_scopes_for_tenant(&tenant);
        let mut aborted_processes = 0_u64;
        for (project, process) in process_scopes {
            self.handle_abort_process_with_reason(
                tenant.as_str().to_owned(),
                project.as_str().to_owned(),
                "hosted-admin".to_owned(),
                process.as_str().to_owned(),
                None,
                "hosted account suspended by administrator",
            )?;
            aborted_processes = aborted_processes.saturating_add(1);
        }
        Ok(HostedAccountMutationResult {
            status: self.hosted_tenant_admin_status(&tenant),
            audit,
            revoked_sessions: u64::try_from(revoked_sessions).unwrap_or(u64::MAX),
            aborted_processes,
        })
    }

    pub fn resume_hosted_account(
        &mut self,
        tenant: TenantId,
        operator: UserId,
        occurred_at_epoch_seconds: u64,
    ) -> Result<HostedAccountMutationResult, CoordinatorServiceError> {
        self.coordinator.resume_tenant(&tenant);
        let audit = self.coordinator.record_hosted_admin_audit(
            tenant.clone(),
            "account_resume",
            None,
            None,
            operator,
            occurred_at_epoch_seconds,
        );
        self.persist_durable_state()?;
        Ok(HostedAccountMutationResult {
            status: self.hosted_tenant_admin_status(&tenant),
            audit,
            revoked_sessions: 0,
            aborted_processes: 0,
        })
    }

    pub(super) fn handle_admin_status(
        &mut self,
        tenant: String,
        actor_user: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.verify_admin_request(
            "admin_status",
            &tenant,
            &actor_user,
            &tenant,
            &admin_proof,
            &admin_nonce,
            issued_at_epoch_seconds,
        )?;
        let tenant = TenantId::new(tenant);
        let actor = UserId::new(actor_user);
        Ok(CoordinatorResponse::AdminStatus {
            suspended: self.coordinator.tenant_suspended(&tenant),
            tenant,
            actor,
            safe_default: "read_only".to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_suspend_tenant(
        &mut self,
        tenant: String,
        actor_user: String,
        target_tenant: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.verify_admin_request(
            "suspend_tenant",
            &tenant,
            &actor_user,
            &target_tenant,
            &admin_proof,
            &admin_nonce,
            issued_at_epoch_seconds,
        )?;
        let actor_tenant = TenantId::new(tenant);
        let actor = UserId::new(actor_user);
        let target_tenant = TenantId::new(target_tenant);
        self.coordinator.upsert_tenant(actor_tenant.clone());
        self.coordinator.upsert_user(
            actor_tenant,
            actor.clone(),
            CredentialKind::CliDeviceSession,
        );
        let policy = self
            .coordinator
            .suspend_tenant(target_tenant.clone(), actor.clone());
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::TenantSuspended {
            tenant: target_tenant,
            actor,
            policy,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_admin_request(
        &mut self,
        operation: &str,
        tenant: &str,
        actor_user: &str,
        target_tenant: &str,
        admin_proof: &Digest,
        admin_nonce: &str,
        issued_at_epoch_seconds: u64,
    ) -> Result<(), CoordinatorServiceError> {
        let expected = self.admin_token_digest.as_ref().ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "self-hosted admin credential is not configured".to_owned(),
            )
        })?;
        if admin_nonce.trim().is_empty() || admin_nonce.len() > 256 {
            return Err(CoordinatorError::Unauthorized(
                "admin request nonce is missing or invalid".to_owned(),
            )
            .into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        if now.abs_diff(issued_at_epoch_seconds) > ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS {
            return Err(CoordinatorError::Unauthorized(
                "admin request timestamp is outside the allowed 300-second window".to_owned(),
            )
            .into());
        }
        let expected_proof = admin_request_proof_from_token_digest(
            expected,
            operation,
            tenant,
            actor_user,
            target_tenant,
            admin_nonce,
            issued_at_epoch_seconds,
        );
        if admin_proof != &expected_proof {
            return Err(CoordinatorError::Unauthorized(
                "admin request proof is invalid".to_owned(),
            )
            .into());
        }
        match self.replay_registry.admit_admin(
            admin_nonce.to_owned(),
            issued_at_epoch_seconds,
            now,
            ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS,
            super::MAX_REPLAY_NONCES_PER_AUTHORITY,
        ) {
            Ok(()) => {}
            Err(super::ReplayAdmissionError::Duplicate) => {
                return Err(CoordinatorError::Unauthorized(
                    "admin request nonce was already used".to_owned(),
                )
                .into());
            }
            Err(super::ReplayAdmissionError::Capacity) => {
                return Err(CoordinatorError::Unauthorized(
                    "admin request replay window is full; retry after the bounded signature window advances"
                        .to_owned(),
                )
                .into());
            }
        }
        Ok(())
    }
}
