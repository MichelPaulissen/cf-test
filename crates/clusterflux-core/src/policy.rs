use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Action, AuthContext, Capability, Scope};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyReason {
    Allowed,
    MissingCapability(Capability),
    HostedNativeComputeDenied,
    HostedContainerDenied,
    QuotaExceeded(String),
    Unauthorized(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: PolicyReason,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: PolicyReason::Allowed,
        }
    }

    pub fn deny(reason: PolicyReason) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub action: Action,
    pub required_capabilities: BTreeSet<Capability>,
    pub hosted_control_plane: bool,
}

pub trait CapabilityPolicy {
    fn decide(&self, context: &AuthContext, scope: &Scope, request: &ResourceRequest) -> Decision;
}

pub trait ServicePolicy: CapabilityPolicy + Send + Sync {}

impl<T> ServicePolicy for T where T: CapabilityPolicy + Send + Sync {}

#[derive(Clone, Debug, Default)]
pub struct LocalTrustedPolicy;

impl CapabilityPolicy for LocalTrustedPolicy {
    fn decide(&self, context: &AuthContext, scope: &Scope, request: &ResourceRequest) -> Decision {
        let authz = crate::auth::same_tenant_project(context, scope);
        if !authz.allowed {
            return Decision::deny(PolicyReason::Unauthorized(authz.reason));
        }
        if request.hosted_control_plane && request.action == Action::RunNativeCommand {
            return Decision::deny(PolicyReason::HostedNativeComputeDenied);
        }
        if request.hosted_control_plane && request.action == Action::RunContainer {
            return Decision::deny(PolicyReason::HostedContainerDenied);
        }
        Decision::allow()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Actor, ProjectId, TenantId, UserId};

    use super::*;

    #[test]
    fn public_policy_interface_denies_hosted_native_compute() {
        let policy = LocalTrustedPolicy;
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let scope = Scope {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: None,
            task: None,
            node: None,
            artifact: None,
        };
        let request = ResourceRequest {
            action: Action::RunNativeCommand,
            required_capabilities: BTreeSet::new(),
            hosted_control_plane: true,
        };

        let decision = policy.decide(&context, &scope, &request);

        assert!(!decision.allowed);
        assert_eq!(decision.reason, PolicyReason::HostedNativeComputeDenied);
    }

    #[test]
    fn local_trusted_policy_allows_owner_controlled_native_capability_request() {
        let policy = LocalTrustedPolicy;
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("owner")),
        };
        let scope = Scope {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: None,
            task: None,
            node: None,
            artifact: None,
        };
        let request = ResourceRequest {
            action: Action::RunNativeCommand,
            required_capabilities: BTreeSet::from([Capability::Command]),
            hosted_control_plane: false,
        };

        let decision = policy.decide(&context, &scope, &request);

        assert!(decision.allowed);
        assert_eq!(decision.reason, PolicyReason::Allowed);
    }
}
