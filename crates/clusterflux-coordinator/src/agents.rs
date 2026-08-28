use clusterflux_core::{
    verify_agent_workflow_signature, Actor, AgentId, AgentSignedRequest, AgentWorkflowScope,
    AuthContext, CredentialKind, Digest, ProjectId, TenantId, UserId,
};

use crate::{
    AgentPublicKeyRecord, Coordinator, CoordinatorError, CredentialRecord, ProjectPermissionRecord,
};

impl Coordinator {
    pub fn grant_project_debug(&mut self, tenant: TenantId, project: ProjectId, user: UserId) {
        self.durable.project_permissions.insert(
            (tenant.clone(), project.clone(), user.clone()),
            ProjectPermissionRecord {
                tenant,
                project,
                user,
                can_debug: true,
            },
        );
    }

    pub fn register_agent_public_key(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        user: UserId,
        agent: AgentId,
        public_key: impl Into<String>,
    ) -> AgentPublicKeyRecord {
        let key = (tenant.clone(), project.clone(), agent.clone());
        let version = self
            .durable
            .agent_public_keys
            .get(&key)
            .map_or(1, |record| record.version.saturating_add(1));
        let public_key = public_key.into();
        let public_key_fingerprint = Digest::sha256(&public_key);
        let record = AgentPublicKeyRecord {
            tenant: tenant.clone(),
            project: project.clone(),
            user: user.clone(),
            agent: agent.clone(),
            public_key,
            public_key_fingerprint: public_key_fingerprint.clone(),
            version,
            revoked: false,
            scopes: vec!["project:read".to_owned(), "project:run".to_owned()],
            human_account_creation_privilege: false,
            browser_interaction_required_each_run: false,
        };
        self.durable.agent_public_keys.insert(key, record.clone());
        let subject = format!("agent:{tenant}:{project}:{agent}");
        self.durable.credentials.insert(
            subject.clone(),
            CredentialRecord {
                subject,
                tenant,
                project: Some(project),
                kind: CredentialKind::PublicKey,
                public_key_fingerprint: Some(public_key_fingerprint),
            },
        );
        record
    }

    pub fn list_agent_public_keys(&self, context: &AuthContext) -> Vec<AgentPublicKeyRecord> {
        self.durable
            .agent_public_keys
            .values()
            .filter(|record| record.tenant == context.tenant && record.project == context.project)
            .filter(|record| match &context.actor {
                Actor::User(user) => &record.user == user,
                Actor::Agent(agent) => &record.agent == agent,
                Actor::Node(_) | Actor::Task(_) => false,
            })
            .cloned()
            .collect()
    }

    pub fn revoke_agent_public_key(
        &mut self,
        context: &AuthContext,
        agent: &AgentId,
    ) -> Result<AgentPublicKeyRecord, CoordinatorError> {
        let key = (
            context.tenant.clone(),
            context.project.clone(),
            agent.clone(),
        );
        let record = self
            .durable
            .agent_public_keys
            .get_mut(&key)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "agent public key is not registered for this project".to_owned(),
                )
            })?;
        match &context.actor {
            Actor::User(user) if &record.user == user => {}
            Actor::User(_) => {
                return Err(CoordinatorError::Unauthorized(
                    "agent public key is outside the signed-in user scope".to_owned(),
                ));
            }
            _ => {
                return Err(CoordinatorError::Unauthorized(
                    "agent public-key revocation requires a user identity".to_owned(),
                ));
            }
        }
        record.revoked = true;
        let subject = format!(
            "agent:{}:{}:{}",
            context.tenant, context.project, record.agent
        );
        self.durable.credentials.remove(&subject);
        Ok(record.clone())
    }

    pub fn authorize_agent_project_run(
        &self,
        scope: AgentWorkflowScope<'_>,
        public_key_fingerprint: Option<&Digest>,
        payload_digest: &Digest,
        signature: &AgentSignedRequest,
        now_epoch_seconds: u64,
    ) -> Result<AgentPublicKeyRecord, CoordinatorError> {
        let record = self
            .durable
            .agent_public_keys
            .get(&(
                scope.tenant.clone(),
                scope.project.clone(),
                scope.agent.clone(),
            ))
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "agent public key is not registered for this tenant/project".to_owned(),
                )
            })?;
        if record.revoked {
            return Err(CoordinatorError::Unauthorized(
                "agent public key has been revoked".to_owned(),
            ));
        }
        if let Some(public_key_fingerprint) = public_key_fingerprint {
            if &record.public_key_fingerprint != public_key_fingerprint {
                return Err(CoordinatorError::Unauthorized(
                    "agent public key fingerprint does not match the registered key".to_owned(),
                ));
            }
        }
        let max_signature_skew_seconds = 300;
        if signature
            .issued_at_epoch_seconds
            .abs_diff(now_epoch_seconds)
            > max_signature_skew_seconds
        {
            return Err(CoordinatorError::Unauthorized(
                "agent signed request is expired or outside the allowed clock skew".to_owned(),
            ));
        }
        if !record.scopes.iter().any(|scope| scope == "project:run") {
            return Err(CoordinatorError::Unauthorized(
                "agent public key is not scoped for project runs".to_owned(),
            ));
        }
        verify_agent_workflow_signature(&record.public_key, scope, payload_digest, signature)
            .map_err(CoordinatorError::Unauthorized)?;
        Ok(record.clone())
    }
}
