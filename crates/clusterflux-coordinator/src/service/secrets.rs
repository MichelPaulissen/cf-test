use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{Capability, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId};
use zeroize::Zeroizing;

use crate::{EncryptedProjectSecretRecord, SecretAuditRecord};

use super::{
    AuthenticatedCoordinatorRequest, CoordinatorResponse, CoordinatorService,
    CoordinatorServiceError,
};

const MAX_PROJECT_SECRETS: usize = 32;
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_SECRET_AUDIT_RECORDS: usize = 1024;
const MAX_TASK_SECRET_GRANTS_PER_MINUTE: usize = 16;

#[derive(Clone)]
pub(super) struct SecretCipher {
    cipher: Aes256Gcm,
    key_version: u32,
}

impl SecretCipher {
    #[cfg(test)]
    fn from_test_key(key: [u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key).expect("32-byte test key is valid"),
            key_version: 1,
        }
    }

    pub(super) fn from_environment(
        required: bool,
    ) -> Result<Option<Self>, CoordinatorServiceError> {
        let Some(encoded) = std::env::var("CLUSTERFLUX_SECRET_ROOT_KEY").ok() else {
            if required {
                return Err(CoordinatorServiceError::Protocol(
                    "CLUSTERFLUX_SECRET_ROOT_KEY is required for this deployment".to_owned(),
                ));
            }
            return Ok(None);
        };
        let encoded = Zeroizing::new(encoded);
        let bytes = Zeroizing::new(BASE64_STANDARD.decode(encoded.trim()).map_err(|_| {
            CoordinatorServiceError::Protocol(
                "CLUSTERFLUX_SECRET_ROOT_KEY must be base64-encoded".to_owned(),
            )
        })?);
        if bytes.len() != 32 {
            return Err(CoordinatorServiceError::Protocol(
                "CLUSTERFLUX_SECRET_ROOT_KEY must decode to exactly 32 bytes".to_owned(),
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(&bytes).map_err(|_| {
            CoordinatorServiceError::Protocol("secret root key is invalid".to_owned())
        })?;
        let key_version = std::env::var("CLUSTERFLUX_SECRET_KEY_VERSION")
            .ok()
            .map(|value| value.parse::<u32>())
            .transpose()
            .map_err(|_| {
                CoordinatorServiceError::Protocol(
                    "CLUSTERFLUX_SECRET_KEY_VERSION must be an unsigned integer".to_owned(),
                )
            })?
            .unwrap_or(1);
        if key_version == 0 {
            return Err(CoordinatorServiceError::Protocol(
                "secret key version must be non-zero".to_owned(),
            ));
        }
        Ok(Some(Self {
            cipher,
            key_version,
        }))
    }

    fn encrypt(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        name: &str,
        plaintext: &[u8],
    ) -> Result<(String, String), CoordinatorServiceError> {
        let mut nonce_bytes = [0_u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "failed to generate project-secret nonce: {error}"
            ))
        })?;
        let aad = secret_aad(tenant, project, name, self.key_version);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                CoordinatorServiceError::Protocol("project-secret encryption failed".to_owned())
            })?;
        Ok((
            BASE64_STANDARD.encode(ciphertext),
            BASE64_STANDARD.encode(nonce_bytes),
        ))
    }

    fn decrypt(
        &self,
        record: &EncryptedProjectSecretRecord,
    ) -> Result<Vec<u8>, CoordinatorServiceError> {
        if record.key_version != self.key_version {
            return Err(CoordinatorServiceError::Protocol(format!(
                "project secret uses unavailable key version {}",
                record.key_version
            )));
        }
        let ciphertext = BASE64_STANDARD
            .decode(&record.ciphertext_base64)
            .map_err(|_| {
                CoordinatorServiceError::Protocol(
                    "project-secret ciphertext is malformed".to_owned(),
                )
            })?;
        let nonce = BASE64_STANDARD.decode(&record.nonce_base64).map_err(|_| {
            CoordinatorServiceError::Protocol("project-secret nonce is malformed".to_owned())
        })?;
        if nonce.len() != 12 {
            return Err(CoordinatorServiceError::Protocol(
                "project-secret nonce has the wrong size".to_owned(),
            ));
        }
        let aad = secret_aad(
            &record.tenant,
            &record.project,
            &record.name,
            record.key_version,
        );
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                CoordinatorServiceError::Protocol("project-secret authentication failed".to_owned())
            })
    }
}

impl CoordinatorService {
    #[cfg(test)]
    pub(super) fn enable_project_secrets_for_tests(&mut self, key: [u8; 32]) {
        self.secret_cipher = Some(SecretCipher::from_test_key(key));
    }

    pub(super) fn handle_authenticated_project_secret(
        &mut self,
        context: &clusterflux_core::AuthContext,
        actor: clusterflux_core::UserId,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        match request {
            AuthenticatedCoordinatorRequest::SetProjectSecret { name, value_base64 } => {
                let value_base64 = Zeroizing::new(value_base64);
                let value =
                    Zeroizing::new(BASE64_STANDARD.decode(value_base64.as_bytes()).map_err(
                        |_| {
                            CoordinatorServiceError::Protocol(
                                "project-secret value is not valid base64".to_owned(),
                            )
                        },
                    )?);
                if value.len() < 16 || value.len() > MAX_SECRET_BYTES {
                    return Err(CoordinatorServiceError::Protocol(format!(
                        "project-secret value must contain 16 through {MAX_SECRET_BYTES} bytes"
                    )));
                }
                validate_secret_name(&name)?;
                let key = (
                    context.tenant.clone(),
                    context.project.clone(),
                    name.clone(),
                );
                let exists = self
                    .coordinator
                    .durable_state()
                    .encrypted_project_secrets
                    .contains_key(&key);
                let count = self
                    .coordinator
                    .durable_state()
                    .encrypted_project_secrets
                    .keys()
                    .filter(|(tenant, project, _)| {
                        tenant == &context.tenant && project == &context.project
                    })
                    .count();
                if !exists && count >= MAX_PROJECT_SECRETS {
                    return Err(CoordinatorServiceError::Protocol(format!(
                        "project secret limit of {MAX_PROJECT_SECRETS} reached"
                    )));
                }
                let cipher = self.secret_cipher.as_ref().ok_or_else(|| {
                    CoordinatorServiceError::Protocol(
                        "project secrets are disabled because no root encryption key is configured"
                            .to_owned(),
                    )
                })?;
                let (ciphertext_base64, nonce_base64) =
                    cipher.encrypt(&context.tenant, &context.project, &name, value.as_slice())?;
                let now = self.current_epoch_seconds()?;
                let created_at = self
                    .coordinator
                    .durable_state()
                    .encrypted_project_secrets
                    .get(&key)
                    .map(|record| record.created_at)
                    .unwrap_or(now);
                let record = EncryptedProjectSecretRecord {
                    tenant: context.tenant.clone(),
                    project: context.project.clone(),
                    name: name.clone(),
                    ciphertext_base64,
                    nonce_base64,
                    key_version: cipher.key_version,
                    allowed_entrypoint: "main".to_owned(),
                    allowed_task_definition: "publish".to_owned(),
                    allowed_trusted_refs: vec![
                        "refs/heads/main".to_owned(),
                        "refs/tags/v*".to_owned(),
                    ],
                    created_at,
                    updated_at: now,
                    revoked_at: None,
                };
                self.coordinator
                    .durable_state_mut()
                    .encrypted_project_secrets
                    .insert(key, record.clone());
                self.append_secret_audit(
                    &context.tenant,
                    &context.project,
                    &name,
                    None,
                    None,
                    None,
                    if exists { "updated" } else { "created" },
                    now,
                );
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::ProjectSecretSet {
                    secret: secret_metadata(&record),
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::ListProjectSecrets => {
                let secrets = self
                    .coordinator
                    .durable_state()
                    .encrypted_project_secrets
                    .values()
                    .filter(|record| {
                        record.tenant == context.tenant && record.project == context.project
                    })
                    .map(secret_metadata)
                    .collect();
                Ok(CoordinatorResponse::ProjectSecrets { secrets, actor })
            }
            AuthenticatedCoordinatorRequest::RevokeProjectSecret { name } => {
                validate_secret_name(&name)?;
                let now = self.current_epoch_seconds()?;
                let key = (
                    context.tenant.clone(),
                    context.project.clone(),
                    name.clone(),
                );
                let record = self
                    .coordinator
                    .durable_state_mut()
                    .encrypted_project_secrets
                    .get_mut(&key)
                    .ok_or_else(|| {
                        CoordinatorServiceError::Protocol(
                            "project secret does not exist in this project".to_owned(),
                        )
                    })?;
                record.revoked_at.get_or_insert(now);
                let metadata = secret_metadata(record);
                self.append_secret_audit(
                    &context.tenant,
                    &context.project,
                    &name,
                    None,
                    None,
                    None,
                    "revoked",
                    now,
                );
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::ProjectSecretRevoked {
                    secret: metadata,
                    actor,
                })
            }
            _ => Err(CoordinatorServiceError::Protocol(
                "request is not a project-secret operation".to_owned(),
            )),
        }
    }

    pub fn configure_trusted_secret_node(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        node: NodeId,
    ) -> Result<(), CoordinatorServiceError> {
        self.coordinator
            .node_identity(&tenant, &project, &node)
            .ok_or(crate::CoordinatorError::UnknownNode)?;
        self.coordinator
            .durable_state_mut()
            .trusted_secret_nodes
            .insert((tenant, project), node);
        self.persist_durable_state()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_poll_task_secret_grant(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        process: String,
        task: String,
        secret_name: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        let process = ProcessId::new(process);
        let task = TaskInstanceId::new(task);
        let trusted_node = self
            .coordinator
            .durable_state()
            .trusted_secret_nodes
            .get(&(tenant.clone(), project.clone()));
        if trusted_node != Some(&node) {
            return Err(crate::CoordinatorError::Unauthorized(
                "node is not operator-configured for project-secret materialization".to_owned(),
            )
            .into());
        }
        let descriptor = self
            .node_registry
            .descriptor(&crate::NodeScopeKey::from_refs(&tenant, &project, &node))
            .ok_or_else(|| {
                crate::CoordinatorError::Unauthorized(
                    "secret node has no capability report".to_owned(),
                )
            })?;
        if descriptor.capabilities.work_policy == clusterflux_core::NodeWorkPolicy::SystemTasksOnly
        {
            return Err(crate::CoordinatorError::Unauthorized(
                "system-tasks-only nodes cannot receive task secrets".to_owned(),
            )
            .into());
        }
        if !descriptor
            .capabilities
            .capabilities
            .contains(&Capability::Secrets)
        {
            return Err(crate::CoordinatorError::Unauthorized(
                "trusted node does not support secret materialization".to_owned(),
            )
            .into());
        }
        let task_spec = self
            .task_registry
            .active_task_spec(&tenant, &project, &process, &node, &task)
            .cloned()
            .ok_or_else(|| {
                crate::CoordinatorError::Unauthorized(
                    "secret grant requires the task's active assignment".to_owned(),
                )
            })?;
        if !task_declares_secret_materialization_authority(&task_spec, &secret_name) {
            return Err(crate::CoordinatorError::Unauthorized(
                "task did not explicitly request the secret and declare command, network, and secrets capabilities"
                    .to_owned(),
            )
            .into());
        }
        let run = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .find(|record| {
                record.run.tenant == tenant
                    && record.run.project == project
                    && record.run.process_id.as_ref() == Some(&process)
            })
            .ok_or_else(|| {
                crate::CoordinatorError::Unauthorized(
                    "secret grant process is not a forge-triggered run".to_owned(),
                )
            })?;
        if !run.run.trusted {
            return Err(crate::CoordinatorError::Unauthorized(
                "untrusted trigger cannot receive project secrets".to_owned(),
            )
            .into());
        }
        let record = self
            .coordinator
            .durable_state()
            .encrypted_project_secrets
            .get(&(tenant.clone(), project.clone(), secret_name.clone()))
            .filter(|record| record.revoked_at.is_none())
            .cloned()
            .ok_or_else(|| {
                crate::CoordinatorError::Unauthorized(
                    "project secret is unavailable for this task".to_owned(),
                )
            })?;
        if record.allowed_entrypoint != "main"
            || !secret_ref_is_authorized(&record.allowed_trusted_refs, &run.run.git_ref)
        {
            return Err(crate::CoordinatorError::Unauthorized(
                "project secret policy does not authorize this task".to_owned(),
            )
            .into());
        }
        let now = self.current_epoch_seconds()?;
        let recent_grants = self
            .coordinator
            .durable_state()
            .secret_audit
            .iter()
            .rev()
            .take_while(|audit| now.saturating_sub(audit.occurred_at) < 60)
            .filter(|audit| {
                audit.tenant == tenant
                    && audit.project == project
                    && audit.name == secret_name
                    && audit.process.as_ref() == Some(&process)
                    && audit.task.as_ref() == Some(&task)
                    && audit.event == "granted"
            })
            .count();
        if recent_grants >= MAX_TASK_SECRET_GRANTS_PER_MINUTE {
            return Err(CoordinatorServiceError::Protocol(format!(
                "task secret grant limit of {MAX_TASK_SECRET_GRANTS_PER_MINUTE} per minute reached"
            )));
        }
        let cipher = self.secret_cipher.as_ref().ok_or_else(|| {
            CoordinatorServiceError::Protocol(
                "project-secret root encryption key is unavailable".to_owned(),
            )
        })?;
        let plaintext = Zeroizing::new(cipher.decrypt(&record)?);
        let grant = clusterflux_protocol::TaskSecretGrant {
            process: process.clone(),
            task: task.clone(),
            secret_name: secret_name.clone(),
            value_base64: clusterflux_protocol::RedactedSecret::new(
                BASE64_STANDARD.encode(plaintext.as_slice()),
            ),
            expires_at_epoch_seconds: now.saturating_add(60),
        };
        self.append_secret_audit(
            &tenant,
            &project,
            &secret_name,
            Some(process),
            Some(task),
            Some(node),
            "granted",
            now,
        );
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::TaskSecretGrant { grant: Some(grant) })
    }

    #[allow(clippy::too_many_arguments)]
    fn append_secret_audit(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        name: &str,
        process: Option<ProcessId>,
        task: Option<TaskInstanceId>,
        node: Option<NodeId>,
        event: &str,
        occurred_at: u64,
    ) {
        let audit = &mut self.coordinator.durable_state_mut().secret_audit;
        let sequence = audit.last().map(|record| record.sequence + 1).unwrap_or(1);
        if audit.len() >= MAX_SECRET_AUDIT_RECORDS {
            audit.remove(0);
        }
        audit.push(SecretAuditRecord {
            sequence,
            tenant: tenant.clone(),
            project: project.clone(),
            name: name.to_owned(),
            process,
            task,
            node,
            event: event.to_owned(),
            occurred_at,
        });
    }
}

pub(super) fn task_declares_secret_materialization_authority(
    task_spec: &clusterflux_core::TaskSpec,
    secret_name: &str,
) -> bool {
    task_spec
        .requested_secrets
        .iter()
        .any(|name| name == secret_name)
        && [
            Capability::Command,
            Capability::Network,
            Capability::Secrets,
        ]
        .iter()
        .all(|capability| task_spec.required_capabilities.contains(capability))
}

pub(super) fn secret_ref_is_authorized(allowed_refs: &[String], git_ref: &str) -> bool {
    if allowed_refs.iter().any(|allowed| allowed == git_ref) {
        return true;
    }
    is_stable_release_ref(git_ref)
        && allowed_refs
            .iter()
            .any(|allowed| allowed == "refs/tags/v*" || is_stable_release_ref(allowed))
}

fn is_stable_release_ref(git_ref: &str) -> bool {
    let Some(version) = git_ref.strip_prefix("refs/tags/v") else {
        return false;
    };
    let mut parts = version.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    valid && parts.next().is_none()
}

fn validate_secret_name(name: &str) -> Result<(), CoordinatorServiceError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CoordinatorServiceError::Protocol(
            "project-secret name is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn secret_metadata(
    record: &EncryptedProjectSecretRecord,
) -> clusterflux_protocol::ProjectSecretMetadata {
    clusterflux_protocol::ProjectSecretMetadata {
        name: record.name.clone(),
        key_version: record.key_version,
        allowed_entrypoint: record.allowed_entrypoint.clone(),
        allowed_task_definition: record.allowed_task_definition.clone(),
        allowed_trusted_refs: record.allowed_trusted_refs.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        revoked_at: record.revoked_at,
    }
}

fn secret_aad(tenant: &TenantId, project: &ProjectId, name: &str, key_version: u32) -> String {
    format!(
        "clusterflux-project-secret:v1:{}:{}:{}:{key_version}",
        tenant.as_str(),
        project.as_str(),
        name
    )
}
