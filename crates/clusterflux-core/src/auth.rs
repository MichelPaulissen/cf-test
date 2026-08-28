#[cfg(not(target_arch = "wasm32"))]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AgentId, ArtifactId, Digest, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId, UserId,
};

pub fn admin_request_proof(
    admin_token: &str,
    operation: &str,
    tenant: &str,
    actor_user: &str,
    target_tenant: &str,
    nonce: &str,
    issued_at_epoch_seconds: u64,
) -> Digest {
    admin_request_proof_from_token_digest(
        &Digest::sha256(admin_token),
        operation,
        tenant,
        actor_user,
        target_tenant,
        nonce,
        issued_at_epoch_seconds,
    )
}

pub fn admin_request_proof_from_token_digest(
    admin_token_digest: &Digest,
    operation: &str,
    tenant: &str,
    actor_user: &str,
    target_tenant: &str,
    nonce: &str,
    issued_at_epoch_seconds: u64,
) -> Digest {
    let issued_at_epoch_seconds = issued_at_epoch_seconds.to_string();
    Digest::from_parts([
        b"clusterflux-admin-request-proof:v1".as_slice(),
        admin_token_digest.as_str().as_bytes(),
        operation.as_bytes(),
        tenant.as_bytes(),
        actor_user.as_bytes(),
        target_tenant.as_bytes(),
        nonce.as_bytes(),
        issued_at_epoch_seconds.as_bytes(),
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    User(UserId),
    Agent(AgentId),
    Node(NodeId),
    Task(TaskInstanceId),
}

impl Actor {
    pub fn kind(&self) -> IdentityKind {
        match self {
            Self::User(_) => IdentityKind::User,
            Self::Agent(_) => IdentityKind::Agent,
            Self::Node(_) => IdentityKind::Node,
            Self::Task(_) => IdentityKind::Task,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityKind {
    User,
    Agent,
    Node,
    Project,
    Task,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    BrowserSession,
    CliDeviceSession,
    PublicKey,
    NodeCredential,
    TaskCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub actor: Actor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    CreateProject,
    AttachNode,
    CreateNodeEnrollmentGrant,
    ExchangeNodeEnrollmentGrant,
    LoginBrowser,
    LoginCli,
    EnrollAgent,
    List,
    Inspect,
    Mutate,
    ClaimTask,
    DebugAttach,
    DebugRead,
    DownloadArtifact,
    PublishArtifact,
    RunNativeCommand,
    RunContainer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserLoginFlow {
    pub authorization_url: String,
    pub callback_path: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyIdentity {
    pub subject: Actor,
    pub public_key: String,
    pub fingerprint: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSignedRequest {
    pub nonce: String,
    pub issued_at_epoch_seconds: u64,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSignedRequest {
    pub nonce: String,
    pub issued_at_epoch_seconds: u64,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_authority: Option<AssignmentAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

/// Exact assignment ownership carried by task-related signed node requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentAuthority {
    pub assignment_id: String,
    pub attempt_id: String,
    pub offer_epoch: u64,
}

/// Assignment ownership and stable identity for a retryable terminal operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAssignmentOperation {
    pub assignment_authority: AssignmentAuthority,
    pub operation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentGrant {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub grant_id: String,
    pub scope: String,
    pub expires_at_epoch_seconds: u64,
    pub consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCredential {
    pub node: NodeId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub public_key_fingerprint: Digest,
    pub scope: String,
    pub capability_policy_digest: Digest,
    pub credential_kind: CredentialKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentError {
    Expired,
    AlreadyConsumed,
    WrongScope,
}

impl EnrollmentGrant {
    pub fn exchange_for_node_identity(
        &mut self,
        node: NodeId,
        public_key: &str,
        requested_scope: &str,
        now_epoch_seconds: u64,
    ) -> Result<NodeCredential, EnrollmentError> {
        if self.consumed {
            return Err(EnrollmentError::AlreadyConsumed);
        }
        if now_epoch_seconds > self.expires_at_epoch_seconds {
            return Err(EnrollmentError::Expired);
        }
        if requested_scope != self.scope {
            return Err(EnrollmentError::WrongScope);
        }
        self.consumed = true;
        let capability_policy_digest =
            node_capability_policy_digest(&self.tenant, &self.project, &self.scope);
        Ok(NodeCredential {
            node,
            tenant: self.tenant.clone(),
            project: self.project.clone(),
            public_key_fingerprint: Digest::sha256(public_key),
            scope: self.scope.clone(),
            capability_policy_digest,
            credential_kind: CredentialKind::NodeCredential,
        })
    }
}

pub fn node_capability_policy_digest(
    tenant: &TenantId,
    project: &ProjectId,
    scope: &str,
) -> Digest {
    Digest::from_parts([
        b"node-capability-policy:v1".as_slice(),
        tenant.as_str().as_bytes(),
        project.as_str().as_bytes(),
        scope.as_bytes(),
    ])
}

pub fn agent_ed25519_public_key_from_private_key(private_key: &str) -> Result<String, String> {
    let private_key = decode_ed25519_key(private_key, 32, "agent private key")?;
    let private_key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| "agent private key must be 32 bytes".to_owned())?;
    let signing_key = SigningKey::from_bytes(&private_key);
    Ok(format!(
        "ed25519:{}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    ))
}

pub fn node_ed25519_public_key_from_private_key(private_key: &str) -> Result<String, String> {
    agent_ed25519_public_key_from_private_key(private_key)
}

pub fn derive_ed25519_private_key_from_seed(seed: &str) -> String {
    let digest = Digest::sha256(seed);
    let hex = digest.as_str().trim_start_matches("sha256:");
    let bytes = hex::decode(hex).expect("sha256 digest hex should decode");
    format!("ed25519:{}", STANDARD.encode(bytes))
}

/// Generates a new Ed25519 private key from the operating system CSPRNG.
///
/// Seed-derived keys remain available for deterministic test fixtures, but
/// must not be used for persisted user, Agent, or Node credentials.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_ed25519_private_key() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| format!("operating system random source failed: {err}"))?;
    Ok(format!("ed25519:{}", STANDARD.encode(bytes)))
}

/// Generates an opaque, URL-safe 256-bit token suitable for one-time grants,
/// session secrets, and nonces. The label is non-secret domain separation.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_opaque_token(label: &str) -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| format!("operating system random source failed: {err}"))?;
    Ok(format!("{label}_{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[derive(Clone, Copy, Debug)]
pub struct AgentWorkflowScope<'a> {
    pub tenant: &'a TenantId,
    pub project: &'a ProjectId,
    pub agent: &'a AgentId,
    pub request_kind: &'a str,
    pub process: &'a ProcessId,
    pub task: Option<&'a TaskInstanceId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentWorkflowRequestScope {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub request_kind: String,
    pub process: ProcessId,
    pub task: Option<TaskInstanceId>,
}

impl AgentWorkflowRequestScope {
    pub fn new(
        tenant: TenantId,
        project: ProjectId,
        request_kind: impl Into<String>,
        process: ProcessId,
        task: Option<TaskInstanceId>,
    ) -> Result<Self, String> {
        let request_kind = request_kind.into();
        match request_kind.as_str() {
            "start_process" if task.is_some() => {
                return Err("start_process agent scope must not contain a task instance".to_owned())
            }
            "launch_task" if task.is_none() => {
                return Err("launch_task agent scope requires a task instance".to_owned())
            }
            "start_process" | "launch_task" => {}
            _ => {
                return Err(format!(
                    "request kind `{request_kind}` is not an agent workflow operation"
                ))
            }
        }
        Ok(Self {
            tenant,
            project,
            request_kind,
            process,
            task,
        })
    }

    pub fn for_agent<'a>(&'a self, agent: &'a AgentId) -> AgentWorkflowScope<'a> {
        AgentWorkflowScope {
            tenant: &self.tenant,
            project: &self.project,
            agent,
            request_kind: &self.request_kind,
            process: &self.process,
            task: self.task.as_ref(),
        }
    }
}

pub fn agent_workflow_request_scope_from_payload(
    payload: &Value,
) -> Result<AgentWorkflowRequestScope, String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "agent workflow request payload must be an object".to_owned())?;
    let request_kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "agent workflow request type is missing".to_owned())?;
    let tenant = object
        .get("tenant")
        .and_then(Value::as_str)
        .ok_or_else(|| "agent workflow tenant is missing".to_owned())?;
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .ok_or_else(|| "agent workflow project is missing".to_owned())?;
    let (process, task) = match request_kind {
        "start_process" => (
            object
                .get("process")
                .and_then(Value::as_str)
                .ok_or_else(|| "start_process agent scope is missing process".to_owned())?,
            None,
        ),
        "launch_task" => {
            let task_spec = object
                .get("task_spec")
                .and_then(Value::as_object)
                .ok_or_else(|| "launch_task agent scope is missing task_spec".to_owned())?;
            let process = task_spec
                .get("process")
                .and_then(Value::as_str)
                .ok_or_else(|| "launch_task agent scope is missing process".to_owned())?;
            let task = task_spec
                .get("task_instance")
                .and_then(Value::as_str)
                .ok_or_else(|| "launch_task agent scope is missing task_instance".to_owned())?;
            (
                process,
                Some(
                    TaskInstanceId::try_new(task)
                        .map_err(|error| format!("malformed launch_task task instance: {error}"))?,
                ),
            )
        }
        _ => {
            return Err(format!(
                "request kind `{request_kind}` is not an agent workflow operation"
            ))
        }
    };
    AgentWorkflowRequestScope::new(
        TenantId::try_new(tenant)
            .map_err(|error| format!("malformed agent workflow tenant: {error}"))?,
        ProjectId::try_new(project)
            .map_err(|error| format!("malformed agent workflow project: {error}"))?,
        request_kind,
        ProcessId::try_new(process)
            .map_err(|error| format!("malformed agent workflow process: {error}"))?,
        task,
    )
}

pub fn sign_agent_workflow_request(
    private_key: &str,
    scope: AgentWorkflowScope<'_>,
    payload_digest: &Digest,
    nonce: String,
    issued_at_epoch_seconds: u64,
) -> Result<AgentSignedRequest, String> {
    let private_key = decode_ed25519_key(private_key, 32, "agent private key")?;
    let private_key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| "agent private key must be 32 bytes".to_owned())?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let message =
        agent_workflow_signature_message(scope, payload_digest, &nonce, issued_at_epoch_seconds);
    let signature: Signature = signing_key.sign(&message);
    Ok(AgentSignedRequest {
        nonce,
        issued_at_epoch_seconds,
        signature: format!("ed25519:{}", STANDARD.encode(signature.to_bytes())),
    })
}

pub fn verify_agent_workflow_signature(
    public_key: &str,
    scope: AgentWorkflowScope<'_>,
    payload_digest: &Digest,
    signed_request: &AgentSignedRequest,
) -> Result<(), String> {
    let public_key = decode_ed25519_key(public_key, 32, "agent public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "agent public key must be 32 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "agent public key is not a valid Ed25519 verifying key".to_owned())?;
    let signature = decode_ed25519_key(&signed_request.signature, 64, "agent signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "agent signature must be 64 bytes".to_owned())?;
    let signature = Signature::from_bytes(&signature);
    let message = agent_workflow_signature_message(
        scope,
        payload_digest,
        &signed_request.nonce,
        signed_request.issued_at_epoch_seconds,
    );
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| "agent signature does not verify against the registered public key".to_owned())
}

pub fn sign_node_request(
    private_key: &str,
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: String,
    issued_at_epoch_seconds: u64,
) -> Result<NodeSignedRequest, String> {
    sign_node_request_with_assignment(
        private_key,
        node,
        request_kind,
        payload_digest,
        nonce,
        issued_at_epoch_seconds,
        NodeRequestAuthority::default(),
    )
}

pub fn sign_node_assignment_request(
    private_key: &str,
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: String,
    issued_at_epoch_seconds: u64,
    assignment_authority: AssignmentAuthority,
) -> Result<NodeSignedRequest, String> {
    sign_node_request_with_assignment(
        private_key,
        node,
        request_kind,
        payload_digest,
        nonce,
        issued_at_epoch_seconds,
        NodeRequestAuthority {
            assignment_authority: Some(assignment_authority),
            operation_id: None,
        },
    )
}

pub fn sign_node_assignment_operation_request(
    private_key: &str,
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: String,
    issued_at_epoch_seconds: u64,
    operation: NodeAssignmentOperation,
) -> Result<NodeSignedRequest, String> {
    sign_node_request_with_assignment(
        private_key,
        node,
        request_kind,
        payload_digest,
        nonce,
        issued_at_epoch_seconds,
        NodeRequestAuthority {
            assignment_authority: Some(operation.assignment_authority),
            operation_id: Some(operation.operation_id),
        },
    )
}

#[derive(Default)]
struct NodeRequestAuthority {
    assignment_authority: Option<AssignmentAuthority>,
    operation_id: Option<String>,
}

fn sign_node_request_with_assignment(
    private_key: &str,
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: String,
    issued_at_epoch_seconds: u64,
    authority: NodeRequestAuthority,
) -> Result<NodeSignedRequest, String> {
    let private_key = decode_ed25519_key(private_key, 32, "node private key")?;
    let private_key: [u8; 32] = private_key
        .try_into()
        .map_err(|_| "node private key must be 32 bytes".to_owned())?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let message = node_request_signature_message(
        node,
        request_kind,
        payload_digest,
        &nonce,
        issued_at_epoch_seconds,
        authority.assignment_authority.as_ref(),
        authority.operation_id.as_deref(),
    );
    let signature: Signature = signing_key.sign(&message);
    Ok(NodeSignedRequest {
        nonce,
        issued_at_epoch_seconds,
        signature: format!("ed25519:{}", STANDARD.encode(signature.to_bytes())),
        assignment_authority: authority.assignment_authority,
        operation_id: authority.operation_id,
    })
}

pub fn verify_node_request_signature(
    public_key: &str,
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    signed_request: &NodeSignedRequest,
) -> Result<(), String> {
    let public_key = decode_ed25519_key(public_key, 32, "node public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "node public key must be 32 bytes".to_owned())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| "node public key is not a valid Ed25519 verifying key".to_owned())?;
    let signature = decode_ed25519_key(&signed_request.signature, 64, "node signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "node signature must be 64 bytes".to_owned())?;
    let signature = Signature::from_bytes(&signature);
    let message = node_request_signature_message(
        node,
        request_kind,
        payload_digest,
        &signed_request.nonce,
        signed_request.issued_at_epoch_seconds,
        signed_request.assignment_authority.as_ref(),
        signed_request.operation_id.as_deref(),
    );
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| "node signature does not verify against the enrolled public key".to_owned())
}

fn decode_ed25519_key(value: &str, expected_len: usize, kind: &str) -> Result<Vec<u8>, String> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or_else(|| format!("{kind} must use ed25519:<base64> encoding"))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| format!("{kind} is not valid base64"))?;
    if bytes.len() != expected_len {
        return Err(format!("{kind} must be {expected_len} bytes"));
    }
    Ok(bytes)
}

fn agent_workflow_signature_message(
    scope: AgentWorkflowScope<'_>,
    payload_digest: &Digest,
    nonce: &str,
    issued_at_epoch_seconds: u64,
) -> Vec<u8> {
    let issued_at = issued_at_epoch_seconds.to_string();
    let task = scope.task.map(TaskInstanceId::as_str).unwrap_or("");
    let parts = [
        "clusterflux-agent-workflow-signature:v2",
        scope.tenant.as_str(),
        scope.project.as_str(),
        scope.agent.as_str(),
        scope.request_kind,
        scope.process.as_str(),
        task,
        payload_digest.as_str(),
        nonce,
        &issued_at,
    ];
    let mut message = Vec::new();
    for part in parts {
        message.extend_from_slice(part.len().to_string().as_bytes());
        message.push(b':');
        message.extend_from_slice(part.as_bytes());
        message.push(b'\n');
    }
    message
}

fn node_request_signature_message(
    node: &NodeId,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: &str,
    issued_at_epoch_seconds: u64,
    assignment_authority: Option<&AssignmentAuthority>,
    operation_id: Option<&str>,
) -> Vec<u8> {
    let issued_at = issued_at_epoch_seconds.to_string();
    let offer_epoch = assignment_authority.map(|authority| authority.offer_epoch.to_string());
    let mut parts = vec![
        if operation_id.is_some() {
            "clusterflux-node-request-signature:v4"
        } else if assignment_authority.is_some() {
            "clusterflux-node-request-signature:v3"
        } else {
            "clusterflux-node-request-signature:v2"
        },
        node.as_str(),
        request_kind,
        payload_digest.as_str(),
        nonce,
        &issued_at,
    ];
    if let Some(authority) = assignment_authority {
        parts.extend([
            authority.assignment_id.as_str(),
            authority.attempt_id.as_str(),
            offer_epoch
                .as_deref()
                .expect("assignment offer epoch was formatted"),
        ]);
    }
    if let Some(operation_id) = operation_id {
        parts.push(operation_id);
    }
    let mut message = Vec::new();
    for part in parts {
        message.extend_from_slice(part.len().to_string().as_bytes());
        message.push(b':');
        message.extend_from_slice(part.as_bytes());
        message.push(b'\n');
    }
    message
}

/// Computes the stable digest covered by node and agent request signatures.
///
/// The proof field itself is excluded, and explicit JSON nulls are normalized
/// with omitted optional fields because the wire protocol deserializes both to
/// the same request. Every semantically meaningful key and value remains bound
/// by the signature.
pub fn signed_request_payload_digest(value: &Value) -> Digest {
    fn canonicalize(value: &Value, top_level: bool) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
                    .iter()
                    .filter(|(key, value)| {
                        !value.is_null()
                            && (!top_level
                                || !matches!(key.as_str(), "agent_signature" | "node_signature"))
                    })
                    .map(|(key, value)| (key.clone(), canonicalize(value, false)))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| canonicalize(value, false))
                    .collect(),
            ),
            value => value.clone(),
        }
    }

    let canonical = canonicalize(value, true);
    let bytes = serde_json::to_vec(&canonical)
        .expect("canonical JSON request values are always serializable");
    Digest::sha256(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: Option<ProcessId>,
    pub task: Option<TaskInstanceId>,
    pub node: Option<NodeId>,
    pub artifact: Option<ArtifactId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    pub allowed: bool,
    pub reason: String,
}

impl Authorization {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
        }
    }
}

pub fn same_tenant_project(context: &AuthContext, scope: &Scope) -> Authorization {
    if context.tenant != scope.tenant {
        return Authorization::deny("tenant mismatch");
    }
    if context.project != scope.project {
        return Authorization::deny("project mismatch");
    }
    Authorization::allow("same tenant and project")
}

pub fn task_credentials_do_not_contain_user_session(
    task: &Actor,
    credentials: &[CredentialKind],
) -> Authorization {
    if !matches!(task, Actor::Task(_)) {
        return Authorization::deny("credential check requires task actor");
    }
    if credentials.iter().any(|credential| {
        matches!(
            credential,
            CredentialKind::BrowserSession | CredentialKind::CliDeviceSession
        )
    }) {
        return Authorization::deny(
            "user OAuth/session tokens must not be passed to nodes as task credentials",
        );
    }
    Authorization::allow("task credentials are scoped runtime credentials")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_project_scope_denies_cross_tenant_access() {
        let context = AuthContext {
            tenant: TenantId::from("tenant-a"),
            project: ProjectId::from("project-a"),
            actor: Actor::User(UserId::from("user-a")),
        };
        let scope = Scope {
            tenant: TenantId::from("tenant-b"),
            project: ProjectId::from("project-a"),
            process: None,
            task: None,
            node: None,
            artifact: None,
        };

        assert!(!same_tenant_project(&context, &scope).allowed);
    }

    #[test]
    fn node_enrollment_exchanges_short_lived_grant_once() {
        let mut grant = EnrollmentGrant {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            grant_id: "grant".to_owned(),
            scope: "node:attach".to_owned(),
            expires_at_epoch_seconds: 100,
            consumed: false,
        };

        let credential = grant
            .exchange_for_node_identity(NodeId::from("node"), "public-key", "node:attach", 99)
            .unwrap();

        assert_eq!(credential.credential_kind, CredentialKind::NodeCredential);
        assert_eq!(credential.tenant, TenantId::from("tenant"));
        assert_eq!(credential.project, ProjectId::from("project"));
        assert_eq!(credential.node, NodeId::from("node"));
        assert_eq!(credential.scope, "node:attach");
        assert_eq!(
            credential.capability_policy_digest,
            node_capability_policy_digest(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                "node:attach"
            )
        );
        assert_eq!(
            grant.exchange_for_node_identity(
                NodeId::from("node2"),
                "public-key",
                "node:attach",
                99
            ),
            Err(EnrollmentError::AlreadyConsumed)
        );
    }

    #[test]
    fn node_capability_policy_digest_is_scoped() {
        let base = node_capability_policy_digest(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            "node:attach",
        );
        let other_project = node_capability_policy_digest(
            &TenantId::from("tenant"),
            &ProjectId::from("other"),
            "node:attach",
        );
        let other_scope = node_capability_policy_digest(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            "node:limited",
        );

        assert!(base.is_valid_sha256());
        assert_ne!(base, other_project);
        assert_ne!(base, other_scope);
    }

    #[test]
    fn generated_ed25519_private_keys_are_random_and_valid() {
        let first = generate_ed25519_private_key().unwrap();
        let second = generate_ed25519_private_key().unwrap();

        assert_ne!(first, second);
        assert!(agent_ed25519_public_key_from_private_key(&first)
            .unwrap()
            .starts_with("ed25519:"));
        assert!(node_ed25519_public_key_from_private_key(&second)
            .unwrap()
            .starts_with("ed25519:"));
    }

    #[test]
    fn generated_opaque_tokens_are_random_and_url_safe() {
        let first = generate_opaque_token("grant").unwrap();
        let second = generate_opaque_token("grant").unwrap();

        assert_ne!(first, second);
        assert!(first.starts_with("grant_"));
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')));
    }

    #[test]
    fn assignment_operation_signature_binds_stable_operation_and_fresh_nonce() {
        let private_key = derive_ed25519_private_key_from_seed("operation-signature-test");
        let public_key = node_ed25519_public_key_from_private_key(&private_key).unwrap();
        let node = NodeId::from("node");
        let digest = Digest::sha256("payload");
        let authority = AssignmentAuthority {
            assignment_id: "assignment".to_owned(),
            attempt_id: "attempt".to_owned(),
            offer_epoch: 7,
        };
        let first = sign_node_assignment_operation_request(
            &private_key,
            &node,
            "task_completed",
            &digest,
            "nonce-one".to_owned(),
            10,
            NodeAssignmentOperation {
                assignment_authority: authority.clone(),
                operation_id: "operation-one".to_owned(),
            },
        )
        .unwrap();
        let second = sign_node_assignment_operation_request(
            &private_key,
            &node,
            "task_completed",
            &digest,
            "nonce-two".to_owned(),
            10,
            NodeAssignmentOperation {
                assignment_authority: authority,
                operation_id: "operation-one".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(first.operation_id, second.operation_id);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.signature, second.signature);
        verify_node_request_signature(&public_key, &node, "task_completed", &digest, &first)
            .unwrap();
        verify_node_request_signature(&public_key, &node, "task_completed", &digest, &second)
            .unwrap();
    }

    #[test]
    fn task_credentials_reject_user_session_tokens() {
        for credential in [
            CredentialKind::BrowserSession,
            CredentialKind::CliDeviceSession,
        ] {
            let authz = task_credentials_do_not_contain_user_session(
                &Actor::Task(TaskInstanceId::from("task")),
                &[CredentialKind::TaskCredential, credential],
            );

            assert!(!authz.allowed);
            assert!(authz.reason.contains("must not be passed"));
        }

        let scoped = task_credentials_do_not_contain_user_session(
            &Actor::Task(TaskInstanceId::from("task")),
            &[
                CredentialKind::TaskCredential,
                CredentialKind::NodeCredential,
            ],
        );
        assert!(scoped.allowed);
    }

    #[test]
    fn identities_remain_distinct_for_authorization() {
        assert_eq!(Actor::User(UserId::from("user")).kind(), IdentityKind::User);
        assert_eq!(
            Actor::Agent(AgentId::from("agent")).kind(),
            IdentityKind::Agent
        );
        assert_eq!(Actor::Node(NodeId::from("node")).kind(), IdentityKind::Node);
        assert_eq!(
            Actor::Task(TaskInstanceId::from("task")).kind(),
            IdentityKind::Task
        );

        let scope = Scope {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: Some(ProcessId::from("process")),
            task: Some(TaskInstanceId::from("task")),
            node: Some(NodeId::from("node")),
            artifact: Some(ArtifactId::from("artifact")),
        };
        assert_eq!(scope.process, Some(ProcessId::from("process")));
        assert_eq!(scope.artifact, Some(ArtifactId::from("artifact")));

        assert_ne!(
            CredentialKind::BrowserSession,
            CredentialKind::CliDeviceSession
        );
        assert_ne!(CredentialKind::PublicKey, CredentialKind::NodeCredential);
        assert_ne!(
            CredentialKind::NodeCredential,
            CredentialKind::TaskCredential
        );
    }
}
