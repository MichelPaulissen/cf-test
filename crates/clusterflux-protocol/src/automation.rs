use super::*;
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSecretMetadata {
    pub name: String,
    pub key_version: u32,
    pub allowed_entrypoint: String,
    /// Legacy compatibility metadata. Coordinators authorize the active task's
    /// explicit secret request and capabilities rather than its function name.
    pub allowed_task_definition: String,
    /// Exact trusted refs plus the `refs/tags/v*` stable-release class.
    pub allowed_trusted_refs: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedSecret(String);

impl RedactedSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose_base64(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted task secret>")
    }
}

impl Drop for RedactedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSecretGrant {
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub secret_name: String,
    /// Secret bytes are base64 only for authenticated transport. This type is
    /// node-only and is never embedded in TaskSpec, logs, artifacts, or DAP.
    pub value_base64: RedactedSecret,
    pub expires_at_epoch_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_secret_debug_output_is_always_redacted() {
        let secret = RedactedSecret::new("dG9wLXNlY3JldA==".to_owned());
        assert_eq!(format!("{secret:?}"), "<redacted task secret>");
        let grant = TaskSecretGrant {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("task"),
            secret_name: "TOKEN".to_owned(),
            value_base64: secret,
            expires_at_epoch_seconds: 100,
        };
        let debug = format!("{grant:?}");
        assert!(debug.contains("<redacted task secret>"));
        assert!(!debug.contains("dG9wLXNlY3JldA"));
    }
}
