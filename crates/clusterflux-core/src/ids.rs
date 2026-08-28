#[cfg(not(target_arch = "wasm32"))]
use serde::{de::Error as _, Deserializer};
use serde::{Deserialize, Serialize};

pub const MAX_EXTERNAL_ID_BYTES: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueTokenError {
    reason: String,
}

impl std::fmt::Display for OpaqueTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OpaqueTokenError {}

pub fn validate_opaque_token(value: &str, max_bytes: usize) -> Result<(), OpaqueTokenError> {
    let reason = if value.trim().is_empty() {
        Some("value must not be empty or whitespace-only".to_owned())
    } else if value.len() > max_bytes {
        Some(format!("value exceeds the {max_bytes}-byte limit"))
    } else if value.chars().any(char::is_control) {
        Some("control characters are forbidden".to_owned())
    } else {
        None
    };
    reason.map_or(Ok(()), |reason| Err(OpaqueTokenError { reason }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdParseError {
    id_type: &'static str,
    reason: &'static str,
}

impl IdParseError {
    fn new(id_type: &'static str, reason: &'static str) -> Self {
        Self { id_type, reason }
    }
}

impl std::fmt::Display for IdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is invalid: {}", self.id_type, self.reason)
    }
}

impl std::error::Error for IdParseError {}

fn validate_id(value: &str, id_type: &'static str) -> Result<(), IdParseError> {
    if value.is_empty() || value.trim().is_empty() {
        return Err(IdParseError::new(
            id_type,
            "value must not be empty or whitespace-only",
        ));
    }
    if value.len() > MAX_EXTERNAL_ID_BYTES {
        return Err(IdParseError::new(
            id_type,
            "value exceeds the 255-byte limit",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(IdParseError::new(
            id_type,
            "control characters are forbidden",
        ));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
    }) {
        return Err(IdParseError::new(
            id_type,
            "only ASCII letters, digits, '-', '_', '.', ':', '/', '@', and '+' are allowed",
        ));
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident) => {
        #[cfg_attr(target_arch = "wasm32", derive(Deserialize))]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name(String);

        impl $name {
            pub fn try_new(value: impl Into<String>) -> Result<Self, IdParseError> {
                let value = value.into();
                validate_id(&value, stringify!($name))?;
                Ok(Self(value))
            }

            /// Constructs an identifier from a trusted, internally generated value.
            pub fn new(value: impl Into<String>) -> Self {
                Self::try_new(value).unwrap_or_else(|error| panic!("{error}"))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_new(value).map_err(D::Error::custom)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(AgentId);
id_type!(ArtifactId);
id_type!(NodeId);
id_type!(ProcessId);
id_type!(LaunchAttemptId);
id_type!(ProjectId);
id_type!(RepositoryId);
id_type!(RunId);
id_type!(TaskDefinitionId);
id_type!(TaskInstanceId);
id_type!(TenantId);
id_type!(TriggerId);
id_type!(UserId);

pub type DebugSessionId = ProcessId;
pub type RequestId = LaunchAttemptId;

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_hostile_values<T>(parse: impl Fn(String) -> Result<T, IdParseError>) {
        for value in [
            String::new(),
            "   ".to_owned(),
            "bad\0id".to_owned(),
            "bad id".to_owned(),
            "x".repeat(MAX_EXTERNAL_ID_BYTES + 1),
        ] {
            assert!(parse(value).is_err());
        }
    }

    #[test]
    fn every_external_identifier_type_rejects_hostile_values() {
        assert_hostile_values(AgentId::try_new);
        assert_hostile_values(ArtifactId::try_new);
        assert_hostile_values(DebugSessionId::try_new);
        assert_hostile_values(NodeId::try_new);
        assert_hostile_values(ProcessId::try_new);
        assert_hostile_values(LaunchAttemptId::try_new);
        assert_hostile_values(ProjectId::try_new);
        assert_hostile_values(RepositoryId::try_new);
        assert_hostile_values(RunId::try_new);
        assert_hostile_values(RequestId::try_new);
        assert_hostile_values(TaskDefinitionId::try_new);
        assert_hostile_values(TaskInstanceId::try_new);
        assert_hostile_values(TenantId::try_new);
        assert_hostile_values(TriggerId::try_new);
        assert_hostile_values(UserId::try_new);
    }

    #[test]
    fn every_identifier_type_validates_during_deserialization() {
        macro_rules! assert_deserialization {
            ($id:ty) => {
                assert!(serde_json::from_str::<$id>(r#""valid-id""#).is_ok());
                let error = serde_json::from_str::<$id>(r#""hostile id!""#).unwrap_err();
                assert!(
                    error.to_string().contains("is invalid"),
                    "{} produced an unexpected error: {error}",
                    stringify!($id)
                );
            };
        }

        assert_deserialization!(AgentId);
        assert_deserialization!(ArtifactId);
        assert_deserialization!(NodeId);
        assert_deserialization!(ProcessId);
        assert_deserialization!(LaunchAttemptId);
        assert_deserialization!(ProjectId);
        assert_deserialization!(RepositoryId);
        assert_deserialization!(RunId);
        assert_deserialization!(TaskDefinitionId);
        assert_deserialization!(TaskInstanceId);
        assert_deserialization!(TenantId);
        assert_deserialization!(TriggerId);
        assert_deserialization!(UserId);
    }

    #[test]
    fn opaque_tokens_are_bounded_without_using_identifier_syntax() {
        validate_opaque_token("opaque secret/+==", 64).unwrap();
        assert!(validate_opaque_token("", 64).is_err());
        assert!(validate_opaque_token("bad\0token", 64).is_err());
        assert!(validate_opaque_token(&"x".repeat(65), 64).is_err());
    }
}
