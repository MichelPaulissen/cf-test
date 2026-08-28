use serde::{ser::SerializeStruct, Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SourceSnapshot {
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Blob {
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub digest: String,
    pub size_bytes: u64,
}

impl Artifact {
    /// Releases this process's retention hold. The handle is consumed so ordinary
    /// code cannot accidentally keep using the released value.
    pub async fn release(self) -> Result<(), crate::Error> {
        #[cfg(target_arch = "wasm32")]
        {
            let digest = parse_handle_digest(&self.digest)
                .map_err(|error| crate::Error::Argument(error.to_string()))?;
            crate::sdk_runtime::guest_vfs_operation(
                clusterflux_core::WasmHostVfsOperation::ReleaseArtifact {
                    artifact: clusterflux_core::ArtifactHandle {
                        id: clusterflux_core::ArtifactId::from(self.id.as_str()),
                        digest,
                        size_bytes: self.size_bytes,
                    },
                },
            )?;
            return Ok(());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = self;
            Err(crate::Error::Configuration(
                "Clusterflux artifact holds are released only by a running Wasm task".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Vfs {
    pub digest: String,
}

impl Serialize for SourceSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::__private::serialize_task_handle(
            clusterflux_core::TaskBoundaryHandle::SourceSnapshot(
                parse_handle_digest(&self.digest).map_err(serde::ser::Error::custom)?,
            ),
            serializer,
            |serializer| serialize_digest_struct("SourceSnapshot", &self.digest, serializer),
        )
    }
}

impl Serialize for Blob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::__private::serialize_task_handle(
            clusterflux_core::TaskBoundaryHandle::Blob(
                parse_handle_digest(&self.digest).map_err(serde::ser::Error::custom)?,
            ),
            serializer,
            |serializer| serialize_digest_struct("Blob", &self.digest, serializer),
        )
    }
}

impl Serialize for Vfs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::__private::serialize_task_handle(
            clusterflux_core::TaskBoundaryHandle::VfsManifest(
                parse_handle_digest(&self.digest).map_err(serde::ser::Error::custom)?,
            ),
            serializer,
            |serializer| serialize_digest_struct("Vfs", &self.digest, serializer),
        )
    }
}

impl Serialize for Artifact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.id.trim().is_empty() || self.id.len() > 256 {
            return Err(serde::ser::Error::custom(
                "artifact handle ID must be non-empty and at most 256 bytes",
            ));
        }
        let handle = clusterflux_core::ArtifactHandle {
            id: clusterflux_core::ArtifactId::from(self.id.as_str()),
            digest: parse_handle_digest(&self.digest).map_err(serde::ser::Error::custom)?,
            size_bytes: self.size_bytes,
        };
        crate::__private::serialize_task_handle(
            clusterflux_core::TaskBoundaryHandle::Artifact(handle),
            serializer,
            |serializer| {
                let mut state = serializer.serialize_struct("Artifact", 3)?;
                state.serialize_field("id", &self.id)?;
                state.serialize_field("digest", &self.digest)?;
                state.serialize_field("size_bytes", &self.size_bytes)?;
                state.end()
            },
        )
    }
}

fn serialize_digest_struct<S>(
    name: &'static str,
    digest: &str,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut state = serializer.serialize_struct(name, 1)?;
    state.serialize_field("digest", digest)?;
    state.end()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvRef {
    pub name: &'static str,
}

impl EnvRef {
    pub const fn new_static(name: &'static str) -> Self {
        Self { name }
    }
}

#[macro_export]
macro_rules! env {
    ($name:literal) => {
        $crate::EnvRef::new_static($name)
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskArgKind {
    SmallSerialized,
    Structured,
    Handle,
}

/// A value allowed to cross a Clusterflux task boundary.
///
/// Implementations are deliberately limited to small owned values and explicit
/// Clusterflux handles. Host-only values fail at compile time because they do not
/// implement `TaskArg`:
///
/// ```compile_fail
/// let borrowed = String::from("host-owned");
/// let _ = clusterflux::spawn::task_with_arg(borrowed.as_str(), |_| 1_u32);
/// ```
///
/// ```compile_fail
/// let pointer = std::ptr::null::<u8>();
/// let _ = clusterflux::spawn::task_with_arg(pointer, |_| 1_u32);
/// ```
///
/// ```compile_fail
/// let file = std::fs::File::open("Cargo.toml").unwrap();
/// let _ = clusterflux::spawn::task_with_arg(file, |_| 1_u32);
/// ```
///
/// ```compile_fail
/// let lock = std::sync::Mutex::new(1_u32);
/// let guard = lock.lock().unwrap();
/// let _ = clusterflux::spawn::task_with_arg(guard, |_| 1_u32);
/// ```
pub trait TaskArg: Serialize {
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::SmallSerialized
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        serde_json::to_value(self)
            .map(clusterflux_core::TaskBoundaryValue::SmallJson)
            .map_err(|error| TaskArgError::Serialization(error.to_string()))
    }
}

macro_rules! small_task_arg {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl TaskArg for $ty {}
        )+
    };
}

small_task_arg!(
    (),
    bool,
    char,
    String,
    i8,
    i16,
    i32,
    i64,
    isize,
    u8,
    u16,
    u32,
    u64,
    usize,
    f32,
    f64,
);

impl TaskArg for SourceSnapshot {
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Handle
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        parse_handle_digest(&self.digest).map(clusterflux_core::TaskBoundaryValue::SourceSnapshot)
    }
}

impl TaskArg for Blob {
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Handle
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        parse_handle_digest(&self.digest).map(clusterflux_core::TaskBoundaryValue::Blob)
    }
}

impl TaskArg for Artifact {
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Handle
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        Ok(clusterflux_core::TaskBoundaryValue::Artifact(
            clusterflux_core::ArtifactHandle {
                id: clusterflux_core::ArtifactId::from(self.id.as_str()),
                digest: parse_handle_digest(&self.digest)?,
                size_bytes: self.size_bytes,
            },
        ))
    }
}

impl TaskArg for Vfs {
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Handle
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        parse_handle_digest(&self.digest).map(clusterflux_core::TaskBoundaryValue::VfsManifest)
    }
}

impl<T> TaskArg for Option<T>
where
    T: TaskArg + crate::__private::CollectTaskHandles,
{
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Structured
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        crate::__private::structured_task_boundary(self)
    }
}

impl<T> TaskArg for Vec<T>
where
    T: TaskArg + crate::__private::CollectTaskHandles,
{
    fn task_arg_kind(&self) -> TaskArgKind {
        TaskArgKind::Structured
    }

    fn task_boundary_value(&self) -> Result<clusterflux_core::TaskBoundaryValue, TaskArgError> {
        crate::__private::structured_task_boundary(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskArgBudget {
    pub max_inline_bytes: usize,
}

impl Default for TaskArgBudget {
    fn default() -> Self {
        Self {
            max_inline_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskArgValidation {
    pub inline_bytes: usize,
    pub kind: TaskArgKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskArgError {
    Serialization(String),
    TooLarge { size: usize, limit: usize },
    HostOnly { type_name: &'static str },
}

impl std::fmt::Display for TaskArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(error) => write!(f, "task argument could not serialize: {error}"),
            Self::TooLarge { size, limit } => write!(
                f,
                "task argument is {size} bytes; inline task arguments are limited to {limit} bytes, use SourceSnapshot, Blob, Artifact, or VFS handles"
            ),
            Self::HostOnly { type_name } => write!(
                f,
                "task boundary value `{type_name}` is host-only; use small serialized data or handles"
            ),
        }
    }
}

impl std::error::Error for TaskArgError {}

pub fn validate_task_arg<T>(
    value: &T,
    budget: TaskArgBudget,
) -> Result<TaskArgValidation, TaskArgError>
where
    T: TaskArg + ?Sized,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|error| TaskArgError::Serialization(error.to_string()))?;
    let kind = value.task_arg_kind();
    if kind != TaskArgKind::Handle && bytes.len() > budget.max_inline_bytes {
        return Err(TaskArgError::TooLarge {
            size: bytes.len(),
            limit: budget.max_inline_bytes,
        });
    }
    Ok(TaskArgValidation {
        inline_bytes: bytes.len(),
        kind,
    })
}

pub fn reject_host_only_task_arg<T: ?Sized>() -> TaskArgError {
    TaskArgError::HostOnly {
        type_name: std::any::type_name::<T>(),
    }
}

pub(crate) fn parse_handle_digest(value: &str) -> Result<clusterflux_core::Digest, TaskArgError> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(|_| {
        TaskArgError::Serialization(
            "handle digest must be a serialized sha256 digest issued by Clusterflux".to_owned(),
        )
    })
}
