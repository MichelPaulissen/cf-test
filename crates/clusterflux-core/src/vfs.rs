use std::collections::BTreeMap;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{Digest, NodeId, TaskInstanceId};

pub const MAX_VFS_PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct VfsPath(String);

impl VfsPath {
    pub fn new(path: impl Into<String>) -> Result<Self, VfsError> {
        let path = path.into();
        if !path.starts_with("/vfs/") {
            return Err(VfsError::invalid(path, "path must start with /vfs/"));
        }
        if path.len() > MAX_VFS_PATH_BYTES {
            return Err(VfsError::invalid(
                path,
                "path exceeds the 4096-byte protocol limit",
            ));
        }
        if path.chars().any(char::is_control) {
            return Err(VfsError::invalid(path, "control characters are forbidden"));
        }
        if path.contains('\\') {
            return Err(VfsError::invalid(path, "backslashes are forbidden"));
        }
        let relative = &path["/vfs/".len()..];
        if relative.is_empty() {
            return Err(VfsError::invalid(
                path,
                "path after /vfs/ must not be empty",
            ));
        }
        if relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(VfsError::invalid(
                path,
                "empty, '.', and '..' path components are forbidden",
            ));
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for VfsPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;
        Self::new(path).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsObject {
    pub path: VfsPath,
    pub digest: Digest,
    pub size: u64,
    pub producer: TaskInstanceId,
    pub node: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsManifest {
    pub epoch: u64,
    pub producer: TaskInstanceId,
    pub node: NodeId,
    pub objects: BTreeMap<VfsPath, VfsObject>,
    pub large_bytes_uploaded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncPolicy {
    MetadataOnly,
    ExplicitNode(NodeId),
    ExplicitStore(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsSyncDecision {
    NoBytesMoved,
    MoveBytesToNode(NodeId),
    MoveBytesToStore(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReuseDecision {
    SameNodeZeroCopy,
    NeedsTransfer { from: NodeId, to: NodeId },
    Unavailable,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VfsError {
    #[error("invalid VFS path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("path is not visible in the published VFS manifest: {0}")]
    NotVisible(String),
}

impl VfsError {
    fn invalid(path: String, reason: &'static str) -> Self {
        Self::InvalidPath { path, reason }
    }
}

#[derive(Clone, Debug)]
pub struct VfsOverlay {
    task: TaskInstanceId,
    node: NodeId,
    epoch: u64,
    pending: BTreeMap<VfsPath, VfsObject>,
    published: BTreeMap<VfsPath, VfsObject>,
}

impl VfsOverlay {
    pub fn new(task: TaskInstanceId, node: NodeId) -> Self {
        Self {
            task,
            node,
            epoch: 0,
            pending: BTreeMap::new(),
            published: BTreeMap::new(),
        }
    }

    pub fn write(&mut self, path: VfsPath, digest: Digest, size: u64) -> VfsObject {
        let object = VfsObject {
            path: path.clone(),
            digest,
            size,
            producer: self.task.clone(),
            node: self.node.clone(),
        };
        self.pending.insert(path, object.clone());
        object
    }

    pub fn flush(&mut self) -> VfsManifest {
        self.epoch += 1;
        self.published.append(&mut self.pending);
        VfsManifest {
            epoch: self.epoch,
            producer: self.task.clone(),
            node: self.node.clone(),
            objects: self.published.clone(),
            large_bytes_uploaded: false,
        }
    }

    pub fn sync(&self, policy: SyncPolicy) -> VfsSyncDecision {
        match policy {
            SyncPolicy::MetadataOnly => VfsSyncDecision::NoBytesMoved,
            SyncPolicy::ExplicitNode(node) => VfsSyncDecision::MoveBytesToNode(node),
            SyncPolicy::ExplicitStore(store) => VfsSyncDecision::MoveBytesToStore(store),
        }
    }

    pub fn read_published<'a>(
        manifest: &'a VfsManifest,
        path: &VfsPath,
    ) -> Result<&'a VfsObject, VfsError> {
        manifest
            .objects
            .get(path)
            .ok_or_else(|| VfsError::NotVisible(path.as_str().to_owned()))
    }

    pub fn reuse_for_consumer(
        manifest: &VfsManifest,
        path: &VfsPath,
        consumer_node: &NodeId,
    ) -> ReuseDecision {
        let Some(object) = manifest.objects.get(path) else {
            return ReuseDecision::Unavailable;
        };
        if &object.node == consumer_node {
            ReuseDecision::SameNodeZeroCopy
        } else {
            ReuseDecision::NeedsTransfer {
                from: object.node.clone(),
                to: consumer_node.clone(),
            }
        }
    }

    pub fn discard_unflushed(&mut self) {
        self.pending.clear();
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> VfsPath {
        VfsPath::new("/vfs/artifacts/app").unwrap()
    }

    #[test]
    fn flush_publishes_manifest_without_large_byte_upload() {
        let mut overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node-a"));
        overlay.write(path(), Digest::sha256("binary"), 6);

        let manifest = overlay.flush();

        assert_eq!(manifest.epoch, 1);
        assert!(!manifest.large_bytes_uploaded);
        assert!(manifest.objects.contains_key(&path()));
    }

    #[test]
    fn downstream_task_can_read_after_flush_but_not_before() {
        let mut overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node-a"));
        overlay.write(path(), Digest::sha256("binary"), 6);

        let empty = VfsManifest {
            epoch: 0,
            producer: TaskInstanceId::from("task"),
            node: NodeId::from("node-a"),
            objects: BTreeMap::new(),
            large_bytes_uploaded: false,
        };
        assert!(VfsOverlay::read_published(&empty, &path()).is_err());

        let manifest = overlay.flush();
        assert!(VfsOverlay::read_published(&manifest, &path()).is_ok());
    }

    #[test]
    fn sync_is_explicit_and_policy_driven() {
        let overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node-a"));

        assert_eq!(
            overlay.sync(SyncPolicy::MetadataOnly),
            VfsSyncDecision::NoBytesMoved
        );
        assert_eq!(
            overlay.sync(SyncPolicy::ExplicitStore("s3://bucket/app".to_owned())),
            VfsSyncDecision::MoveBytesToStore("s3://bucket/app".to_owned())
        );
    }

    #[test]
    fn same_node_reuse_avoids_transfer() {
        let mut overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node-a"));
        overlay.write(path(), Digest::sha256("binary"), 6);
        let manifest = overlay.flush();

        assert_eq!(
            VfsOverlay::reuse_for_consumer(&manifest, &path(), &NodeId::from("node-a")),
            ReuseDecision::SameNodeZeroCopy
        );
        assert_eq!(
            VfsOverlay::reuse_for_consumer(&manifest, &path(), &NodeId::from("node-b")),
            ReuseDecision::NeedsTransfer {
                from: NodeId::from("node-a"),
                to: NodeId::from("node-b")
            }
        );
    }

    #[test]
    fn unflushed_task_local_changes_can_be_discarded() {
        let mut overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node-a"));
        overlay.write(path(), Digest::sha256("binary"), 6);

        overlay.discard_unflushed();

        assert_eq!(overlay.pending_len(), 0);
    }

    #[test]
    fn vfs_path_rejects_the_complete_hostile_protocol_matrix() {
        for invalid in [
            "vfs/artifacts/app".to_owned(),
            "/vfs/".to_owned(),
            "/vfs/artifacts//app".to_owned(),
            "/vfs/artifacts/app/".to_owned(),
            "/vfs/artifacts/./app".to_owned(),
            "/vfs/artifacts/../app".to_owned(),
            "/vfs/artifacts\\app".to_owned(),
            "/vfs/artifacts/bad\0app".to_owned(),
            format!("/vfs/{}", "x".repeat(MAX_VFS_PATH_BYTES)),
        ] {
            assert!(
                VfsPath::new(&invalid).is_err(),
                "hostile VFS path unexpectedly passed: {invalid:?}"
            );
            assert!(
                serde_json::from_value::<VfsPath>(serde_json::json!(invalid)).is_err(),
                "hostile VFS path unexpectedly deserialized"
            );
        }
    }

    #[test]
    fn vfs_path_accepts_the_4096_byte_boundary() {
        let path = format!("/vfs/{}", "x".repeat(MAX_VFS_PATH_BYTES - "/vfs/".len()));
        assert_eq!(path.len(), MAX_VFS_PATH_BYTES);
        assert_eq!(VfsPath::new(&path).unwrap().as_str(), path);

        let overlong = format!("{path}x");
        assert_eq!(overlong.len(), MAX_VFS_PATH_BYTES + 1);
        assert!(VfsPath::new(overlong).is_err());
    }
}
