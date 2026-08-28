use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::TaskInstanceId;

/// Fastest supported interval for a node's signed artifact/assignment polling loop.
/// The coordinator's bounded replay window is sized against this protocol limit.
pub const MIN_SIGNED_NODE_POLL_INTERVAL_MS: u64 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LimitKind {
    ApiCall,
    Spawn,
    LogBytes,
    MetadataBytes,
    DebugReadBytes,
    UiEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub limits: BTreeMap<LimitKind, u64>,
}

impl ResourceLimits {
    pub fn new(limits: impl IntoIterator<Item = (LimitKind, u64)>) -> Self {
        Self {
            limits: limits.into_iter().collect(),
        }
    }

    pub fn unlimited() -> Self {
        Self::new(LimitKind::ALL.into_iter().map(|kind| (kind, u64::MAX)))
    }

    pub fn limit(&self, kind: &LimitKind) -> u64 {
        *self.limits.get(kind).unwrap_or(&0)
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

impl LimitKind {
    pub const ALL: [Self; 6] = [
        Self::ApiCall,
        Self::Spawn,
        Self::LogBytes,
        Self::MetadataBytes,
        Self::DebugReadBytes,
        Self::UiEvent,
    ];
}

pub const TASK_JOIN_TIMEOUT_SECONDS_ENV: &str = "CLUSTERFLUX_TASK_JOIN_TIMEOUT_SECONDS";
pub const DEFAULT_TASK_JOIN_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;

pub fn task_join_timeout() -> Duration {
    std::env::var(TASK_JOIN_TIMEOUT_SECONDS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TASK_JOIN_TIMEOUT_SECONDS))
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TaskJoinError {
    #[error(
        "timed out after {waited_seconds} seconds waiting for task {task}; the child task was left running"
    )]
    Timeout {
        task: crate::TaskInstanceId,
        waited_seconds: u64,
    },
    #[error("task join for {task} was cancelled; the child task was left running")]
    Cancelled { task: crate::TaskInstanceId },
}

impl TaskJoinError {
    pub fn timeout(task: crate::TaskInstanceId, waited: Duration) -> Self {
        Self::Timeout {
            task,
            waited_seconds: waited.as_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMeter {
    used: BTreeMap<LimitKind, u64>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LimitError {
    #[error(
        "resource limit exceeded for {kind:?}: requested {requested}, used {used}, limit {limit}"
    )]
    Exceeded {
        kind: LimitKind,
        requested: u64,
        used: u64,
        limit: u64,
    },
    #[error("task argument is too large: {size} bytes exceeds {limit} bytes")]
    LargeTaskArgument { size: u64, limit: u64 },
}

impl ResourceMeter {
    pub fn can_charge(
        &self,
        limits: &ResourceLimits,
        kind: LimitKind,
        amount: u64,
    ) -> Result<(), LimitError> {
        let used = self.used.get(&kind).copied().unwrap_or(0);
        let limit = limits.limit(&kind);
        if used.saturating_add(amount) > limit {
            return Err(LimitError::Exceeded {
                kind,
                requested: amount,
                used,
                limit,
            });
        }
        Ok(())
    }

    pub fn charge(
        &mut self,
        limits: &ResourceLimits,
        kind: LimitKind,
        amount: u64,
    ) -> Result<(), LimitError> {
        self.can_charge(limits, kind, amount)?;
        let used = self.used.get(&kind).copied().unwrap_or(0);
        self.used.insert(kind, used + amount);
        Ok(())
    }

    pub fn used(&self, kind: &LimitKind) -> u64 {
        self.used.get(kind).copied().unwrap_or(0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    pub task: TaskInstanceId,
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogBuffer {
    max_bytes: usize,
    used_bytes: usize,
    records: Vec<LogRecord>,
    backpressured: bool,
}

impl LogBuffer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
            records: Vec::new(),
            backpressured: false,
        }
    }

    pub fn push(&mut self, task: TaskInstanceId, bytes: impl AsRef<[u8]>) {
        let bytes = bytes.as_ref();
        let remaining = self.max_bytes.saturating_sub(self.used_bytes);
        let truncated = bytes.len() > remaining;
        let stored = bytes[..bytes.len().min(remaining)].to_vec();
        self.used_bytes += stored.len();
        if truncated {
            self.backpressured = true;
        }
        self.records.push(LogRecord {
            task,
            bytes: stored,
            truncated,
        });
    }

    pub fn records(&self) -> &[LogRecord] {
        &self.records
    }

    pub fn backpressured(&self) -> bool {
        self.backpressured
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LargeArgumentPolicy {
    Allow,
    Warn,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskArgumentBudget {
    pub max_inline_bytes: u64,
    pub policy: LargeArgumentPolicy,
}

impl TaskArgumentBudget {
    pub fn validate(&self, size: u64) -> Result<Option<String>, LimitError> {
        if size <= self.max_inline_bytes {
            return Ok(None);
        }

        match self.policy {
            LargeArgumentPolicy::Allow => Ok(None),
            LargeArgumentPolicy::Warn => Ok(Some(format!(
                "task argument is {size} bytes; prefer SourceSnapshot, Blob, Artifact, or VFS handles"
            ))),
            LargeArgumentPolicy::Reject => Err(LimitError::LargeTaskArgument {
                size,
                limit: self.max_inline_bytes,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_meter_rejects_usage_before_work_starts() {
        let limits = ResourceLimits {
            limits: BTreeMap::from([(LimitKind::Spawn, 1)]),
        };
        let mut meter = ResourceMeter::default();

        meter.charge(&limits, LimitKind::Spawn, 1).unwrap();
        let error = meter.charge(&limits, LimitKind::Spawn, 1).unwrap_err();

        assert!(matches!(error, LimitError::Exceeded { .. }));
    }

    #[test]
    fn resource_meter_can_check_limits_without_consuming() {
        let limits = ResourceLimits {
            limits: BTreeMap::from([(LimitKind::DebugReadBytes, 4)]),
        };
        let mut meter = ResourceMeter::default();

        meter
            .can_charge(&limits, LimitKind::DebugReadBytes, 4)
            .unwrap();
        assert_eq!(meter.used(&LimitKind::DebugReadBytes), 0);
        meter.charge(&limits, LimitKind::DebugReadBytes, 3).unwrap();
        assert!(matches!(
            meter.can_charge(&limits, LimitKind::DebugReadBytes, 2),
            Err(LimitError::Exceeded { .. })
        ));
    }

    #[test]
    fn log_buffer_caps_backpressures_and_keeps_task_association() {
        let mut logs = LogBuffer::new(4);
        logs.push(TaskInstanceId::from("task-a"), b"abcdef");

        assert!(logs.backpressured());
        assert_eq!(logs.records()[0].task, TaskInstanceId::from("task-a"));
        assert_eq!(logs.records()[0].bytes, b"abcd");
        assert!(logs.records()[0].truncated);
    }

    #[test]
    fn large_task_arguments_are_rejected_or_warned() {
        let reject = TaskArgumentBudget {
            max_inline_bytes: 4,
            policy: LargeArgumentPolicy::Reject,
        };
        assert!(reject.validate(5).is_err());

        let warn = TaskArgumentBudget {
            max_inline_bytes: 4,
            policy: LargeArgumentPolicy::Warn,
        };
        assert!(warn.validate(5).unwrap().unwrap().contains("Artifact"));
    }
}
