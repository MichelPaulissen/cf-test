use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskLogStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentLogEntry {
    pub sequence: u64,
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub stream: TaskLogStream,
    pub text: String,
    pub server_timestamp_epoch_seconds: u64,
    pub truncated: bool,
}
