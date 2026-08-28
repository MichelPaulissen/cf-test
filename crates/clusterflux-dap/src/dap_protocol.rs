use std::io::{self, BufRead, Write};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

#[derive(Clone)]
pub(crate) struct DapWriter {
    seq: i64,
}

impl DapWriter {
    pub(crate) fn new() -> Self {
        Self { seq: 1 }
    }

    pub(crate) fn response(
        &mut self,
        request: &Value,
        success: bool,
        body: Value,
    ) -> io::Result<()> {
        let command = request
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let request_seq = request.get("seq").and_then(Value::as_i64).unwrap_or(0);
        let seq = self.next_seq();
        self.write(json!({
            "seq": seq,
            "type": "response",
            "request_seq": request_seq,
            "success": success,
            "command": command,
            "body": body,
        }))
    }

    pub(crate) fn error_response(
        &mut self,
        request: &Value,
        message: impl Into<String>,
    ) -> io::Result<()> {
        let command = request
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let request_seq = request.get("seq").and_then(Value::as_i64).unwrap_or(0);
        let seq = self.next_seq();
        self.write(json!({
            "seq": seq,
            "type": "response",
            "request_seq": request_seq,
            "success": false,
            "command": command,
            "message": message.into(),
        }))
    }

    pub(crate) fn event(&mut self, event: &str, body: Value) -> io::Result<()> {
        let seq = self.next_seq();
        self.write(json!({
            "seq": seq,
            "type": "event",
            "event": event,
            "body": body,
        }))
    }

    pub(crate) fn output(&mut self, category: &str, output: impl Into<String>) -> io::Result<()> {
        self.event(
            "output",
            json!({
                "category": category,
                "output": output.into(),
            }),
        )
    }

    fn next_seq(&mut self) -> i64 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }

    fn write(&mut self, message: Value) -> io::Result<()> {
        let payload = serde_json::to_vec(&message)?;
        let mut out = io::stdout().lock();
        write!(out, "Content-Length: {}\r\n\r\n", payload.len())?;
        out.write_all(&payload)?;
        out.flush()
    }
}

pub(crate) fn initialize_capabilities() -> Value {
    json!({
        "supportsConfigurationDoneRequest": true,
        "supportsTerminateRequest": true,
        "supportsRestartRequest": true,
        "supportsRestartFrame": true,
        "supportsEvaluateForHovers": true,
        "supportsStepBack": false,
    })
}

pub(crate) fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>> {
    let mut content_length = None;

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }

        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }

    let length = content_length.ok_or_else(|| anyhow!("DAP message missing Content-Length"))?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(serde_json::from_slice(&payload)?))
}
