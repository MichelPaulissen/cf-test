#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
#[cfg(not(target_arch = "wasm32"))]
use std::net::TcpStream;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use clusterflux_protocol::{
    coordinator_wire_request, login_wire_request, CoordinatorRequest, CoordinatorResponse,
    LoginRequest, LoginResponse,
};
pub use clusterflux_protocol::{CONTROL_API_PATH, LOGIN_API_PATH, MAX_CONTROL_FRAME_BYTES};

#[derive(Debug, Error)]
pub enum ControlTransportError {
    #[error("invalid coordinator endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("insecure remote coordinator endpoint is forbidden: {0}")]
    InsecureRemote(String),
    #[error("coordinator transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("coordinator transport JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("coordinator protocol failed: {0}")]
    Protocol(String),
    #[error("coordinator HTTP request failed: {0}")]
    Http(String),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("coordinator returned HTTP {status} {status_text}")]
    HttpStatus {
        status: u16,
        status_text: String,
        retry_after: Option<Duration>,
    },
    #[error("coordinator control frame exceeds {MAX_CONTROL_FRAME_BYTES} bytes")]
    FrameTooLarge,
    #[error("coordinator closed the local control session without a response")]
    Closed,
    #[error("coordinator request failed: {0}")]
    Coordinator(String),
    #[error("coordinator network transport is unavailable inside a Wasm guest")]
    UnavailableInWasm,
}

impl ControlTransportError {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::HttpStatus { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

enum ControlTransport {
    #[cfg(not(target_arch = "wasm32"))]
    Https { agent: ureq::Agent, url: String },
    #[cfg(not(target_arch = "wasm32"))]
    LoopbackJsonLine {
        writer: TcpStream,
        reader: BufReader<TcpStream>,
    },
    #[cfg(target_arch = "wasm32")]
    #[allow(dead_code)]
    Unavailable,
}

pub struct ControlSession {
    transport: ControlTransport,
    requests: u64,
}

pub struct ProtocolSession {
    inner: ControlSession,
    request_id_prefix: String,
}

pub struct LoginSession {
    inner: ControlSession,
    request_id_prefix: String,
}

impl ProtocolSession {
    pub fn connect(
        endpoint: &str,
        request_id_prefix: impl Into<String>,
    ) -> Result<Self, ControlTransportError> {
        Ok(Self {
            inner: ControlSession::connect(endpoint)?,
            request_id_prefix: request_id_prefix.into(),
        })
    }

    pub fn connect_with_timeouts(
        endpoint: &str,
        request_id_prefix: impl Into<String>,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        Ok(Self {
            inner: ControlSession::connect_with_timeouts(endpoint, connect_timeout, io_timeout)?,
            request_id_prefix: request_id_prefix.into(),
        })
    }

    pub fn request(
        &mut self,
        request: &CoordinatorRequest,
    ) -> Result<CoordinatorResponse, ControlTransportError> {
        let response = self.request_allow_error(request)?;
        match response {
            CoordinatorResponse::Error { ref error } => {
                Err(ControlTransportError::Coordinator(error.to_string()))
            }
            response => Ok(response),
        }
    }

    pub fn request_allow_error(
        &mut self,
        request: &CoordinatorRequest,
    ) -> Result<CoordinatorResponse, ControlTransportError> {
        request
            .validate_external_identifiers()
            .map_err(ControlTransportError::Coordinator)?;
        let request_id = format!("{}-{}", self.request_id_prefix, self.inner.requests() + 1);
        let envelope = coordinator_wire_request(request_id, request.clone());
        let response: CoordinatorResponse = self.inner.request_typed(&envelope)?;
        if let CoordinatorResponse::Error { error } = &response {
            if error.request_id != envelope.request_id {
                return Err(ControlTransportError::Protocol(format!(
                    "error response request_id {} does not match {}",
                    error.request_id, envelope.request_id
                )));
            }
        }
        Ok(response)
    }

    pub fn requests(&self) -> u64 {
        self.inner.requests()
    }
}

impl LoginSession {
    pub fn connect(
        endpoint: &str,
        request_id_prefix: impl Into<String>,
    ) -> Result<Self, ControlTransportError> {
        Ok(Self {
            inner: ControlSession::connect_to_api_path(endpoint, LOGIN_API_PATH)?,
            request_id_prefix: request_id_prefix.into(),
        })
    }

    pub fn connect_with_timeouts(
        endpoint: &str,
        request_id_prefix: impl Into<String>,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        Ok(Self {
            inner: ControlSession::connect_to_api_path_with_timeouts(
                endpoint,
                LOGIN_API_PATH,
                connect_timeout,
                io_timeout,
            )?,
            request_id_prefix: request_id_prefix.into(),
        })
    }

    pub fn request(
        &mut self,
        request: &LoginRequest,
    ) -> Result<LoginResponse, ControlTransportError> {
        let response = self.request_allow_error(request)?;
        match response {
            LoginResponse::Error { ref error } => {
                Err(ControlTransportError::Coordinator(error.to_string()))
            }
            response => Ok(response),
        }
    }

    pub fn request_allow_error(
        &mut self,
        request: &LoginRequest,
    ) -> Result<LoginResponse, ControlTransportError> {
        request
            .validate_external_inputs()
            .map_err(ControlTransportError::Coordinator)?;
        let request_id = format!("{}-{}", self.request_id_prefix, self.inner.requests() + 1);
        let envelope = login_wire_request(request_id, request.clone());
        let response: LoginResponse = self.inner.request_typed(&envelope)?;
        if let LoginResponse::Error { error } = &response {
            if error.request_id != envelope.request_id {
                return Err(ControlTransportError::Protocol(format!(
                    "error response request_id {} does not match {}",
                    error.request_id, envelope.request_id
                )));
            }
        }
        Ok(response)
    }

    pub fn requests(&self) -> u64 {
        self.inner.requests()
    }
}

impl ControlSession {
    pub fn connect(endpoint: &str) -> Result<Self, ControlTransportError> {
        Self::connect_with_timeouts(endpoint, Duration::from_secs(10), Duration::from_secs(30))
    }

    pub fn connect_to_api_path(
        endpoint: &str,
        api_path: &str,
    ) -> Result<Self, ControlTransportError> {
        Self::connect_to_api_path_with_timeouts(
            endpoint,
            api_path,
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
    }

    pub fn connect_to_api_path_with_timeouts(
        endpoint: &str,
        api_path: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        let session = Self::connect_with_timeouts(endpoint, connect_timeout, io_timeout)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut session = session;
            if let ControlTransport::Https { url, .. } = &mut session.transport {
                *url = endpoint_api_url(endpoint, api_path)?;
            }
            Ok(session)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = api_path;
            Ok(session)
        }
    }

    pub fn connect_with_timeouts(
        endpoint: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, ControlTransportError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (endpoint, connect_timeout, io_timeout);
            return Err(ControlTransportError::UnavailableInWasm);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let endpoint = validate_endpoint_text(endpoint)?;
            if endpoint.starts_with("https://") || endpoint.starts_with("http://") {
                let url = control_api_url(endpoint)?;
                if endpoint.starts_with("http://") && !endpoint_is_loopback(endpoint) {
                    return Err(ControlTransportError::InsecureRemote(endpoint.to_owned()));
                }
                let agent = ureq::AgentBuilder::new()
                    .timeout_connect(connect_timeout)
                    .timeout_read(io_timeout)
                    .timeout_write(io_timeout)
                    .build();
                return Ok(Self {
                    transport: ControlTransport::Https { agent, url },
                    requests: 0,
                });
            }

            let loopback_address = endpoint
                .strip_prefix("clusterflux+tcp://")
                .unwrap_or(endpoint);
            if !endpoint_is_loopback(loopback_address) {
                return Err(ControlTransportError::InsecureRemote(endpoint.to_owned()));
            }
            let writer = TcpStream::connect(loopback_address)?;
            writer.set_read_timeout(Some(io_timeout))?;
            writer.set_write_timeout(Some(io_timeout))?;
            let reader = BufReader::new(writer.try_clone()?);
            Ok(Self {
                transport: ControlTransport::LoopbackJsonLine { writer, reader },
                requests: 0,
            })
        }
    }

    pub(crate) fn request_bytes(
        &mut self,
        encoded: &[u8],
    ) -> Result<Vec<u8>, ControlTransportError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (&self.transport, self.requests, encoded);
            return Err(ControlTransportError::UnavailableInWasm);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if encoded.len() > MAX_CONTROL_FRAME_BYTES {
                return Err(ControlTransportError::FrameTooLarge);
            }
            let inject_response_loss = should_inject_response_loss(encoded);
            let response = match &mut self.transport {
                #[cfg(not(target_arch = "wasm32"))]
                ControlTransport::Https { agent, url } => {
                    let response = match agent
                        .post(url)
                        .set("Content-Type", "application/json")
                        .set("Accept", "application/json")
                        .send_bytes(encoded)
                    {
                        Ok(response) => response,
                        Err(ureq::Error::Status(status, response)) => {
                            return Err(ControlTransportError::HttpStatus {
                                status,
                                status_text: response.status_text().to_owned(),
                                retry_after: parse_retry_after(response.header("Retry-After")),
                            });
                        }
                        Err(error) => return Err(ControlTransportError::Http(error.to_string())),
                    };
                    if inject_response_loss {
                        return Err(ControlTransportError::Closed);
                    }
                    if response.status() != 200 {
                        return Err(ControlTransportError::Http(format!(
                            "coordinator returned HTTP {} {}",
                            response.status(),
                            response.status_text()
                        )));
                    }
                    let mut bytes = Vec::new();
                    response
                        .into_reader()
                        .take((MAX_CONTROL_FRAME_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
                        return Err(ControlTransportError::FrameTooLarge);
                    }
                    bytes
                }
                ControlTransport::LoopbackJsonLine { writer, reader } => {
                    writer.write_all(encoded)?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                    if inject_response_loss {
                        return Err(ControlTransportError::Closed);
                    }
                    let mut bytes = Vec::new();
                    reader
                        .take((MAX_CONTROL_FRAME_BYTES + 1) as u64)
                        .read_until(b'\n', &mut bytes)?;
                    if bytes.is_empty() {
                        return Err(ControlTransportError::Closed);
                    }
                    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
                        return Err(ControlTransportError::FrameTooLarge);
                    }
                    bytes
                }
            };
            self.requests += 1;
            Ok(response)
        }
    }

    fn request_typed<Request, Response>(
        &mut self,
        request: &Request,
    ) -> Result<Response, ControlTransportError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let encoded = serde_json::to_vec(request)?;
        let response = self.request_bytes(&encoded)?;
        serde_json::from_slice(&response).map_err(ControlTransportError::Json)
    }

    pub fn requests(&self) -> u64 {
        self.requests
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    let value = value?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let deadline = httpdate::parse_http_date(value).ok()?;
    Some(
        deadline
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn should_inject_response_loss(encoded: &[u8]) -> bool {
    static INJECTED: AtomicBool = AtomicBool::new(false);
    let Ok(expected_operation) = std::env::var("CLUSTERFLUX_TEST_DROP_RESPONSE_AFTER_OPERATION")
    else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(encoded) else {
        return false;
    };
    let operation = value
        .pointer("/payload/request/type")
        .or_else(|| value.pointer("/payload/type"))
        .or_else(|| value.get("type"))
        .and_then(Value::as_str);
    operation == Some(expected_operation.as_str())
        && INJECTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
}

pub fn control_api_url(endpoint: &str) -> Result<String, ControlTransportError> {
    endpoint_api_url(endpoint, CONTROL_API_PATH)
}

pub fn endpoint_api_url(endpoint: &str, api_path: &str) -> Result<String, ControlTransportError> {
    let endpoint = validate_endpoint_text(endpoint)?;
    let endpoint = endpoint.trim_end_matches('/');
    if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
        return Err(ControlTransportError::InvalidEndpoint(endpoint.to_owned()));
    }
    if !api_path.starts_with('/') {
        return Err(ControlTransportError::InvalidEndpoint(api_path.to_owned()));
    }
    if endpoint.ends_with(api_path) {
        Ok(endpoint.to_owned())
    } else {
        let base = endpoint
            .strip_suffix(CONTROL_API_PATH)
            .or_else(|| endpoint.strip_suffix(LOGIN_API_PATH))
            .unwrap_or(endpoint);
        Ok(format!("{base}{api_path}"))
    }
}

pub fn endpoint_identity(endpoint: &str) -> Result<String, ControlTransportError> {
    let endpoint = validate_endpoint_text(endpoint)?;
    if endpoint.starts_with("https://") || endpoint.starts_with("http://") {
        if endpoint.starts_with("http://") && !endpoint_is_loopback(endpoint) {
            return Err(ControlTransportError::InsecureRemote(endpoint.to_owned()));
        }
        return control_api_url(endpoint);
    }
    let loopback_address = endpoint
        .strip_prefix("clusterflux+tcp://")
        .unwrap_or(endpoint);
    if endpoint_is_loopback(loopback_address) {
        return Ok(format!("clusterflux+tcp://{loopback_address}"));
    }
    Err(ControlTransportError::InsecureRemote(endpoint.to_owned()))
}

pub fn endpoint_is_loopback(endpoint: &str) -> bool {
    if validate_endpoint_text(endpoint).is_err() {
        return false;
    }
    let authority = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .or_else(|| endpoint.strip_prefix("clusterflux+tcp://"))
        .unwrap_or(endpoint)
        .split('/')
        .next()
        .unwrap_or_default();
    let host = if authority.starts_with('[') {
        authority
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .map(|(host, _)| host)
            .unwrap_or(authority)
    } else {
        authority
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn validate_endpoint_text(endpoint: &str) -> Result<&str, ControlTransportError> {
    if endpoint.trim() != endpoint
        || endpoint.len() > 2_048
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('@')
        || endpoint.contains('?')
        || endpoint.contains('#')
    {
        return Err(ControlTransportError::InvalidEndpoint(
            "endpoint must be at most 2048 bytes without surrounding whitespace, credentials, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn hosted_endpoints_are_real_https_api_urls() {
        assert_eq!(
            control_api_url("https://clusterflux.example").unwrap(),
            "https://clusterflux.example/api/v1/control"
        );
        assert_eq!(
            endpoint_identity("https://clusterflux.example/api/v1/control").unwrap(),
            "https://clusterflux.example/api/v1/control"
        );
    }

    #[test]
    fn plaintext_transport_is_restricted_to_loopback() {
        assert!(endpoint_is_loopback("127.0.0.1:7999"));
        assert!(endpoint_is_loopback("clusterflux+tcp://127.0.0.1:7999"));
        assert!(endpoint_is_loopback("http://[::1]:7999"));
        assert!(!endpoint_is_loopback(
            "http://operator:secret@127.0.0.1:7999"
        ));
        assert!(endpoint_identity("https://operator:secret@example.com").is_err());
        assert!(endpoint_identity("https://example.com?token=secret").is_err());
        assert!(matches!(
            ControlSession::connect("http://example.com:7999"),
            Err(ControlTransportError::InsecureRemote(_))
        ));
        assert!(matches!(
            ControlSession::connect("example.com:7999"),
            Err(ControlTransportError::InsecureRemote(_))
        ));
    }

    #[test]
    fn http_429_preserves_retry_after_for_callers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nRetry-After: 7\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let mut session =
            LoginSession::connect(&format!("http://{address}"), "test-login").unwrap();
        let error = session
            .request_allow_error(&LoginRequest::BeginWebBrowserLogin {})
            .unwrap_err();
        server.join().unwrap();

        assert_eq!(error.status_code(), Some(429));
        assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
    }

    #[test]
    fn protocol_session_wraps_typed_requests_and_decodes_typed_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["request_id"], "test-1");
            assert_eq!(request["operation"], "ping");
            assert_eq!(request["payload"]["type"], "ping");
            writer
                .write_all(b"{\"type\":\"pong\",\"epoch\":7}\n")
                .unwrap();
        });

        let mut session = ProtocolSession::connect(&address.to_string(), "test").unwrap();
        assert_eq!(
            session.request(&CoordinatorRequest::Ping).unwrap(),
            CoordinatorResponse::Pong { epoch: 7 }
        );
        assert_eq!(session.requests(), 1);
        server.join().unwrap();
    }

    #[test]
    fn protocol_session_rejects_a_mismatched_error_request_id() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap();
            writeln!(
                writer,
                "{}",
                serde_json::to_value(CoordinatorResponse::error(
                    "another-request",
                    "request rejected"
                ))
                .unwrap()
            )
            .unwrap();
        });

        let mut session = ProtocolSession::connect(&address.to_string(), "test").unwrap();
        let error = session
            .request_allow_error(&CoordinatorRequest::Ping)
            .unwrap_err();
        assert!(matches!(error, ControlTransportError::Protocol(_)));
        assert!(error.to_string().contains("does not match test-1"));
        server.join().unwrap();
    }
}
