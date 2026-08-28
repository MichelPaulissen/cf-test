#[cfg(test)]
use clusterflux_client::endpoint_identity;
use clusterflux_client::{ClusterfluxClient, ControlTransport};
use clusterflux_client::{ControlTransportError, ProtocolSession};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use std::time::Duration;

pub(crate) struct CoordinatorSession {
    inner: ProtocolSession,
    endpoint: String,
    reconnect_max_delay: Option<Duration>,
    requests: usize,
    connection_generation: u64,
}

#[derive(Clone)]
pub(crate) struct AsyncCoordinatorSession {
    inner: ClusterfluxClient,
}

impl AsyncCoordinatorSession {
    pub(crate) fn connect_with_timeouts(
        addr: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, String> {
        let transport = ControlTransport::with_timeouts(addr, connect_timeout, io_timeout)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            inner: ClusterfluxClient::with_transport(transport),
        })
    }

    pub(crate) async fn request(
        &self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, String> {
        self.inner
            .send_coordinator_request(request)
            .await
            .map_err(|error| error.to_string())
    }
}

impl CoordinatorSession {
    #[cfg(test)]
    pub(crate) fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: ProtocolSession::connect(addr, "node")?,
            endpoint: addr.to_owned(),
            reconnect_max_delay: None,
            requests: 0,
            connection_generation: 0,
        })
    }

    pub(crate) fn connect_with_retries(
        addr: &str,
        reconnect_max_delay: Option<Duration>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: ProtocolSession::connect(addr, "node")?,
            endpoint: addr.to_owned(),
            reconnect_max_delay,
            requests: 0,
            connection_generation: 0,
        })
    }

    pub(crate) fn connect_with_timeouts(
        addr: &str,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: ProtocolSession::connect_with_timeouts(
                addr,
                "node",
                connect_timeout,
                io_timeout,
            )?,
            endpoint: addr.to_owned(),
            reconnect_max_delay: None,
            requests: 0,
            connection_generation: 0,
        })
    }

    pub(crate) fn request(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, Box<dyn std::error::Error>> {
        if self.reconnect_max_delay.is_some()
            && matches!(
                request,
                CoordinatorRequest::SignedNode { .. }
                    | CoordinatorRequest::NodeHeartbeat {
                        node_signature: Some(_),
                        ..
                    }
            )
        {
            return Err(
                "signed node requests must use request_signed so every retry gets a fresh nonce"
                    .into(),
            );
        }
        self.request_with(|| Ok(request.clone()))
    }

    pub(crate) fn request_signed<F>(
        &mut self,
        mut request: F,
    ) -> Result<CoordinatorResponse, Box<dyn std::error::Error>>
    where
        F: FnMut() -> Result<CoordinatorRequest, Box<dyn std::error::Error>>,
    {
        self.request_with(|| {
            let request = request()?;
            if !matches!(request, CoordinatorRequest::SignedNode { .. }) {
                return Err("request_signed factory returned an unsigned request".into());
            }
            Ok(request)
        })
    }

    fn request_with<F>(
        &mut self,
        mut request: F,
    ) -> Result<CoordinatorResponse, Box<dyn std::error::Error>>
    where
        F: FnMut() -> Result<CoordinatorRequest, Box<dyn std::error::Error>>,
    {
        let Some(max_delay) = self.reconnect_max_delay else {
            let response = self.inner.request_allow_error(&request()?)?;
            self.requests = self.requests.saturating_add(1);
            return match response {
                CoordinatorResponse::Error { error } => Err(Box::new(error)),
                response => Ok(response),
            };
        };
        let mut base_delay = Duration::from_secs(1).min(max_delay);
        let mut attempt = 0_u64;
        loop {
            match self.inner.request_allow_error(&request()?) {
                Ok(CoordinatorResponse::Error { error }) => {
                    self.requests = self.requests.saturating_add(1);
                    return Err(Box::new(error));
                }
                Ok(response) => {
                    self.requests = self.requests.saturating_add(1);
                    return Ok(response);
                }
                Err(error) if retryable_transport_error(&error) => {
                    self.requests = self.requests.saturating_add(1);
                    let mut error = error.to_string();
                    loop {
                        let delay = jittered_reconnect_delay(base_delay, max_delay, attempt);
                        eprintln!(
                            "Coordinator temporarily unavailable ({error}); retrying in {:.1}s. Set --coordinator-reconnect-max-seconds 0 to disable retries.",
                            delay.as_secs_f64()
                        );
                        std::thread::sleep(delay);
                        base_delay = base_delay.saturating_mul(2).min(max_delay);
                        attempt = attempt.saturating_add(1);
                        match ProtocolSession::connect(&self.endpoint, "node") {
                            Ok(session) => {
                                self.inner = session;
                                self.connection_generation =
                                    self.connection_generation.saturating_add(1);
                                break;
                            }
                            Err(reconnect_error) if retryable_transport_error(&reconnect_error) => {
                                error = reconnect_error.to_string();
                            }
                            Err(reconnect_error) => return Err(reconnect_error.into()),
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(crate) fn request_signed_heartbeat<F>(
        &mut self,
        mut request: F,
    ) -> Result<CoordinatorResponse, Box<dyn std::error::Error>>
    where
        F: FnMut() -> Result<CoordinatorRequest, Box<dyn std::error::Error>>,
    {
        self.request_with(|| {
            let request = request()?;
            if !matches!(
                request,
                CoordinatorRequest::NodeHeartbeat {
                    node_signature: Some(_),
                    ..
                }
            ) {
                return Err("signed heartbeat factory returned a non-heartbeat request".into());
            }
            Ok(request)
        })
    }

    pub(crate) fn requests(&self) -> usize {
        self.requests
    }

    pub(crate) fn connection_generation(&self) -> u64 {
        self.connection_generation
    }
}

fn retryable_transport_error(error: &ControlTransportError) -> bool {
    match error {
        ControlTransportError::Io(_)
        | ControlTransportError::Json(_)
        | ControlTransportError::Http(_)
        | ControlTransportError::Closed => true,
        ControlTransportError::HttpStatus { status, .. } => {
            matches!(*status, 408 | 425 | 429 | 500..=599)
        }
        ControlTransportError::InvalidEndpoint(_)
        | ControlTransportError::InsecureRemote(_)
        | ControlTransportError::Protocol(_)
        | ControlTransportError::FrameTooLarge
        | ControlTransportError::Coordinator(_)
        | ControlTransportError::UnavailableInWasm => false,
    }
}

fn jittered_reconnect_delay(base: Duration, maximum: Duration, attempt: u64) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::from(duration.subsec_nanos()))
        .unwrap_or(0);
    let entropy = nanos ^ u64::from(std::process::id()).rotate_left(17) ^ attempt.rotate_left(31);
    let permille = 500 + entropy % 1_001;
    let millis = base.as_millis().saturating_mul(u128::from(permille)) / 1_000;
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX)).min(maximum)
}

#[cfg(test)]
pub(crate) fn control_endpoint_identity(
    endpoint: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(endpoint_identity(endpoint)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut content_length = 0_usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line
                .strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
            {
                content_length = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        body
    }

    #[test]
    fn reconnect_jitter_is_bounded_and_grows_with_the_base() {
        for attempt in 0..100 {
            let delay =
                jittered_reconnect_delay(Duration::from_secs(8), Duration::from_secs(60), attempt);
            assert!(delay >= Duration::from_secs(4));
            assert!(delay <= Duration::from_secs(12));
        }
        let capped = jittered_reconnect_delay(Duration::from_secs(60), Duration::from_secs(60), 1);
        assert!(capped >= Duration::from_secs(30));
        assert!(capped <= Duration::from_secs(60));
    }

    #[test]
    fn only_transient_transport_failures_are_retried() {
        assert!(retryable_transport_error(
            &ControlTransportError::HttpStatus {
                status: 502,
                status_text: "Bad Gateway".to_owned(),
                retry_after: None,
            }
        ));
        assert!(!retryable_transport_error(
            &ControlTransportError::Coordinator("node identity is not enrolled".to_owned())
        ));
    }

    #[test]
    fn coordinator_api_errors_remain_typed_for_worker_recovery() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            let body = br#"{"type":"error","code":"no_capable_node","category":"availability","message":"node has no capability report","retryable":true,"request_id":"node-1"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let mut session = CoordinatorSession::connect(&endpoint).unwrap();
        let error = session
            .request(CoordinatorRequest::Ping)
            .expect_err("coordinator API error must remain an error");
        let api_error = error
            .downcast_ref::<clusterflux_core::ApiError>()
            .unwrap_or_else(|| panic!("coordinator API error lost its typed code: {error:?}"));
        assert_eq!(
            api_error.code,
            clusterflux_core::ApiErrorCode::NoCapableNode
        );
        server.join().unwrap();
    }

    #[test]
    fn bad_gateway_is_retried_without_terminating_the_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let first_body = read_http_request(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();

            let (mut second, _) = listener.accept().unwrap();
            let second_body = read_http_request(&mut second);
            let body = br#"{"type":"node_heartbeat","node":"node","epoch":1}"#;
            write!(
                second,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            second.write_all(body).unwrap();
            (first_body, second_body)
        });
        let mut session =
            CoordinatorSession::connect_with_retries(&endpoint, Some(Duration::from_millis(1)))
                .unwrap();

        let builds = std::cell::Cell::new(0_u8);
        let response = session
            .request_signed_heartbeat(|| {
                let build = builds.get().saturating_add(1);
                builds.set(build);
                Ok(CoordinatorRequest::NodeHeartbeat {
                    tenant: "tenant".to_owned(),
                    project: "project".to_owned(),
                    node: "node".to_owned(),
                    node_signature: Some(clusterflux_core::NodeSignedRequest {
                        nonce: format!("heartbeat-{build}"),
                        issued_at_epoch_seconds: 1,
                        signature: "signature".to_owned(),
                        assignment_authority: None,
                        operation_id: None,
                    }),
                })
            })
            .unwrap();

        let (first, second) = server.join().unwrap();
        assert!(matches!(
            response,
            CoordinatorResponse::NodeHeartbeat { .. }
        ));
        assert_eq!(session.requests(), 2);
        assert_eq!(session.connection_generation(), 1);
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(first["payload"]["node_signature"]["nonce"], "heartbeat-1");
        assert_eq!(second["payload"]["node_signature"]["nonce"], "heartbeat-2");
    }

    #[test]
    fn retry_factory_rebuilds_a_request_after_response_loss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let first_body = read_http_request(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let (mut second, _) = listener.accept().unwrap();
            let second_body = read_http_request(&mut second);
            let body = br#"{"type":"node_heartbeat","node":"node","epoch":1}"#;
            write!(
                second,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            second.write_all(body).unwrap();
            (first_body, second_body)
        });
        let mut session =
            CoordinatorSession::connect_with_retries(&endpoint, Some(Duration::from_millis(1)))
                .unwrap();
        let builds = std::cell::Cell::new(0_u8);
        session
            .request_signed(|| {
                let build = builds.get().saturating_add(1);
                builds.set(build);
                Ok(CoordinatorRequest::SignedNode {
                    node: "node".to_owned(),
                    node_signature: clusterflux_core::NodeSignedRequest {
                        nonce: format!("nonce-{build}"),
                        issued_at_epoch_seconds: 1,
                        signature: "signature".to_owned(),
                        assignment_authority: None,
                        operation_id: None,
                    },
                    request: Box::new(CoordinatorRequest::PollNodeAssignment {
                        tenant: "tenant".to_owned(),
                        project: "project".to_owned(),
                        node: "node".to_owned(),
                        accept_system_tasks: false,
                        accept_process_tasks: false,
                        active_assignment: None,
                    }),
                })
            })
            .unwrap();
        let (first, second) = server.join().unwrap();
        assert_eq!(builds.get(), 2);
        let first: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&second).unwrap();
        assert_eq!(first["payload"]["node_signature"]["nonce"], "nonce-1");
        assert_eq!(second["payload"]["node_signature"]["nonce"], "nonce-2");
        assert_eq!(first["payload"]["request"], second["payload"]["request"]);
    }

    #[test]
    fn reconnecting_session_rejects_pre_signed_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mut session =
            CoordinatorSession::connect_with_retries(&endpoint, Some(Duration::from_millis(1)))
                .unwrap();
        let error = session
            .request(CoordinatorRequest::SignedNode {
                node: "node".to_owned(),
                request: Box::new(CoordinatorRequest::Ping),
                node_signature: clusterflux_core::NodeSignedRequest {
                    nonce: "nonce".to_owned(),
                    issued_at_epoch_seconds: 1,
                    signature: "signature".to_owned(),
                    assignment_authority: None,
                    operation_id: None,
                },
            })
            .unwrap_err();
        assert!(error.to_string().contains("must use request_signed"));
    }
}
