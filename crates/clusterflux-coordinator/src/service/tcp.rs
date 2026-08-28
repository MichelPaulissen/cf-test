use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clusterflux_protocol::MAX_CONTROL_FRAME_BYTES;

use super::{
    coordinator_service_error_response, CoordinatorRequest, CoordinatorResponse,
    CoordinatorService, CoordinatorServiceError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthorityMode {
    Strict,
    LocalTrustedLoopback,
}

impl CoordinatorService {
    pub fn serve_tcp(self, listener: TcpListener) -> Result<(), CoordinatorServiceError> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(CoordinatorServiceError::Protocol(
                "the native coordinator transport is plaintext and restricted to loopback; expose a remote coordinator only through a secure transport"
                    .to_owned(),
            ));
        }
        self.serve_tcp_with_authority(listener, ClientAuthorityMode::Strict)
    }

    pub fn serve_tcp_local_trusted(
        self,
        listener: TcpListener,
    ) -> Result<(), CoordinatorServiceError> {
        if !listener.local_addr()?.ip().is_loopback() {
            return Err(CoordinatorServiceError::Protocol(
                "local trusted request mode is restricted to a loopback listener".to_owned(),
            ));
        }
        self.serve_tcp_with_authority(listener, ClientAuthorityMode::LocalTrustedLoopback)
    }

    pub fn serve_tcp_with_relay_callback(
        self,
        listener: TcpListener,
        relay_callback_listener: TcpListener,
        relay_callback_bearer: String,
    ) -> Result<(), CoordinatorServiceError> {
        self.serve_tcp_with_authority_and_relay_callback(
            listener,
            ClientAuthorityMode::Strict,
            Some((relay_callback_listener, relay_callback_bearer)),
        )
    }

    pub fn serve_tcp_local_trusted_with_relay_callback(
        self,
        listener: TcpListener,
        relay_callback_listener: TcpListener,
        relay_callback_bearer: String,
    ) -> Result<(), CoordinatorServiceError> {
        self.serve_tcp_with_authority_and_relay_callback(
            listener,
            ClientAuthorityMode::LocalTrustedLoopback,
            Some((relay_callback_listener, relay_callback_bearer)),
        )
    }

    fn serve_tcp_with_authority(
        self,
        listener: TcpListener,
        authority_mode: ClientAuthorityMode,
    ) -> Result<(), CoordinatorServiceError> {
        self.serve_tcp_with_authority_and_relay_callback(listener, authority_mode, None)
    }

    fn serve_tcp_with_authority_and_relay_callback(
        self,
        listener: TcpListener,
        authority_mode: ClientAuthorityMode,
        relay_callback: Option<(TcpListener, String)>,
    ) -> Result<(), CoordinatorServiceError> {
        let shared = Arc::new(Mutex::new(self));
        if let Some((relay_listener, bearer)) = relay_callback {
            if !relay_listener.local_addr()?.ip().is_loopback() {
                return Err(CoordinatorServiceError::Protocol(
                    "relay authorization callback listener must be restricted to loopback"
                        .to_owned(),
                ));
            }
            if bearer.is_empty() || bearer.len() > 4_096 {
                return Err(CoordinatorServiceError::Protocol(
                    "relay authorization callback bearer must be non-empty and bounded".to_owned(),
                ));
            }
            let relay_service = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("clusterflux-relay-authorization".to_owned())
                .spawn(move || {
                    for stream in relay_listener.incoming() {
                        match stream {
                            Ok(stream) => {
                                let relay_service = Arc::clone(&relay_service);
                                let bearer = bearer.clone();
                                std::thread::spawn(move || {
                                    if let Err(error) =
                                        handle_relay_callback_stream(relay_service, stream, &bearer)
                                    {
                                        eprintln!("relay authorization callback failed: {error}");
                                    }
                                });
                            }
                            Err(error) => {
                                eprintln!("relay authorization listener failed: {error}");
                                break;
                            }
                        }
                    }
                })?;
        }
        for stream in listener.incoming() {
            let stream = stream?;
            let service = Arc::clone(&shared);
            std::thread::spawn(move || {
                if let Err(err) = handle_shared_stream(service, stream, authority_mode) {
                    eprintln!("coordinator stream failed: {err}");
                }
            });
        }
        Ok(())
    }

    pub fn handle_stream(&mut self, stream: TcpStream) -> Result<(), CoordinatorServiceError> {
        self.handle_stream_with_authority(stream, ClientAuthorityMode::Strict)
    }

    #[cfg(test)]
    pub(super) fn handle_stream_local_trusted(
        &mut self,
        stream: TcpStream,
    ) -> Result<(), CoordinatorServiceError> {
        self.handle_stream_with_authority(stream, ClientAuthorityMode::LocalTrustedLoopback)
    }

    fn handle_stream_with_authority(
        &mut self,
        stream: TcpStream,
        authority_mode: ClientAuthorityMode,
    ) -> Result<(), CoordinatorServiceError> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        loop {
            let Some(line) = read_control_line(&mut reader)? else {
                return Ok(());
            };
            if line.trim().is_empty() {
                continue;
            }
            let response = match decode_wire_request(&line) {
                Ok((request_id, request)) => {
                    match authorize_client_request(&request, authority_mode)
                        .and_then(|()| self.handle_request(request))
                    {
                        Ok(response) => response,
                        Err(err) => coordinator_service_error_response(request_id, &err),
                    }
                }
                Err(err) => coordinator_service_error_response(wire_request_id_hint(&line), &err),
            };
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
}

fn handle_relay_callback_stream(
    service: Arc<Mutex<CoordinatorService>>,
    mut stream: TcpStream,
    expected_bearer: &str,
) -> Result<(), CoordinatorServiceError> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_valid = request_line.trim_end() == "POST /internal/relay/authorize HTTP/1.1";
    let mut total = request_line.len();
    let mut authorization = None;
    let mut endpoint_id = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        total = total.saturating_add(line.len());
        if total > MAX_HEADER_BYTES {
            write_relay_callback_response(&mut stream, 413, None)?;
            return Ok(());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("x-iroh-endpoint-id") {
                endpoint_id = Some(value.trim().to_owned());
            }
        }
    }
    let expected_authorization = format!("Bearer {expected_bearer}");
    if !request_valid
        || !authorization
            .as_deref()
            .is_some_and(|provided| constant_time_eq(&expected_authorization, provided))
    {
        write_relay_callback_response(&mut stream, 403, None)?;
        return Ok(());
    }
    let scope = match endpoint_id {
        Some(endpoint_id) if !endpoint_id.is_empty() && endpoint_id.len() <= 128 => service
            .lock()
            .map_err(|_| {
                CoordinatorServiceError::Protocol(
                    "coordinator relay authorization lock was poisoned".to_owned(),
                )
            })?
            .authorized_relay_endpoint_scope(&endpoint_id)?,
        _ => None,
    };
    write_relay_callback_response(
        &mut stream,
        200,
        scope.as_ref().map(|scope| scope.tenant.as_str()),
    )
}

fn write_relay_callback_response(
    stream: &mut TcpStream,
    status: u16,
    tenant: Option<&str>,
) -> Result<(), CoordinatorServiceError> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        413 => "Content Too Large",
        _ => "Error",
    };
    let body = serde_json::to_string(&serde_json::json!({
        "allowed": tenant.is_some(),
        "tenant": tenant,
        // The relay performs an uncached live check every second. This brief cache
        // only absorbs simultaneous connection attempts for the same EndpointId.
        "valid_for_ms": tenant.map(|_| 1_000_u64),
    }))?;
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;
    Ok(())
}

fn constant_time_eq(expected: &str, provided: &str) -> bool {
    let maximum = expected.len().max(provided.len());
    let mut difference = expected.len() ^ provided.len();
    for index in 0..maximum {
        difference |= usize::from(
            expected.as_bytes().get(index).copied().unwrap_or_default()
                ^ provided.as_bytes().get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn handle_shared_stream(
    service: Arc<Mutex<CoordinatorService>>,
    stream: TcpStream,
    authority_mode: ClientAuthorityMode,
) -> Result<(), CoordinatorServiceError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    loop {
        let Some(line) = read_control_line(&mut reader)? else {
            return Ok(());
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match decode_wire_request(&line) {
            Ok((request_id, request)) => match authorize_client_request(&request, authority_mode) {
                Ok(()) => match service.lock() {
                    Ok(mut service) => match service.handle_request(request) {
                        Ok(response) => response,
                        Err(err) => coordinator_service_error_response(request_id, &err),
                    },
                    Err(_) => {
                        CoordinatorResponse::error(request_id, "coordinator service lock poisoned")
                    }
                },
                Err(err) => coordinator_service_error_response(request_id, &err),
            },
            Err(err) => coordinator_service_error_response(wire_request_id_hint(&line), &err),
        };
        serde_json::to_writer(&mut writer, &response)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
}

fn read_control_line(reader: &mut impl BufRead) -> Result<Option<String>, CoordinatorServiceError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CONTROL_FRAME_BYTES + 2) as u64)
        .read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let content_bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if content_bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(CoordinatorServiceError::Protocol(format!(
            "coordinator control frame exceeds {MAX_CONTROL_FRAME_BYTES} bytes"
        )));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        CoordinatorServiceError::Protocol("coordinator control frame is not valid UTF-8".to_owned())
    })
}

pub fn bind_listener(addr: &str) -> Result<(TcpListener, SocketAddr), CoordinatorServiceError> {
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

fn decode_wire_request(
    line: &str,
) -> Result<(String, CoordinatorRequest), CoordinatorServiceError> {
    serde_json::from_str::<super::CoordinatorWireRequest>(line)?
        .into_parts()
        .map_err(CoordinatorServiceError::Protocol)
}

fn wire_request_id_hint(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| {
            value
                .get("request_id")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .filter(|request_id| clusterflux_core::RequestId::try_new(request_id.clone()).is_ok())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn authorize_client_request(
    request: &CoordinatorRequest,
    authority_mode: ClientAuthorityMode,
) -> Result<(), CoordinatorServiceError> {
    if authority_mode == ClientAuthorityMode::LocalTrustedLoopback {
        return Ok(());
    }
    match request {
        CoordinatorRequest::Ping
        | CoordinatorRequest::Authenticated { .. }
        | CoordinatorRequest::ExchangeNodeEnrollmentGrant { .. }
        | CoordinatorRequest::SignedNode { .. }
        | CoordinatorRequest::NodeHeartbeat {
            node_signature: Some(_),
            ..
        }
        | CoordinatorRequest::StartProcess {
            actor_agent: Some(_),
            agent_signature: Some(_),
            ..
        }
        | CoordinatorRequest::LaunchTask {
            actor_agent: Some(_),
            agent_signature: Some(_),
            ..
        }
        | CoordinatorRequest::AdminStatus { .. }
        | CoordinatorRequest::SuspendTenant { .. } => Ok(()),
        _ => Err(crate::CoordinatorError::Unauthorized(
            "strict Core Client authority requires an authenticated CLI session, signed Agent, signed Node, enrollment grant exchange, or admin credential; request-body identity fields are not authority"
                .to_owned(),
        )
        .into()),
    }
}

#[cfg(test)]
mod transport_boundary_tests {
    use std::io::{BufRead as _, BufReader, Cursor};

    use clusterflux_core::{ProjectId, TenantId, UserId};
    use clusterflux_protocol::{coordinator_wire_request, AuthenticatedCoordinatorRequest};

    use super::*;

    #[test]
    fn native_control_frame_read_is_bounded_before_json_decoding() {
        let maximum = vec![b'x'; MAX_CONTROL_FRAME_BYTES];
        assert_eq!(
            read_control_line(&mut Cursor::new(maximum))
                .unwrap()
                .unwrap()
                .len(),
            MAX_CONTROL_FRAME_BYTES
        );

        let oversized = vec![b'x'; MAX_CONTROL_FRAME_BYTES + 1];
        let error = read_control_line(&mut Cursor::new(oversized))
            .unwrap_err()
            .to_string();
        assert!(error.contains("control frame exceeds"));
    }

    #[test]
    fn native_plaintext_service_refuses_non_loopback_listener() {
        let (listener, _) = bind_listener("0.0.0.0:0").unwrap();
        let error = CoordinatorService::new(1).serve_tcp(listener).unwrap_err();
        assert!(error.to_string().contains("restricted to loopback"));
    }

    #[test]
    fn malformed_identifiers_are_rejected_before_the_shared_service_lock_and_do_not_poison_it() {
        let (listener, addr) = bind_listener("127.0.0.1:0").unwrap();
        let mut coordinator = CoordinatorService::new(11);
        coordinator
            .issue_cli_session(
                TenantId::from("tenant"),
                ProjectId::from("project"),
                UserId::from("user"),
                "healthy-session",
                None,
            )
            .unwrap();
        let shared = Arc::new(Mutex::new(coordinator));
        let server_shared = Arc::clone(&shared);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_shared_stream(server_shared, stream, ClientAuthorityMode::Strict).unwrap();
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for (index, malformed_process) in [
            String::new(),
            "   ".to_owned(),
            "bad\0process".to_owned(),
            "bad process!".to_owned(),
            "x".repeat(clusterflux_core::MAX_EXTERNAL_ID_BYTES + 1),
        ]
        .into_iter()
        .enumerate()
        {
            let malformed = coordinator_wire_request(
                format!("malformed-{index}"),
                CoordinatorRequest::Authenticated {
                    session_secret: "healthy-session".to_owned(),
                    request: AuthenticatedCoordinatorRequest::AbortProcess {
                        process: malformed_process,
                        launch_attempt: Some("valid-attempt".to_owned()),
                    },
                },
            );
            serde_json::to_writer(&mut stream, &malformed).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let CoordinatorResponse::Error { error } =
                serde_json::from_str::<CoordinatorResponse>(&line).unwrap()
            else {
                panic!("malformed identifier request unexpectedly succeeded");
            };
            assert!(
                error.message.contains("malformed external identifier")
                    && error.message.contains("request.request.process"),
                "unexpected malformed identifier response: {}",
                error.message
            );
            assert_eq!(error.request_id, format!("malformed-{index}"));
            assert_eq!(error.code, clusterflux_core::ApiErrorCode::ValidationError);

            let valid = coordinator_wire_request(
                format!("healthy-{index}"),
                CoordinatorRequest::Authenticated {
                    session_secret: "healthy-session".to_owned(),
                    request: AuthenticatedCoordinatorRequest::AuthStatus,
                },
            );
            serde_json::to_writer(&mut stream, &valid).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(
                matches!(
                    serde_json::from_str::<CoordinatorResponse>(&line).unwrap(),
                    CoordinatorResponse::AuthStatus {
                        authenticated: true,
                        ..
                    }
                ),
                "valid authenticated traffic failed after malformed request {index}"
            );
        }

        stream.shutdown(std::net::Shutdown::Both).unwrap();
        server.join().unwrap();
        assert!(!shared.is_poisoned());
    }
}
