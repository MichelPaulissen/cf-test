use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thiserror::Error;

use crate::{endpoint_identity, ControlSession};

pub type TransportFuture =
    Pin<Box<dyn Future<Output = Result<TransportResponse, ClientTransportError>> + Send + 'static>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRequest {
    pub api_path: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportResponse {
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ClientTransportError {
    #[error("client transport failed: {0}")]
    Failed(String),
    #[error("client transport task failed: {0}")]
    Task(String),
}

pub trait ClientTransport: Send + Sync + 'static {
    fn send(&self, request: TransportRequest) -> TransportFuture;
}

type ControlSessionPool = Arc<Vec<Mutex<Option<ControlSession>>>>;

pub struct ControlTransport {
    endpoint: String,
    connect_timeout: Duration,
    io_timeout: Duration,
    sessions: Arc<Mutex<BTreeMap<String, ControlSessionPool>>>,
    next_session: Arc<AtomicU64>,
}

// A small pool allows independent HTMX reads to progress concurrently while
// keeping connection and blocking-worker use strictly bounded.
const SESSIONS_PER_API_PATH: usize = 4;

impl ControlTransport {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, ClientTransportError> {
        Self::with_timeouts(endpoint, Duration::from_secs(10), Duration::from_secs(30))
    }

    pub fn with_timeouts(
        endpoint: impl Into<String>,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, ClientTransportError> {
        let endpoint = endpoint.into();
        endpoint_identity(&endpoint)
            .map_err(|error| ClientTransportError::Failed(error.to_string()))?;
        Ok(Self {
            endpoint,
            connect_timeout,
            io_timeout,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            next_session: Arc::new(AtomicU64::new(0)),
        })
    }
}

impl ClientTransport for ControlTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture {
        let endpoint = self.endpoint.clone();
        let connect_timeout = self.connect_timeout;
        let io_timeout = self.io_timeout;
        let sessions = Arc::clone(&self.sessions);
        let next_session = Arc::clone(&self.next_session);
        Box::pin(async move {
            let pool = {
                let mut sessions = sessions.lock().map_err(|_| {
                    ClientTransportError::Failed(
                        "client transport pool lock was poisoned".to_owned(),
                    )
                })?;
                Arc::clone(sessions.entry(request.api_path.clone()).or_insert_with(|| {
                    Arc::new(
                        (0..SESSIONS_PER_API_PATH)
                            .map(|_| Mutex::new(None))
                            .collect(),
                    )
                }))
            };
            let slot_index =
                next_session.fetch_add(1, Ordering::Relaxed) as usize % SESSIONS_PER_API_PATH;
            tokio::task::spawn_blocking(move || {
                let mut selected = None;
                for offset in 0..SESSIONS_PER_API_PATH {
                    let index = (slot_index + offset) % SESSIONS_PER_API_PATH;
                    match pool[index].try_lock() {
                        Ok(session) if session.is_some() => {
                            selected = Some(session);
                            break;
                        }
                        Ok(_) | Err(std::sync::TryLockError::WouldBlock) => {}
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            return Err(ClientTransportError::Failed(
                                "client transport session lock was poisoned".to_owned(),
                            ));
                        }
                    }
                }
                if selected.is_none() {
                    for offset in 0..SESSIONS_PER_API_PATH {
                        let index = (slot_index + offset) % SESSIONS_PER_API_PATH;
                        match pool[index].try_lock() {
                            Ok(session) => {
                                selected = Some(session);
                                break;
                            }
                            Err(std::sync::TryLockError::WouldBlock) => {}
                            Err(std::sync::TryLockError::Poisoned(_)) => {
                                return Err(ClientTransportError::Failed(
                                    "client transport session lock was poisoned".to_owned(),
                                ));
                            }
                        }
                    }
                }
                let mut session = match selected {
                    Some(session) => session,
                    None => pool[slot_index].lock().map_err(|_| {
                        ClientTransportError::Failed(
                            "client transport session lock was poisoned".to_owned(),
                        )
                    })?,
                };
                if session.is_none() {
                    *session = Some(
                        ControlSession::connect_to_api_path_with_timeouts(
                            &endpoint,
                            &request.api_path,
                            connect_timeout,
                            io_timeout,
                        )
                        .map_err(|error| ClientTransportError::Failed(error.to_string()))?,
                    );
                }
                let response = session
                    .as_mut()
                    .expect("session was initialized for the requested API path")
                    .request_bytes(&request.body);
                match response {
                    Ok(body) => Ok(TransportResponse { body }),
                    Err(error) => {
                        *session = None;
                        Err(ClientTransportError::Failed(error.to_string()))
                    }
                }
            })
            .await
            .map_err(|error| ClientTransportError::Task(error.to_string()))?
        })
    }
}

#[derive(Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<MockTransportState>>,
}

#[derive(Default)]
struct MockTransportState {
    responses: VecDeque<Result<Vec<u8>, ClientTransportError>>,
    requests: Vec<TransportRequest>,
}

impl MockTransport {
    pub fn from_json_responses(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let responses = responses
            .into_iter()
            .map(|response| Ok(response.into().into_bytes()))
            .collect();
        Self {
            state: Arc::new(Mutex::new(MockTransportState {
                responses,
                requests: Vec::new(),
            })),
        }
    }

    pub fn push_json_response(&self, response: impl Into<String>) {
        self.state
            .lock()
            .expect("mock transport lock is not poisoned")
            .responses
            .push_back(Ok(response.into().into_bytes()));
    }

    pub fn push_error(&self, message: impl Into<String>) {
        self.state
            .lock()
            .expect("mock transport lock is not poisoned")
            .responses
            .push_back(Err(ClientTransportError::Failed(message.into())));
    }

    pub fn request_bodies(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock transport lock is not poisoned")
            .requests
            .iter()
            .map(|request| String::from_utf8_lossy(&request.body).into_owned())
            .collect()
    }

    pub fn requests(&self) -> Vec<TransportRequest> {
        self.state
            .lock()
            .expect("mock transport lock is not poisoned")
            .requests
            .clone()
    }
}

impl ClientTransport for MockTransport {
    fn send(&self, request: TransportRequest) -> TransportFuture {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().map_err(|_| {
                ClientTransportError::Failed("mock transport lock was poisoned".to_owned())
            })?;
            state.requests.push(request);
            state
                .responses
                .pop_front()
                .ok_or_else(|| {
                    ClientTransportError::Failed("mock transport has no queued response".to_owned())
                })?
                .map(|body| TransportResponse { body })
        })
    }
}
