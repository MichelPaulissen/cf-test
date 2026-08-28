pub const COORDINATOR_PROTOCOL_VERSION: u64 = 1;
pub const COORDINATOR_WIRE_REQUEST_TYPE: &str = "coordinator_request";
pub const CONTROL_API_PATH: &str = "/api/v1/control";
pub const LOGIN_API_PATH: &str = "/api/v1/login";
// A compiler result can carry a bounded 4 MiB Wasm module plus base64 and
// metadata overhead. Keep one finite control-frame ceiling large enough for
// that appliance output without opening an unbounded request path.
// Hosted compiler results carry independently bounded execution and debug
// artifacts as base64 in one authenticated JSON response.
pub const MAX_CONTROL_FRAME_BYTES: usize = 16 * 1024 * 1024;
