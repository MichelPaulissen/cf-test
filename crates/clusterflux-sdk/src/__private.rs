#[cfg(target_arch = "wasm32")]
use serde::de::DeserializeOwned;

#[cfg(target_arch = "wasm32")]
use crate::TaskArg;

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn clusterflux_alloc_v1(length: u32) -> u32 {
    if length as usize > clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES {
        return 0;
    }
    let mut bytes = Vec::<u8>::with_capacity(length as usize);
    let pointer = bytes.as_mut_ptr() as usize;
    std::mem::forget(bytes);
    u32::try_from(pointer).unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task0_v1<R, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    R: TaskArg,
    F: FnOnce() -> R,
{
    invoke_task0_output(
        expected_task,
        input_pointer,
        input_length,
        || Ok(function()),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task0_result_v1<R, E, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    R: TaskArg,
    E: std::fmt::Display,
    F: FnOnce() -> Result<R, E>,
{
    invoke_task0_output(expected_task, input_pointer, input_length, || {
        function().map_err(|error| error.to_string())
    })
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task0_async_v1<R, F, Fut>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    R: TaskArg,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = R>,
{
    invoke_task0_output(expected_task, input_pointer, input_length, || {
        Ok(futures_executor::block_on(function()))
    })
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task0_async_result_v1<R, E, F, Fut>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    R: TaskArg,
    E: std::fmt::Display,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<R, E>>,
{
    invoke_task0_output(expected_task, input_pointer, input_length, || {
        futures_executor::block_on(function()).map_err(|error| error.to_string())
    })
}

#[cfg(target_arch = "wasm32")]
fn invoke_task0_output<R, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    R: TaskArg,
    F: FnOnce() -> Result<R, String>,
{
    let invocation = match decode_invocation(expected_task, input_pointer, input_length) {
        Ok(invocation) => invocation,
        Err(error) => return encode_result(failed_result(expected_task, error)),
    };
    if !invocation.args.is_empty() {
        return encode_result(failed_result(
            invocation.task_instance.clone(),
            format!(
                "task expected zero arguments but received {}",
                invocation.args.len()
            ),
        ));
    }
    let result = match function() {
        Ok(output) => match output.task_boundary_value() {
            Ok(result) => {
                clusterflux_core::WasmTaskResult::completed(invocation.task_instance, result)
            }
            Err(error) => clusterflux_core::WasmTaskResult::failed(
                invocation.task_instance,
                bounded_task_error(error.to_string()),
            ),
        },
        Err(error) => clusterflux_core::WasmTaskResult::failed(
            invocation.task_instance,
            bounded_task_error(error),
        ),
    };
    encode_result(result)
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task1_v1<A, R, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    A: TaskArg + DeserializeOwned,
    R: TaskArg,
    F: FnOnce(A) -> R,
{
    invoke_task1_output(expected_task, input_pointer, input_length, |argument| {
        Ok(function(argument))
    })
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task1_result_v1<A, R, E, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    A: TaskArg + DeserializeOwned,
    R: TaskArg,
    E: std::fmt::Display,
    F: FnOnce(A) -> Result<R, E>,
{
    invoke_task1_output(expected_task, input_pointer, input_length, |argument| {
        function(argument).map_err(|error| error.to_string())
    })
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task1_async_v1<A, R, F, Fut>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    A: TaskArg + DeserializeOwned,
    R: TaskArg,
    F: FnOnce(A) -> Fut,
    Fut: std::future::Future<Output = R>,
{
    invoke_task1_output(expected_task, input_pointer, input_length, |argument| {
        Ok(futures_executor::block_on(function(argument)))
    })
}

#[cfg(target_arch = "wasm32")]
pub fn invoke_task1_async_result_v1<A, R, E, F, Fut>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    A: TaskArg + DeserializeOwned,
    R: TaskArg,
    E: std::fmt::Display,
    F: FnOnce(A) -> Fut,
    Fut: std::future::Future<Output = Result<R, E>>,
{
    invoke_task1_output(expected_task, input_pointer, input_length, |argument| {
        futures_executor::block_on(function(argument)).map_err(|error| error.to_string())
    })
}

#[cfg(target_arch = "wasm32")]
fn invoke_task1_output<A, R, F>(
    expected_task: &str,
    input_pointer: u32,
    input_length: u32,
    function: F,
) -> u64
where
    A: TaskArg + DeserializeOwned,
    R: TaskArg,
    F: FnOnce(A) -> Result<R, String>,
{
    let invocation = match decode_invocation(expected_task, input_pointer, input_length) {
        Ok(invocation) => invocation,
        Err(error) => return encode_result(failed_result(expected_task, error)),
    };
    let [argument] = invocation.args.as_slice() else {
        return encode_result(failed_result(
            invocation.task_instance.clone(),
            format!(
                "task expected one argument but received {}",
                invocation.args.len()
            ),
        ));
    };
    let argument = match decode_boundary_value(argument.clone()) {
        Ok(argument) => argument,
        Err(error) => {
            return encode_result(clusterflux_core::WasmTaskResult::failed(
                invocation.task_instance,
                error,
            ))
        }
    };
    let result = match function(argument) {
        Ok(output) => match output.task_boundary_value() {
            Ok(result) => {
                clusterflux_core::WasmTaskResult::completed(invocation.task_instance, result)
            }
            Err(error) => clusterflux_core::WasmTaskResult::failed(
                invocation.task_instance,
                bounded_task_error(error.to_string()),
            ),
        },
        Err(error) => clusterflux_core::WasmTaskResult::failed(
            invocation.task_instance,
            bounded_task_error(error),
        ),
    };
    encode_result(result)
}

#[cfg(any(target_arch = "wasm32", test))]
fn bounded_task_error(error: String) -> String {
    const LIMIT: usize = 4 * 1024;
    const SEPARATOR: &str = "\n… [middle truncated]\n";
    if error.len() <= LIMIT {
        return error;
    }
    let available = LIMIT.saturating_sub(SEPARATOR.len());
    let mut head_end = available / 3;
    while !error.is_char_boundary(head_end) {
        head_end = head_end.saturating_sub(1);
    }
    let mut tail_start = error.len().saturating_sub(available - head_end);
    while tail_start < error.len() && !error.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!(
        "{}{}{}",
        &error[..head_end],
        SEPARATOR,
        &error[tail_start..]
    )
}

#[cfg(test)]
mod bounded_task_error_tests {
    use super::bounded_task_error;

    #[test]
    fn oversized_task_errors_preserve_context_and_root_cause() {
        let error = format!(
            "command failed: {}root cause: compiler image digest mismatch",
            "é".repeat(4_000)
        );
        let bounded = bounded_task_error(error);
        assert!(bounded.starts_with("command failed:"));
        assert!(bounded.contains("[middle truncated]"));
        assert!(bounded.ends_with("root cause: compiler image digest mismatch"));
        assert!(bounded.len() <= 4 * 1024);
    }
}

#[cfg(target_arch = "wasm32")]
fn decode_invocation(
    expected_task: &str,
    pointer: u32,
    length: u32,
) -> Result<clusterflux_core::WasmTaskInvocation, String> {
    if length as usize > clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES {
        return Err(format!(
            "task invocation exceeds {} byte ABI limit",
            clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES
        ));
    }
    if pointer == 0 && length != 0 {
        return Err("task invocation pointer is null".to_owned());
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, length as usize) };
    let invocation: clusterflux_core::WasmTaskInvocation =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    invocation.validate()?;
    if invocation.task_definition.as_str() != expected_task {
        return Err(format!(
            "task export `{expected_task}` received invocation for `{}`",
            invocation.task_definition
        ));
    }
    Ok(invocation)
}

#[cfg(target_arch = "wasm32")]
fn decode_boundary_value<T>(value: clusterflux_core::TaskBoundaryValue) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let value = match value {
        clusterflux_core::TaskBoundaryValue::SmallJson(value) => value,
        clusterflux_core::TaskBoundaryValue::Structured(structured) => structured.materialize()?,
        clusterflux_core::TaskBoundaryValue::SourceSnapshot(digest)
        | clusterflux_core::TaskBoundaryValue::Blob(digest)
        | clusterflux_core::TaskBoundaryValue::VfsManifest(digest) => {
            serde_json::json!({ "digest": digest })
        }
        clusterflux_core::TaskBoundaryValue::Artifact(artifact) => {
            serde_json::json!({
                "id": artifact.id,
                "digest": artifact.digest,
                "size_bytes": artifact.size_bytes,
            })
        }
    };
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[cfg(target_arch = "wasm32")]
fn failed_result(
    task_instance: impl Into<FailedTaskInstance>,
    error: impl Into<String>,
) -> clusterflux_core::WasmTaskResult {
    clusterflux_core::WasmTaskResult::failed(task_instance.into().0, error)
}

#[cfg(target_arch = "wasm32")]
struct FailedTaskInstance(clusterflux_core::TaskInstanceId);

#[cfg(target_arch = "wasm32")]
impl From<&str> for FailedTaskInstance {
    fn from(task_definition: &str) -> Self {
        Self(clusterflux_core::TaskInstanceId::new(format!(
            "invalid-invocation:{task_definition}"
        )))
    }
}

#[cfg(target_arch = "wasm32")]
impl From<clusterflux_core::TaskInstanceId> for FailedTaskInstance {
    fn from(task_instance: clusterflux_core::TaskInstanceId) -> Self {
        Self(task_instance)
    }
}

#[cfg(target_arch = "wasm32")]
fn encode_result(mut result: clusterflux_core::WasmTaskResult) -> u64 {
    let mut bytes = serde_json::to_vec(&result).unwrap_or_default();
    if bytes.len() > clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES {
        result = clusterflux_core::WasmTaskResult::failed(
            result.task_instance,
            format!(
                "task result exceeds {} byte ABI limit",
                clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES
            ),
        );
        bytes = serde_json::to_vec(&result).unwrap_or_default();
    }
    let length = bytes.len() as u32;
    let pointer = bytes.as_mut_ptr() as usize;
    let pointer = u32::try_from(pointer).unwrap_or(0);
    std::mem::forget(bytes);
    ((length as u64) << 32) | pointer as u64
}
std::thread_local! {
    static TASK_HANDLE_ENCODING: std::cell::RefCell<Option<Vec<clusterflux_core::TaskBoundaryHandle>>> =
        const { std::cell::RefCell::new(None) };
}

#[doc(hidden)]
pub trait CollectTaskHandles {}

#[doc(hidden)]
pub fn serialize_task_handle<S, F>(
    handle: clusterflux_core::TaskBoundaryHandle,
    serializer: S,
    serialize_plain: F,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    F: FnOnce(S) -> Result<S::Ok, S::Error>,
{
    TASK_HANDLE_ENCODING.with(|encoding| {
        let mut encoding = encoding.borrow_mut();
        let Some(handles) = encoding.as_mut() else {
            drop(encoding);
            return serialize_plain(serializer);
        };
        let index = handles.len();
        let kind = match &handle {
            clusterflux_core::TaskBoundaryHandle::SourceSnapshot(_) => "source_snapshot",
            clusterflux_core::TaskBoundaryHandle::Blob(_) => "blob",
            clusterflux_core::TaskBoundaryHandle::Artifact(_) => "artifact",
            clusterflux_core::TaskBoundaryHandle::VfsManifest(_) => "vfs_manifest",
        };
        handles.push(handle);
        serde::Serialize::serialize(
            &serde_json::json!({
                "$task_handle": {
                    "index": index,
                    "kind": kind,
                }
            }),
            serializer,
        )
    })
}

#[doc(hidden)]
pub fn structured_task_boundary<T>(
    value: &T,
) -> Result<clusterflux_core::TaskBoundaryValue, crate::TaskArgError>
where
    T: serde::Serialize + CollectTaskHandles + ?Sized,
{
    TASK_HANDLE_ENCODING.with(|encoding| {
        if encoding.borrow().is_some() {
            return Err(crate::TaskArgError::Serialization(
                "nested structured task argument encoding is not allowed".to_owned(),
            ));
        }
        *encoding.borrow_mut() = Some(Vec::new());
        let serialized = serde_json::to_value(value)
            .map_err(|error| crate::TaskArgError::Serialization(error.to_string()));
        let handles = encoding.borrow_mut().take().unwrap_or_default();
        let serialized = serialized?;
        let boundary = clusterflux_core::StructuredTaskBoundary {
            value: serialized,
            handles,
        };
        boundary
            .validate()
            .map_err(crate::TaskArgError::Serialization)?;
        Ok(clusterflux_core::TaskBoundaryValue::Structured(boundary))
    })
}

macro_rules! no_task_handles {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CollectTaskHandles for $ty {}
        )+
    };
}

no_task_handles!(
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

impl CollectTaskHandles for crate::SourceSnapshot {}
impl CollectTaskHandles for crate::Blob {}
impl CollectTaskHandles for crate::Artifact {}
impl CollectTaskHandles for crate::Vfs {}

impl<T> CollectTaskHandles for Option<T> where T: CollectTaskHandles {}

impl<T> CollectTaskHandles for Vec<T> where T: CollectTaskHandles {}
