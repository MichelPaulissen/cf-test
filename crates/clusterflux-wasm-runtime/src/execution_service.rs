use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;

use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinSet, LocalSet};

use super::*;

const DEFAULT_COMMAND_CAPACITY: usize = 256;
const DEFAULT_MODULE_CACHE_CAPACITY: usize = 64;
const DEFAULT_MAX_QUEUED_MODULE_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_QUEUED_INVOCATION_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_CACHED_MODULE_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_MAX_BLOCKING_THREADS: usize = 16;
pub const DEFAULT_MAX_RESIDENT_INVOCATIONS: usize = 1_024;
const DEFAULT_EPOCH_TICK: Duration = Duration::from_millis(10);
const MAX_COMMAND_CAPACITY: usize = 4_096;
const MAX_MODULE_CACHE_CAPACITY: usize = 1_024;
const MAX_LANE_BYTE_CAPACITY: usize = 8 * 1024 * 1024 * 1024;
const MAX_BLOCKING_THREADS: usize = 256;
const MAX_RESIDENT_INVOCATIONS: usize = 4_096;
const MODULE_COMPILER_THREAD_NAME: &str = "clusterflux-wc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmExecutionServiceConfiguration {
    pub thread_name: String,
    pub command_capacity: usize,
    pub module_cache_capacity: usize,
    pub max_queued_module_bytes: usize,
    pub max_queued_invocation_bytes: usize,
    pub max_cached_module_bytes: usize,
    pub max_blocking_threads: usize,
    pub max_resident_invocations: usize,
    pub fuel_yield_interval: u64,
    pub epoch_tick: Duration,
}

impl Default for WasmExecutionServiceConfiguration {
    fn default() -> Self {
        Self {
            thread_name: "clusterflux-wasm-lane".to_owned(),
            command_capacity: DEFAULT_COMMAND_CAPACITY,
            module_cache_capacity: DEFAULT_MODULE_CACHE_CAPACITY,
            max_queued_module_bytes: DEFAULT_MAX_QUEUED_MODULE_BYTES,
            max_queued_invocation_bytes: DEFAULT_MAX_QUEUED_INVOCATION_BYTES,
            max_cached_module_bytes: DEFAULT_MAX_CACHED_MODULE_BYTES,
            max_blocking_threads: DEFAULT_MAX_BLOCKING_THREADS,
            max_resident_invocations: DEFAULT_MAX_RESIDENT_INVOCATIONS,
            fuel_yield_interval: DEFAULT_ASYNC_FUEL_YIELD_INTERVAL,
            epoch_tick: DEFAULT_EPOCH_TICK,
        }
    }
}

impl WasmExecutionServiceConfiguration {
    fn validate(&self) -> Result<(), WasmTaskError> {
        if self.thread_name.trim().is_empty() || self.thread_name.len() > 63 {
            return Err(WasmTaskError::Runtime(
                "Wasm execution lane thread name must contain 1 to 63 bytes".to_owned(),
            ));
        }
        if self.command_capacity == 0 || self.command_capacity > MAX_COMMAND_CAPACITY {
            return Err(WasmTaskError::Runtime(format!(
                "Wasm execution lane command capacity must be between 1 and {MAX_COMMAND_CAPACITY}"
            )));
        }
        if self.module_cache_capacity == 0 || self.module_cache_capacity > MAX_MODULE_CACHE_CAPACITY
        {
            return Err(WasmTaskError::Runtime(format!(
                "Wasm module cache capacity must be between 1 and {MAX_MODULE_CACHE_CAPACITY}"
            )));
        }
        if self.max_queued_module_bytes == 0
            || self.max_queued_invocation_bytes == 0
            || self.max_cached_module_bytes == 0
            || self.max_queued_module_bytes > MAX_LANE_BYTE_CAPACITY
            || self.max_queued_invocation_bytes > MAX_LANE_BYTE_CAPACITY
            || self.max_cached_module_bytes > MAX_LANE_BYTE_CAPACITY
        {
            return Err(WasmTaskError::Runtime(
                "Wasm execution lane byte capacities are zero or exceed their safety ceiling"
                    .to_owned(),
            ));
        }
        if self.max_blocking_threads == 0 || self.max_blocking_threads > MAX_BLOCKING_THREADS {
            return Err(WasmTaskError::Runtime(format!(
                "Wasm execution lane blocking-thread limit must be between 1 and {MAX_BLOCKING_THREADS}"
            )));
        }
        if self.max_resident_invocations == 0
            || self.max_resident_invocations > MAX_RESIDENT_INVOCATIONS
        {
            return Err(WasmTaskError::Runtime(format!(
                "Wasm execution lane resident-invocation limit must be between 1 and {MAX_RESIDENT_INVOCATIONS}"
            )));
        }
        if self.fuel_yield_interval == 0 || self.epoch_tick.is_zero() {
            return Err(WasmTaskError::Runtime(
                "Wasm execution lane yield interval and epoch tick must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WasmExecutionServiceMetrics {
    pub submitted: u64,
    pub completed: u64,
    pub queued: usize,
    pub max_queued: usize,
    pub queued_module_bytes: usize,
    pub max_queued_module_bytes: usize,
    pub queued_invocation_bytes: usize,
    pub max_queued_invocation_bytes: usize,
    pub resident: usize,
    pub active: usize,
    pub max_active: usize,
    pub module_compilations: u64,
    pub module_cache_hits: u64,
    pub cached_modules: usize,
    pub cached_module_bytes: usize,
    pub module_registry_entries: usize,
    pub abort_signal_records: usize,
}

#[derive(Default)]
struct LaneMetrics {
    submitted: AtomicU64,
    completed: AtomicU64,
    queued: AtomicUsize,
    max_queued: AtomicUsize,
    queued_module_bytes: AtomicUsize,
    max_queued_module_bytes: AtomicUsize,
    queued_invocation_bytes: AtomicUsize,
    max_queued_invocation_bytes: AtomicUsize,
    resident: AtomicUsize,
    active: AtomicUsize,
    max_active: AtomicUsize,
    module_compilations: AtomicU64,
    module_cache_hits: AtomicU64,
    cached_modules: AtomicUsize,
    cached_module_bytes: AtomicUsize,
    abort_signal_records: AtomicUsize,
}

impl LaneMetrics {
    fn snapshot(&self) -> WasmExecutionServiceMetrics {
        WasmExecutionServiceMetrics {
            submitted: self.submitted.load(Ordering::Acquire),
            completed: self.completed.load(Ordering::Acquire),
            queued: self.queued.load(Ordering::Acquire),
            max_queued: self.max_queued.load(Ordering::Acquire),
            queued_module_bytes: self.queued_module_bytes.load(Ordering::Acquire),
            max_queued_module_bytes: self.max_queued_module_bytes.load(Ordering::Acquire),
            queued_invocation_bytes: self.queued_invocation_bytes.load(Ordering::Acquire),
            max_queued_invocation_bytes: self.max_queued_invocation_bytes.load(Ordering::Acquire),
            resident: self.resident.load(Ordering::Acquire),
            active: self.active.load(Ordering::Acquire),
            max_active: self.max_active.load(Ordering::Acquire),
            module_compilations: self.module_compilations.load(Ordering::Acquire),
            module_cache_hits: self.module_cache_hits.load(Ordering::Acquire),
            cached_modules: self.cached_modules.load(Ordering::Acquire),
            cached_module_bytes: self.cached_module_bytes.load(Ordering::Acquire),
            module_registry_entries: 0,
            abort_signal_records: self.abort_signal_records.load(Ordering::Acquire),
        }
    }

    fn try_admit(&self, maximum: usize) -> bool {
        let mut resident = self.resident.load(Ordering::Acquire);
        loop {
            if resident >= maximum {
                return false;
            }
            match self.resident.compare_exchange_weak(
                resident,
                resident + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(current) => resident = current,
            }
        }
    }

    fn cancel_admission(&self) {
        self.resident.fetch_sub(1, Ordering::AcqRel);
    }

    fn enqueue(&self, module_bytes: usize, invocation_bytes: usize) {
        let queued = self.queued.fetch_add(1, Ordering::AcqRel) + 1;
        let mut observed = self.max_queued.load(Ordering::Acquire);
        while queued > observed {
            match self.max_queued.compare_exchange_weak(
                observed,
                queued,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        reserve_metric(
            &self.queued_module_bytes,
            &self.max_queued_module_bytes,
            module_bytes,
        );
        reserve_metric(
            &self.queued_invocation_bytes,
            &self.max_queued_invocation_bytes,
            invocation_bytes,
        );
    }

    fn dequeue(&self, module_bytes: usize, invocation_bytes: usize) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
        self.queued_module_bytes
            .fetch_sub(module_bytes, Ordering::AcqRel);
        self.queued_invocation_bytes
            .fetch_sub(invocation_bytes, Ordering::AcqRel);
    }

    fn begin_invocation(&self) {
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        let mut observed = self.max_active.load(Ordering::Acquire);
        while active > observed {
            match self.max_active.compare_exchange_weak(
                observed,
                active,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
    }

    fn finish_invocation(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.resident.fetch_sub(1, Ordering::AcqRel);
        self.completed.fetch_add(1, Ordering::AcqRel);
    }

    fn finish_before_invocation(&self) {
        self.resident.fetch_sub(1, Ordering::AcqRel);
        self.completed.fetch_add(1, Ordering::AcqRel);
    }
}

fn reserve_metric(current: &AtomicUsize, maximum: &AtomicUsize, bytes: usize) {
    let current = current.fetch_add(bytes, Ordering::AcqRel) + bytes;
    let mut observed = maximum.load(Ordering::Acquire);
    while current > observed {
        match maximum.compare_exchange_weak(observed, current, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(value) => observed = value,
        }
    }
}

fn try_reserve(current: &AtomicUsize, maximum: usize, bytes: usize) -> bool {
    let mut observed = current.load(Ordering::Acquire);
    loop {
        let Some(next) = observed.checked_add(bytes) else {
            return false;
        };
        if next > maximum {
            return false;
        }
        match current.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(value) => observed = value,
        }
    }
}

struct InvocationGuard {
    metrics: Arc<LaneMetrics>,
}

impl Drop for InvocationGuard {
    fn drop(&mut self) {
        self.metrics.finish_invocation();
    }
}

struct SubmitCommand {
    module: Arc<[u8]>,
    queued_module_bytes: usize,
    queued_invocation_bytes: usize,
    bundle_digest: Digest,
    export: String,
    invocation: WasmTaskInvocation,
    runtime_limits: WasmtimeRuntimeLimits,
    host: Box<dyn AsyncWasmTaskHost>,
    abort: Option<Arc<AtomicBool>>,
    result: oneshot::Sender<Result<WasmTaskResult, WasmTaskError>>,
}

enum LaneCommand {
    Submit(SubmitCommand),
    Shutdown(std_mpsc::SyncSender<()>),
}

pub struct WasmExecution {
    result: oneshot::Receiver<Result<WasmTaskResult, WasmTaskError>>,
}

impl WasmExecution {
    pub async fn wait(self) -> Result<WasmTaskResult, WasmTaskError> {
        self.result.await.map_err(|_| {
            WasmTaskError::Runtime(
                "Wasm execution lane closed before returning the task result".to_owned(),
            )
        })?
    }

    pub fn blocking_wait(self) -> Result<WasmTaskResult, WasmTaskError> {
        self.result.blocking_recv().map_err(|_| {
            WasmTaskError::Runtime(
                "Wasm execution lane closed before returning the task result".to_owned(),
            )
        })?
    }

    pub fn try_result(&mut self) -> Option<Result<WasmTaskResult, WasmTaskError>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => Some(Err(WasmTaskError::Runtime(
                "Wasm execution lane closed before returning the task result".to_owned(),
            ))),
        }
    }
}

pub struct WasmExecutionService {
    sender: Option<mpsc::Sender<LaneCommand>>,
    lane_thread: Option<JoinHandle<()>>,
    metrics: Arc<LaneMetrics>,
    max_resident_invocations: usize,
    max_queued_module_bytes: usize,
    max_queued_invocation_bytes: usize,
    command_capacity: usize,
    max_module_registry_entries: usize,
    module_bytes: Mutex<BTreeMap<Digest, Weak<[u8]>>>,
}

impl WasmExecutionService {
    pub fn new(configuration: WasmExecutionServiceConfiguration) -> Result<Self, WasmTaskError> {
        configuration.validate()?;
        let (sender, receiver) = mpsc::channel(configuration.command_capacity);
        let (ready_sender, ready_receiver) = std_mpsc::sync_channel(1);
        let metrics = Arc::new(LaneMetrics::default());
        let lane_metrics = Arc::clone(&metrics);
        let max_resident_invocations = configuration.max_resident_invocations;
        let max_queued_module_bytes = configuration.max_queued_module_bytes;
        let max_queued_invocation_bytes = configuration.max_queued_invocation_bytes;
        let command_capacity = configuration.command_capacity;
        let max_module_registry_entries = configuration
            .command_capacity
            .saturating_add(configuration.max_resident_invocations);
        let thread_name = configuration.thread_name.clone();
        let lane_thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if let Err(error) =
                    run_lane(receiver, configuration, lane_metrics, ready_sender.clone())
                {
                    let _ = ready_sender.send(Err(error));
                }
            })
            .map_err(|error| {
                WasmTaskError::Runtime(format!("start Wasm execution lane thread: {error}"))
            })?;
        ready_receiver.recv().map_err(|_| {
            WasmTaskError::Runtime("Wasm execution lane exited before startup completed".to_owned())
        })??;
        Ok(Self {
            sender: Some(sender),
            lane_thread: Some(lane_thread),
            metrics,
            max_resident_invocations,
            max_queued_module_bytes,
            max_queued_invocation_bytes,
            command_capacity,
            max_module_registry_entries,
            module_bytes: Mutex::new(BTreeMap::new()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_task_export_verified(
        &self,
        module: Vec<u8>,
        bundle_digest: Digest,
        export: String,
        invocation: WasmTaskInvocation,
        runtime_limits: WasmtimeRuntimeLimits,
        host: Box<dyn AsyncWasmTaskHost>,
    ) -> Result<WasmExecution, WasmTaskError> {
        invocation.validate().map_err(WasmTaskError::TaskAbi)?;
        runtime_limits.validate()?;
        let actual = Digest::sha256(&module);
        if actual != bundle_digest {
            return Err(WasmTaskError::BundleDigestMismatch {
                expected: bundle_digest,
                actual,
            });
        }
        let sender = self.sender.as_ref().ok_or_else(|| {
            WasmTaskError::Runtime("Wasm execution lane is shutting down".to_owned())
        })?;
        if !self.metrics.try_admit(self.max_resident_invocations) {
            return Err(WasmTaskError::TemporaryCapacity {
                resource: "resident-invocation",
                limit: self.max_resident_invocations,
            });
        }
        let invocation_bytes = match serde_json::to_vec(&invocation) {
            Ok(bytes) => bytes.len(),
            Err(error) => {
                self.metrics.cancel_admission();
                return Err(WasmTaskError::TaskAbi(error.to_string()));
            }
        };
        let module = {
            let mut modules = match self.module_bytes.lock() {
                Ok(modules) => modules,
                Err(_) => {
                    self.metrics.cancel_admission();
                    return Err(WasmTaskError::Runtime(
                        "Wasm module-byte registry is unavailable".to_owned(),
                    ));
                }
            };
            modules.retain(|_, module| module.strong_count() > 0);
            if let Some(existing) = modules.get(&bundle_digest).and_then(Weak::upgrade) {
                existing
            } else {
                if modules.len() >= self.max_module_registry_entries {
                    self.metrics.cancel_admission();
                    return Err(WasmTaskError::TemporaryCapacity {
                        resource: "module-byte-registry",
                        limit: self.max_module_registry_entries,
                    });
                }
                let shared: Arc<[u8]> = Arc::from(module);
                modules.insert(bundle_digest.clone(), Arc::downgrade(&shared));
                shared
            }
        };
        let module_bytes = module.len();
        if !try_reserve(
            &self.metrics.queued_module_bytes,
            self.max_queued_module_bytes,
            module_bytes,
        ) {
            self.metrics.cancel_admission();
            return Err(WasmTaskError::TemporaryCapacity {
                resource: "queued-module-byte",
                limit: self.max_queued_module_bytes,
            });
        }
        if !try_reserve(
            &self.metrics.queued_invocation_bytes,
            self.max_queued_invocation_bytes,
            invocation_bytes,
        ) {
            self.metrics
                .queued_module_bytes
                .fetch_sub(module_bytes, Ordering::AcqRel);
            self.metrics.cancel_admission();
            return Err(WasmTaskError::TemporaryCapacity {
                resource: "queued-invocation-byte",
                limit: self.max_queued_invocation_bytes,
            });
        }
        let (result_sender, result) = oneshot::channel();
        let abort = host.abort_signal();
        self.metrics.enqueue(0, 0);
        if let Err(error) = sender.try_send(LaneCommand::Submit(SubmitCommand {
            module,
            queued_module_bytes: module_bytes,
            queued_invocation_bytes: invocation_bytes,
            bundle_digest,
            export,
            invocation,
            runtime_limits,
            host,
            abort,
            result: result_sender,
        })) {
            self.metrics.dequeue(module_bytes, invocation_bytes);
            self.metrics.cancel_admission();
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => WasmTaskError::TemporaryCapacity {
                    resource: "command-count",
                    limit: self.command_capacity,
                },
                mpsc::error::TrySendError::Closed(_) => {
                    WasmTaskError::Runtime("Wasm execution lane is unavailable".to_owned())
                }
            });
        }
        self.metrics.submitted.fetch_add(1, Ordering::AcqRel);
        Ok(WasmExecution { result })
    }

    pub fn metrics(&self) -> WasmExecutionServiceMetrics {
        let mut snapshot = self.metrics.snapshot();
        if let Ok(mut modules) = self.module_bytes.lock() {
            modules.retain(|_, module| module.strong_count() > 0);
            snapshot.module_registry_entries = modules.len();
        }
        snapshot
    }

    pub fn shutdown(&mut self) -> Result<(), WasmTaskError> {
        let Some(sender) = self.sender.take() else {
            return Ok(());
        };
        let (acknowledge, acknowledged) = std_mpsc::sync_channel(1);
        let mut command = LaneCommand::Shutdown(acknowledge);
        loop {
            match sender.try_send(command) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    command = returned;
                    std::thread::yield_now();
                }
                Err(mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
        drop(sender);
        let _ = acknowledged.recv_timeout(Duration::from_secs(5));
        if let Some(thread) = self.lane_thread.take() {
            thread.join().map_err(|_| {
                WasmTaskError::Runtime("Wasm execution lane thread panicked".to_owned())
            })?;
        }
        Ok(())
    }
}

impl Drop for WasmExecutionService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct ModuleCache {
    modules: BTreeMap<Digest, (Module, usize)>,
    order: VecDeque<Digest>,
    capacity: usize,
    maximum_bytes: usize,
    bytes: usize,
}

impl ModuleCache {
    fn new(capacity: usize, maximum_bytes: usize) -> Self {
        Self {
            modules: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
            maximum_bytes,
            bytes: 0,
        }
    }

    fn get(&mut self, digest: &Digest, metrics: &LaneMetrics) -> Option<Module> {
        if let Some((module, _)) = self.modules.get(digest).cloned() {
            self.order.retain(|retained| retained != digest);
            self.order.push_back(digest.clone());
            metrics.module_cache_hits.fetch_add(1, Ordering::AcqRel);
            return Some(module);
        }
        None
    }

    fn insert(
        &mut self,
        digest: Digest,
        module: Module,
        source_bytes: usize,
        metrics: &LaneMetrics,
    ) {
        while self.modules.len() >= self.capacity
            || self.bytes.saturating_add(source_bytes) > self.maximum_bytes
        {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if let Some((_, bytes)) = self.modules.remove(&evicted) {
                self.bytes = self.bytes.saturating_sub(bytes);
            }
        }
        if source_bytes <= self.maximum_bytes {
            self.bytes = self.bytes.saturating_add(source_bytes);
            self.modules.insert(digest.clone(), (module, source_bytes));
            self.order.push_back(digest);
        }
        metrics.module_compilations.fetch_add(1, Ordering::AcqRel);
        metrics
            .cached_modules
            .store(self.modules.len(), Ordering::Release);
        metrics
            .cached_module_bytes
            .store(self.bytes, Ordering::Release);
    }
}

struct CompileRequest {
    digest: Digest,
    bytes: Arc<[u8]>,
}

struct CompileResult {
    digest: Digest,
    source_bytes: usize,
    module: Result<Module, String>,
}

fn spawn_compiled_invocation(
    tasks: &mut JoinSet<()>,
    engine: &Engine,
    linker: &Rc<Linker<AsyncWasmtimeTaskHostState>>,
    module: Module,
    command: SubmitCommand,
    fuel_yield_interval: u64,
    metrics: &Arc<LaneMetrics>,
) {
    let engine = engine.clone();
    let linker = Rc::clone(linker);
    metrics.begin_invocation();
    let invocation_guard = InvocationGuard {
        metrics: Arc::clone(metrics),
    };
    tasks.spawn_local(async move {
        let result = run_task_export_module_with_task_host_async(
            &engine,
            &linker,
            &module,
            &command.export,
            &command.invocation,
            command.host,
            &command.runtime_limits,
            fuel_yield_interval,
        )
        .await;
        drop(invocation_guard);
        let _ = command.result.send(result);
    });
}

fn run_lane(
    receiver: mpsc::Receiver<LaneCommand>,
    configuration: WasmExecutionServiceConfiguration,
    metrics: Arc<LaneMetrics>,
    ready: std_mpsc::SyncSender<Result<(), WasmTaskError>>,
) -> Result<(), WasmTaskError> {
    let mut engine_configuration = Config::new();
    engine_configuration.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    engine_configuration.epoch_interruption(true);
    engine_configuration.consume_fuel(true);
    let engine = Engine::new(&engine_configuration).map_err(wasmtime_error)?;
    let compiler_engine = engine.clone();
    let (compile_sender, compile_receiver) = std_mpsc::sync_channel::<CompileRequest>(1);
    let (compiled_sender, compiled_receiver) = mpsc::unbounded_channel::<CompileResult>();
    let compiler = std::thread::Builder::new()
        .name(MODULE_COMPILER_THREAD_NAME.to_owned())
        .spawn(move || {
            while let Ok(request) = compile_receiver.recv() {
                let source_bytes = request.bytes.len();
                let module = Module::new(&compiler_engine, request.bytes.as_ref())
                    .map_err(|error| error.to_string());
                if compiled_sender
                    .send(CompileResult {
                        digest: request.digest,
                        source_bytes,
                        module,
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .map_err(|error| {
            WasmTaskError::Runtime(format!("start bounded Wasm compilation worker: {error}"))
        })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(configuration.max_blocking_threads)
        .build()
        .map_err(|error| {
            WasmTaskError::Runtime(format!("create Wasm lane Tokio runtime: {error}"))
        })?;
    let local_set = LocalSet::new();
    let result = local_set.block_on(
        &runtime,
        lane_loop(
            receiver,
            configuration,
            metrics,
            ready,
            engine,
            compile_sender.clone(),
            compiled_receiver,
        ),
    );
    drop(compile_sender);
    compiler
        .join()
        .map_err(|_| WasmTaskError::Runtime("Wasm compilation worker panicked".to_owned()))?;
    result
}

async fn lane_loop(
    mut receiver: mpsc::Receiver<LaneCommand>,
    configuration: WasmExecutionServiceConfiguration,
    metrics: Arc<LaneMetrics>,
    ready: std_mpsc::SyncSender<Result<(), WasmTaskError>>,
    engine: Engine,
    compile_sender: std_mpsc::SyncSender<CompileRequest>,
    mut compiled_receiver: mpsc::UnboundedReceiver<CompileResult>,
) -> Result<(), WasmTaskError> {
    let linker = Rc::new(async_task_host_linker(&engine)?);
    let mut cache = ModuleCache::new(
        configuration.module_cache_capacity,
        configuration.max_cached_module_bytes,
    );
    let mut tasks = JoinSet::new();
    let mut abort_signals = Vec::<Weak<AtomicBool>>::new();
    let max_abort_signals = configuration.max_resident_invocations;
    let mut compile_active = None::<Digest>;
    let mut compile_order = VecDeque::<Digest>::new();
    let mut compile_pending = BTreeMap::<Digest, Vec<SubmitCommand>>::new();
    let mut epoch_tick = tokio::time::interval(configuration.epoch_tick);
    epoch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = ready.send(Ok(()));

    loop {
        tokio::select! {
            command = receiver.recv() => {
                match command {
                    Some(LaneCommand::Submit(command)) => {
                        metrics.dequeue(
                            command.queued_module_bytes,
                            command.queued_invocation_bytes,
                        );
                        abort_signals.retain(|signal| signal.strong_count() > 0);
                        metrics
                            .abort_signal_records
                            .store(abort_signals.len(), Ordering::Release);
                        if let Some(abort) = &command.abort {
                            if abort_signals.len() >= max_abort_signals {
                                let _ = command.result.send(Err(WasmTaskError::TemporaryCapacity {
                                    resource: "abort-signal-registry",
                                    limit: max_abort_signals,
                                }));
                                metrics.finish_before_invocation();
                                continue;
                            }
                            abort_signals.push(Arc::downgrade(abort));
                            metrics
                                .abort_signal_records
                                .store(abort_signals.len(), Ordering::Release);
                        }
                        if let Some(module) = cache.get(&command.bundle_digest, &metrics) {
                            spawn_compiled_invocation(
                                &mut tasks,
                                &engine,
                                &linker,
                                module,
                                command,
                                configuration.fuel_yield_interval,
                                &metrics,
                            );
                            continue;
                        }
                        let digest = command.bundle_digest.clone();
                        let bytes = Arc::clone(&command.module);
                        let first = !compile_pending.contains_key(&digest);
                        compile_pending.entry(digest.clone()).or_default().push(command);
                        if first {
                            if compile_active.is_none() {
                                compile_sender.send(CompileRequest {
                                    digest: digest.clone(),
                                    bytes,
                                }).map_err(|_| WasmTaskError::Runtime(
                                    "Wasm compilation worker is unavailable".to_owned()
                                ))?;
                                compile_active = Some(digest);
                            } else {
                                compile_order.push_back(digest);
                            }
                        }
                    }
                    Some(LaneCommand::Shutdown(acknowledge)) => {
                        receiver.close();
                        for signal in abort_signals.iter().filter_map(Weak::upgrade) {
                            signal.store(true, Ordering::Release);
                        }
                        abort_signals.clear();
                        metrics.abort_signal_records.store(0, Ordering::Release);
                        for commands in compile_pending.values() {
                            for command in commands {
                                if let Some(signal) = &command.abort {
                                    signal.store(true, Ordering::Release);
                                }
                            }
                        }
                        let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                        while !tasks.is_empty() && tokio::time::Instant::now() < cleanup_deadline {
                            tokio::select! {
                                _ = tasks.join_next() => {}
                                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                                    engine.increment_epoch();
                                }
                            }
                        }
                        tasks.abort_all();
                        while tasks.join_next().await.is_some() {}
                        for (_, commands) in compile_pending {
                            for command in commands {
                                let _ = command.result.send(Err(WasmTaskError::Runtime(
                                    "Wasm execution lane shut down before compilation completed"
                                        .to_owned(),
                                )));
                                metrics.finish_before_invocation();
                            }
                        }
                        let _ = acknowledge.send(());
                        break;
                    }
                    None => {
                        tasks.abort_all();
                        while tasks.join_next().await.is_some() {}
                        break;
                    }
                }
            }
            _ = epoch_tick.tick() => {
                engine.increment_epoch();
                abort_signals.retain(|signal| signal.strong_count() > 0);
                metrics
                    .abort_signal_records
                    .store(abort_signals.len(), Ordering::Release);
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {
                abort_signals.retain(|signal| signal.strong_count() > 0);
                metrics
                    .abort_signal_records
                    .store(abort_signals.len(), Ordering::Release);
            }
            compiled = compiled_receiver.recv(), if compile_active.is_some() => {
                let Some(compiled) = compiled else {
                    return Err(WasmTaskError::Runtime(
                        "Wasm compilation worker closed unexpectedly".to_owned(),
                    ));
                };
                compile_active = None;
                let commands = compile_pending.remove(&compiled.digest).unwrap_or_default();
                match compiled.module {
                    Ok(module) => {
                        cache.insert(
                            compiled.digest,
                            module.clone(),
                            compiled.source_bytes,
                            &metrics,
                        );
                        for command in commands {
                            spawn_compiled_invocation(
                                &mut tasks,
                                &engine,
                                &linker,
                                module.clone(),
                                command,
                                configuration.fuel_yield_interval,
                                &metrics,
                            );
                        }
                    }
                    Err(error) => {
                        for command in commands {
                            let _ = command.result.send(Err(WasmTaskError::Runtime(format!(
                                "compile Wasm module: {error}"
                            ))));
                            metrics.finish_before_invocation();
                        }
                    }
                }
                if let Some(next) = compile_order.pop_front() {
                    let bytes = compile_pending
                        .get(&next)
                        .and_then(|commands| commands.first())
                        .map(|command| Arc::clone(&command.module))
                        .ok_or_else(|| WasmTaskError::Runtime(
                            "Wasm compilation queue lost its module bytes".to_owned(),
                        ))?;
                    compile_sender.send(CompileRequest {
                        digest: next.clone(),
                        bytes,
                    }).map_err(|_| WasmTaskError::Runtime(
                        "Wasm compilation worker is unavailable".to_owned(),
                    ))?;
                    compile_active = Some(next);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{TaskBoundaryValue, TaskDefinitionId};

    use super::*;

    struct TestHost {
        abort: Arc<AtomicBool>,
        gate: Option<oneshot::Receiver<()>>,
        thread_names: Arc<Mutex<Vec<String>>>,
    }

    impl TestHost {
        fn immediate() -> Self {
            Self {
                abort: Arc::new(AtomicBool::new(false)),
                gate: None,
                thread_names: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl AsyncWasmTaskHost for TestHost {
        fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
            Some(Arc::clone(&self.abort))
        }

        fn start_task(
            &mut self,
            _request: WasmHostTaskStartRequest,
        ) -> WasmHostFuture<'_, WasmHostTaskHandle> {
            Box::pin(async { Err("not used".to_owned()) })
        }

        fn join_task(
            &mut self,
            _request: WasmHostTaskJoinRequest,
        ) -> WasmHostFuture<'_, WasmHostTaskJoinResult> {
            Box::pin(async { Err("not used".to_owned()) })
        }

        fn run_command(
            &mut self,
            _request: WasmHostCommandRequest,
        ) -> WasmHostFuture<'_, WasmHostCommandResult> {
            Box::pin(async { Err("not used".to_owned()) })
        }

        fn poll_task_control(
            &mut self,
            request: WasmHostTaskControlRequest,
        ) -> WasmHostFuture<'_, WasmHostTaskControlResult> {
            let gate = self.gate.take();
            let thread_names = Arc::clone(&self.thread_names);
            Box::pin(async move {
                request.validate()?;
                thread_names
                    .lock()
                    .expect("test thread-name lock poisoned")
                    .push(
                        std::thread::current()
                            .name()
                            .unwrap_or("unnamed")
                            .to_owned(),
                    );
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
                Ok(WasmHostTaskControlResult {
                    abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                    cancellation_requested: false,
                })
            })
        }

        fn vfs_operation(
            &mut self,
            _request: WasmHostVfsRequest,
        ) -> WasmHostFuture<'_, WasmHostVfsResult> {
            Box::pin(async { Err("not used".to_owned()) })
        }

        fn snapshot_source(
            &mut self,
            _request: WasmHostSourceSnapshotRequest,
        ) -> WasmHostFuture<'_, WasmHostSourceSnapshotResult> {
            Box::pin(async { Err("not used".to_owned()) })
        }
    }

    fn invocation(task: &str) -> WasmTaskInvocation {
        WasmTaskInvocation::new(
            TaskDefinitionId::from("task"),
            TaskInstanceId::from(task),
            Vec::new(),
        )
    }

    fn completed_module(task: &str, host_control: bool) -> Vec<u8> {
        let result = serde_json::to_string(&WasmTaskResult::completed(
            TaskInstanceId::from(task),
            TaskBoundaryValue::SmallJson(serde_json::json!({ "task": task })),
        ))
        .unwrap();
        let result_data = result.replace('\\', "\\\\").replace('"', "\\\"");
        let request = serde_json::to_string(&WasmHostTaskControlRequest {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        })
        .unwrap();
        let request_data = request.replace('\\', "\\\\").replace('"', "\\\"");
        let packed = ((result.len() as u64) << 32) | 2_048;
        let host_import = host_control.then_some(
            r#"(import "clusterflux" "task_control_v1"
                    (func $task_control (param i32 i32 i32 i32) (result i32)))"#,
        );
        let host_call = host_control.then_some(format!(
            "i32.const 64 i32.const {} i32.const 4096 i32.const 1024 call $task_control drop",
            request.len()
        ));
        format!(
            r#"(module
                {}
                (memory (export "memory") 1)
                (data (i32.const 64) "{}")
                (data (i32.const 2048) "{}")
                (func (export "clusterflux_alloc_v1") (param i32) (result i32)
                  i32.const 1024)
                (func (export "task") (param i32 i32) (result i64)
                  {}
                  i64.const {}))"#,
            host_import.unwrap_or_default(),
            request_data,
            result_data,
            host_call.unwrap_or_default(),
            packed,
        )
        .into_bytes()
    }

    fn spinning_module() -> Vec<u8> {
        br#"(module
            (memory (export "memory") 1)
            (func (export "clusterflux_alloc_v1") (param i32) (result i32)
              i32.const 1024)
            (func (export "task") (param i32 i32) (result i64)
              (loop $forever br $forever)
              i64.const 0))"#
            .to_vec()
    }

    fn submit(
        service: &WasmExecutionService,
        module: Vec<u8>,
        invocation: WasmTaskInvocation,
        host: TestHost,
    ) -> WasmExecution {
        let digest = Digest::sha256(&module);
        service
            .submit_task_export_verified(
                module,
                digest,
                "task".to_owned(),
                invocation,
                WasmtimeRuntimeLimits::default(),
                Box::new(host),
            )
            .unwrap()
    }

    #[test]
    fn waiting_host_call_yields_and_reuses_one_lane_module() {
        let configuration = WasmExecutionServiceConfiguration {
            thread_name: "clusterflux-test-wasm-lane".to_owned(),
            ..WasmExecutionServiceConfiguration::default()
        };
        let mut service = WasmExecutionService::new(configuration).unwrap();
        let module = completed_module("shared-task", true);
        let (release, gate) = oneshot::channel();
        let thread_names = Arc::new(Mutex::new(Vec::new()));
        let waiting = submit(
            &service,
            module.clone(),
            invocation("shared-task"),
            TestHost {
                abort: Arc::new(AtomicBool::new(false)),
                gate: Some(gate),
                thread_names: Arc::clone(&thread_names),
            },
        );
        let ready = submit(
            &service,
            module,
            invocation("shared-task"),
            TestHost {
                abort: Arc::new(AtomicBool::new(false)),
                gate: None,
                thread_names: Arc::clone(&thread_names),
            },
        );

        ready.blocking_wait().unwrap();
        release.send(()).unwrap();
        waiting.blocking_wait().unwrap();
        let metrics = service.metrics();
        assert_eq!(metrics.module_compilations, 1);
        assert!(metrics.module_cache_hits <= 1);
        assert_eq!(metrics.resident, 0);
        assert_eq!(metrics.max_active, 2);
        assert_eq!(
            *thread_names.lock().unwrap(),
            vec![
                "clusterflux-test-wasm-lane".to_owned(),
                "clusterflux-test-wasm-lane".to_owned(),
            ]
        );
        service.shutdown().unwrap();
    }

    #[test]
    fn resident_invocation_admission_is_bounded_and_released() {
        let configuration = WasmExecutionServiceConfiguration {
            max_resident_invocations: 1,
            ..WasmExecutionServiceConfiguration::default()
        };
        let mut service = WasmExecutionService::new(configuration).unwrap();
        let module = completed_module("bounded-task", true);
        let (release, gate) = oneshot::channel();
        let resident = submit(
            &service,
            module.clone(),
            invocation("bounded-task"),
            TestHost {
                abort: Arc::new(AtomicBool::new(false)),
                gate: Some(gate),
                thread_names: Arc::new(Mutex::new(Vec::new())),
            },
        );

        let error = match service.submit_task_export_verified(
            module.clone(),
            Digest::sha256(&module),
            "task".to_owned(),
            invocation("bounded-task"),
            WasmtimeRuntimeLimits::default(),
            Box::new(TestHost::immediate()),
        ) {
            Ok(_) => panic!("resident invocation admission should be bounded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("resident-invocation limit of 1"));

        release.send(()).unwrap();
        resident.blocking_wait().unwrap();
        submit(
            &service,
            module,
            invocation("bounded-task"),
            TestHost::immediate(),
        )
        .blocking_wait()
        .unwrap();
        service.shutdown().unwrap();
    }

    #[test]
    fn unique_modules_and_completed_abort_signals_reach_zero_metadata_state() {
        let mut service = WasmExecutionService::new(WasmExecutionServiceConfiguration {
            command_capacity: 4,
            max_resident_invocations: 4,
            module_cache_capacity: 2,
            ..WasmExecutionServiceConfiguration::default()
        })
        .unwrap();
        for index in 0..32 {
            let task = format!("unique-{index}");
            submit(
                &service,
                completed_module(&task, false),
                invocation(&task),
                TestHost::immediate(),
            )
            .blocking_wait()
            .unwrap();
        }
        for _ in 0..100 {
            let metrics = service.metrics();
            if metrics.module_registry_entries == 0 && metrics.abort_signal_records == 0 {
                service.shutdown().unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let metrics = service.metrics();
        panic!("auxiliary metadata did not drain: {metrics:?}");
    }

    #[test]
    fn queued_module_and_invocation_byte_limits_return_typed_capacity_errors() {
        let module = completed_module("byte-bounded-task", true);
        let digest = Digest::sha256(&module);
        let mut module_bounded = WasmExecutionService::new(WasmExecutionServiceConfiguration {
            max_queued_module_bytes: module.len() - 1,
            ..WasmExecutionServiceConfiguration::default()
        })
        .unwrap();
        let error = match module_bounded.submit_task_export_verified(
            module.clone(),
            digest.clone(),
            "task".to_owned(),
            invocation("byte-bounded-task"),
            WasmtimeRuntimeLimits::default(),
            Box::new(TestHost::immediate()),
        ) {
            Ok(_) => panic!("module-byte admission should be bounded"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            WasmTaskError::TemporaryCapacity {
                resource: "queued-module-byte",
                ..
            }
        ));
        module_bounded.shutdown().unwrap();

        let mut invocation_bounded = WasmExecutionService::new(WasmExecutionServiceConfiguration {
            max_queued_invocation_bytes: 1,
            ..WasmExecutionServiceConfiguration::default()
        })
        .unwrap();
        let error = match invocation_bounded.submit_task_export_verified(
            module,
            digest,
            "task".to_owned(),
            invocation("byte-bounded-task"),
            WasmtimeRuntimeLimits::default(),
            Box::new(TestHost::immediate()),
        ) {
            Ok(_) => panic!("invocation-byte admission should be bounded"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            WasmTaskError::TemporaryCapacity {
                resource: "queued-invocation-byte",
                ..
            }
        ));
        invocation_bounded.shutdown().unwrap();
    }

    #[test]
    fn busy_guest_cannot_starve_another_lane_invocation() {
        let configuration = WasmExecutionServiceConfiguration {
            fuel_yield_interval: 1_000,
            ..WasmExecutionServiceConfiguration::default()
        };
        let mut service = WasmExecutionService::new(configuration).unwrap();
        let abort = Arc::new(AtomicBool::new(false));
        let spinning = submit(
            &service,
            spinning_module(),
            invocation("spinning-task"),
            TestHost {
                abort: Arc::clone(&abort),
                gate: None,
                thread_names: Arc::new(Mutex::new(Vec::new())),
            },
        );
        let ready = submit(
            &service,
            completed_module("ready-task", false),
            invocation("ready-task"),
            TestHost::immediate(),
        );

        let started = Instant::now();
        ready.blocking_wait().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        abort.store(true, Ordering::Release);
        let error = spinning.blocking_wait().unwrap_err();
        assert!(matches!(error, WasmTaskError::HostControl(_)));
        service.shutdown().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn linux_task_entry_disappeared(error: &std::io::Error) -> bool {
        const ESRCH: i32 = 3;
        error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(ESRCH)
    }

    #[cfg(target_os = "linux")]
    fn linux_thread_name(path: &std::path::Path) -> Option<String> {
        match std::fs::read_to_string(path) {
            Ok(name) => Some(name.trim().to_owned()),
            Err(error) if linux_task_entry_disappeared(&error) => None,
            Err(error) => panic!(
                "failed to read Linux thread name from {}: {error}",
                path.display()
            ),
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_thread_snapshot(lane_name: &str) -> serde_json::Value {
        let os_lane_name = lane_name.chars().take(15).collect::<String>();
        let os_compiler_name = MODULE_COMPILER_THREAD_NAME
            .chars()
            .take(15)
            .collect::<String>();
        let mut names = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|entry| match entry {
                Ok(entry) => linux_thread_name(&entry.path().join("comm")),
                Err(error) if linux_task_entry_disappeared(&error) => None,
                Err(error) => panic!("failed to enumerate Linux threads: {error}"),
            })
            .collect::<Vec<_>>();
        names.sort();
        serde_json::json!({
            "total": names.len(),
            "wasm_execution_lane_threads": names.iter().filter(|name| name.as_str() == os_lane_name).count(),
            "wasm_module_compiler_threads": names.iter().filter(|name| name.as_str() == os_compiler_name).count(),
            "os_lane_thread_name": os_lane_name,
            "os_compiler_thread_name": os_compiler_name,
            "thread_names": names,
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_thread_snapshot_tolerates_a_thread_that_already_exited() {
        assert!(linux_task_entry_disappeared(
            &std::io::Error::from_raw_os_error(3)
        ));
        assert_eq!(
            linux_thread_name(std::path::Path::new(
                "/proc/self/task/clusterflux-nonexistent-thread/comm"
            )),
            None
        );
    }

    #[cfg(target_os = "linux")]
    fn metrics_json(metrics: &WasmExecutionServiceMetrics) -> serde_json::Value {
        serde_json::json!({
            "submitted": metrics.submitted,
            "completed": metrics.completed,
            "queue_count": metrics.queued,
            "max_queued": metrics.max_queued,
            "queued_module_bytes": metrics.queued_module_bytes,
            "max_queued_module_bytes": metrics.max_queued_module_bytes,
            "queued_invocation_bytes": metrics.queued_invocation_bytes,
            "max_queued_invocation_bytes": metrics.max_queued_invocation_bytes,
            "resident_wasm_instance_count": metrics.resident,
            "active_store_instances": metrics.active,
            "max_active_store_instances": metrics.max_active,
            "module_compilations": metrics.module_compilations,
            "module_cache_hits": metrics.module_cache_hits,
            "module_cache_entries": metrics.cached_modules,
            "module_cache_bytes": metrics.cached_module_bytes,
            "module_registry_entries": metrics.module_registry_entries,
            "abort_signal_records": metrics.abort_signal_records,
        })
    }

    #[cfg(target_os = "linux")]
    fn wait_for_active(service: &WasmExecutionService, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while service.metrics().active != expected && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(service.metrics().active, expected);
    }

    #[cfg(target_os = "linux")]
    fn wait_for_lane_thread_shutdown(lane_name: &str) -> (serde_json::Value, u128) {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        let strict_thread_counts = std::env::var_os("CLUSTERFLUX_WASM_LANE_PROOF_PATH").is_some();
        loop {
            let snapshot = linux_thread_snapshot(lane_name);
            if (snapshot["wasm_execution_lane_threads"] == 0
                && (!strict_thread_counts || snapshot["wasm_module_compiler_threads"] == 0))
                || Instant::now() >= deadline
            {
                return (snapshot, started.elapsed().as_millis());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lane_shutdown_observation_waits_for_a_named_thread_to_exit() {
        let lane_name = "cf-wasm-wait";
        let (started_sender, started_receiver) = std_mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name(lane_name.to_owned())
            .spawn(move || {
                started_sender.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(25));
            })
            .unwrap();
        started_receiver.recv().unwrap();
        assert_eq!(
            linux_thread_snapshot(lane_name)["wasm_execution_lane_threads"],
            1
        );

        let (shutdown, observation_ms) = wait_for_lane_thread_shutdown(lane_name);
        thread.join().unwrap();

        assert_eq!(shutdown["wasm_execution_lane_threads"], 0);
        assert!(observation_ms <= 5_000);
    }

    #[cfg(target_os = "linux")]
    fn run_lane_resource_proof(role: &str, lane_name: &str) -> serde_json::Value {
        const RESIDENT_TASKS: usize = 24;
        const EXECUTION_LANE_THREADS: usize = 1;
        const MODULE_COMPILER_THREADS: usize = 1;
        const SERVICE_THREADS: usize = EXECUTION_LANE_THREADS + MODULE_COMPILER_THREADS;
        let strict_thread_counts = std::env::var_os("CLUSTERFLUX_WASM_LANE_PROOF_PATH").is_some();
        let before = linux_thread_snapshot(lane_name);
        let configuration = WasmExecutionServiceConfiguration {
            thread_name: lane_name.to_owned(),
            command_capacity: 64,
            module_cache_capacity: 2,
            max_resident_invocations: 32,
            fuel_yield_interval: 1_000,
            ..WasmExecutionServiceConfiguration::default()
        };
        let mut service = WasmExecutionService::new(configuration).unwrap();
        let idle = linux_thread_snapshot(lane_name);
        if strict_thread_counts {
            assert_eq!(idle["wasm_execution_lane_threads"], EXECUTION_LANE_THREADS);
            assert_eq!(
                idle["wasm_module_compiler_threads"],
                MODULE_COMPILER_THREADS
            );
            assert_eq!(
                idle["total"].as_u64(),
                before["total"]
                    .as_u64()
                    .map(|count| count + SERVICE_THREADS as u64)
            );
        }

        let module = completed_module("resident-task", true);
        let thread_names = Arc::new(Mutex::new(Vec::new()));
        let (one_release, one_gate) = oneshot::channel();
        let one_execution = submit(
            &service,
            module.clone(),
            invocation("resident-task"),
            TestHost {
                abort: Arc::new(AtomicBool::new(false)),
                gate: Some(one_gate),
                thread_names: Arc::clone(&thread_names),
            },
        );
        wait_for_active(&service, 1);
        let one_resident_threads = linux_thread_snapshot(lane_name);
        let one_resident_metrics = service.metrics();
        if strict_thread_counts {
            assert_eq!(one_resident_threads["wasm_execution_lane_threads"], 1);
            assert_eq!(one_resident_threads["wasm_module_compiler_threads"], 1);
            assert_eq!(one_resident_threads["total"], idle["total"]);
        }
        one_release.send(()).unwrap();
        one_execution.blocking_wait().unwrap();

        let mut releases = Vec::new();
        let mut executions = Vec::new();
        for _ in 0..RESIDENT_TASKS {
            let (release, gate) = oneshot::channel();
            releases.push(release);
            executions.push(submit(
                &service,
                module.clone(),
                invocation("resident-task"),
                TestHost {
                    abort: Arc::new(AtomicBool::new(false)),
                    gate: Some(gate),
                    thread_names: Arc::clone(&thread_names),
                },
            ));
        }
        wait_for_active(&service, RESIDENT_TASKS);
        let resident_threads = linux_thread_snapshot(lane_name);
        let resident_metrics = service.metrics();
        assert_eq!(resident_metrics.resident, RESIDENT_TASKS);
        assert_eq!(resident_metrics.active, RESIDENT_TASKS);
        assert_eq!(resident_metrics.cached_modules, 1);
        assert_eq!(resident_metrics.module_compilations, 1);
        assert!(resident_metrics.module_cache_hits <= RESIDENT_TASKS as u64);
        assert!(resident_metrics.max_queued > 0);
        if strict_thread_counts {
            assert_eq!(resident_threads["wasm_execution_lane_threads"], 1);
            assert_eq!(resident_threads["wasm_module_compiler_threads"], 1);
            assert_eq!(resident_threads["total"], idle["total"]);
        }

        for release in releases {
            release.send(()).unwrap();
        }
        for execution in executions {
            execution.blocking_wait().unwrap();
        }

        let abort = Arc::new(AtomicBool::new(false));
        let spinning = submit(
            &service,
            spinning_module(),
            invocation("spinning-task"),
            TestHost {
                abort: Arc::clone(&abort),
                gate: None,
                thread_names: Arc::new(Mutex::new(Vec::new())),
            },
        );
        let ready = submit(
            &service,
            completed_module("ready-task", false),
            invocation("ready-task"),
            TestHost::immediate(),
        );
        let fairness_started = Instant::now();
        ready.blocking_wait().unwrap();
        let fairness_ms = fairness_started.elapsed().as_millis();
        assert!(fairness_ms < 2_000);
        abort.store(true, Ordering::Release);
        assert!(matches!(
            spinning.blocking_wait().unwrap_err(),
            WasmTaskError::HostControl(_)
        ));

        let completed_metrics = service.metrics();
        assert_eq!(completed_metrics.queued, 0);
        assert_eq!(completed_metrics.resident, 0);
        assert_eq!(completed_metrics.active, 0);
        assert_eq!(completed_metrics.cached_modules, 2);
        assert!(completed_metrics.max_active >= RESIDENT_TASKS);
        service.shutdown().unwrap();
        let (shutdown, shutdown_observation_ms) = wait_for_lane_thread_shutdown(lane_name);
        if strict_thread_counts {
            assert_eq!(
                shutdown["wasm_execution_lane_threads"], 0,
                "{role} lane thread survived shutdown: {shutdown}"
            );
            assert_eq!(
                shutdown["wasm_module_compiler_threads"], 0,
                "{role} compiler thread survived shutdown: {shutdown}"
            );
            assert_eq!(shutdown["total"], before["total"]);
        }

        serde_json::json!({
            "role": role,
            "lane_thread_name": lane_name,
            "resident_virtual_tasks": RESIDENT_TASKS,
            "threads_before": before,
            "threads_idle": idle,
            "threads_with_one_resident_task": one_resident_threads,
            "one_resident_metrics": metrics_json(&one_resident_metrics),
            "threads_with_resident_tasks": resident_threads,
            "resident_metrics": metrics_json(&resident_metrics),
            "fuel_fairness_ready_ms": fairness_ms,
            "completed_metrics": metrics_json(&completed_metrics),
            "threads_after_shutdown": shutdown,
            "shutdown_observation_ms": shutdown_observation_ms,
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lane_resource_proof_records_constant_os_threads_and_cleanup() {
        let report = serde_json::json!({
            "kind": "clusterflux-wasm-lane-resource-proof",
            "source_commit": std::env::var("CLUSTERFLUX_SOURCE_COMMIT").ok(),
            "roles": [
                run_lane_resource_proof("coordinator", "clusterflux-coordinator-wasm"),
                run_lane_resource_proof("node", "clusterflux-node-wasm"),
            ],
            "passed": true,
        });
        if let Some(path) = std::env::var_os("CLUSTERFLUX_WASM_LANE_PROOF_PATH") {
            let path = std::path::PathBuf::from(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
            )
            .unwrap();
        }
    }
}
