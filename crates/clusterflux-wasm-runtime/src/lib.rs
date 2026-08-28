use clusterflux_core::{
    DebugEpoch, DebugParticipant, DebugParticipantKind, DebugRuntimeState, Digest, ProcessId,
    TaskInstanceId, WasmHostCommandRequest, WasmHostCommandResult, WasmHostDebugProbeRequest,
    WasmHostDebugProbeResult, WasmHostSourceSnapshotRequest, WasmHostSourceSnapshotResult,
    WasmHostTaskControlRequest, WasmHostTaskControlResult, WasmHostTaskHandle,
    WasmHostTaskJoinRequest, WasmHostTaskJoinResult, WasmHostTaskStartRequest,
    WasmHostTriggerContextRequest, WasmHostTriggerContextResult, WasmHostVfsRequest,
    WasmHostVfsResult, WasmTaskInvocation, WasmTaskResult, MAX_WASM_TASK_ENVELOPE_BYTES,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use wasmtime::{
    Caller, Config, DebugEvent, DebugHandler, Engine, Linker, Module, OptLevel, Store,
    StoreContextMut, StoreLimits, StoreLimitsBuilder, UpdateDeadline, WasmBacktrace,
};

mod async_task_host_linker;
mod execution_service;
mod task_host_linker;
use async_task_host_linker::async_task_host_linker;
pub use execution_service::{
    WasmExecution, WasmExecutionService, WasmExecutionServiceConfiguration,
    WasmExecutionServiceMetrics, DEFAULT_MAX_RESIDENT_INVOCATIONS,
};
use task_host_linker::{task_host_linker, task_host_stub_linker};

const INACTIVE_EPOCH_DEADLINE_TICKS: u64 = u64::MAX / 2;
const DEFAULT_MAX_WASM_MEMORY_BYTES: usize = 256 * 1024 * 1024;
const MAX_WASM_MEMORY_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_WASM_TABLE_ELEMENTS: usize = 100_000;
const DEFAULT_WASM_FUEL_UNITS_PER_SECOND: u64 = 10_000_000;
const DEFAULT_WASM_FUEL_BURST_SECONDS: u64 = 60;
const MAX_WASM_FUEL_UNITS_PER_SECOND: u64 = 1_000_000_000_000;
const MAX_WASM_FUEL_BURST_SECONDS: u64 = 60 * 60;
const DEFAULT_ASYNC_FUEL_YIELD_INTERVAL: u64 = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmtimeRuntimeLimits {
    pub fuel_units_per_second: u64,
    pub fuel_burst_seconds: u64,
    pub memory_bytes: usize,
}

impl WasmtimeRuntimeLimits {
    pub fn validate(&self) -> Result<(), WasmTaskError> {
        if self.fuel_units_per_second == 0
            || self.fuel_units_per_second > MAX_WASM_FUEL_UNITS_PER_SECOND
            || self.fuel_burst_seconds == 0
            || self.fuel_burst_seconds > MAX_WASM_FUEL_BURST_SECONDS
        {
            return Err(WasmTaskError::Runtime(
                "Wasm fuel rate or burst duration is outside its bounded range".to_owned(),
            ));
        }
        if self.memory_bytes == 0 || self.memory_bytes > MAX_WASM_MEMORY_BYTES {
            return Err(WasmTaskError::Runtime(
                "Wasm memory limit is outside its bounded range".to_owned(),
            ));
        }
        self.fuel_capacity().ok_or_else(|| {
            WasmTaskError::Runtime("Wasm fuel burst capacity overflowed u64".to_owned())
        })?;
        Ok(())
    }

    fn fuel_capacity(&self) -> Option<u64> {
        self.fuel_units_per_second
            .checked_mul(self.fuel_burst_seconds)
    }
}

impl Default for WasmtimeRuntimeLimits {
    fn default() -> Self {
        Self {
            fuel_units_per_second: DEFAULT_WASM_FUEL_UNITS_PER_SECOND,
            fuel_burst_seconds: DEFAULT_WASM_FUEL_BURST_SECONDS,
            memory_bytes: DEFAULT_MAX_WASM_MEMORY_BYTES,
        }
    }
}

fn task_store_limits(runtime: &WasmtimeRuntimeLimits) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(runtime.memory_bytes)
        .table_elements(MAX_WASM_TABLE_ELEMENTS)
        .instances(8)
        .tables(8)
        .memories(8)
        .trap_on_grow_failure(true)
        .build()
}

fn ensure_module_store_engine<T>(store: &Store<T>, module: &Module) -> Result<(), WasmTaskError> {
    if Engine::same(store.engine(), module.engine()) {
        Ok(())
    } else {
        Err(WasmTaskError::Runtime(
            "refusing to instantiate a Wasm module with a store from another engine".to_owned(),
        ))
    }
}

fn debug_control_trace(message: impl std::fmt::Display) {
    if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
        eprintln!("clusterflux debug control: {message}");
    }
}

#[derive(Clone)]
pub struct WasmtimeTaskRuntime {
    engine: Engine,
    runtime_limits: WasmtimeRuntimeLimits,
}

pub trait WasmTaskHost {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        None
    }

    fn debug_control(&self) -> Option<Arc<WasmDebugControl>> {
        None
    }

    fn start_task(
        &mut self,
        request: WasmHostTaskStartRequest,
    ) -> Result<WasmHostTaskHandle, String>;
    fn join_task(
        &mut self,
        request: WasmHostTaskJoinRequest,
    ) -> Result<WasmHostTaskJoinResult, String>;
    fn run_command(
        &mut self,
        request: WasmHostCommandRequest,
    ) -> Result<WasmHostCommandResult, String>;
    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> Result<WasmHostTaskControlResult, String>;
    fn debug_probe(
        &mut self,
        request: WasmHostDebugProbeRequest,
    ) -> Result<WasmHostDebugProbeResult, String> {
        request.validate()?;
        Ok(WasmHostDebugProbeResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            breakpoint_matched: false,
            debug_epoch: None,
        })
    }
    fn vfs_operation(&mut self, request: WasmHostVfsRequest) -> Result<WasmHostVfsResult, String>;
    fn snapshot_source(
        &mut self,
        request: WasmHostSourceSnapshotRequest,
    ) -> Result<WasmHostSourceSnapshotResult, String>;
    fn trigger_context(
        &mut self,
        request: WasmHostTriggerContextRequest,
    ) -> Result<WasmHostTriggerContextResult, String> {
        request.validate()?;
        Err("this Wasm invocation has no forge trigger context".to_owned())
    }
}

pub type WasmHostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// Async host boundary used by the cooperative Wasm execution lane. Futures
/// may borrow per-invocation host state, but must never block the lane thread.
pub trait AsyncWasmTaskHost: Send {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        None
    }

    fn debug_control(&self) -> Option<Arc<WasmDebugControl>> {
        None
    }

    fn start_task(
        &mut self,
        request: WasmHostTaskStartRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskHandle>;
    fn join_task(
        &mut self,
        request: WasmHostTaskJoinRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskJoinResult>;
    fn run_command(
        &mut self,
        request: WasmHostCommandRequest,
    ) -> WasmHostFuture<'_, WasmHostCommandResult>;
    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskControlResult>;
    fn debug_probe(
        &mut self,
        request: WasmHostDebugProbeRequest,
    ) -> WasmHostFuture<'_, WasmHostDebugProbeResult> {
        Box::pin(async move {
            request.validate()?;
            Ok(WasmHostDebugProbeResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                breakpoint_matched: false,
                debug_epoch: None,
            })
        })
    }
    fn vfs_operation(
        &mut self,
        request: WasmHostVfsRequest,
    ) -> WasmHostFuture<'_, WasmHostVfsResult>;
    fn snapshot_source(
        &mut self,
        request: WasmHostSourceSnapshotRequest,
    ) -> WasmHostFuture<'_, WasmHostSourceSnapshotResult>;
    fn trigger_context(
        &mut self,
        request: WasmHostTriggerContextRequest,
    ) -> WasmHostFuture<'_, WasmHostTriggerContextResult> {
        Box::pin(async move {
            request.validate()?;
            Err("this Wasm invocation has no forge trigger context".to_owned())
        })
    }
}

#[derive(Debug, Default)]
struct WasmDebugControlState {
    requested_epoch: Option<u64>,
    frozen_epoch: Option<u64>,
    resumed_through_epoch: u64,
    execution_armed: bool,
    quiescent_host_boundary_depth: usize,
    frozen_at_host_boundary: bool,
    stack_frames: Vec<String>,
    current_source_location: Option<clusterflux_core::SourceLocation>,
}

#[derive(Debug, Default)]
pub struct WasmDebugControl {
    state: Mutex<WasmDebugControlState>,
    changed: Condvar,
    async_changed: tokio::sync::Notify,
}

impl WasmDebugControl {
    pub fn request_freeze(&self, epoch: u64) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        if state
            .requested_epoch
            .is_none_or(|requested| epoch >= requested)
        {
            state.requested_epoch = Some(epoch);
            if (!state.execution_armed || state.quiescent_host_boundary_depth > 0)
                && state.resumed_through_epoch < epoch
            {
                state.frozen_epoch = Some(epoch);
                state.frozen_at_host_boundary = true;
            }
            self.changed.notify_all();
            self.async_changed.notify_waiters();
        }
    }

    pub fn request_resume(&self, epoch: u64) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        state.resumed_through_epoch = state.resumed_through_epoch.max(epoch);
        if state.frozen_epoch == Some(epoch) && state.frozen_at_host_boundary {
            state.frozen_epoch = None;
            state.frozen_at_host_boundary = false;
        }
        self.changed.notify_all();
        self.async_changed.notify_waiters();
    }

    pub fn requested_epoch(&self) -> Option<u64> {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .requested_epoch
    }

    pub fn frozen_epoch(&self) -> Option<u64> {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .frozen_epoch
    }

    pub fn resume_requested(&self, epoch: u64) -> bool {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .resumed_through_epoch
            >= epoch
    }

    pub fn mark_frozen(&self, epoch: u64) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        state.frozen_epoch = Some(epoch);
        state.frozen_at_host_boundary = false;
        self.changed.notify_all();
        self.async_changed.notify_waiters();
    }

    pub fn mark_running(&self, epoch: u64) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        if state.frozen_epoch == Some(epoch) {
            state.frozen_epoch = None;
            state.frozen_at_host_boundary = false;
        }
        self.changed.notify_all();
        self.async_changed.notify_waiters();
    }

    pub fn wait_until_frozen(&self, epoch: u64, timeout: Duration) -> bool {
        let state = self.state.lock().expect("debug control lock poisoned");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.frozen_epoch != Some(epoch))
            .expect("debug control lock poisoned while waiting for freeze");
        state.frozen_epoch == Some(epoch)
    }

    pub fn wait_until_running(&self, epoch: u64, timeout: Duration) -> bool {
        let state = self.state.lock().expect("debug control lock poisoned");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| state.frozen_epoch == Some(epoch))
            .expect("debug control lock poisoned while waiting for resume");
        state.frozen_epoch != Some(epoch)
    }

    pub async fn wait_until_frozen_async(&self, epoch: u64, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.async_changed.notified();
                if self
                    .state
                    .lock()
                    .expect("debug control lock poisoned")
                    .frozen_epoch
                    == Some(epoch)
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    pub async fn wait_until_running_async(&self, epoch: u64, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                let notified = self.async_changed.notified();
                if self
                    .state
                    .lock()
                    .expect("debug control lock poisoned")
                    .frozen_epoch
                    != Some(epoch)
                {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }

    pub fn stack_frames(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .stack_frames
            .clone()
    }

    pub fn current_source_location(&self) -> Option<clusterflux_core::SourceLocation> {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .current_source_location
            .clone()
    }

    pub fn record_source_location(&self, location: Option<clusterflux_core::SourceLocation>) {
        if let Some(location) = location {
            self.state
                .lock()
                .expect("debug control lock poisoned")
                .current_source_location = Some(location);
        }
    }

    fn record_stack_frames(&self, stack_frames: Vec<String>) {
        self.state
            .lock()
            .expect("debug control lock poisoned")
            .stack_frames = stack_frames;
    }

    fn arm_execution(&self, abort: &AtomicBool) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        state.execution_armed = true;
        while state.frozen_at_host_boundary
            && state.frozen_epoch.is_some()
            && !abort.load(Ordering::Acquire)
        {
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(50))
                .expect("debug control lock poisoned at Wasm startup safepoint")
                .0;
        }
    }

    async fn arm_execution_async(&self, abort: &AtomicBool) {
        {
            let mut state = self.state.lock().expect("debug control lock poisoned");
            state.execution_armed = true;
        }
        self.wait_for_host_boundary_resume_async(abort).await;
    }

    async fn wait_for_host_boundary_resume_async(&self, abort: &AtomicBool) {
        loop {
            let notified = self.async_changed.notified();
            let waiting = {
                let state = self.state.lock().expect("debug control lock poisoned");
                state.frozen_at_host_boundary
                    && state.frozen_epoch.is_some()
                    && !abort.load(Ordering::Acquire)
            };
            if !waiting {
                return;
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    async fn wait_until_epoch_resumed_async(&self, epoch: u64, abort: &AtomicBool) {
        loop {
            let notified = self.async_changed.notified();
            let resumed = {
                let state = self.state.lock().expect("debug control lock poisoned");
                state.resumed_through_epoch >= epoch || abort.load(Ordering::Acquire)
            };
            if resumed {
                self.mark_running(epoch);
                return;
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    fn pause_at_requested_epoch(&self, abort: &AtomicBool) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        let Some(epoch) = state.requested_epoch else {
            return;
        };
        if state.resumed_through_epoch >= epoch {
            return;
        }
        debug_control_trace(format_args!("Wasm epoch callback freezing epoch {epoch}"));
        state.frozen_epoch = Some(epoch);
        state.frozen_at_host_boundary = false;
        self.changed.notify_all();
        while state.resumed_through_epoch < epoch && !abort.load(Ordering::Acquire) {
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(50))
                .expect("debug control lock poisoned while Wasm was frozen")
                .0;
        }
        state.frozen_epoch = None;
        debug_control_trace(format_args!("Wasm epoch callback resumed epoch {epoch}"));
        self.changed.notify_all();
    }

    fn enter_quiescent_host_boundary(&self, abort: Option<&AtomicBool>) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        state.quiescent_host_boundary_depth += 1;
        if let Some(epoch) = state.requested_epoch {
            if state.resumed_through_epoch < epoch {
                state.frozen_epoch = Some(epoch);
                state.frozen_at_host_boundary = true;
                self.changed.notify_all();
            }
        }
        while state.frozen_at_host_boundary
            && state.frozen_epoch.is_some()
            && !abort.is_some_and(|abort| abort.load(Ordering::Acquire))
        {
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(50))
                .expect("debug control lock poisoned entering host-call safepoint")
                .0;
        }
    }

    fn leave_quiescent_host_boundary(&self, abort: Option<&AtomicBool>) {
        let mut state = self.state.lock().expect("debug control lock poisoned");
        while state.frozen_at_host_boundary
            && state.frozen_epoch.is_some()
            && !abort.is_some_and(|abort| abort.load(Ordering::Acquire))
        {
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(50))
                .expect("debug control lock poisoned at host-call safepoint")
                .0;
        }
        state.quiescent_host_boundary_depth = state.quiescent_host_boundary_depth.saturating_sub(1);
        if state.quiescent_host_boundary_depth == 0 && state.frozen_at_host_boundary {
            state.frozen_epoch = None;
            state.frozen_at_host_boundary = false;
            self.changed.notify_all();
        }
    }

    async fn enter_quiescent_host_boundary_async(&self, abort: Option<&AtomicBool>) {
        {
            let mut state = self.state.lock().expect("debug control lock poisoned");
            state.quiescent_host_boundary_depth += 1;
            if let Some(epoch) = state.requested_epoch {
                if state.resumed_through_epoch < epoch {
                    state.frozen_epoch = Some(epoch);
                    state.frozen_at_host_boundary = true;
                    self.changed.notify_all();
                    self.async_changed.notify_waiters();
                }
            }
        }
        loop {
            let notified = self.async_changed.notified();
            let waiting = {
                let state = self.state.lock().expect("debug control lock poisoned");
                state.frozen_at_host_boundary
                    && state.frozen_epoch.is_some()
                    && !abort.is_some_and(|abort| abort.load(Ordering::Acquire))
            };
            if !waiting {
                return;
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    async fn leave_quiescent_host_boundary_async(&self, abort: Option<&AtomicBool>) {
        loop {
            let notified = self.async_changed.notified();
            let waiting = {
                let state = self.state.lock().expect("debug control lock poisoned");
                state.frozen_at_host_boundary
                    && state.frozen_epoch.is_some()
                    && !abort.is_some_and(|abort| abort.load(Ordering::Acquire))
            };
            if !waiting {
                break;
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        let mut state = self.state.lock().expect("debug control lock poisoned");
        state.quiescent_host_boundary_depth = state.quiescent_host_boundary_depth.saturating_sub(1);
        if state.quiescent_host_boundary_depth == 0 && state.frozen_at_host_boundary {
            state.frozen_epoch = None;
            state.frozen_at_host_boundary = false;
            self.changed.notify_all();
            self.async_changed.notify_waiters();
        }
    }
}

struct WasmtimeTaskHostState {
    host: Box<dyn WasmTaskHost>,
    fatal_host_error: Option<String>,
    limits: StoreLimits,
    fuel_budget: FuelTokenBucket,
}

struct AsyncWasmtimeTaskHostState {
    host: Box<dyn AsyncWasmTaskHost>,
    fatal_host_error: Option<String>,
    limits: StoreLimits,
    fuel_budget: FuelTokenBucket,
}

struct BasicStoreState {
    limits: StoreLimits,
}

struct FuelTokenBucket {
    fuel_units_per_second: u64,
    capacity: u64,
    last_refill: Instant,
    fractional_fuel_numerator: u128,
}

impl FuelTokenBucket {
    fn new(limits: &WasmtimeRuntimeLimits) -> Self {
        Self {
            fuel_units_per_second: limits.fuel_units_per_second,
            capacity: limits
                .fuel_capacity()
                .expect("validated Wasm fuel capacity"),
            last_refill: Instant::now(),
            fractional_fuel_numerator: 0,
        }
    }

    fn refill(&mut self, current_fuel: u64) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;
        self.refill_after(current_fuel, elapsed)
    }

    fn refill_after(&mut self, current_fuel: u64, elapsed: Duration) -> u64 {
        let earned_numerator = elapsed
            .as_nanos()
            .saturating_mul(self.fuel_units_per_second as u128)
            .saturating_add(self.fractional_fuel_numerator);
        let refill = earned_numerator
            .checked_div(1_000_000_000)
            .unwrap_or(0)
            .min(u64::MAX as u128) as u64;
        let refilled = current_fuel.saturating_add(refill).min(self.capacity);
        self.fractional_fuel_numerator = if refilled == self.capacity {
            0
        } else {
            earned_numerator % 1_000_000_000
        };
        refilled
    }
}

#[cfg(test)]
mod fuel_token_bucket_tests {
    use super::*;

    #[test]
    fn frequent_refills_preserve_fractional_credit() {
        let limits = WasmtimeRuntimeLimits {
            fuel_units_per_second: 10,
            fuel_burst_seconds: 60,
            memory_bytes: 1024,
        };
        let mut bucket = FuelTokenBucket::new(&limits);
        let mut fuel = 0;
        for _ in 0..4 {
            fuel = bucket.refill_after(fuel, Duration::from_millis(25));
        }
        assert_eq!(fuel, 1);
        assert_eq!(bucket.fractional_fuel_numerator, 0);
    }
}

impl WasmtimeTaskHostState {
    pub(crate) fn refill_fuel_after_host_call(&mut self, current_fuel: u64) -> u64 {
        self.fuel_budget.refill(current_fuel)
    }
}

impl AsyncWasmtimeTaskHostState {
    pub(crate) fn refill_fuel_after_host_call(&mut self, current_fuel: u64) -> u64 {
        self.fuel_budget.refill(current_fuel)
    }
}

struct EpochControlGuard {
    stop: Arc<AtomicBool>,
    watcher: Option<thread::JoinHandle<()>>,
}

struct AsyncEpochTickerGuard {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl AsyncEpochTickerGuard {
    fn arm(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while !task_stop.load(Ordering::Acquire) {
                tick.tick().await;
                engine.increment_epoch();
            }
        });
        Self { stop, task }
    }
}

impl Drop for AsyncEpochTickerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.abort();
    }
}

impl EpochControlGuard {
    fn arm<T: 'static>(
        engine: &Engine,
        store: &mut Store<T>,
        abort: Arc<AtomicBool>,
        debug: Option<Arc<WasmDebugControl>>,
    ) -> Self {
        debug_control_trace(format_args!(
            "arming epoch control (debug={:?})",
            debug.as_ref().map(Arc::as_ptr)
        ));
        let callback_abort = Arc::clone(&abort);
        let callback_debug = debug.clone();
        store.epoch_deadline_callback(move |_store| {
            if callback_abort.load(Ordering::Acquire) {
                return Ok(UpdateDeadline::Interrupt);
            }
            if let Some(debug) = &callback_debug {
                debug.pause_at_requested_epoch(&callback_abort);
                if callback_abort.load(Ordering::Acquire) {
                    return Ok(UpdateDeadline::Interrupt);
                }
            }
            // Epochs are engine-wide. Another task may increment the shared
            // engine's epoch to control its own store; keep this store running
            // unless this store's own control signal requires action.
            Ok(UpdateDeadline::Continue(1))
        });
        store.set_epoch_deadline(1);
        if let Some(debug) = &debug {
            debug.arm_execution(&abort);
        }
        let engine = engine.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_stop = Arc::clone(&stop);
        let watcher = thread::spawn(move || {
            debug_control_trace("epoch control watcher started");
            let mut triggered_debug_epoch = None;
            while !watcher_stop.load(Ordering::Acquire) {
                if abort.load(Ordering::Acquire) {
                    engine.increment_epoch();
                    return;
                }
                if let Some(epoch) = debug.as_ref().and_then(|debug| debug.requested_epoch()) {
                    if triggered_debug_epoch != Some(epoch) {
                        triggered_debug_epoch = Some(epoch);
                        debug_control_trace(format_args!(
                            "incrementing engine epoch for debug epoch {epoch}"
                        ));
                        engine.increment_epoch();
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        Self {
            stop,
            watcher: Some(watcher),
        }
    }
}

fn defer_epoch_interruption<T>(store: &mut Store<T>) {
    // Stores default to an already-expired epoch deadline. ABI setup and stores
    // without an abort signal must explicitly opt out of interruption, especially
    // after a previous task has incremented the shared engine epoch.
    store.set_epoch_deadline(INACTIVE_EPOCH_DEADLINE_TICKS);
}

fn arm_async_epoch_control(
    store: &mut Store<AsyncWasmtimeTaskHostState>,
    abort: Arc<AtomicBool>,
    debug: Option<Arc<WasmDebugControl>>,
) {
    let callback_abort = Arc::clone(&abort);
    store.epoch_deadline_callback(move |_store| {
        if callback_abort.load(Ordering::Acquire) {
            return Ok(UpdateDeadline::Interrupt);
        }
        if let Some(debug) = &debug {
            if let Some(epoch) = debug.requested_epoch() {
                if !debug.resume_requested(epoch) {
                    debug.mark_frozen(epoch);
                    let debug = Arc::clone(debug);
                    let abort = Arc::clone(&callback_abort);
                    return Ok(UpdateDeadline::YieldCustom(
                        1,
                        Box::pin(async move {
                            debug.wait_until_epoch_resumed_async(epoch, &abort).await;
                        }),
                    ));
                }
            }
        }
        Ok(UpdateDeadline::Yield(1))
    });
    store.set_epoch_deadline(1);
}

impl Drop for EpochControlGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

fn abort_error(
    store: &Store<WasmtimeTaskHostState>,
    abort: Option<&Arc<AtomicBool>>,
    error: wasmtime::Error,
) -> WasmTaskError {
    if abort.is_some_and(|signal| signal.load(Ordering::Acquire)) {
        return WasmTaskError::HostControl(
            "task execution cancelled: coordinator requested process abort".to_owned(),
        );
    }
    store
        .data()
        .fatal_host_error
        .clone()
        .map(WasmTaskError::HostControl)
        .unwrap_or_else(|| wasmtime_error(error))
}

fn async_abort_error(
    store: &Store<AsyncWasmtimeTaskHostState>,
    abort: Option<&Arc<AtomicBool>>,
    error: wasmtime::Error,
) -> WasmTaskError {
    if abort.is_some_and(|signal| signal.load(Ordering::Acquire)) {
        return WasmTaskError::HostControl(
            "task execution cancelled: coordinator requested process abort".to_owned(),
        );
    }
    store
        .data()
        .fatal_host_error
        .clone()
        .map(WasmTaskError::HostControl)
        .unwrap_or_else(|| wasmtime_error(error))
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WasmTaskError {
    #[error("wasmtime task failed: {0}")]
    Runtime(String),
    #[error("Wasm task ABI failed: {0}")]
    TaskAbi(String),
    #[error("{0}")]
    HostControl(String),
    #[error("Wasm execution lane {resource} limit of {limit} is exhausted (temporary capacity)")]
    TemporaryCapacity {
        resource: &'static str,
        limit: usize,
    },
    #[error(
        "bundle digest mismatch before wasmtime execution: expected {expected}, actual {actual}"
    )]
    BundleDigestMismatch { expected: Digest, actual: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmtimeDebugProbe {
    pub task: TaskInstanceId,
    pub frozen_state: DebugRuntimeState,
    pub resumed_state: DebugRuntimeState,
    pub result: i32,
    pub stack_frames: Vec<String>,
    pub local_values: Vec<(String, String)>,
    pub wasm_function: Option<String>,
    pub wasm_pc: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WasmtimeFrameSnapshot {
    stack_frames: Vec<String>,
    local_values: Vec<(String, String)>,
    wasm_function: Option<String>,
    wasm_pc: Option<u32>,
}

#[derive(Debug)]
struct WasmtimeDebugState {
    snapshot: Option<WasmtimeFrameSnapshot>,
    limits: StoreLimits,
}

impl Default for WasmtimeDebugState {
    fn default() -> Self {
        Self {
            snapshot: None,
            limits: task_store_limits(&WasmtimeRuntimeLimits::default()),
        }
    }
}

#[derive(Clone, Debug)]
struct WasmtimeLocalSnapshotHandler {
    export: String,
}

impl DebugHandler for WasmtimeLocalSnapshotHandler {
    type Data = WasmtimeDebugState;

    async fn handle(&self, mut store: StoreContextMut<'_, Self::Data>, _event: DebugEvent<'_>) {
        if store.data().snapshot.is_some() {
            if let Some(mut edit) = store.edit_breakpoints() {
                let _ = edit.single_step(false);
            }
            return;
        }

        let mut snapshot = WasmtimeFrameSnapshot {
            stack_frames: vec![format!("{}::wasm_export", self.export)],
            ..WasmtimeFrameSnapshot::default()
        };
        // The debugger only presents the top Wasm frame here. Bounding the iterator is
        // also essential for modules with linked host imports, whose exit-frame chain
        // may include runtime trampolines that are not user-visible frames.
        if let Some(frame) = store
            .debug_exit_frames()
            .take(1)
            .collect::<Vec<_>>()
            .into_iter()
            .next()
        {
            if let Ok(Some((function, pc))) = frame.wasm_function_index_and_pc(&mut store) {
                snapshot.wasm_function = Some(format!("{function:?}"));
                snapshot.wasm_pc = Some(pc);
            }

            if let Ok(count) = frame.num_locals(&mut store) {
                for index in 0..count.min(16) {
                    let value = match frame.local(&mut store, index) {
                        Ok(value) => format!("{value:?}"),
                        Err(err) => format!("<error: {err:#}>"),
                    };
                    snapshot
                        .local_values
                        .push((format!("wasm_local_{index}"), value));
                }
            }
        }

        if let Some(function) = &snapshot.wasm_function {
            snapshot.stack_frames = vec![format!("{} / {function}", self.export)];
        }
        store.data_mut().snapshot = Some(snapshot);
        if let Some(mut edit) = store.edit_breakpoints() {
            let _ = edit.single_step(false);
        }
    }
}

impl WasmtimeTaskRuntime {
    pub fn new() -> Result<Self, WasmTaskError> {
        Self::new_with_limits(WasmtimeRuntimeLimits::default())
    }

    pub fn new_with_limits(runtime_limits: WasmtimeRuntimeLimits) -> Result<Self, WasmTaskError> {
        runtime_limits.validate()?;
        let mut config = Config::new();
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.epoch_interruption(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(wasmtime_error)?;
        Ok(Self {
            engine,
            runtime_limits,
        })
    }

    fn debug_engine() -> Result<Engine, WasmTaskError> {
        let mut config = Config::new();
        config.debug_info(true);
        config.guest_debug(true);
        config.generate_address_map(true);
        config.cranelift_opt_level(OptLevel::None);
        Engine::new(&config).map_err(wasmtime_error)
    }

    pub fn run_i32_export(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        export: &str,
        arg: i32,
    ) -> Result<i32, WasmTaskError> {
        self.run_i32_export_bytes(wasm_or_wat.as_ref(), export, arg)
    }

    pub fn run_i32_export_verified(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
        export: &str,
        arg: i32,
    ) -> Result<i32, WasmTaskError> {
        let wasm_or_wat = Self::verified_module_bytes(wasm_or_wat, expected_bundle_digest)?;
        self.run_i32_export_bytes(&wasm_or_wat, export, arg)
    }

    pub fn run_i32_export_verified_with_task_host(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
        export: &str,
        arg: i32,
        host: Box<dyn WasmTaskHost>,
    ) -> Result<i32, WasmTaskError> {
        let module_bytes = Self::verified_module_bytes(wasm_or_wat, expected_bundle_digest)?;
        let module = Module::new(&self.engine, &module_bytes).map_err(wasmtime_error)?;
        let linker = task_host_linker(&self.engine)?;
        let abort_signal = host.abort_signal();
        let debug_control = host.debug_control();
        let mut store = Store::new(
            &self.engine,
            WasmtimeTaskHostState {
                host,
                fatal_host_error: None,
                limits: task_store_limits(&self.runtime_limits),
                fuel_budget: FuelTokenBucket::new(&self.runtime_limits),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(
                self.runtime_limits
                    .fuel_capacity()
                    .expect("validated fuel capacity"),
            )
            .map_err(wasmtime_error)?;
        defer_epoch_interruption(&mut store);
        ensure_module_store_engine(&store, &module)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(wasmtime_error)?;
        let function = instance
            .get_typed_func::<i32, i32>(&mut store, export)
            .map_err(wasmtime_error)?;
        let _abort_guard = abort_signal.as_ref().map(|signal| {
            EpochControlGuard::arm(&self.engine, &mut store, Arc::clone(signal), debug_control)
        });
        match function.call(&mut store, arg) {
            Ok(result) => Ok(result),
            Err(error) => Err(abort_error(&store, abort_signal.as_ref(), error)),
        }
    }

    pub fn run_task_export_verified(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
        export: &str,
        invocation: &WasmTaskInvocation,
    ) -> Result<WasmTaskResult, WasmTaskError> {
        invocation.validate().map_err(WasmTaskError::TaskAbi)?;
        let module_bytes = Self::verified_module_bytes(wasm_or_wat, expected_bundle_digest)?;
        let encoded = serde_json::to_vec(invocation)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        let module = Module::new(&self.engine, &module_bytes).map_err(wasmtime_error)?;
        let linker = task_host_stub_linker(&self.engine)?;
        let mut store = Store::new(
            &self.engine,
            BasicStoreState {
                limits: task_store_limits(&self.runtime_limits),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(
                self.runtime_limits
                    .fuel_capacity()
                    .expect("validated fuel capacity"),
            )
            .map_err(wasmtime_error)?;
        defer_epoch_interruption(&mut store);
        ensure_module_store_engine(&store, &module)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(wasmtime_error)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmTaskError::TaskAbi("guest module exports no memory".to_owned()))?;
        let allocate = instance
            .get_typed_func::<u32, u32>(&mut store, "clusterflux_alloc_v1")
            .map_err(wasmtime_error)?;
        let input_length = u32::try_from(encoded.len())
            .map_err(|_| WasmTaskError::TaskAbi("task invocation is too large".to_owned()))?;
        let input_pointer = allocate
            .call(&mut store, input_length)
            .map_err(wasmtime_error)?;
        debug_control_trace("task ABI input allocation completed");
        if input_pointer == 0 && input_length != 0 {
            return Err(WasmTaskError::TaskAbi(
                "guest refused task invocation allocation".to_owned(),
            ));
        }
        memory
            .write(&mut store, input_pointer as usize, &encoded)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        let task = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, export)
            .map_err(wasmtime_error)?;
        let packed = task
            .call(&mut store, (input_pointer, input_length))
            .map_err(wasmtime_error)?;
        let result_pointer = packed as u32;
        let result_length = (packed >> 32) as u32;
        if result_length as usize > MAX_WASM_TASK_ENVELOPE_BYTES {
            return Err(WasmTaskError::TaskAbi(format!(
                "guest task result is {result_length} bytes; maximum is {MAX_WASM_TASK_ENVELOPE_BYTES}"
            )));
        }
        if result_pointer == 0 && result_length != 0 {
            return Err(WasmTaskError::TaskAbi(
                "guest returned a null task result pointer".to_owned(),
            ));
        }
        let mut result_bytes = vec![0_u8; result_length as usize];
        memory
            .read(&store, result_pointer as usize, &mut result_bytes)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        let result: WasmTaskResult = serde_json::from_slice(&result_bytes)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        result
            .validate_for(&invocation.task_instance)
            .map_err(WasmTaskError::TaskAbi)?;
        Ok(result)
    }

    pub fn run_task_export_verified_with_task_host(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
        export: &str,
        invocation: &WasmTaskInvocation,
        host: Box<dyn WasmTaskHost>,
    ) -> Result<WasmTaskResult, WasmTaskError> {
        invocation.validate().map_err(WasmTaskError::TaskAbi)?;
        let module_bytes = Self::verified_module_bytes(wasm_or_wat, expected_bundle_digest)?;
        let encoded = serde_json::to_vec(invocation)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        let module = Module::new(&self.engine, &module_bytes).map_err(wasmtime_error)?;
        let linker = task_host_linker(&self.engine)?;
        let abort_signal = host.abort_signal();
        let debug_control = host.debug_control();
        let mut store = Store::new(
            &self.engine,
            WasmtimeTaskHostState {
                host,
                fatal_host_error: None,
                limits: task_store_limits(&self.runtime_limits),
                fuel_budget: FuelTokenBucket::new(&self.runtime_limits),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(
                self.runtime_limits
                    .fuel_capacity()
                    .expect("validated fuel capacity"),
            )
            .map_err(wasmtime_error)?;
        defer_epoch_interruption(&mut store);
        ensure_module_store_engine(&store, &module)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(wasmtime_error)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| WasmTaskError::TaskAbi("guest module exports no memory".to_owned()))?;
        let allocate = instance
            .get_typed_func::<u32, u32>(&mut store, "clusterflux_alloc_v1")
            .map_err(wasmtime_error)?;
        let input_length = u32::try_from(encoded.len())
            .map_err(|_| WasmTaskError::TaskAbi("task invocation is too large".to_owned()))?;
        let input_pointer = allocate
            .call(&mut store, input_length)
            .map_err(wasmtime_error)?;
        if input_pointer == 0 && input_length != 0 {
            return Err(WasmTaskError::TaskAbi(
                "guest refused task invocation allocation".to_owned(),
            ));
        }
        memory
            .write(&mut store, input_pointer as usize, &encoded)
            .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
        let task = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, export)
            .map_err(wasmtime_error)?;
        let _abort_guard = abort_signal.as_ref().map(|signal| {
            EpochControlGuard::arm(&self.engine, &mut store, Arc::clone(signal), debug_control)
        });
        debug_control_trace("calling task ABI export");
        let packed = match task.call(&mut store, (input_pointer, input_length)) {
            Ok(packed) => packed,
            Err(error) => return Err(abort_error(&store, abort_signal.as_ref(), error)),
        };
        decode_guest_task_result(&store, &memory, packed, &invocation.task_instance)
    }

    pub async fn run_task_export_verified_with_task_host_async(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
        export: &str,
        invocation: &WasmTaskInvocation,
        host: Box<dyn AsyncWasmTaskHost>,
    ) -> Result<WasmTaskResult, WasmTaskError> {
        invocation.validate().map_err(WasmTaskError::TaskAbi)?;
        let module_bytes = Self::verified_module_bytes(wasm_or_wat, expected_bundle_digest)?;
        let module = Module::new(&self.engine, &module_bytes).map_err(wasmtime_error)?;
        let linker = async_task_host_linker(&self.engine)?;
        let _epoch_ticker = AsyncEpochTickerGuard::arm(self.engine.clone());
        run_task_export_module_with_task_host_async(
            &self.engine,
            &linker,
            &module,
            export,
            invocation,
            host,
            &self.runtime_limits,
            DEFAULT_ASYNC_FUEL_YIELD_INTERVAL,
        )
        .await
    }

    fn run_i32_export_bytes(
        &self,
        wasm_or_wat: &[u8],
        export: &str,
        arg: i32,
    ) -> Result<i32, WasmTaskError> {
        let module = Module::new(&self.engine, wasm_or_wat).map_err(wasmtime_error)?;
        let linker = task_host_stub_linker(&self.engine)?;
        let mut store = Store::new(
            &self.engine,
            BasicStoreState {
                limits: task_store_limits(&self.runtime_limits),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(
                self.runtime_limits
                    .fuel_capacity()
                    .expect("validated fuel capacity"),
            )
            .map_err(wasmtime_error)?;
        defer_epoch_interruption(&mut store);
        ensure_module_store_engine(&store, &module)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(wasmtime_error)?;
        let func = instance
            .get_typed_func::<i32, i32>(&mut store, export)
            .map_err(wasmtime_error)?;
        func.call(&mut store, arg).map_err(wasmtime_error)
    }

    pub fn freeze_resume_i32_export_probe(
        &self,
        wasm_or_wat: impl AsRef<[u8]>,
        export: &str,
        arg: i32,
    ) -> Result<WasmtimeDebugProbe, WasmTaskError> {
        let task = TaskInstanceId::from(export);
        let snapshot = Self::debug_i32_export_snapshot(wasm_or_wat.as_ref(), export, arg)?;
        let mut epoch = DebugEpoch::pause(
            ProcessId::from("wasmtime-debug-probe"),
            1,
            vec![DebugParticipant {
                task: task.clone(),
                name: export.to_owned(),
                kind: DebugParticipantKind::WasmTask,
                can_freeze: true,
                state: DebugRuntimeState::Running,
                stack_frames: snapshot.stack_frames.clone(),
                local_values: snapshot.local_values.clone(),
                task_args: vec![("arg".to_owned(), arg.to_string())],
                handles: Vec::new(),
                command_status: None,
                recent_output: Vec::new(),
            }],
        )
        .map_err(|err| WasmTaskError::Runtime(err.to_string()))?;
        let frozen_state = epoch
            .participant_state(&task)
            .cloned()
            .ok_or_else(|| WasmTaskError::Runtime("Wasm debug participant missing".to_owned()))?;
        let inspection = epoch
            .inspection(&task)
            .map_err(|err| WasmTaskError::Runtime(err.to_string()))?;
        epoch.continue_all();
        let resumed_state = epoch
            .participant_state(&task)
            .cloned()
            .ok_or_else(|| WasmTaskError::Runtime("Wasm debug participant missing".to_owned()))?;
        let result = self.run_i32_export(wasm_or_wat, export, arg)?;

        Ok(WasmtimeDebugProbe {
            task,
            frozen_state,
            resumed_state,
            result,
            stack_frames: inspection.stack_frames,
            local_values: inspection.local_values,
            wasm_function: snapshot.wasm_function,
            wasm_pc: snapshot.wasm_pc,
        })
    }

    fn debug_i32_export_snapshot(
        wasm_or_wat: &[u8],
        export: &str,
        arg: i32,
    ) -> Result<WasmtimeFrameSnapshot, WasmTaskError> {
        let engine = Self::debug_engine()?;
        let module = Module::new(&engine, wasm_or_wat).map_err(wasmtime_error)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| WasmTaskError::Runtime(format!("create debug runtime: {err:#}")))?;
        let state = runtime.block_on(async {
            let linker = task_host_stub_linker(&engine)?;
            let mut store = Store::new(&engine, WasmtimeDebugState::default());
            store.limiter(|state| &mut state.limits);
            store.set_debug_handler(WasmtimeLocalSnapshotHandler {
                export: export.to_owned(),
            });
            ensure_module_store_engine(&store, &module)?;
            let instance = linker
                .instantiate_async(&mut store, &module)
                .await
                .map_err(wasmtime_error)?;
            if let Some(mut edit) = store.edit_breakpoints() {
                edit.single_step(true).map_err(wasmtime_error)?;
            }
            let func = instance
                .get_typed_func::<i32, i32>(&mut store, export)
                .map_err(wasmtime_error)?;
            let _ = func
                .call_async(&mut store, arg)
                .await
                .map_err(wasmtime_error)?;
            Ok::<_, WasmTaskError>(store.into_data())
        })?;

        state.snapshot.ok_or_else(|| {
            WasmTaskError::Runtime(
                "Wasmtime guest debug did not produce a frame-local snapshot".to_owned(),
            )
        })
    }

    fn verified_module_bytes(
        wasm_or_wat: impl AsRef<[u8]>,
        expected_bundle_digest: &Digest,
    ) -> Result<Vec<u8>, WasmTaskError> {
        let bytes = wasm_or_wat.as_ref();
        let actual = Digest::sha256(bytes);
        if &actual != expected_bundle_digest {
            return Err(WasmTaskError::BundleDigestMismatch {
                expected: expected_bundle_digest.clone(),
                actual,
            });
        }
        Ok(bytes.to_vec())
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_task_export_module_with_task_host_async(
    engine: &Engine,
    linker: &Linker<AsyncWasmtimeTaskHostState>,
    module: &Module,
    export: &str,
    invocation: &WasmTaskInvocation,
    host: Box<dyn AsyncWasmTaskHost>,
    runtime_limits: &WasmtimeRuntimeLimits,
    fuel_yield_interval: u64,
) -> Result<WasmTaskResult, WasmTaskError> {
    invocation.validate().map_err(WasmTaskError::TaskAbi)?;
    runtime_limits.validate()?;
    let encoded = serde_json::to_vec(invocation)
        .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
    let abort_signal = host.abort_signal();
    let debug_control = host.debug_control();
    let lane_abort = abort_signal
        .as_ref()
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let mut store = Store::new(
        engine,
        AsyncWasmtimeTaskHostState {
            host,
            fatal_host_error: None,
            limits: task_store_limits(runtime_limits),
            fuel_budget: FuelTokenBucket::new(runtime_limits),
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(
            runtime_limits
                .fuel_capacity()
                .expect("validated fuel capacity"),
        )
        .map_err(wasmtime_error)?;
    store
        .fuel_async_yield_interval(Some(fuel_yield_interval))
        .map_err(wasmtime_error)?;
    arm_async_epoch_control(&mut store, Arc::clone(&lane_abort), debug_control.clone());
    if let Some(debug) = &debug_control {
        debug.arm_execution_async(&lane_abort).await;
    }
    ensure_module_store_engine(&store, module)?;
    let instance = linker
        .instantiate_async(&mut store, module)
        .await
        .map_err(|error| async_abort_error(&store, abort_signal.as_ref(), error))?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| WasmTaskError::TaskAbi("guest module exports no memory".to_owned()))?;
    let allocate = instance
        .get_typed_func::<u32, u32>(&mut store, "clusterflux_alloc_v1")
        .map_err(wasmtime_error)?;
    let input_length = u32::try_from(encoded.len())
        .map_err(|_| WasmTaskError::TaskAbi("task invocation is too large".to_owned()))?;
    let input_pointer = allocate
        .call_async(&mut store, input_length)
        .await
        .map_err(|error| async_abort_error(&store, abort_signal.as_ref(), error))?;
    if input_pointer == 0 && input_length != 0 {
        return Err(WasmTaskError::TaskAbi(
            "guest refused task invocation allocation".to_owned(),
        ));
    }
    memory
        .write(&mut store, input_pointer as usize, &encoded)
        .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
    let task = instance
        .get_typed_func::<(u32, u32), u64>(&mut store, export)
        .map_err(wasmtime_error)?;
    debug_control_trace("calling async task ABI export");
    let packed = task
        .call_async(&mut store, (input_pointer, input_length))
        .await
        .map_err(|error| async_abort_error(&store, abort_signal.as_ref(), error))?;
    decode_guest_task_result(&store, &memory, packed, &invocation.task_instance)
}

fn wasmtime_error(err: wasmtime::Error) -> WasmTaskError {
    WasmTaskError::Runtime(format!("{err:?}"))
}

fn decode_guest_task_result<T>(
    store: &Store<T>,
    memory: &wasmtime::Memory,
    packed: u64,
    expected_task: &TaskInstanceId,
) -> Result<WasmTaskResult, WasmTaskError> {
    let result_pointer = packed as u32;
    let result_length = (packed >> 32) as u32;
    if result_length as usize > MAX_WASM_TASK_ENVELOPE_BYTES {
        return Err(WasmTaskError::TaskAbi(format!(
            "guest task result is {result_length} bytes; maximum is {MAX_WASM_TASK_ENVELOPE_BYTES}"
        )));
    }
    let mut result_bytes = vec![0_u8; result_length as usize];
    memory
        .read(store, result_pointer as usize, &mut result_bytes)
        .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
    let result: WasmTaskResult = serde_json::from_slice(&result_bytes)
        .map_err(|error| WasmTaskError::TaskAbi(error.to_string()))?;
    result
        .validate_for(expected_task)
        .map_err(WasmTaskError::TaskAbi)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
