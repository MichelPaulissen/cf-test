use super::*;

#[test]
fn async_debug_waiters_observe_freeze_and_resume_without_blocking_a_thread() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let control = Arc::new(WasmDebugControl::default());
        let transition = Arc::clone(&control);
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            transition.mark_frozen(7);
            tokio::task::yield_now().await;
            transition.mark_running(7);
        });

        assert!(
            control
                .wait_until_frozen_async(7, Duration::from_secs(1))
                .await
        );
        assert!(
            control
                .wait_until_running_async(7, Duration::from_secs(1))
                .await
        );
        task.await.unwrap();
    });
}

#[test]
fn cross_engine_modules_are_rejected_before_instantiation() {
    let module_engine = Engine::default();
    let store_engine = Engine::default();
    let module = Module::new(&module_engine, "(module)").unwrap();
    let store = Store::new(&store_engine, ());

    let error = ensure_module_store_engine(&store, &module).unwrap_err();
    assert!(matches!(
        error,
        WasmTaskError::Runtime(message) if message.contains("another engine")
    ));
}

#[test]
fn runtime_limits_reject_zero_and_effectively_unbounded_values() {
    assert!(WasmtimeRuntimeLimits::default().validate().is_ok());
    for limits in [
        WasmtimeRuntimeLimits {
            fuel_units_per_second: 0,
            ..WasmtimeRuntimeLimits::default()
        },
        WasmtimeRuntimeLimits {
            fuel_units_per_second: u64::MAX,
            ..WasmtimeRuntimeLimits::default()
        },
        WasmtimeRuntimeLimits {
            fuel_burst_seconds: u64::MAX,
            ..WasmtimeRuntimeLimits::default()
        },
        WasmtimeRuntimeLimits {
            memory_bytes: usize::MAX,
            ..WasmtimeRuntimeLimits::default()
        },
    ] {
        assert!(limits.validate().is_err());
    }
}

#[test]
fn fuel_token_bucket_refills_after_idle_and_never_exceeds_burst() {
    let limits = WasmtimeRuntimeLimits {
        fuel_units_per_second: 100,
        fuel_burst_seconds: 2,
        memory_bytes: 1024 * 1024,
    };
    let mut bucket = FuelTokenBucket::new(&limits);
    bucket.last_refill = Instant::now() - Duration::from_millis(1_500);
    let refilled = bucket.refill(0);
    assert!((150..=151).contains(&refilled));

    bucket.last_refill = Instant::now() - Duration::from_secs(10);
    assert_eq!(bucket.refill(refilled), 200);
    for _ in 0..10_000 {
        assert!(bucket.refill(200) <= 200);
    }
}

struct AbortSignalHost {
    abort: Arc<AtomicBool>,
    debug: Option<Arc<WasmDebugControl>>,
}

impl WasmTaskHost for AbortSignalHost {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        Some(Arc::clone(&self.abort))
    }

    fn debug_control(&self) -> Option<Arc<WasmDebugControl>> {
        self.debug.clone()
    }

    fn start_task(
        &mut self,
        _request: WasmHostTaskStartRequest,
    ) -> Result<WasmHostTaskHandle, String> {
        Err("not used".to_owned())
    }

    fn join_task(
        &mut self,
        _request: WasmHostTaskJoinRequest,
    ) -> Result<WasmHostTaskJoinResult, String> {
        Err("not used".to_owned())
    }

    fn run_command(
        &mut self,
        _request: WasmHostCommandRequest,
    ) -> Result<WasmHostCommandResult, String> {
        Err("not used".to_owned())
    }

    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> Result<WasmHostTaskControlResult, String> {
        request.validate()?;
        Ok(WasmHostTaskControlResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            cancellation_requested: false,
        })
    }

    fn vfs_operation(&mut self, _request: WasmHostVfsRequest) -> Result<WasmHostVfsResult, String> {
        Err("not used".to_owned())
    }

    fn snapshot_source(
        &mut self,
        _request: WasmHostSourceSnapshotRequest,
    ) -> Result<WasmHostSourceSnapshotResult, String> {
        Err("not used".to_owned())
    }
}

#[test]
fn epoch_interruption_aborts_cpu_bound_wasm_without_a_host_call() {
    let abort = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&abort);
    let trigger_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        trigger.store(true, Ordering::Release);
    });
    let wasm = r#"
            (module
              (func (export "spin") (param i32) (result i32)
                (loop $forever
                  br $forever)
                i32.const 0))
        "#;
    let started = std::time::Instant::now();
    let error = WasmtimeTaskRuntime::new()
        .unwrap()
        .run_i32_export_verified_with_task_host(
            wasm,
            &Digest::sha256(wasm),
            "spin",
            1,
            Box::new(AbortSignalHost { abort, debug: None }),
        )
        .unwrap_err();
    trigger_thread.join().unwrap();

    assert!(matches!(error, WasmTaskError::HostControl(_)));
    assert!(error.to_string().contains("process abort"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn aborting_one_store_does_not_poison_the_shared_engine() {
    let runtime = WasmtimeTaskRuntime::new().unwrap();
    let abort = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&abort);
    let trigger_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        trigger.store(true, Ordering::Release);
    });
    let spinning_wasm = r#"
            (module
              (func (export "spin") (param i32) (result i32)
                (loop $forever
                  br $forever)
                i32.const 0))
        "#;
    let error = runtime
        .run_i32_export_verified_with_task_host(
            spinning_wasm,
            &Digest::sha256(spinning_wasm),
            "spin",
            0,
            Box::new(AbortSignalHost { abort, debug: None }),
        )
        .unwrap_err();
    trigger_thread.join().unwrap();
    assert!(matches!(error, WasmTaskError::HostControl(_)));

    let succeeding_wasm = r#"
            (module
              (func (export "increment") (param i32) (result i32)
                local.get 0
                i32.const 1
                i32.add))
        "#;
    assert_eq!(
        runtime
            .run_i32_export_verified(
                succeeding_wasm,
                &Digest::sha256(succeeding_wasm),
                "increment",
                41,
            )
            .unwrap(),
        42
    );
}

#[test]
fn debug_control_freezes_and_resumes_executing_wasm_before_abort() {
    let runtime = WasmtimeTaskRuntime::new().unwrap();
    let abort = Arc::new(AtomicBool::new(false));
    let debug = Arc::new(WasmDebugControl::default());
    let execution_abort = Arc::clone(&abort);
    let execution_debug = Arc::clone(&debug);
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let execution = thread::spawn(move || {
        let wasm = r#"
                (module
                  (func (export "spin") (param i32) (result i32)
                    (loop $forever
                      br $forever)
                    i32.const 0))
            "#;
        let result = runtime.run_i32_export_verified_with_task_host(
            wasm,
            &Digest::sha256(wasm),
            "spin",
            0,
            Box::new(AbortSignalHost {
                abort: execution_abort,
                debug: Some(execution_debug),
            }),
        );
        let _ = finished_tx.send(());
        result
    });

    debug.request_freeze(7);
    assert!(debug.wait_until_frozen(7, Duration::from_secs(2)));
    assert!(finished_rx.try_recv().is_err());
    debug.request_resume(7);
    assert!(debug.wait_until_running(7, Duration::from_secs(2)));
    abort.store(true, Ordering::Release);

    let error = execution.join().unwrap().unwrap_err();
    assert!(matches!(error, WasmTaskError::HostControl(_)));
    assert!(error.to_string().contains("process abort"));
}

#[test]
fn pending_freeze_blocks_a_quiescent_host_call_before_it_starts() {
    let debug = Arc::new(WasmDebugControl::default());
    debug.request_freeze(9);
    let boundary_debug = Arc::clone(&debug);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let boundary = thread::spawn(move || {
        boundary_debug.enter_quiescent_host_boundary(None);
        entered_tx.send(()).unwrap();
        boundary_debug.leave_quiescent_host_boundary(None);
    });

    assert!(debug.wait_until_frozen(9, Duration::from_secs(1)));
    assert!(entered_rx.try_recv().is_err());
    debug.request_resume(9);
    assert!(debug.wait_until_running(9, Duration::from_secs(1)));
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    boundary.join().unwrap();
}

#[test]
fn wasm_linear_memory_growth_is_bounded_per_store() {
    let wasm = r#"
        (module
          (memory 1)
          (func (export "grow") (param i32) (result i32)
            i32.const 5000
            memory.grow
            drop
            local.get 0))
    "#;
    let runtime = WasmtimeTaskRuntime::new().unwrap();
    let error = runtime.run_i32_export(wasm, "grow", 7).unwrap_err();

    assert!(error.to_string().contains("memory") || error.to_string().contains("grow"));
    assert_eq!(
        runtime
            .run_i32_export(
                "(module (func (export \"healthy\") (param i32) (result i32) local.get 0))",
                "healthy",
                11,
            )
            .unwrap(),
        11
    );
}
