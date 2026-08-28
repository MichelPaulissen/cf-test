extern crate self as clusterflux;

use serde::Serialize;

pub use clusterflux_core as core;
pub use clusterflux_macros::{main, task, TaskArg};
#[doc(hidden)]
pub use serde;

mod sdk_runtime;
mod task_args;
pub use task_args::{
    reject_host_only_task_arg, validate_task_arg, Artifact, Blob, EnvRef, SourceSnapshot, TaskArg,
    TaskArgBudget, TaskArgError, TaskArgKind, TaskArgValidation, Vfs,
};

pub use clusterflux_core::TaskFailurePolicy;
pub use sdk_runtime::TaskRuntimeError as Error;
pub type Result<T> = std::result::Result<T, Error>;

pub mod prelude {
    pub use crate::{
        command::Command, fs, source, trigger, Artifact, Result, SourceSnapshot, TaskFailurePolicy,
    };
}

#[macro_export]
macro_rules! spawn {
    ($task:ident()) => {
        $crate::spawn::__product_async_task($task, stringify!($task))
    };
    ($task:ident($argument:expr)) => {
        $crate::spawn::__product_async_task_with_arg($argument, $task, stringify!($task))
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EntrypointDescriptor {
    pub name: &'static str,
    pub function: &'static str,
    pub export: &'static str,
    pub stable_id: &'static str,
    pub argument_schema: &'static str,
    pub result_schema: &'static str,
    pub abi_version: u32,
    pub bundle_manifest_entry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TaskDescriptor {
    pub name: &'static str,
    pub function: &'static str,
    pub export: &'static str,
    pub stable_id: &'static str,
    pub argument_schema: &'static str,
    pub result_schema: &'static str,
    pub required_capabilities: &'static [&'static str],
    pub restart_compatibility_hash: &'static str,
    pub abi_version: u32,
    pub source_file: &'static str,
    pub source_line: u32,
    pub probe_symbol: &'static str,
    pub bundle_manifest_entry: bool,
    pub remotely_startable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredProgram {
    pub entrypoints: &'static [EntrypointDescriptor],
    pub tasks: &'static [TaskDescriptor],
}

impl RegisteredProgram {
    pub fn select_entrypoint(&self, name: &str) -> Option<EntrypointDescriptor> {
        self.entrypoints
            .iter()
            .copied()
            .find(|entrypoint| entrypoint.name == name)
    }

    pub fn task(&self, name: &str) -> Option<TaskDescriptor> {
        self.tasks.iter().copied().find(|task| task.name == name)
    }
}

#[doc(hidden)]
pub mod __private;

pub mod spawn {
    use std::future::{Future, IntoFuture};
    use std::pin::Pin;
    #[cfg(target_arch = "wasm32")]
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    pub use clusterflux_core::TaskFailurePolicy;
    use serde::de::DeserializeOwned;

    #[cfg(target_arch = "wasm32")]
    use crate::sdk_runtime::start_guest_host_task;
    pub use crate::sdk_runtime::TaskRuntimeError;
    use crate::sdk_runtime::{join_remote_task, RemoteTaskHandle};
    #[cfg(target_arch = "wasm32")]
    use crate::validate_task_arg;
    use crate::{EnvRef, TaskArg, TaskArgBudget};

    #[cfg(target_arch = "wasm32")]
    static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);
    static RUNTIME_THREADS: OnceLock<Mutex<Vec<RuntimeSpawnEvent>>> = OnceLock::new();

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RuntimeSpawnEvent {
        pub virtual_thread_id: u64,
        pub name: &'static str,
        pub env: Option<EnvRef>,
        pub debugger_visible: bool,
    }

    fn runtime_threads() -> &'static Mutex<Vec<RuntimeSpawnEvent>> {
        RUNTIME_THREADS.get_or_init(|| Mutex::new(Vec::new()))
    }

    #[cfg(target_arch = "wasm32")]
    fn register_runtime_thread(
        virtual_thread_id: u64,
        name: &'static str,
        env: Option<EnvRef>,
    ) -> RuntimeSpawnEvent {
        let event = RuntimeSpawnEvent {
            virtual_thread_id,
            name,
            env,
            debugger_visible: true,
        };
        runtime_threads().lock().unwrap().push(event.clone());
        event
    }

    pub fn drain_runtime_spawn_events() -> Vec<RuntimeSpawnEvent> {
        runtime_threads().lock().unwrap().drain(..).collect()
    }

    pub fn runtime_spawn_events() -> Vec<RuntimeSpawnEvent> {
        runtime_threads().lock().unwrap().clone()
    }

    #[doc(hidden)]
    pub fn __product_async_task<F, Fut, R>(
        entry: F,
        task_id: &'static str,
    ) -> ProductAsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg,
    {
        ProductAsyncTaskBuilder {
            entry: Some(entry),
            env: None,
            name: task_id,
            task_id,
            failure_policy: TaskFailurePolicy::FailFast,
            secrets: Vec::new(),
            marker: std::marker::PhantomData,
        }
    }

    #[doc(hidden)]
    pub fn __product_async_task_with_arg<A, F, Fut, R>(
        arg: A,
        entry: F,
        task_id: &'static str,
    ) -> ProductAsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg,
    {
        ProductAsyncTaskWithArgBuilder {
            arg: Some(arg),
            entry: Some(entry),
            env: None,
            name: task_id,
            task_id,
            arg_budget: TaskArgBudget::default(),
            failure_policy: TaskFailurePolicy::FailFast,
            secrets: Vec::new(),
            marker: std::marker::PhantomData,
        }
    }

    pub struct ProductAsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg,
    {
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        task_id: &'static str,
        failure_policy: TaskFailurePolicy,
        secrets: Vec<String>,
        marker: std::marker::PhantomData<fn() -> (Fut, R)>,
    }

    impl<F, Fut, R> ProductAsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg + DeserializeOwned,
    {
        pub fn on(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        /// Requests an opaque project secret for this task. Only its name is
        /// visible to Wasm; bytes are materialized by the assigned node.
        pub fn secret(mut self, name: impl Into<String>) -> Self {
            self.secrets.push(name.into());
            self
        }

        pub async fn start(self) -> crate::Result<TaskHandle<R>> {
            #[cfg(target_arch = "wasm32")]
            {
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(self.task_id),
                    self.env,
                    Vec::new(),
                    self.secrets,
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    impl<F, Fut, R> IntoFuture for ProductAsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut + 'static,
        Fut: Future<Output = crate::Result<R>> + 'static,
        R: TaskArg + DeserializeOwned + 'static,
    {
        type Output = crate::Result<TaskHandle<R>>;
        type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

        fn into_future(self) -> Self::IntoFuture {
            Box::pin(self.start())
        }
    }

    pub struct ProductAsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg,
    {
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        arg: Option<A>,
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        task_id: &'static str,
        arg_budget: TaskArgBudget,
        failure_policy: TaskFailurePolicy,
        secrets: Vec<String>,
        marker: std::marker::PhantomData<fn() -> (Fut, R)>,
    }

    impl<A, F, Fut, R> ProductAsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: Future<Output = crate::Result<R>>,
        R: TaskArg + DeserializeOwned,
    {
        pub fn on(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn arg_budget(mut self, arg_budget: TaskArgBudget) -> Self {
            self.arg_budget = arg_budget;
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        pub fn secret(mut self, name: impl Into<String>) -> Self {
            self.secrets.push(name.into());
            self
        }

        pub async fn start(self) -> crate::Result<TaskHandle<R>> {
            #[cfg(target_arch = "wasm32")]
            {
                let arg = self.arg.expect("task argument used once");
                validate_task_arg(&arg, self.arg_budget)
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let boundary = arg
                    .task_boundary_value()
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(self.task_id),
                    self.env,
                    vec![boundary],
                    self.secrets,
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    impl<A, F, Fut, R> IntoFuture for ProductAsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg + 'static,
        F: FnOnce(A) -> Fut + 'static,
        Fut: Future<Output = crate::Result<R>> + 'static,
        R: TaskArg + DeserializeOwned + 'static,
    {
        type Output = crate::Result<TaskHandle<R>>;
        type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

        fn into_future(self) -> Self::IntoFuture {
            Box::pin(self.start())
        }
    }

    pub fn task<F, R>(entry: F) -> TaskBuilder<F, R>
    where
        F: FnOnce() -> R,
        R: TaskArg,
    {
        TaskBuilder {
            entry: Some(entry),
            env: None,
            name: "task",
            task_id: None,
            failure_policy: TaskFailurePolicy::FailFast,
        }
    }

    pub fn task_with_arg<A, F, R>(arg: A, entry: F) -> TaskWithArgBuilder<A, F, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> R,
        R: TaskArg,
    {
        TaskWithArgBuilder {
            arg: Some(arg),
            entry: Some(entry),
            env: None,
            name: "task",
            task_id: None,
            arg_budget: TaskArgBudget::default(),
            failure_policy: TaskFailurePolicy::FailFast,
        }
    }

    pub fn async_task<F, Fut, R>(entry: F) -> AsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg,
    {
        AsyncTaskBuilder {
            entry: Some(entry),
            env: None,
            name: "task",
            task_id: None,
            failure_policy: TaskFailurePolicy::FailFast,
            marker: std::marker::PhantomData,
        }
    }

    pub fn async_task_with_arg<A, F, Fut, R>(
        arg: A,
        entry: F,
    ) -> AsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg,
    {
        AsyncTaskWithArgBuilder {
            arg: Some(arg),
            entry: Some(entry),
            env: None,
            name: "task",
            task_id: None,
            arg_budget: TaskArgBudget::default(),
            failure_policy: TaskFailurePolicy::FailFast,
            marker: std::marker::PhantomData,
        }
    }

    pub struct AsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg,
    {
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        task_id: Option<String>,
        failure_policy: TaskFailurePolicy,
        marker: std::marker::PhantomData<fn() -> (Fut, R)>,
    }

    impl<F, Fut, R> AsyncTaskBuilder<F, Fut, R>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg + DeserializeOwned,
    {
        pub fn env(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn task_id(mut self, task_id: impl Into<String>) -> Self {
            self.task_id = Some(task_id.into());
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        pub async fn start(self) -> Result<TaskHandle<R>, TaskRuntimeError> {
            #[cfg(target_arch = "wasm32")]
            {
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let task_id = product_task_id::<F>(self.task_id)?;
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(task_id.as_str()),
                    self.env,
                    Vec::new(),
                    Vec::new(),
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    pub struct AsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg,
    {
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        arg: Option<A>,
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        task_id: Option<String>,
        arg_budget: TaskArgBudget,
        failure_policy: TaskFailurePolicy,
        marker: std::marker::PhantomData<fn() -> (Fut, R)>,
    }

    impl<A, F, Fut, R> AsyncTaskWithArgBuilder<A, F, Fut, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> Fut,
        Fut: std::future::Future<Output = R>,
        R: TaskArg + DeserializeOwned,
    {
        pub fn env(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn task_id(mut self, task_id: impl Into<String>) -> Self {
            self.task_id = Some(task_id.into());
            self
        }

        pub fn arg_budget(mut self, arg_budget: TaskArgBudget) -> Self {
            self.arg_budget = arg_budget;
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        pub async fn start(self) -> Result<TaskHandle<R>, TaskRuntimeError> {
            #[cfg(target_arch = "wasm32")]
            {
                let arg = self.arg.expect("task argument used once");
                validate_task_arg(&arg, self.arg_budget)
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let task_id = product_task_id::<F>(self.task_id)?;
                let boundary = arg
                    .task_boundary_value()
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(task_id.as_str()),
                    self.env,
                    vec![boundary],
                    Vec::new(),
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    pub struct TaskBuilder<F, R>
    where
        F: FnOnce() -> R,
        R: TaskArg,
    {
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        task_id: Option<String>,
        failure_policy: TaskFailurePolicy,
    }

    impl<F, R> TaskBuilder<F, R>
    where
        F: FnOnce() -> R,
        R: TaskArg + DeserializeOwned,
    {
        pub fn env(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn task_id(mut self, task_id: impl Into<String>) -> Self {
            self.task_id = Some(task_id.into());
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        pub async fn start(self) -> Result<TaskHandle<R>, TaskRuntimeError> {
            #[cfg(target_arch = "wasm32")]
            {
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let task_id = product_task_id::<F>(self.task_id)?;
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(task_id.as_str()),
                    self.env,
                    Vec::new(),
                    Vec::new(),
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    pub struct TaskWithArgBuilder<A, F, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> R,
        R: TaskArg,
    {
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        arg: Option<A>,
        #[allow(dead_code)]
        entry: Option<F>,
        env: Option<EnvRef>,
        name: &'static str,
        task_id: Option<String>,
        arg_budget: TaskArgBudget,
        failure_policy: TaskFailurePolicy,
    }

    impl<A, F, R> TaskWithArgBuilder<A, F, R>
    where
        A: TaskArg,
        F: FnOnce(A) -> R,
        R: TaskArg + DeserializeOwned,
    {
        pub fn env(mut self, env: EnvRef) -> Self {
            self.env = Some(env);
            self
        }

        pub fn name(mut self, name: &'static str) -> Self {
            self.name = name;
            self
        }

        pub fn task_id(mut self, task_id: impl Into<String>) -> Self {
            self.task_id = Some(task_id.into());
            self
        }

        pub fn arg_budget(mut self, arg_budget: TaskArgBudget) -> Self {
            self.arg_budget = arg_budget;
            self
        }

        pub fn failure_policy(mut self, failure_policy: TaskFailurePolicy) -> Self {
            self.failure_policy = failure_policy;
            self
        }

        pub async fn start(self) -> Result<TaskHandle<R>, TaskRuntimeError> {
            #[cfg(target_arch = "wasm32")]
            {
                let arg = self.arg.expect("task argument used once");
                validate_task_arg(&arg, self.arg_budget)
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let id = NEXT_THREAD_ID.fetch_add(1, Ordering::SeqCst);
                let runtime_event = register_runtime_thread(id, self.name, self.env);
                let task_id = product_task_id::<F>(self.task_id)?;
                let boundary = arg
                    .task_boundary_value()
                    .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
                let remote = start_guest_host_task(
                    clusterflux_core::TaskDefinitionId::from(task_id.as_str()),
                    self.env,
                    vec![boundary],
                    Vec::new(),
                    self.failure_policy,
                )?;
                return Ok(TaskHandle {
                    virtual_thread_id: id,
                    name: self.name,
                    env: self.env,
                    debugger_visible: runtime_event.debugger_visible,
                    remote: Some(remote),
                    marker: std::marker::PhantomData,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = self;
                Err(TaskRuntimeError::NotRunningInsideClusterflux)
            }
        }
    }

    pub struct TaskHandle<R> {
        virtual_thread_id: u64,
        name: &'static str,
        env: Option<EnvRef>,
        debugger_visible: bool,
        remote: Option<RemoteTaskHandle>,
        marker: std::marker::PhantomData<fn() -> R>,
    }

    impl<R> TaskHandle<R>
    where
        R: TaskArg + DeserializeOwned,
    {
        pub fn virtual_thread_id(&self) -> u64 {
            self.virtual_thread_id
        }

        pub fn name(&self) -> &'static str {
            self.name
        }

        pub fn env(&self) -> Option<EnvRef> {
            self.env
        }

        pub fn debugger_visible(&self) -> bool {
            self.debugger_visible
        }

        pub fn task_spec(&self) -> Option<&clusterflux_core::TaskSpec> {
            self.remote.as_ref().map(|remote| &remote.spec)
        }

        pub async fn join(mut self) -> Result<R, TaskRuntimeError> {
            if let Some(remote) = self.remote.take() {
                return join_remote_task(remote);
            }
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn product_task_id<F>(explicit: Option<String>) -> Result<String, TaskRuntimeError> {
        if let Some(explicit) = explicit {
            return Ok(explicit);
        }
        let inferred = std::any::type_name::<F>()
            .rsplit("::")
            .next()
            .unwrap_or_default();
        if inferred.is_empty() || inferred.contains("closure") {
            return Err(TaskRuntimeError::Configuration(
                "product-mode spawn from a closure requires .task_id(\"registered-export\")"
                    .to_owned(),
            ));
        }
        Ok(inferred.to_owned())
    }
}

pub mod command {
    use std::collections::BTreeMap;
    use std::time::Duration;

    pub use crate::sdk_runtime::TaskRuntimeError;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Output {
        pub status_code: Option<i32>,
        pub stdout: String,
        pub stderr: String,
        pub stdout_truncated: bool,
        pub stderr_truncated: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Command {
        program: String,
        args: Vec<String>,
        working_directory: String,
        environment_variables: BTreeMap<String, String>,
        secret_environment_variables: BTreeMap<String, String>,
        timeout: Duration,
        network: clusterflux_core::CommandNetworkPolicy,
    }

    impl Command {
        pub fn new(program: impl Into<String>) -> Self {
            Self {
                program: program.into(),
                args: Vec::new(),
                working_directory: "/workspace".to_owned(),
                environment_variables: BTreeMap::new(),
                secret_environment_variables: BTreeMap::new(),
                timeout: Duration::from_secs(15 * 60),
                network: clusterflux_core::CommandNetworkPolicy::Disabled,
            }
        }

        pub fn arg(mut self, arg: impl Into<String>) -> Self {
            self.args.push(arg.into());
            self
        }

        pub fn args<I, S>(mut self, args: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            self.args.extend(args.into_iter().map(Into::into));
            self
        }

        pub fn current_dir(mut self, directory: impl Into<String>) -> Self {
            self.working_directory = directory.into();
            self
        }

        pub fn cwd(self, directory: impl Into<String>) -> Self {
            self.current_dir(directory)
        }

        pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
            self.environment_variables.insert(name.into(), value.into());
            self
        }

        /// Binds a previously task-granted secret directly into a native
        /// command environment variable without exposing its value to Wasm.
        pub fn secret_env(
            mut self,
            environment_name: impl Into<String>,
            secret_name: impl Into<String>,
        ) -> Self {
            self.secret_environment_variables
                .insert(environment_name.into(), secret_name.into());
            self
        }

        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        pub fn network_disabled(mut self) -> Self {
            self.network = clusterflux_core::CommandNetworkPolicy::Disabled;
            self
        }

        pub fn network_enabled(mut self) -> Self {
            self.network = clusterflux_core::CommandNetworkPolicy::Enabled;
            self
        }

        pub async fn output(self) -> Result<Output, TaskRuntimeError> {
            #[cfg(target_arch = "wasm32")]
            {
                let timeout_ms = u64::try_from(self.timeout.as_millis()).map_err(|_| {
                    TaskRuntimeError::Argument(
                        "command timeout does not fit the task ABI".to_owned(),
                    )
                })?;
                let output = crate::sdk_runtime::run_guest_host_command(
                    self.program,
                    self.args,
                    self.working_directory,
                    self.environment_variables,
                    self.secret_environment_variables,
                    timeout_ms,
                    self.network,
                )?;
                return Ok(Output {
                    status_code: output.status_code,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    stdout_truncated: output.stdout_truncated,
                    stderr_truncated: output.stderr_truncated,
                });
            }
            #[cfg(not(target_arch = "wasm32"))]
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }

        pub async fn run(self) -> Result<Output, TaskRuntimeError> {
            let program = self.program.clone();
            let output = self.output().await?;
            if output.status_code == Some(0) {
                return Ok(output);
            }
            Err(TaskRuntimeError::CommandFailed {
                program,
                status_code: output.status_code,
                stdout: bounded_tail(output.stdout),
                stderr: bounded_tail(output.stderr),
                stdout_truncated: output.stdout_truncated,
                stderr_truncated: output.stderr_truncated,
            })
        }
    }

    fn bounded_tail(value: String) -> String {
        const LIMIT: usize = 4 * 1024;
        if value.len() <= LIMIT {
            return value;
        }
        let mut start = value.len() - LIMIT;
        while !value.is_char_boundary(start) {
            start += 1;
        }
        value[start..].to_owned()
    }
}

pub mod source {
    use crate::{spawn::TaskRuntimeError, SourceSnapshot};

    /// Snapshots the node-local project checkout without sending its source bytes
    /// through the coordinator.
    pub async fn snapshot() -> Result<SourceSnapshot, TaskRuntimeError> {
        #[cfg(target_arch = "wasm32")]
        {
            let result = crate::sdk_runtime::guest_source_snapshot()?;
            return Ok(SourceSnapshot {
                digest: result.snapshot.as_str().to_owned(),
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        Err(TaskRuntimeError::NotRunningInsideClusterflux)
    }

    pub struct CurrentProject;

    pub fn current_project() -> CurrentProject {
        CurrentProject
    }

    impl CurrentProject {
        pub async fn snapshot(self) -> Result<SourceSnapshot, TaskRuntimeError> {
            crate::spawn::__product_async_task(snapshot_current_project, "snapshot_current_project")
                .await?
                .join()
                .await
        }
    }

    #[clusterflux::task(capabilities = "source_filesystem")]
    async fn snapshot_current_project() -> crate::Result<SourceSnapshot> {
        snapshot().await
    }
}

pub mod trigger {
    use serde::{Deserialize, Serialize};

    use crate::{spawn::TaskRuntimeError, SourceSnapshot};

    /// Immutable, coordinator-verified metadata for the forge event that started
    /// the current workflow. This contains no forge credentials.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Current {
        pub repository_id: String,
        pub commit_sha: String,
        pub git_ref: String,
        pub trusted: bool,
        pub source: SourceSnapshot,
    }

    /// Returns the exact accepted commit and its immutable source snapshot.
    pub async fn current() -> Result<Current, TaskRuntimeError> {
        #[cfg(target_arch = "wasm32")]
        {
            let result = crate::sdk_runtime::guest_trigger_context()?;
            return Ok(Current {
                repository_id: result.context.repository_id.as_str().to_owned(),
                commit_sha: result.context.commit_sha,
                git_ref: result.context.git_ref,
                trusted: result.context.trusted,
                source: SourceSnapshot {
                    digest: result.context.source_snapshot.as_str().to_owned(),
                },
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        Err(TaskRuntimeError::NotRunningInsideClusterflux)
    }
}

impl SourceSnapshot {
    pub fn mount(&self) -> Result<&'static str> {
        crate::task_args::parse_handle_digest(&self.digest)
            .map_err(|error| Error::Argument(error.to_string()))?;
        Ok("/workspace")
    }
}

pub mod fs {
    use crate::{spawn::TaskRuntimeError, Artifact};

    pub const OUTPUT_ROOT: &str = "/clusterflux/output";

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct OutputPath {
        relative: String,
        container_path: String,
    }

    impl OutputPath {
        pub fn relative(&self) -> &str {
            &self.relative
        }

        pub fn as_str(&self) -> &str {
            &self.container_path
        }
    }

    pub fn output_path(relative: impl Into<String>) -> Result<OutputPath, TaskRuntimeError> {
        let relative = relative.into();
        validate_relative_path(&relative)?;
        Ok(OutputPath {
            container_path: format!("{OUTPUT_ROOT}/{relative}"),
            relative,
        })
    }

    pub fn output(relative: impl Into<String>) -> Result<OutputPath, TaskRuntimeError> {
        output_path(relative)
    }

    pub async fn flush(path: &OutputPath) -> Result<Artifact, TaskRuntimeError> {
        #[cfg(target_arch = "wasm32")]
        {
            let retained = crate::sdk_runtime::guest_vfs_operation(
                clusterflux_core::WasmHostVfsOperation::FlushOutput {
                    relative_path: path.relative.clone(),
                },
            )?;
            return Ok(Artifact {
                id: retained.artifact.id.as_str().to_owned(),
                digest: retained.artifact.digest.as_str().to_owned(),
                size_bytes: retained.artifact.size_bytes,
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = path;
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }
    }

    pub async fn publish(path: &OutputPath) -> Result<Artifact, TaskRuntimeError> {
        flush(path).await
    }

    pub async fn materialize(
        artifact: &Artifact,
        relative: impl Into<String>,
    ) -> Result<OutputPath, TaskRuntimeError> {
        let output = output_path(relative)?;
        #[cfg(target_arch = "wasm32")]
        {
            let digest = crate::task_args::parse_handle_digest(&artifact.digest)
                .map_err(|error| TaskRuntimeError::Argument(error.to_string()))?;
            crate::sdk_runtime::guest_vfs_operation(
                clusterflux_core::WasmHostVfsOperation::MaterializeArtifact {
                    artifact: clusterflux_core::ArtifactHandle {
                        id: clusterflux_core::ArtifactId::from(artifact.id.as_str()),
                        digest,
                        size_bytes: artifact.size_bytes,
                    },
                    relative_path: output.relative.clone(),
                },
            )?;
            return Ok(output);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&output, artifact);
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }
    }

    fn validate_relative_path(path: &str) -> Result<(), TaskRuntimeError> {
        if path.is_empty()
            || path.len() > 240
            || path.starts_with('/')
            || path.starts_with('\\')
            || path.split('/').any(|component| {
                component.is_empty()
                    || component == "."
                    || component == ".."
                    || !component.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "._-".contains(character)
                    })
            })
        {
            return Err(TaskRuntimeError::Argument(
                "output path must be a safe task-output-relative path".to_owned(),
            ));
        }
        Ok(())
    }
}

pub mod process {
    pub use crate::sdk_runtime::TaskRuntimeError;

    pub fn cancellation_requested() -> Result<bool, TaskRuntimeError> {
        #[cfg(target_arch = "wasm32")]
        {
            return crate::sdk_runtime::guest_cancellation_requested();
        }
        #[cfg(not(target_arch = "wasm32"))]
        Err(TaskRuntimeError::NotRunningInsideClusterflux)
    }
}

#[doc(hidden)]
pub mod debug {
    pub use crate::sdk_runtime::TaskRuntimeError;

    pub fn probe(symbol: impl Into<String>) -> Result<(), TaskRuntimeError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = crate::sdk_runtime::guest_debug_probe(symbol.into(), None)?;
            return Ok(());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = symbol.into();
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }
    }

    #[doc(hidden)]
    pub fn probe_at(
        symbol: impl Into<String>,
        source_path: impl Into<String>,
        line: u32,
    ) -> Result<(), TaskRuntimeError> {
        let symbol = symbol.into();
        let source_path = source_path.into().replace('\\', "/");
        #[cfg(target_arch = "wasm32")]
        {
            let location = project_source_location(&symbol, &source_path, line);
            let _ = crate::sdk_runtime::guest_debug_probe(symbol, location)?;
            return Ok(());
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (symbol, source_path, line);
            Err(TaskRuntimeError::NotRunningInsideClusterflux)
        }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn project_source_location(
        probe_id: &str,
        source_path: &str,
        line: u32,
    ) -> Option<clusterflux_core::SourceLocation> {
        let windows_absolute = source_path.as_bytes().get(1) == Some(&b':')
            && source_path.as_bytes().get(2) == Some(&b'/');
        if source_path.is_empty()
            || source_path.len() > 512
            || source_path.starts_with('/')
            || windows_absolute
            || source_path.split('/').any(|part| part == "..")
            || line == 0
        {
            return None;
        }
        Some(clusterflux_core::SourceLocation {
            source_path: source_path.to_owned(),
            line,
            column: None,
            probe_id: probe_id.to_owned(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::project_source_location;

        #[test]
        fn dependency_absolute_paths_do_not_become_project_source_locations() {
            assert!(project_source_location("probe", "/workspace/sdk/src/lib.rs", 1).is_none());
            assert!(project_source_location("probe", "C:/workspace/sdk/src/lib.rs", 1).is_none());
            assert_eq!(
                project_source_location("probe", ".clusterflux/main.rs", 7)
                    .expect("project-relative source location")
                    .source_path,
                ".clusterflux/main.rs"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    #[test]
    fn env_macro_creates_logical_environment_reference() {
        let env = crate::env!("linux");

        assert_eq!(env.name, "linux");
    }

    #[test]
    fn native_spawn_returns_one_typed_error_without_invoking_or_registering_a_task() {
        let invoked = std::cell::Cell::new(false);
        let result = block_on(async {
            crate::spawn::task(|| {
                invoked.set(true);
                7_u32
            })
            .name("sdk-runtime-thread-test")
            .env(crate::env!("linux"))
            .start()
            .await
        });

        assert!(matches!(
            result,
            Err(crate::spawn::TaskRuntimeError::NotRunningInsideClusterflux)
        ));
        assert!(!invoked.get());
        assert!(crate::spawn::runtime_spawn_events()
            .iter()
            .all(|event| event.name != "sdk-runtime-thread-test"));
    }

    #[test]
    fn task_arg_validation_allows_handles_and_rejects_oversized_inline_values() {
        let artifact = crate::Artifact {
            id: "artifact://build/app".to_owned(),
            digest: clusterflux_core::Digest::sha256("app").as_str().to_owned(),
            size_bytes: 3,
        };
        let artifact_validation = crate::validate_task_arg(
            &artifact,
            crate::TaskArgBudget {
                max_inline_bytes: 4,
            },
        )
        .unwrap();
        assert_eq!(artifact_validation.kind, crate::TaskArgKind::Handle);

        let bytes = vec![1_u8, 2, 3, 4, 5];
        let error = crate::validate_task_arg(
            &bytes,
            crate::TaskArgBudget {
                max_inline_bytes: 4,
            },
        )
        .unwrap_err();
        assert!(matches!(error, crate::TaskArgError::TooLarge { .. }));
    }

    #[test]
    fn native_spawn_with_arg_returns_runtime_error_before_argument_or_closure_dispatch() {
        let dispatched = std::cell::Cell::new(false);
        let result = block_on(async {
            crate::spawn::task_with_arg(vec![1_u8, 2, 3, 4, 5], |_| {
                dispatched.set(true);
                42_u32
            })
            .arg_budget(crate::TaskArgBudget {
                max_inline_bytes: 4,
            })
            .start()
            .await
        });

        assert!(matches!(
            result,
            Err(crate::spawn::TaskRuntimeError::NotRunningInsideClusterflux)
        ));
        assert!(!dispatched.get());
    }

    #[test]
    fn host_only_task_arg_error_names_rejected_type() {
        let error = crate::reject_host_only_task_arg::<*const u8>();

        assert!(error.to_string().contains("*const u8"));
        assert!(error.to_string().contains("host-only"));
    }
}
