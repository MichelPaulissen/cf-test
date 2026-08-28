use anyhow::Result;
#[cfg(test)]
use std::path::Path;

mod adapter;
mod breakpoints;
mod dap_protocol;
mod demo_backend;
mod runtime_client;
mod source;
mod variables;
mod view_state;
mod virtual_model;

#[cfg(test)]
use adapter::runtime_backend_from_launch_arg;
#[cfg(test)]
use breakpoints::{
    freeze_all, resolve_breakpoints, resolve_breakpoints_for_source,
    restart_requires_whole_process, stopped_thread_for_breakpoint,
};
#[cfg(test)]
use dap_protocol::{initialize_capabilities, read_message};
#[cfg(test)]
use runtime_client::{client_user_request, parse_task_restart_response, whole_process_status_code};
#[cfg(test)]
use variables::variables_response;
#[cfg(test)]
use virtual_model::{AdapterState, RuntimeLaunchRecord};

#[cfg(test)]
use clusterflux_core::{BundleDebugProbe, DebugRuntimeState};
#[cfg(test)]
use demo_backend::{LINUX_THREAD, MAIN_THREAD, PACKAGE_THREAD, WINDOWS_THREAD};
#[cfg(test)]
use virtual_model::{process_id, RuntimeBackend};

fn main() -> Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    match raw_args.as_slice() {
        [flag] if matches!(flag.as_str(), "--version" | "-V") => {
            println!("clusterflux-debug-dap {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        [flag] if matches!(flag.as_str(), "--help" | "-h") => {
            println!(
                "Clusterflux Debug Adapter Protocol server.\n\n\
                 Usage: clusterflux-debug-dap\n\n\
                 The adapter communicates over standard input and output.\n\n\
                 Options:\n  \
                   -h, --help\n  \
                   -V, --version"
            );
            return Ok(());
        }
        [] => {}
        [argument, ..] => anyhow::bail!("unknown argument: {argument}"),
    }
    adapter::run_adapter()
}

#[cfg(test)]
mod tests;
