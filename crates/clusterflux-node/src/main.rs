mod artifact_interchange;
mod assignment_runner;
mod coordinator_session;
mod daemon;
mod debug_agent;
mod node_identity;
mod system_compiler;
mod task_artifacts;
mod task_reports;

fn main() {
    if let Err(error) = daemon::run() {
        eprintln!("Clusterflux node failed: {error}");
        std::process::exit(1);
    }
}
