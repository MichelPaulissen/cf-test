mod artifact_interchange;
mod assignment_runner;
mod coordinator_session;
mod daemon;
mod debug_agent;
mod node_identity;
mod system_compiler;
mod task_artifacts;
mod task_reports;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    daemon::run()
}
