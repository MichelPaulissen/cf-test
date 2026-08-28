// Regression fixture: this file is intentionally absent from the Cargo module graph.
// Source inspection may list it as an approximate candidate, but it must never
// define or invalidate a runnable entrypoint.
#[clusterflux::main]
pub fn build() {}
