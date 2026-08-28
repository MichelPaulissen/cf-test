use clusterflux_core::Digest;
use serde::Serialize;

use crate::AgentEnrollArgs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct AgentEnrollmentPlan {
    pub(crate) public_key_fingerprint: Digest,
    pub(crate) browser_interaction_required_each_run: bool,
}

pub(crate) fn agent_enrollment_plan(args: AgentEnrollArgs) -> AgentEnrollmentPlan {
    AgentEnrollmentPlan {
        public_key_fingerprint: Digest::sha256(args.public_key),
        browser_interaction_required_each_run: false,
    }
}
