use clusterflux_core::{AuthContext, UserId};

use super::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, CoordinatorService,
    CoordinatorServiceError,
};

impl CoordinatorService {
    pub(super) fn handle_authenticated_agent_key_request(
        &mut self,
        context: &AuthContext,
        actor: &UserId,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let request = match request {
            AuthenticatedCoordinatorRequest::RegisterAgentPublicKey { agent, public_key } => {
                CoordinatorRequest::RegisterAgentPublicKey {
                    tenant: context.tenant.as_str().to_owned(),
                    project: context.project.as_str().to_owned(),
                    user: actor.as_str().to_owned(),
                    agent,
                    public_key,
                }
            }
            AuthenticatedCoordinatorRequest::ListAgentPublicKeys => {
                CoordinatorRequest::ListAgentPublicKeys {
                    tenant: context.tenant.as_str().to_owned(),
                    project: context.project.as_str().to_owned(),
                    user: actor.as_str().to_owned(),
                }
            }
            AuthenticatedCoordinatorRequest::RotateAgentPublicKey { agent, public_key } => {
                CoordinatorRequest::RotateAgentPublicKey {
                    tenant: context.tenant.as_str().to_owned(),
                    project: context.project.as_str().to_owned(),
                    user: actor.as_str().to_owned(),
                    agent,
                    public_key,
                }
            }
            AuthenticatedCoordinatorRequest::RevokeAgentPublicKey { agent } => {
                CoordinatorRequest::RevokeAgentPublicKey {
                    tenant: context.tenant.as_str().to_owned(),
                    project: context.project.as_str().to_owned(),
                    user: actor.as_str().to_owned(),
                    agent,
                }
            }
            _ => unreachable!("caller filters authenticated agent key operations"),
        };
        self.handle_request(request)
    }

    pub(super) fn handle_authenticated_launch_task(
        &mut self,
        context: &AuthContext,
        actor: &UserId,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let AuthenticatedCoordinatorRequest::LaunchTask {
            task_spec,
            wait_for_node,
            artifact_path,
            wasm_module_base64,
        } = request
        else {
            unreachable!("caller filters authenticated task launches");
        };
        self.handle_launch_task(
            context.tenant.as_str().to_owned(),
            context.project.as_str().to_owned(),
            Some(actor.as_str().to_owned()),
            None,
            None,
            None,
            None,
            *task_spec,
            wait_for_node,
            artifact_path,
            wasm_module_base64,
        )
    }

    pub(super) fn handle_authenticated_schedule_task(
        &mut self,
        context: &AuthContext,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let AuthenticatedCoordinatorRequest::ScheduleTask {
            environment,
            environment_digest,
            required_capabilities,
            dependency_cache,
            source_snapshot,
            required_artifacts,
            prefer_node,
        } = request
        else {
            unreachable!("caller filters authenticated task scheduling");
        };
        self.handle_schedule_task(
            context.tenant.as_str().to_owned(),
            context.project.as_str().to_owned(),
            environment,
            environment_digest,
            required_capabilities,
            dependency_cache,
            source_snapshot,
            required_artifacts,
            prefer_node,
        )
    }

    pub(super) fn handle_authenticated_artifact_export(
        &mut self,
        context: &AuthContext,
        actor: &UserId,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let AuthenticatedCoordinatorRequest::ExportArtifactToNode {
            artifact,
            receiver_node,
        } = request
        else {
            unreachable!("caller filters authenticated artifact exports");
        };
        self.handle_export_artifact_to_node(
            context.tenant.as_str().to_owned(),
            context.project.as_str().to_owned(),
            actor.as_str().to_owned(),
            artifact,
            receiver_node,
        )
    }
}
