use super::*;

pub(crate) fn validate_external_token(
    value: &str,
    path: &str,
    max_bytes: usize,
) -> Result<(), String> {
    clusterflux_core::validate_opaque_token(value, max_bytes)
        .map_err(|error| format!("malformed external token {path}: {error}"))
}

pub(crate) fn validate_coordinator_request(
    request: &CoordinatorRequest,
    path: &str,
) -> Result<(), String> {
    match request {
        CoordinatorRequest::Ping => Ok(()),
        CoordinatorRequest::Authenticated {
            session_secret,
            request,
        } => {
            validate_external_token(session_secret, &format!("{path}.session_secret"), 512)?;
            validate_authenticated_request(request, &format!("{path}.request"))
        }
        CoordinatorRequest::AuthStatus {
            tenant,
            project,
            actor_user,
        }
        | CoordinatorRequest::CreateProject {
            tenant,
            project,
            actor_user,
            ..
        }
        | CoordinatorRequest::SelectProject {
            tenant,
            project,
            actor_user,
        } => {
            validate_tenant(tenant, &format!("{path}.tenant"))?;
            validate_project(project, &format!("{path}.project"))?;
            validate_user(actor_user, &format!("{path}.actor_user"))
        }
        CoordinatorRequest::ListProjects { tenant, actor_user } => {
            validate_tenant(tenant, &format!("{path}.tenant"))?;
            validate_user(actor_user, &format!("{path}.actor_user"))
        }
        CoordinatorRequest::AdminStatus {
            tenant,
            actor_user,
            admin_nonce,
            ..
        } => {
            validate_tenant(tenant, &format!("{path}.tenant"))?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_external_token(admin_nonce, &format!("{path}.admin_nonce"), 256)
        }
        CoordinatorRequest::SuspendTenant {
            tenant,
            actor_user,
            target_tenant,
            admin_nonce,
            ..
        } => {
            validate_tenant(tenant, &format!("{path}.tenant"))?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_tenant(target_tenant, &format!("{path}.target_tenant"))?;
            validate_external_token(admin_nonce, &format!("{path}.admin_nonce"), 256)
        }
        CoordinatorRequest::RegisterAgentPublicKey {
            tenant,
            project,
            user,
            agent,
            public_key,
        }
        | CoordinatorRequest::RotateAgentPublicKey {
            tenant,
            project,
            user,
            agent,
            public_key,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(user, &format!("{path}.user"))?;
            validate_agent(agent, &format!("{path}.agent"))?;
            validate_external_token(public_key, &format!("{path}.public_key"), 1024)
        }
        CoordinatorRequest::ListAgentPublicKeys {
            tenant,
            project,
            user,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(user, &format!("{path}.user"))
        }
        CoordinatorRequest::RevokeAgentPublicKey {
            tenant,
            project,
            user,
            agent,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(user, &format!("{path}.user"))?;
            validate_agent(agent, &format!("{path}.agent"))
        }
        CoordinatorRequest::AttachNode {
            tenant,
            project,
            node,
            public_key,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_external_token(public_key, &format!("{path}.public_key"), 1024)
        }
        CoordinatorRequest::CreateNodeEnrollmentGrant {
            tenant,
            project,
            actor_user,
            ..
        }
        | CoordinatorRequest::ListNodeDescriptors {
            tenant,
            project,
            actor_user,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))
        }
        CoordinatorRequest::ListNodeSummaries {
            tenant,
            project,
            actor_user,
            cursor,
            limit,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        CoordinatorRequest::ExchangeNodeEnrollmentGrant {
            tenant,
            project,
            node,
            public_key,
            enrollment_grant,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_external_token(public_key, &format!("{path}.public_key"), 1024)?;
            validate_external_token(enrollment_grant, &format!("{path}.enrollment_grant"), 512)
        }
        CoordinatorRequest::NodeHeartbeat {
            tenant,
            project,
            node,
            node_signature,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            if let Some(signature) = node_signature {
                validate_node_signature(signature, &format!("{path}.node_signature"))?;
            }
            Ok(())
        }
        CoordinatorRequest::SignedNode {
            node,
            node_signature,
            request,
        } => {
            validate_node(node, &format!("{path}.node"))?;
            validate_node_signature(node_signature, &format!("{path}.node_signature"))?;
            validate_coordinator_request(request, &format!("{path}.request"))
        }
        CoordinatorRequest::ReportNodeCapabilities {
            tenant,
            project,
            node,
            artifact_locations,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_artifact_array(artifact_locations, &format!("{path}.artifact_locations"))
        }
        CoordinatorRequest::ReportSystemTask {
            tenant,
            project,
            node,
            result,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            match &result.result {
                SystemTaskOutput::CompileWorkflow { result } => {
                    validate_existing_id(
                        &result.run_id,
                        &format!("{path}.result.result.run_id"),
                        RunId::try_new,
                    )?;
                    validate_existing_id(
                        &result.node,
                        &format!("{path}.result.result.node"),
                        NodeId::try_new,
                    )?;
                }
            }
            result
                .validate()
                .map_err(|error| format!("{path}.result: {error}"))
        }
        CoordinatorRequest::PollTaskSecretGrant {
            tenant,
            project,
            node,
            process,
            task,
            secret_name,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_process(process, &format!("{path}.process"))?;
            validate_task_instance(task, &format!("{path}.task"))?;
            validate_external_token(secret_name, &format!("{path}.secret_name"), 128)
        }
        CoordinatorRequest::GetArtifactDataPlanePolicy {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::PollArtifactProviderAssignment {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::PollArtifactReceiverAssignment {
            tenant,
            project,
            node,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))
        }
        CoordinatorRequest::AcknowledgeArtifactAssignment {
            tenant,
            project,
            node,
            transfer_id,
            role: _,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_external_token(transfer_id, &format!("{path}.transfer_id"), 256)
        }
        CoordinatorRequest::ReportIrohEndpointAdvertisement {
            tenant,
            project,
            node,
            advertisement,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            advertisement
                .validate_bounds()
                .map_err(|error| format!("{path}.advertisement: {error}"))
        }
        CoordinatorRequest::RequestArtifactInterchange {
            tenant,
            project,
            process,
            node,
            artifact,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_artifact(artifact, &format!("{path}.artifact"))
        }
        CoordinatorRequest::ReportArtifactInterchange {
            tenant,
            project,
            node,
            transfer_id,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_external_token(transfer_id, &format!("{path}.transfer_id"), 256)
        }
        CoordinatorRequest::ReleaseArtifact {
            tenant,
            project,
            process,
            node,
            task,
            artifact,
            digest,
            size_bytes: _,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_task_instance(task, &format!("{path}.task"))?;
            validate_artifact(artifact, &format!("{path}.artifact"))?;
            if !digest.is_valid_sha256() {
                return Err(format!("{path}.digest is not SHA-256"));
            }
            Ok(())
        }
        CoordinatorRequest::BeginNodeDrain {
            tenant,
            project,
            node,
            ephemeral: _,
            provider_deadline_epoch_seconds: _,
            soft_drain_deadline_epoch_seconds: _,
            hard_drain_deadline_epoch_seconds: _,
        }
        | CoordinatorRequest::FinalizeNodeRelease {
            tenant,
            project,
            node,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))
        }
        CoordinatorRequest::RevokeNodeCredential {
            tenant,
            project,
            actor_user,
            node,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_node(node, &format!("{path}.node"))
        }
        CoordinatorRequest::ScheduleTask {
            tenant,
            project,
            required_artifacts,
            prefer_node,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_artifact_array(required_artifacts, &format!("{path}.required_artifacts"))?;
            validate_optional_node(prefer_node.as_deref(), &format!("{path}.prefer_node"))
        }
        CoordinatorRequest::LaunchTask {
            tenant,
            project,
            actor_user,
            actor_agent,
            agent_signature,
            task_spec,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_optional_user(actor_user.as_deref(), &format!("{path}.actor_user"))?;
            validate_optional_agent(actor_agent.as_deref(), &format!("{path}.actor_agent"))?;
            if let Some(signature) = agent_signature {
                validate_agent_signature(signature, &format!("{path}.agent_signature"))?;
            }
            validate_task_spec(task_spec, &format!("{path}.task_spec"))
        }
        CoordinatorRequest::LaunchChildTask {
            tenant,
            project,
            process,
            node,
            parent_task,
            task_spec,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_task_instance(parent_task, &format!("{path}.parent_task"))?;
            validate_task_spec(task_spec, &format!("{path}.task_spec"))
        }
        CoordinatorRequest::JoinChildTask {
            tenant,
            project,
            process,
            node,
            parent_task,
            task,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_task_instance(parent_task, &format!("{path}.parent_task"))?;
            validate_task_instance(task, &format!("{path}.task"))
        }
        CoordinatorRequest::PollNodeAssignment {
            tenant,
            project,
            node,
            active_assignment,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            if let Some(active) = active_assignment {
                if active.assignment_id.is_empty()
                    || active.assignment_id.len() > 256
                    || active.assignment_id.chars().any(char::is_whitespace)
                    || active.lease_epoch == 0
                {
                    return Err(format!("{path}.active_assignment is invalid"));
                }
            }
            Ok(())
        }
        CoordinatorRequest::CompleteSourcePreparation {
            tenant,
            project,
            node,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))
        }
        CoordinatorRequest::AcknowledgeNodeAssignment {
            tenant,
            project,
            node,
            assignment_id,
            lease_epoch,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            if assignment_id.is_empty()
                || assignment_id.len() > 256
                || assignment_id.chars().any(char::is_whitespace)
                || *lease_epoch == 0
            {
                return Err(format!("{path}.assignment acknowledgement is invalid"));
            }
            Ok(())
        }
        CoordinatorRequest::RequestSourcePreparation {
            tenant, project, ..
        } => validate_tenant_project(tenant, project, path),
        CoordinatorRequest::StartProcess {
            tenant,
            project,
            actor_user,
            actor_agent,
            agent_signature,
            process,
            launch_attempt,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_optional_user(actor_user.as_deref(), &format!("{path}.actor_user"))?;
            validate_optional_agent(actor_agent.as_deref(), &format!("{path}.actor_agent"))?;
            if let Some(signature) = agent_signature {
                validate_agent_signature(signature, &format!("{path}.agent_signature"))?;
            }
            validate_process(process, &format!("{path}.process"))?;
            validate_optional_launch_attempt(
                launch_attempt.as_deref(),
                &format!("{path}.launch_attempt"),
            )
        }
        CoordinatorRequest::ReconnectNode {
            tenant,
            project,
            node,
            process,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_node(node, &format!("{path}.node"))?;
            validate_process(process, &format!("{path}.process"))
        }
        CoordinatorRequest::PollTaskControl {
            tenant,
            project,
            process,
            node,
            task,
            child_tasks,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_task_instance(task, &format!("{path}.task"))?;
            if child_tasks.len() > 256 {
                return Err(format!("{path}.child_tasks exceeds 256 entries"));
            }
            let mut unique = std::collections::BTreeSet::new();
            for (index, child) in child_tasks.iter().enumerate() {
                validate_task_instance(child, &format!("{path}.child_tasks[{index}]"))?;
                if !unique.insert(child) {
                    return Err(format!("{path}.child_tasks contains a duplicate task"));
                }
            }
            Ok(())
        }
        CoordinatorRequest::CancelTask {
            tenant,
            project,
            process,
            node,
            task,
        }
        | CoordinatorRequest::PollDebugCommand {
            tenant,
            project,
            process,
            node,
            task,
        }
        | CoordinatorRequest::ReportDebugProbeHit {
            tenant,
            project,
            process,
            node,
            task,
            ..
        }
        | CoordinatorRequest::ReportTaskLog {
            tenant,
            project,
            process,
            node,
            task,
            ..
        }
        | CoordinatorRequest::ReportTaskLogChunk {
            tenant,
            project,
            process,
            node,
            task,
            ..
        }
        | CoordinatorRequest::ReportVfsMetadata {
            tenant,
            project,
            process,
            node,
            task,
            ..
        }
        | CoordinatorRequest::TaskCompleted {
            tenant,
            project,
            process,
            node,
            task,
            ..
        }
        | CoordinatorRequest::ReportDebugState {
            tenant,
            project,
            process,
            node,
            task,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_node(node, &format!("{path}.node"))?;
            validate_task_instance(task, &format!("{path}.task"))
        }
        CoordinatorRequest::CancelProcess {
            tenant,
            project,
            actor_user,
            process,
        }
        | CoordinatorRequest::DebugAttach {
            tenant,
            project,
            actor_user,
            process,
        }
        | CoordinatorRequest::SetDebugBreakpoints {
            tenant,
            project,
            actor_user,
            process,
            ..
        }
        | CoordinatorRequest::InspectDebugBreakpoints {
            tenant,
            project,
            actor_user,
            process,
        }
        | CoordinatorRequest::ResumeDebugEpoch {
            tenant,
            project,
            actor_user,
            process,
            ..
        }
        | CoordinatorRequest::InspectDebugEpoch {
            tenant,
            project,
            actor_user,
            process,
            ..
        }
        | CoordinatorRequest::ListTaskSnapshots {
            tenant,
            project,
            actor_user,
            process,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_process(process, &format!("{path}.process"))
        }
        CoordinatorRequest::ListRecentLogs {
            tenant,
            project,
            actor_user,
            process,
            task,
            limit,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_process(process, &format!("{path}.process"))?;
            if let Some(task) = task {
                validate_task_instance(task, &format!("{path}.task"))?;
            }
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        CoordinatorRequest::AbortProcess {
            tenant,
            project,
            actor_user,
            process,
            launch_attempt,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_process(process, &format!("{path}.process"))?;
            validate_optional_launch_attempt(
                launch_attempt.as_deref(),
                &format!("{path}.launch_attempt"),
            )
        }
        CoordinatorRequest::ListProcesses {
            tenant,
            project,
            actor_user,
        }
        | CoordinatorRequest::QuotaStatus {
            tenant,
            project,
            actor_user,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))
        }
        CoordinatorRequest::ListProcessSummaries {
            tenant,
            project,
            actor_user,
            cursor,
            limit,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 100)
        }
        CoordinatorRequest::RestartTask {
            tenant,
            project,
            actor_user,
            process,
            task,
            ..
        }
        | CoordinatorRequest::ResolveTaskFailure {
            tenant,
            project,
            actor_user,
            process,
            task,
            ..
        }
        | CoordinatorRequest::JoinTask {
            tenant,
            project,
            actor_user,
            process,
            task,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_process(process, &format!("{path}.process"))?;
            validate_task_instance(task, &format!("{path}.task"))
        }
        CoordinatorRequest::CreateDebugEpoch {
            tenant,
            project,
            actor_user,
            process,
            stopped_task,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_process(process, &format!("{path}.process"))?;
            validate_task_instance(stopped_task, &format!("{path}.stopped_task"))
        }
        CoordinatorRequest::ListTaskEvents {
            tenant,
            project,
            actor_user,
            process,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_optional_process(process.as_deref(), &format!("{path}.process"))
        }
        CoordinatorRequest::RenderOperatorPanel {
            tenant,
            project,
            process,
            actor_user,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_user(actor_user, &format!("{path}.actor_user"))
        }
        CoordinatorRequest::SubmitPanelEvent {
            tenant,
            project,
            process,
            actor_user,
            widget_id,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_process(process, &format!("{path}.process"))?;
            validate_optional_user(actor_user.as_deref(), &format!("{path}.actor_user"))?;
            validate_external_token(widget_id, &format!("{path}.widget_id"), 256)
        }
        CoordinatorRequest::ListArtifacts {
            tenant,
            project,
            actor_user,
            process,
            cursor,
            limit,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_optional_process(process.as_deref(), &format!("{path}.process"))?;
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        CoordinatorRequest::CreateArtifactDownloadLink {
            tenant,
            project,
            actor_user,
            artifact,
            ..
        }
        | CoordinatorRequest::RevokeArtifactDownloadLink {
            tenant,
            project,
            actor_user,
            artifact,
            ..
        }
        | CoordinatorRequest::GetArtifact {
            tenant,
            project,
            actor_user,
            artifact,
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_artifact(artifact, &format!("{path}.artifact"))
        }
        CoordinatorRequest::ExportArtifactToNode {
            tenant,
            project,
            actor_user,
            artifact,
            receiver_node,
            ..
        } => {
            validate_tenant_project(tenant, project, path)?;
            validate_user(actor_user, &format!("{path}.actor_user"))?;
            validate_artifact(artifact, &format!("{path}.artifact"))?;
            validate_node(receiver_node, &format!("{path}.receiver_node"))
        }
    }
}

fn validate_authenticated_request(
    request: &AuthenticatedCoordinatorRequest,
    path: &str,
) -> Result<(), String> {
    match request {
        AuthenticatedCoordinatorRequest::AuthStatus
        | AuthenticatedCoordinatorRequest::RevokeCliSession
        | AuthenticatedCoordinatorRequest::ListProjects
        | AuthenticatedCoordinatorRequest::ListProjectSecrets
        | AuthenticatedCoordinatorRequest::CreateNodeEnrollmentGrant { .. }
        | AuthenticatedCoordinatorRequest::ListNodeDescriptors
        | AuthenticatedCoordinatorRequest::ListProcesses
        | AuthenticatedCoordinatorRequest::QuotaStatus => Ok(()),
        AuthenticatedCoordinatorRequest::ListAutomatedRuns { cursor, limit } => {
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 64)
        }
        AuthenticatedCoordinatorRequest::GetAutomatedRun { run }
        | AuthenticatedCoordinatorRequest::CancelAutomatedRun { run }
        | AuthenticatedCoordinatorRequest::RetryAutomatedRun { run } => {
            validate_external_id(run, &format!("{path}.run"), RunId::try_new)
        }
        AuthenticatedCoordinatorRequest::TriggerAutomatedRun {
            repository,
            git_ref,
            commit,
        } => {
            validate_external_id(
                repository,
                &format!("{path}.repository"),
                RepositoryId::try_new,
            )?;
            if git_ref.len() > 512
                || !(git_ref.starts_with("refs/heads/") || git_ref.starts_with("refs/tags/"))
                || git_ref.ends_with('/')
            {
                return Err(format!("{path}.git_ref must identify a branch or tag"));
            }
            if let Some(commit) = commit {
                clusterflux_core::validate_commit_sha(commit)
                    .map_err(|error| format!("{path}.commit is invalid: {error}"))?;
            }
            Ok(())
        }
        AuthenticatedCoordinatorRequest::ListWebhookDeliveries { cursor, limit } => {
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 100)
        }
        AuthenticatedCoordinatorRequest::SetProjectSecret { name, value_base64 } => {
            validate_external_token(name, &format!("{path}.name"), 128)?;
            validate_external_token(value_base64, &format!("{path}.value_base64"), 24 * 1024)
        }
        AuthenticatedCoordinatorRequest::RevokeProjectSecret { name } => {
            validate_external_token(name, &format!("{path}.name"), 128)
        }
        AuthenticatedCoordinatorRequest::ListNodeSummaries { cursor, limit } => {
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        AuthenticatedCoordinatorRequest::ListProcessSummaries { cursor, limit } => {
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 100)
        }
        AuthenticatedCoordinatorRequest::CreateProject { project, .. }
        | AuthenticatedCoordinatorRequest::SelectProject { project } => {
            validate_project(project, &format!("{path}.project"))
        }
        AuthenticatedCoordinatorRequest::RegisterAgentPublicKey {
            agent, public_key, ..
        }
        | AuthenticatedCoordinatorRequest::RotateAgentPublicKey {
            agent, public_key, ..
        } => {
            validate_agent(agent, &format!("{path}.agent"))?;
            validate_external_token(public_key, &format!("{path}.public_key"), 1024)
        }
        AuthenticatedCoordinatorRequest::ListAgentPublicKeys => Ok(()),
        AuthenticatedCoordinatorRequest::RevokeAgentPublicKey { agent } => {
            validate_agent(agent, &format!("{path}.agent"))
        }
        AuthenticatedCoordinatorRequest::RevokeNodeCredential { node } => {
            validate_node(node, &format!("{path}.node"))
        }
        AuthenticatedCoordinatorRequest::StartProcess {
            process,
            launch_attempt,
            ..
        }
        | AuthenticatedCoordinatorRequest::AbortProcess {
            process,
            launch_attempt,
        } => {
            validate_process(process, &format!("{path}.process"))?;
            validate_optional_launch_attempt(
                launch_attempt.as_deref(),
                &format!("{path}.launch_attempt"),
            )
        }
        AuthenticatedCoordinatorRequest::ScheduleTask {
            required_artifacts,
            prefer_node,
            ..
        } => {
            validate_artifact_array(required_artifacts, &format!("{path}.required_artifacts"))?;
            validate_optional_node(prefer_node.as_deref(), &format!("{path}.prefer_node"))
        }
        AuthenticatedCoordinatorRequest::LaunchTask { task_spec, .. } => {
            validate_task_spec(task_spec, &format!("{path}.task_spec"))
        }
        AuthenticatedCoordinatorRequest::CancelProcess { process }
        | AuthenticatedCoordinatorRequest::DebugAttach { process }
        | AuthenticatedCoordinatorRequest::SetDebugBreakpoints { process, .. }
        | AuthenticatedCoordinatorRequest::InspectDebugBreakpoints { process }
        | AuthenticatedCoordinatorRequest::ResumeDebugEpoch { process, .. }
        | AuthenticatedCoordinatorRequest::InspectDebugEpoch { process, .. }
        | AuthenticatedCoordinatorRequest::ListTaskSnapshots { process } => {
            validate_process(process, &format!("{path}.process"))
        }
        AuthenticatedCoordinatorRequest::ListRecentLogs {
            process,
            task,
            limit,
            ..
        } => {
            validate_process(process, &format!("{path}.process"))?;
            if let Some(task) = task {
                validate_task_instance(task, &format!("{path}.task"))?;
            }
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        AuthenticatedCoordinatorRequest::RestartTask { process, task, .. }
        | AuthenticatedCoordinatorRequest::ResolveTaskFailure { process, task, .. }
        | AuthenticatedCoordinatorRequest::JoinTask { process, task } => {
            validate_process(process, &format!("{path}.process"))?;
            validate_task_instance(task, &format!("{path}.task"))
        }
        AuthenticatedCoordinatorRequest::CreateDebugEpoch {
            process,
            stopped_task,
            ..
        } => {
            validate_process(process, &format!("{path}.process"))?;
            validate_task_instance(stopped_task, &format!("{path}.stopped_task"))
        }
        AuthenticatedCoordinatorRequest::ListTaskEvents { process } => {
            validate_optional_process(process.as_deref(), &format!("{path}.process"))
        }
        AuthenticatedCoordinatorRequest::ListArtifacts {
            process,
            cursor,
            limit,
        } => {
            validate_optional_process(process.as_deref(), &format!("{path}.process"))?;
            validate_optional_cursor(cursor.as_deref(), &format!("{path}.cursor"))?;
            validate_page_limit(*limit, &format!("{path}.limit"), 200)
        }
        AuthenticatedCoordinatorRequest::CreateArtifactDownloadLink { artifact, .. }
        | AuthenticatedCoordinatorRequest::RevokeArtifactDownloadLink { artifact, .. }
        | AuthenticatedCoordinatorRequest::GetArtifact { artifact } => {
            validate_artifact(artifact, &format!("{path}.artifact"))
        }
        AuthenticatedCoordinatorRequest::ExportArtifactToNode {
            artifact,
            receiver_node,
            ..
        } => {
            validate_artifact(artifact, &format!("{path}.artifact"))?;
            validate_node(receiver_node, &format!("{path}.receiver_node"))
        }
    }
}

fn validate_task_spec(task_spec: &TaskSpec, path: &str) -> Result<(), String> {
    validate_existing_id(
        &task_spec.tenant,
        &format!("{path}.tenant"),
        TenantId::try_new,
    )?;
    validate_existing_id(
        &task_spec.project,
        &format!("{path}.project"),
        ProjectId::try_new,
    )?;
    validate_existing_id(
        &task_spec.process,
        &format!("{path}.process"),
        ProcessId::try_new,
    )?;
    validate_existing_id(
        &task_spec.task_definition,
        &format!("{path}.task_definition"),
        TaskDefinitionId::try_new,
    )?;
    validate_existing_id(
        &task_spec.task_instance,
        &format!("{path}.task_instance"),
        TaskInstanceId::try_new,
    )?;
    if let Some(environment_id) = &task_spec.environment_id {
        validate_external_token(environment_id, &format!("{path}.environment_id"), 128)?;
    }
    for (index, artifact) in task_spec.required_artifacts.iter().enumerate() {
        validate_existing_id(
            artifact,
            &format!("{path}.required_artifacts[{index}]"),
            ArtifactId::try_new,
        )?;
    }
    for (argument_index, argument) in task_spec.args.iter().enumerate() {
        validate_task_boundary_value(argument, &format!("{path}.args[{argument_index}]"))?;
    }
    Ok(())
}

fn validate_task_boundary_value(value: &TaskBoundaryValue, path: &str) -> Result<(), String> {
    match value {
        TaskBoundaryValue::Artifact(artifact) => validate_existing_id(
            &artifact.id,
            &format!("{path}.artifact.id"),
            ArtifactId::try_new,
        ),
        TaskBoundaryValue::Structured(structured) => {
            for (index, handle) in structured.handles.iter().enumerate() {
                if let TaskBoundaryHandle::Artifact(artifact) = handle {
                    validate_existing_id(
                        &artifact.id,
                        &format!("{path}.handles[{index}].artifact.id"),
                        ArtifactId::try_new,
                    )?;
                }
            }
            Ok(())
        }
        TaskBoundaryValue::SmallJson(_)
        | TaskBoundaryValue::SourceSnapshot(_)
        | TaskBoundaryValue::Blob(_)
        | TaskBoundaryValue::VfsManifest(_) => Ok(()),
    }
}

fn validate_node_signature(signature: &NodeSignedRequest, path: &str) -> Result<(), String> {
    validate_external_token(&signature.nonce, &format!("{path}.nonce"), 256)?;
    validate_external_token(&signature.signature, &format!("{path}.signature"), 512)?;
    if let Some(authority) = &signature.assignment_authority {
        validate_external_token(
            &authority.assignment_id,
            &format!("{path}.assignment_authority.assignment_id"),
            256,
        )?;
        validate_external_token(
            &authority.attempt_id,
            &format!("{path}.assignment_authority.attempt_id"),
            256,
        )?;
        if authority.offer_epoch == 0 {
            return Err(format!(
                "{path}.assignment_authority.offer_epoch must be greater than zero"
            ));
        }
    }
    Ok(())
}

fn validate_agent_signature(signature: &AgentSignedRequest, path: &str) -> Result<(), String> {
    validate_external_token(&signature.nonce, &format!("{path}.nonce"), 256)?;
    validate_external_token(&signature.signature, &format!("{path}.signature"), 512)
}

fn validate_tenant_project(tenant: &str, project: &str, path: &str) -> Result<(), String> {
    validate_tenant(tenant, &format!("{path}.tenant"))?;
    validate_project(project, &format!("{path}.project"))
}

fn validate_artifact_array(values: &[String], path: &str) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        validate_artifact(value, &format!("{path}[{index}]"))?;
    }
    Ok(())
}

fn validate_optional_user(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_user(value, path))
}

fn validate_optional_agent(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_agent(value, path))
}

fn validate_optional_node(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_node(value, path))
}

fn validate_optional_process(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_process(value, path))
}

fn validate_optional_cursor(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_external_token(value, path, 256))
}

fn validate_page_limit(value: u32, path: &str, maximum: u32) -> Result<(), String> {
    if value == 0 || value > maximum {
        return Err(format!(
            "malformed pagination limit {path}: expected 1 through {maximum}, received {value}"
        ));
    }
    Ok(())
}

fn validate_optional_launch_attempt(value: Option<&str>, path: &str) -> Result<(), String> {
    value.map_or(Ok(()), |value| validate_launch_attempt(value, path))
}

fn validate_tenant(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, TenantId::try_new)
}

fn validate_project(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, ProjectId::try_new)
}

fn validate_user(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, UserId::try_new)
}

fn validate_agent(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, AgentId::try_new)
}

fn validate_node(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, NodeId::try_new)
}

fn validate_process(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, ProcessId::try_new)
}

fn validate_task_instance(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, TaskInstanceId::try_new)
}

fn validate_artifact(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, ArtifactId::try_new)
}

fn validate_launch_attempt(value: &str, path: &str) -> Result<(), String> {
    validate_external_id(value, path, LaunchAttemptId::try_new)
}

fn validate_external_id<T, E>(
    value: &str,
    path: &str,
    parser: impl FnOnce(String) -> Result<T, E>,
) -> Result<(), String>
where
    E: std::fmt::Display,
{
    parser(value.to_owned())
        .map(|_| ())
        .map_err(|error| format!("malformed external identifier {path}: {error}"))
}

fn validate_existing_id<T, E>(
    value: &T,
    path: &str,
    parser: impl FnOnce(String) -> Result<T, E>,
) -> Result<(), String>
where
    T: std::fmt::Display,
    E: std::fmt::Display,
{
    validate_external_id(&value.to_string(), path, parser)
}
