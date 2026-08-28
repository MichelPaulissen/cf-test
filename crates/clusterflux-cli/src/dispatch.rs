use anyhow::Result;
use clap::Parser;

use super::*;

pub(crate) fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor(args) => {
            let json_output = args.scope.json;
            let report = doctor_report(args, std::env::current_dir()?)?;
            emit_report(&report, json_output)?;
        }
        Commands::Login(args) => {
            let args = crate::auth_scope::login_args_for_project(args, &std::env::current_dir()?)?;
            let json_output = args.json;
            if args.non_interactive && !args.plan {
                let report = non_interactive_browser_login_report(&args);
                emit_report(&report, json_output)?;
            } else if !args.plan {
                let report = execute_interactive_browser_login(args)?;
                emit_report(&report, json_output)?;
            } else {
                let plan = login_plan(args);
                emit_report(&plan, json_output)?;
            }
        }
        Commands::Logout(args) => {
            let json_output = args.scope.json;
            let report = logout_report(args, std::env::current_dir()?, "logout")?;
            emit_report(&report, json_output)?;
        }
        Commands::Auth { command } => {
            let (report, json_output) = match command {
                AuthCommands::Status(args) => {
                    let json_output = args.scope.json;
                    (
                        auth_status_report(args, std::env::current_dir()?)?,
                        json_output,
                    )
                }
                AuthCommands::ConnectSelfHosted(args) => {
                    let json_output = args.scope.json;
                    let secret = read_session_secret_from_stdin()?;
                    (
                        connect_self_hosted_report(args, std::env::current_dir()?, secret)?,
                        json_output,
                    )
                }
                AuthCommands::Logout(args) => {
                    let json_output = args.scope.json;
                    (
                        auth_logout_report(args, std::env::current_dir()?)?,
                        json_output,
                    )
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Agent {
            command: AgentCommands::Enroll(args),
        } => {
            let json_output = args.json;
            let plan = agent_enrollment_plan(args);
            emit_report(&plan, json_output)?;
        }
        Commands::Key { command } => {
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            let (report, json_output) = match command {
                KeyCommands::Add(args) => {
                    let json_output = args.scope.json;
                    (
                        key_add_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                KeyCommands::List(args) => {
                    let json_output = args.scope.json;
                    (
                        key_list_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                KeyCommands::Revoke(args) => {
                    let json_output = args.scope.json;
                    (
                        key_revoke_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Project { command } => {
            let cwd = std::env::current_dir()?;
            let (report, json_output) = match command {
                ProjectCommands::Init(args) => {
                    let json_output = args.scope.json;
                    (project_init_report(args, cwd)?, json_output)
                }
                ProjectCommands::Inspect(args) => {
                    let json_output = args.json;
                    (
                        serde_json::to_value(bundle_inspection(args, cwd.clone())?)?,
                        json_output,
                    )
                }
                ProjectCommands::Status(args) => {
                    let json_output = args.scope.json;
                    (project_status_report(args, cwd)?, json_output)
                }
                ProjectCommands::List(args) => {
                    let json_output = args.scope.json;
                    (project_list_report(args, cwd)?, json_output)
                }
                ProjectCommands::Select(args) => {
                    let json_output = args.scope.json;
                    (project_select_report(args, cwd)?, json_output)
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Inspect(args) => {
            let json_output = args.json;
            let inspection = bundle_inspection(args, std::env::current_dir()?)?;
            emit_report(&inspection, json_output)?;
        }
        Commands::Check(args) => {
            let json_output = args.json || args.message_format == "rustc-json";
            let report = check_report(args, std::env::current_dir()?)?;
            emit_report(&report, json_output)?;
        }
        Commands::Build(args) => {
            let json_output = args.json;
            let report = build_report(args, std::env::current_dir()?)?;
            emit_report(&report, json_output)?;
        }
        Commands::Bundle {
            command: BundleCommands::Inspect(args),
        } => {
            let json_output = args.json;
            let inspection = bundle_inspection(args, std::env::current_dir()?)?;
            emit_report(&inspection, json_output)?;
        }
        Commands::Run(args) => {
            let json_output = args.json;
            let cwd = std::env::current_dir()?;
            let session_project = args.project.clone().unwrap_or_else(|| cwd.clone());
            let session = session_from_sources(&session_project)?;
            let report = run_report(args, cwd, session)?;
            emit_report(&report, json_output)?;
        }
        Commands::Wait { command } => {
            let json_output = command.json_output();
            let cwd = std::env::current_dir()?;
            let report = crate::wait::wait_report(command, &cwd)?;
            emit_report(&report, json_output)?;
        }
        Commands::Runs { command } => {
            let cwd = std::env::current_dir()?;
            let (report, json_output) = match command {
                RunsCommands::List(args) => {
                    let json = args.scope.json;
                    (run_list_report(args, &cwd)?, json)
                }
                RunsCommands::Show(args) => {
                    let json = args.scope.json;
                    (run_show_report(args, &cwd)?, json)
                }
                RunsCommands::Cancel(args) => {
                    let json = args.scope.json;
                    (run_cancel_report(args, &cwd)?, json)
                }
                RunsCommands::Retry(args) => {
                    let json = args.scope.json;
                    (run_retry_report(args, &cwd)?, json)
                }
                RunsCommands::Trigger(args) => {
                    let json = args.scope.json;
                    (run_trigger_report(args, &cwd)?, json)
                }
                RunsCommands::Diagnose(args) => {
                    let json = args.scope.json;
                    (run_diagnose_report(args, &cwd)?, json)
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Secret { command } => {
            let cwd = std::env::current_dir()?;
            let (report, json_output) = match command {
                SecretCommands::Set(args) => {
                    let json = args.scope.json;
                    (secret_set_report(args, &cwd)?, json)
                }
                SecretCommands::List(args) => {
                    let json = args.scope.json;
                    (secret_list_report(args, &cwd)?, json)
                }
                SecretCommands::Revoke(args) => {
                    let json = args.scope.json;
                    (secret_revoke_report(args, &cwd)?, json)
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Webhook {
            command: WebhookCommands::Deliveries(args),
        } => {
            let json_output = args.scope.json;
            let report = webhook_deliveries_report(args, &std::env::current_dir()?)?;
            emit_report(&report, json_output)?;
        }
        Commands::Node {
            command: NodeCommands::Attach(args),
        } => {
            let json_output = args.json;
            let cwd = std::env::current_dir()?;
            let report = execute_node_attach(args, &cwd)?;
            emit_report(&report, json_output)?;
        }
        Commands::Node { command } => {
            let cwd = std::env::current_dir()?;
            let (report, json_output) = match command {
                NodeCommands::Enroll(args) => {
                    let json_output = args.scope.json;
                    (node_enroll_report(args, cwd.clone())?, json_output)
                }
                NodeCommands::List(args) => {
                    let json_output = args.scope.json;
                    (node_list_report(args, cwd.clone())?, json_output)
                }
                NodeCommands::Status(args) => {
                    let json_output = args.scope.json;
                    (node_status_report(args, cwd.clone())?, json_output)
                }
                NodeCommands::Revoke(args) => {
                    let json_output = args.scope.json;
                    (node_revoke_report(args, cwd)?, json_output)
                }
                NodeCommands::Doctor(args) => {
                    let json_output = args.scope.json;
                    (node_doctor_report(args, cwd)?, json_output)
                }
                NodeCommands::Attach(_) => unreachable!("node attach is handled above"),
            };
            emit_report(&report, json_output)?;
        }
        Commands::Process { command } => {
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            let (report, json_output) = match command {
                ProcessCommands::List(args) => {
                    let json_output = args.scope.json;
                    (
                        process_list_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ProcessCommands::Status(args) => {
                    let json_output = args.scope.json;
                    (
                        process_status_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ProcessCommands::Restart(args) => {
                    let json_output = args.scope.json;
                    (
                        process_restart_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ProcessCommands::Cancel(args) => {
                    let json_output = args.scope.json;
                    (
                        process_cancel_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ProcessCommands::Abort(args) => {
                    let json_output = args.scope.json;
                    (
                        process_abort_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Task { command } => {
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            let (report, json_output) = match command {
                TaskCommands::List(args) => {
                    let json_output = args.scope.json;
                    (
                        task_list_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                TaskCommands::Restart(args) => {
                    let json_output = args.scope.json;
                    (
                        task_restart_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Logs(args) => {
            let json_output = args.scope.json;
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            emit_report(
                &logs_report_with_session(args, stored_session.as_ref())?,
                json_output,
            )?;
        }
        Commands::Artifact { command } => {
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            let (report, json_output) = match command {
                ArtifactCommands::List(args) => {
                    let json_output = args.scope.json;
                    (
                        artifact_list_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ArtifactCommands::Download(args) => {
                    let json_output = args.scope.json;
                    (
                        artifact_download_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
                ArtifactCommands::Export(args) => {
                    let json_output = args.scope.json;
                    (
                        artifact_export_report_with_session(args, stored_session.as_ref())?,
                        json_output,
                    )
                }
            };
            emit_report(&report, json_output)?;
        }
        Commands::Dap(args) => {
            let json_output = args.json;
            if args.plan {
                emit_report(&dap_plan(args)?, json_output)?;
            } else {
                return exec_dap(args);
            }
        }
        Commands::Debug {
            command: DebugCommands::Attach(args),
        } => {
            let json_output = args.scope.json;
            let cwd = std::env::current_dir()?;
            let stored_session = read_cli_session(&cwd)?;
            let dap = dap_binary_path()?.display().to_string();
            emit_report(
                &debug_attach_report_with_dap_and_session(args, dap, stored_session.as_ref())?,
                json_output,
            )?;
        }
        Commands::Quota {
            command: QuotaCommands::Status(args),
        } => {
            let json_output = args.scope.json;
            emit_report(
                &quota_status_report(args, std::env::current_dir()?)?,
                json_output,
            )?;
        }
        Commands::Admin { command } => {
            let (report, json_output) = match command {
                AdminCommands::Status(args) => {
                    let json_output = args.scope.json;
                    (admin_status_report(args)?, json_output)
                }
                AdminCommands::Bootstrap(args) => {
                    let json_output = args.scope.json;
                    (
                        admin_bootstrap_report(args, std::env::current_dir()?)?,
                        json_output,
                    )
                }
                AdminCommands::RevokeNode(args) => {
                    let json_output = args.scope.json;
                    (
                        node_revoke_report(args, std::env::current_dir()?)?,
                        json_output,
                    )
                }
                AdminCommands::StopProcess(args) => {
                    let json_output = args.scope.json;
                    (process_cancel_report(args)?, json_output)
                }
                AdminCommands::SuspendTenant(args) => {
                    let json_output = args.scope.json;
                    (admin_suspend_tenant_report(args)?, json_output)
                }
            };
            emit_report(&report, json_output)?;
        }
    }
    Ok(())
}
