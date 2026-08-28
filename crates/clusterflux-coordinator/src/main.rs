use std::io::Write;
use std::net::{SocketAddr, TcpListener};

use clap::Parser;
use clusterflux_coordinator::{
    service::bind_listener, CoordinatorArtifactInterchangeConfiguration, CoordinatorService,
    CoordinatorServiceStartupConfiguration,
};
use clusterflux_core::{
    ArtifactRelayPolicy, ClusterfluxDeploymentMode, ClusterfluxRelayConfig, IrohRelayConfiguration,
    ProjectId, TenantId, UserId,
};
use serde_json::json;

type RelayAuthorizationCallback = (TcpListener, SocketAddr, String);

struct RelayAuthorizationCallbackConfiguration {
    listen: SocketAddr,
    bearer: String,
}

impl RelayAuthorizationCallbackConfiguration {
    fn bind(self) -> Result<RelayAuthorizationCallback, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(self.listen)?;
        let address = listener.local_addr()?;
        Ok((listener, address, self.bearer))
    }
}

struct SelfHostedSessionConfiguration {
    tenant: TenantId,
    project: ProjectId,
    user: UserId,
    secret: String,
}

struct CoordinatorStartupConfiguration {
    listen: SocketAddr,
    allow_local_trusted: bool,
    database_url: Option<String>,
    admin_token: Option<String>,
    service: CoordinatorServiceStartupConfiguration,
    artifact_interchange: CoordinatorArtifactInterchangeConfiguration,
    relay_authorization_callback: Option<RelayAuthorizationCallbackConfiguration>,
    self_hosted_session: Option<SelfHostedSessionConfiguration>,
}

#[derive(Parser)]
#[command(
    name = "clusterflux-coordinator",
    version,
    about = "Clusterflux coordinator"
)]
struct CoordinatorArgs {
    #[arg(long, default_value = "127.0.0.1:0", value_name = "ADDRESS")]
    listen: SocketAddr,
    #[arg(long)]
    allow_local_trusted_loopback: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CoordinatorArgs::parse();
    let configuration = startup_configuration(args)?;
    let CoordinatorStartupConfiguration {
        listen,
        allow_local_trusted,
        database_url,
        admin_token,
        service: service_configuration,
        artifact_interchange,
        relay_authorization_callback,
        self_hosted_session,
    } = configuration;
    let relay_authorization_callback = relay_authorization_callback
        .map(RelayAuthorizationCallbackConfiguration::bind)
        .transpose()?;
    let (listener, addr) = bind_listener(&listen.to_string())?;
    let mut service = CoordinatorService::new_with_startup_configuration(
        1,
        admin_token,
        database_url.as_deref(),
        service_configuration,
    )?;
    service.configure_artifact_interchange(artifact_interchange.clone())?;
    if let Some(session) = self_hosted_session.as_ref() {
        service.issue_cli_session(
            session.tenant.clone(),
            session.project.clone(),
            session.user.clone(),
            &session.secret,
            None,
        )?;
    }
    println!(
        "{}",
        json!({
            "listen": addr.to_string(),
            "client_authority": if allow_local_trusted { "local_trusted_loopback" } else { "strict" },
            "self_hosted_session_bootstrapped": self_hosted_session.is_some(),
            "durable_store": service.durable_store_kind(),
            "artifact_data_plane": {
                "deployment_mode": artifact_interchange.deployment_mode,
                "relay_configured": !matches!(artifact_interchange.relay, IrohRelayConfiguration::Disabled),
                "artifact_relay_policy": artifact_interchange.artifact_relay_policy,
                "relay_authorization_callback": relay_authorization_callback
                    .as_ref()
                    .map(|(_, address, _)| address.to_string()),
            },
        })
    );
    std::io::stdout().flush()?;

    match (allow_local_trusted, relay_authorization_callback) {
        (true, Some((relay_listener, _, bearer))) => {
            service.serve_tcp_local_trusted_with_relay_callback(listener, relay_listener, bearer)?
        }
        (false, Some((relay_listener, _, bearer))) => {
            service.serve_tcp_with_relay_callback(listener, relay_listener, bearer)?
        }
        (true, None) => service.serve_tcp_local_trusted(listener)?,
        (false, None) => service.serve_tcp(listener)?,
    }
    Ok(())
}

fn startup_configuration(
    args: CoordinatorArgs,
) -> Result<CoordinatorStartupConfiguration, Box<dyn std::error::Error>> {
    let allow_local_trusted = args.allow_local_trusted_loopback
        || environment_flag("CLUSTERFLUX_ALLOW_LOCAL_TRUSTED_LOOPBACK")?;
    validate_listener_security(args.listen, allow_local_trusted)?;
    let database_url = optional_environment("DATABASE_URL")?;
    if database_url
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("DATABASE_URL must not be empty when configured".into());
    }
    let admin_token = validated_optional_token("CLUSTERFLUX_ADMIN_TOKEN", 4_096)?;
    let service = CoordinatorServiceStartupConfiguration {
        node_stale_after_seconds: environment_u64("CLUSTERFLUX_NODE_STALE_AFTER_SECONDS", 30)?,
    }
    .validate()?;
    Ok(CoordinatorStartupConfiguration {
        listen: args.listen,
        allow_local_trusted,
        database_url,
        admin_token,
        service,
        artifact_interchange: artifact_interchange_configuration_from_environment()?,
        relay_authorization_callback: relay_authorization_callback_configuration_from_environment(
        )?,
        self_hosted_session: self_hosted_session_configuration_from_environment()?,
    })
}

fn validate_listener_security(
    listen: SocketAddr,
    allow_local_trusted: bool,
) -> Result<(), &'static str> {
    if allow_local_trusted && !listen.ip().is_loopback() {
        return Err("--allow-local-trusted-loopback requires a loopback --listen address");
    }
    Ok(())
}

fn relay_authorization_callback_configuration_from_environment(
) -> Result<Option<RelayAuthorizationCallbackConfiguration>, Box<dyn std::error::Error>> {
    let listen = match std::env::var("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_LISTEN") {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) | Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bearer = required_environment_token("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_BEARER", 4_096)?;
    let listen = listen
        .parse::<SocketAddr>()
        .map_err(|error| format!("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_LISTEN is invalid: {error}"))?;
    if !listen.ip().is_loopback() {
        return Err("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_LISTEN must bind a loopback address".into());
    }
    Ok(Some(RelayAuthorizationCallbackConfiguration {
        listen,
        bearer,
    }))
}

fn self_hosted_session_configuration_from_environment(
) -> Result<Option<SelfHostedSessionConfiguration>, Box<dyn std::error::Error>> {
    let Some(secret) = validated_optional_token("CLUSTERFLUX_SELF_HOSTED_SESSION_SECRET", 4_096)?
    else {
        return Ok(None);
    };
    let tenant = TenantId::try_new(
        optional_environment("CLUSTERFLUX_SELF_HOSTED_TENANT")?
            .unwrap_or_else(|| "tenant".to_owned()),
    )?;
    let project = ProjectId::try_new(
        optional_environment("CLUSTERFLUX_SELF_HOSTED_PROJECT")?
            .unwrap_or_else(|| "project".to_owned()),
    )?;
    let user = UserId::try_new(
        optional_environment("CLUSTERFLUX_SELF_HOSTED_USER")?.unwrap_or_else(|| "user".to_owned()),
    )?;
    Ok(Some(SelfHostedSessionConfiguration {
        tenant,
        project,
        user,
        secret,
    }))
}

fn optional_environment(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} must contain valid Unicode").into())
        }
    }
}

fn environment_flag(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match optional_environment(name)?.as_deref() {
        None | Some("0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        Some(_) => Err(format!("{name} must be one of 0, 1, false, or true").into()),
    }
}

fn required_environment_token(
    name: &str,
    maximum_bytes: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = optional_environment(name)?.ok_or_else(|| format!("{name} must be configured"))?;
    clusterflux_core::validate_opaque_token(&value, maximum_bytes)
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    Ok(value)
}

fn validated_optional_token(
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    optional_environment(name)?
        .map(|value| {
            clusterflux_core::validate_opaque_token(&value, maximum_bytes)
                .map_err(|error| format!("{name} is invalid: {error}"))?;
            Ok(value)
        })
        .transpose()
}

fn artifact_interchange_configuration_from_environment(
) -> Result<CoordinatorArtifactInterchangeConfiguration, Box<dyn std::error::Error>> {
    let deployment_mode = match optional_environment("CLUSTERFLUX_DEPLOYMENT_MODE")?
        .unwrap_or_else(|| "self-hosted".to_owned())
        .as_str()
    {
        "hosted-public" => ClusterfluxDeploymentMode::HostedPublic,
        "self-hosted" => ClusterfluxDeploymentMode::SelfHosted,
        "local-offline" => ClusterfluxDeploymentMode::LocalOffline,
        value => {
            return Err(format!(
                "CLUSTERFLUX_DEPLOYMENT_MODE must be hosted-public, self-hosted, or local-offline; got {value}"
            )
            .into())
        }
    };
    let configured_artifact_relay_policy = match std::env::var("CLUSTERFLUX_ARTIFACT_RELAY_POLICY") {
        Ok(value) => match value.as_str() {
            "direct-required" => Some(ArtifactRelayPolicy::DirectRequired),
            "relay-fallback-allowed" => Some(ArtifactRelayPolicy::RelayFallbackAllowed),
            _ => {
                return Err(format!(
                    "CLUSTERFLUX_ARTIFACT_RELAY_POLICY must be direct-required or relay-fallback-allowed; got {value}"
                )
                .into())
            }
        },
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };
    let relay_urls = optional_environment("CLUSTERFLUX_IROH_RELAY_URLS")?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let relay_access_token =
        validated_optional_token("CLUSTERFLUX_IROH_RELAY_ACCESS_TOKEN", 4_096)?;
    let relay = if relay_urls.is_empty() {
        IrohRelayConfiguration::Disabled
    } else {
        IrohRelayConfiguration::Custom(
            relay_urls
                .into_iter()
                .map(|url| ClusterfluxRelayConfig {
                    url,
                    access_token: relay_access_token.clone(),
                })
                .collect(),
        )
    };
    let artifact_relay_policy = configured_artifact_relay_policy.unwrap_or_else(|| {
        if matches!(relay, IrohRelayConfiguration::Disabled) {
            ArtifactRelayPolicy::DirectRequired
        } else {
            deployment_mode.default_artifact_relay_policy()
        }
    });
    if deployment_mode == ClusterfluxDeploymentMode::SelfHosted
        && matches!(relay, IrohRelayConfiguration::Disabled)
    {
        eprintln!(
            "warning: no self-hosted Iroh relay URL is configured; artifact interchange is running direct-only"
        );
    }
    let defaults = CoordinatorArtifactInterchangeConfiguration::default();
    let configuration = CoordinatorArtifactInterchangeConfiguration {
        deployment_mode,
        relay,
        artifact_relay_policy,
        // The in-memory bootstrap policy is generation one. Runtime configuration is generation
        // two so nodes can never confuse it with an unconfigured default.
        generation: 2,
        endpoint_advertisement_ttl_seconds: environment_u64(
            "CLUSTERFLUX_ARTIFACT_ENDPOINT_ADVERTISEMENT_TTL_SECONDS",
            defaults.endpoint_advertisement_ttl_seconds,
        )?,
        transfer_lease_ttl_seconds: environment_u64(
            "CLUSTERFLUX_ARTIFACT_STREAM_TICKET_TTL_SECONDS",
            defaults.transfer_lease_ttl_seconds,
        )?,
        active_transfer_lease_ttl_seconds: environment_u64(
            "CLUSTERFLUX_ARTIFACT_ACTIVE_TRANSFER_LEASE_TTL_SECONDS",
            defaults.active_transfer_lease_ttl_seconds,
        )?,
        no_progress_timeout_seconds: environment_u64(
            "CLUSTERFLUX_ARTIFACT_NO_PROGRESS_TIMEOUT_SECONDS",
            defaults.no_progress_timeout_seconds,
        )?,
        absolute_transfer_max_seconds: environment_optional_u64(
            "CLUSTERFLUX_ARTIFACT_ABSOLUTE_TRANSFER_MAX_SECONDS",
            defaults.absolute_transfer_max_seconds,
        )?,
        max_active_transfers_per_tenant: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_TENANT",
            defaults.max_active_transfers_per_tenant,
        )?,
        max_active_transfers_per_project: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_PROJECT",
            defaults.max_active_transfers_per_project,
        )?,
        max_active_transfers_per_process: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_PROCESS",
            defaults.max_active_transfers_per_process,
        )?,
        max_provider_leases_per_node: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_PROVIDER_LEASES_PER_NODE",
            defaults.max_provider_leases_per_node,
        )?,
        max_receiver_leases_per_node: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_RECEIVER_LEASES_PER_NODE",
            defaults.max_receiver_leases_per_node,
        )?,
        max_transfer_creations_per_tenant_node_minute: environment_usize(
            "CLUSTERFLUX_ARTIFACT_MAX_TRANSFER_CREATIONS_PER_TENANT_NODE_MINUTE",
            defaults.max_transfer_creations_per_tenant_node_minute,
        )?,
        max_partial_bytes_per_node_project: environment_u64(
            "CLUSTERFLUX_ARTIFACT_MAX_PARTIAL_BYTES_PER_NODE_PROJECT",
            defaults.max_partial_bytes_per_node_project,
        )?,
        direct_path_deadline_ms: environment_u64(
            "CLUSTERFLUX_ARTIFACT_DIRECT_PATH_DEADLINE_MS",
            defaults.direct_path_deadline_ms,
        )?,
        direct_path_grace_period_ms: environment_u64_allow_zero(
            "CLUSTERFLUX_ARTIFACT_DIRECT_PATH_GRACE_PERIOD_MS",
            defaults.direct_path_grace_period_ms,
        )?,
    };
    configuration
        .validate()
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    Ok(configuration)
}

fn environment_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let value = environment_u64_allow_zero(name, default)?;
    if value == 0 {
        return Err(format!("{name} must be positive").into());
    }
    Ok(value)
}

fn environment_u64_allow_zero(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|error| format!("{name} is invalid: {error}").into()),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn environment_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value
                .parse::<usize>()
                .map_err(|error| format!("{name} is invalid: {error}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be positive").into());
            }
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn environment_optional_u64(
    name: &str,
    default: Option<u64>,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if matches!(value.trim(), "" | "0" | "none" | "unlimited") => Ok(None),
        Ok(value) => Ok(Some(
            value
                .parse::<u64>()
                .map_err(|error| format!("{name} is invalid: {error}"))?,
        )),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_configuration_types_addresses_and_rejects_unknown_flags() {
        let args = CoordinatorArgs::try_parse_from([
            "clusterflux-coordinator",
            "--listen",
            "127.0.0.1:7999",
        ])
        .unwrap();
        assert_eq!(args.listen, "127.0.0.1:7999".parse().unwrap());
        assert!(
            CoordinatorArgs::try_parse_from(["clusterflux-coordinator", "--unknown",]).is_err()
        );
    }

    #[test]
    fn local_trusted_mode_is_loopback_only() {
        assert!(validate_listener_security("127.0.0.1:0".parse().unwrap(), true).is_ok());
        assert!(validate_listener_security("[::1]:0".parse().unwrap(), true).is_ok());
        assert!(validate_listener_security("0.0.0.0:7999".parse().unwrap(), true).is_err());
        assert!(validate_listener_security("0.0.0.0:7999".parse().unwrap(), false).is_ok());
    }
}
