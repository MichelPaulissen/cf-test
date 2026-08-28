use postgres::{Client, NoTls};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::{
    AgentPublicKeyRecord, AutomationDurableState, CliSessionRecord, CredentialRecord, DurableState,
    FallibleDurableStore, HostedAdminDurableState, NodeIdentityRecord, NodeScopeKey,
    ProjectPermissionRecord, ProjectRecord, ServicePolicyRecord, SourceProviderConfigRecord,
    TenantRecord, UserRecord,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresTable {
    pub name: &'static str,
    pub durable_record: &'static str,
    pub restart_surviving: bool,
}

pub const POSTGRES_DURABLE_TABLES: &[PostgresTable] = &[
    PostgresTable {
        name: "clusterflux_tenants",
        durable_record: "tenants",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_users",
        durable_record: "users",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_projects",
        durable_record: "projects",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_node_identities",
        durable_record: "node identities",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_credentials",
        durable_record: "credentials",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_cli_sessions",
        durable_record: "CLI sessions",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_agent_public_keys",
        durable_record: "agent public keys",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_source_provider_configs",
        durable_record: "source-provider configuration",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_service_policy_records",
        durable_record: "durable service policy records",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_project_permissions",
        durable_record: "explicit project permissions",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_automation_state",
        durable_record: "trigger, run, environment, and encrypted secret state",
        restart_surviving: true,
    },
    PostgresTable {
        name: "clusterflux_hosted_admin_state",
        durable_record: "bounded tenant quota overrides and hosted admin audit",
        restart_surviving: true,
    },
];

#[derive(Debug, Error)]
pub enum PostgresStoreError {
    #[error("postgres durable store error: {0}")]
    Postgres(#[from] postgres::Error),
    #[error("durable state serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub struct PostgresDurableStore {
    client: Client,
}

impl PostgresDurableStore {
    pub fn connect(connection_string: &str) -> Result<Self, PostgresStoreError> {
        let mut store = Self {
            client: Client::connect(connection_string, NoTls)?,
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn from_client(client: Client) -> Result<Self, PostgresStoreError> {
        let mut store = Self { client };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_sql() -> &'static str {
        POSTGRES_SCHEMA_SQL
    }

    pub fn durable_tables() -> &'static [PostgresTable] {
        POSTGRES_DURABLE_TABLES
    }

    pub fn migrate(&mut self) -> Result<(), PostgresStoreError> {
        self.client.batch_execute(Self::schema_sql())?;
        Ok(())
    }

    fn query_records<T: DeserializeOwned>(
        &mut self,
        sql: &str,
    ) -> Result<Vec<T>, PostgresStoreError> {
        self.client
            .query(sql, &[])?
            .into_iter()
            .map(|row| {
                let value: serde_json::Value = row.get("record");
                Ok(serde_json::from_value(value)?)
            })
            .collect()
    }

    fn record_value(record: &impl Serialize) -> Result<serde_json::Value, PostgresStoreError> {
        Ok(serde_json::to_value(record)?)
    }
}

impl FallibleDurableStore for PostgresDurableStore {
    type Error = PostgresStoreError;

    fn load_state(&mut self) -> Result<DurableState, Self::Error> {
        let mut state = DurableState::default();

        for record in self.query_records::<TenantRecord>(
            "SELECT record FROM clusterflux_tenants ORDER BY tenant_id",
        )? {
            state.tenants.insert(record.id.clone(), record);
        }
        for record in self
            .query_records::<UserRecord>("SELECT record FROM clusterflux_users ORDER BY user_id")?
        {
            state.users.insert(record.id.clone(), record);
        }
        for record in self.query_records::<ProjectRecord>(
            "SELECT record FROM clusterflux_projects ORDER BY project_id",
        )? {
            state.projects.insert(record.id.clone(), record);
        }
        for record in self.query_records::<NodeIdentityRecord>(
            "SELECT record FROM clusterflux_node_identities ORDER BY tenant_id, project_id, node_id",
        )? {
            state.node_identities.insert(
                NodeScopeKey::new(
                    record.tenant.clone(),
                    record.project.clone(),
                    record.id.clone(),
                ),
                record,
            );
        }
        for record in self.query_records::<CredentialRecord>(
            "SELECT record FROM clusterflux_credentials ORDER BY subject",
        )? {
            state.credentials.insert(record.subject.clone(), record);
        }
        for record in self.query_records::<CliSessionRecord>(
            "SELECT record FROM clusterflux_cli_sessions ORDER BY session_digest",
        )? {
            state
                .cli_sessions
                .insert(record.session_digest.clone(), record);
        }
        for record in self.query_records::<AgentPublicKeyRecord>(
            "SELECT record FROM clusterflux_agent_public_keys ORDER BY tenant_id, project_id, agent_id",
        )? {
            state.agent_public_keys.insert(
                (
                    record.tenant.clone(),
                    record.project.clone(),
                    record.agent.clone(),
                ),
                record,
            );
        }
        for record in self.query_records::<SourceProviderConfigRecord>(
            "SELECT record FROM clusterflux_source_provider_configs ORDER BY tenant_id, project_id, provider_key",
        )? {
            let provider_key = format!("{:?}", record.provider);
            state.source_provider_configs.insert(
                (record.tenant.clone(), record.project.clone(), provider_key),
                record,
            );
        }
        for record in self.query_records::<ServicePolicyRecord>(
            "SELECT record FROM clusterflux_service_policy_records ORDER BY tenant_id, name",
        )? {
            state
                .service_policy_records
                .insert((record.tenant.clone(), record.name.clone()), record);
        }
        for record in self.query_records::<ProjectPermissionRecord>(
            "SELECT record FROM clusterflux_project_permissions ORDER BY tenant_id, project_id, user_id",
        )? {
            state.project_permissions.insert(
                (
                    record.tenant.clone(),
                    record.project.clone(),
                    record.user.clone(),
                ),
                record,
            );
        }
        if let Some(automation) = self
            .query_records::<AutomationDurableState>(
                "SELECT record FROM clusterflux_automation_state WHERE state_name = 'primary'",
            )?
            .into_iter()
            .next()
        {
            state.replace_automation(automation);
        }
        if let Some(hosted_admin) = self
            .query_records::<HostedAdminDurableState>(
                "SELECT record FROM clusterflux_hosted_admin_state WHERE state_name = 'primary'",
            )?
            .into_iter()
            .next()
        {
            state.hosted_admin = hosted_admin;
        }

        Ok(state)
    }

    fn save_state(&mut self, state: &DurableState) -> Result<(), Self::Error> {
        let mut tx = self.client.transaction()?;
        tx.batch_execute(
            "
            DELETE FROM clusterflux_project_permissions;
            DELETE FROM clusterflux_hosted_admin_state;
            DELETE FROM clusterflux_automation_state;
            DELETE FROM clusterflux_service_policy_records;
            DELETE FROM clusterflux_source_provider_configs;
            DELETE FROM clusterflux_agent_public_keys;
            DELETE FROM clusterflux_cli_sessions;
            DELETE FROM clusterflux_credentials;
            DELETE FROM clusterflux_node_identities;
            DELETE FROM clusterflux_projects;
            DELETE FROM clusterflux_users;
            DELETE FROM clusterflux_tenants;
            ",
        )?;

        for record in state.tenants.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_tenants (tenant_id, record) VALUES ($1, $2)",
                &[&record.id.as_str(), &value],
            )?;
        }
        for record in state.users.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_users (user_id, tenant_id, record) VALUES ($1, $2, $3)",
                &[&record.id.as_str(), &record.tenant.as_str(), &value],
            )?;
        }
        for record in state.projects.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_projects (project_id, tenant_id, record) VALUES ($1, $2, $3)",
                &[&record.id.as_str(), &record.tenant.as_str(), &value],
            )?;
        }
        for record in state.node_identities.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_node_identities (node_id, tenant_id, project_id, record) VALUES ($1, $2, $3, $4)",
                &[
                    &record.id.as_str(),
                    &record.tenant.as_str(),
                    &record.project.as_str(),
                    &value,
                ],
            )?;
        }
        for record in state.credentials.values() {
            let value = Self::record_value(record)?;
            let project_id = record.project.as_ref().map(|project| project.as_str());
            tx.execute(
                "INSERT INTO clusterflux_credentials (subject, tenant_id, project_id, record) VALUES ($1, $2, $3, $4)",
                &[&record.subject.as_str(), &record.tenant.as_str(), &project_id, &value],
            )?;
        }
        for record in state.cli_sessions.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_cli_sessions (session_digest, tenant_id, project_id, user_id, record) VALUES ($1, $2, $3, $4, $5)",
                &[
                    &record.session_digest.as_str(),
                    &record.tenant.as_str(),
                    &record.project.as_str(),
                    &record.user.as_str(),
                    &value,
                ],
            )?;
        }
        for record in state.agent_public_keys.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_agent_public_keys (tenant_id, project_id, user_id, agent_id, record) VALUES ($1, $2, $3, $4, $5)",
                &[
                    &record.tenant.as_str(),
                    &record.project.as_str(),
                    &record.user.as_str(),
                    &record.agent.as_str(),
                    &value,
                ],
            )?;
        }
        for ((_, _, provider_key), record) in &state.source_provider_configs {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_source_provider_configs (tenant_id, project_id, provider_key, record) VALUES ($1, $2, $3, $4)",
                &[
                    &record.tenant.as_str(),
                    &record.project.as_str(),
                    &provider_key.as_str(),
                    &value,
                ],
            )?;
        }
        for record in state.service_policy_records.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_service_policy_records (tenant_id, name, record) VALUES ($1, $2, $3)",
                &[&record.tenant.as_str(), &record.name.as_str(), &value],
            )?;
        }
        for record in state.project_permissions.values() {
            let value = Self::record_value(record)?;
            tx.execute(
                "INSERT INTO clusterflux_project_permissions (tenant_id, project_id, user_id, record) VALUES ($1, $2, $3, $4)",
                &[
                    &record.tenant.as_str(),
                    &record.project.as_str(),
                    &record.user.as_str(),
                    &value,
                ],
            )?;
        }
        let automation = Self::record_value(&state.automation())?;
        tx.execute(
            "INSERT INTO clusterflux_automation_state (state_name, record) VALUES ('primary', $1)",
            &[&automation],
        )?;
        let hosted_admin = Self::record_value(&state.hosted_admin)?;
        tx.execute(
            "INSERT INTO clusterflux_hosted_admin_state (state_name, record) VALUES ('primary', $1)",
            &[&hosted_admin],
        )?;

        tx.commit()?;
        Ok(())
    }
}

const POSTGRES_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS clusterflux_tenants (
    tenant_id TEXT PRIMARY KEY,
    record JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS clusterflux_users (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    record JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS clusterflux_projects (
    project_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    record JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS clusterflux_node_identities (
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, project_id, node_id)
);

DO $clusterflux_node_scope_migration$
DECLARE
    current_primary_key TEXT;
    current_primary_key_columns TEXT[];
BEGIN
    IF EXISTS (
        SELECT 1
        FROM clusterflux_node_identities
        WHERE record->>'id' IS DISTINCT FROM node_id
           OR record->>'tenant' IS DISTINCT FROM tenant_id
           OR record->>'project' IS DISTINCT FROM project_id
    ) THEN
        RAISE EXCEPTION
            'clusterflux node identity migration refused an internally inconsistent legacy row';
    END IF;

    SELECT
        constraint_record.conname,
        array_agg(attribute.attname ORDER BY key_column.ordinality)
    INTO current_primary_key, current_primary_key_columns
    FROM pg_constraint AS constraint_record
    CROSS JOIN LATERAL unnest(constraint_record.conkey)
        WITH ORDINALITY AS key_column(attribute_number, ordinality)
    JOIN pg_attribute AS attribute
      ON attribute.attrelid = constraint_record.conrelid
     AND attribute.attnum = key_column.attribute_number
    WHERE constraint_record.conrelid = 'clusterflux_node_identities'::regclass
      AND constraint_record.contype = 'p'
    GROUP BY constraint_record.conname;

    IF current_primary_key_columns = ARRAY['node_id']::TEXT[] THEN
        EXECUTE format(
            'ALTER TABLE clusterflux_node_identities DROP CONSTRAINT %I',
            current_primary_key
        );
        ALTER TABLE clusterflux_node_identities
            ADD PRIMARY KEY (tenant_id, project_id, node_id);
    ELSIF current_primary_key_columns
        IS DISTINCT FROM ARRAY['tenant_id', 'project_id', 'node_id']::TEXT[]
    THEN
        RAISE EXCEPTION
            'clusterflux node identity migration found an unexpected primary key shape';
    END IF;
END
$clusterflux_node_scope_migration$;

CREATE TABLE IF NOT EXISTS clusterflux_credentials (
    subject TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    record JSONB NOT NULL
);

DO $clusterflux_node_credential_migration$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM clusterflux_credentials
        WHERE record->>'subject' IS DISTINCT FROM subject
           OR record->>'tenant' IS DISTINCT FROM tenant_id
           OR record->>'project' IS DISTINCT FROM project_id
    ) THEN
        RAISE EXCEPTION
            'clusterflux node credential migration refused an internally inconsistent legacy row';
    END IF;

    UPDATE clusterflux_credentials AS credential
    SET subject = format(
            'node:%s:%s:%s:%s:%s:%s',
            octet_length(identity.tenant_id),
            identity.tenant_id,
            octet_length(identity.project_id),
            identity.project_id,
            octet_length(identity.node_id),
            identity.node_id
        ),
        record = jsonb_set(
            credential.record,
            '{subject}',
            to_jsonb(format(
                'node:%s:%s:%s:%s:%s:%s',
                octet_length(identity.tenant_id),
                identity.tenant_id,
                octet_length(identity.project_id),
                identity.project_id,
                octet_length(identity.node_id),
                identity.node_id
            )),
            false
        )
    FROM clusterflux_node_identities AS identity
    WHERE credential.subject = 'node:' || identity.node_id
      AND credential.tenant_id = identity.tenant_id
      AND credential.project_id = identity.project_id;

    IF EXISTS (
        SELECT 1
        FROM clusterflux_credentials AS credential
        WHERE credential.subject LIKE 'node:%'
          AND NOT EXISTS (
              SELECT 1
              FROM clusterflux_node_identities AS identity
              WHERE credential.tenant_id = identity.tenant_id
                AND credential.project_id = identity.project_id
                AND credential.subject = format(
                    'node:%s:%s:%s:%s:%s:%s',
                    octet_length(identity.tenant_id),
                    identity.tenant_id,
                    octet_length(identity.project_id),
                    identity.project_id,
                    octet_length(identity.node_id),
                    identity.node_id
                )
          )
    ) THEN
        RAISE EXCEPTION
            'clusterflux node credential migration found an unscoped or orphaned node subject';
    END IF;
END
$clusterflux_node_credential_migration$;

CREATE TABLE IF NOT EXISTS clusterflux_cli_sessions (
    session_digest TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES clusterflux_users(user_id) ON DELETE CASCADE,
    record JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS clusterflux_agent_public_keys (
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES clusterflux_users(user_id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, project_id, agent_id)
);

CREATE TABLE IF NOT EXISTS clusterflux_source_provider_configs (
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, project_id, provider_key)
);

CREATE TABLE IF NOT EXISTS clusterflux_service_policy_records (
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS clusterflux_project_permissions (
    tenant_id TEXT NOT NULL REFERENCES clusterflux_tenants(tenant_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES clusterflux_projects(project_id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES clusterflux_users(user_id) ON DELETE CASCADE,
    record JSONB NOT NULL,
    PRIMARY KEY (tenant_id, project_id, user_id)
);

CREATE TABLE IF NOT EXISTS clusterflux_automation_state (
    state_name TEXT PRIMARY KEY,
    record JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS clusterflux_hosted_admin_state (
    state_name TEXT PRIMARY KEY,
    record JSONB NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use clusterflux_core::{
        CredentialKind, Digest, NodeId, ProjectId, SourceProviderKind, TenantId, UserId,
    };

    use super::*;
    use crate::{Coordinator, DurableStore, FallibleDurableStore, InMemoryDurableStore};

    #[test]
    fn postgres_schema_contains_only_restart_surviving_durable_tables() {
        let names = PostgresDurableStore::durable_tables()
            .iter()
            .map(|table| table.name)
            .collect::<Vec<_>>();

        assert_eq!(names.len(), 12);
        assert!(names.contains(&"clusterflux_tenants"));
        assert!(names.contains(&"clusterflux_users"));
        assert!(names.contains(&"clusterflux_projects"));
        assert!(names.contains(&"clusterflux_node_identities"));
        assert!(names.contains(&"clusterflux_credentials"));
        assert!(names.contains(&"clusterflux_cli_sessions"));
        assert!(names.contains(&"clusterflux_agent_public_keys"));
        assert!(names.contains(&"clusterflux_source_provider_configs"));
        assert!(names.contains(&"clusterflux_service_policy_records"));
        assert!(names.contains(&"clusterflux_project_permissions"));
        assert!(names.contains(&"clusterflux_automation_state"));
        assert!(names.contains(&"clusterflux_hosted_admin_state"));
        assert!(PostgresDurableStore::durable_tables()
            .iter()
            .all(|table| table.restart_surviving));

        for runtime_only in [
            "active_process",
            "virtual_thread",
            "scheduler_state",
            "debug_epoch",
            "vfs_manifest",
            "transient_artifact_location",
        ] {
            assert!(
                !PostgresDurableStore::schema_sql().contains(runtime_only),
                "{runtime_only} must remain outside Postgres durable state"
            );
        }
    }

    #[test]
    fn fallible_store_boot_uses_durable_state_and_still_drops_live_processes() {
        #[derive(Default)]
        struct FallibleMemoryStore {
            inner: InMemoryDurableStore,
        }

        impl FallibleDurableStore for FallibleMemoryStore {
            type Error = std::convert::Infallible;

            fn load_state(&mut self) -> Result<DurableState, Self::Error> {
                Ok(self.inner.load())
            }

            fn save_state(&mut self, state: &DurableState) -> Result<(), Self::Error> {
                self.inner.save(state.clone());
                Ok(())
            }
        }

        let mut store = FallibleMemoryStore::default();
        let mut first = Coordinator::try_boot(&mut store, 1).unwrap();
        first.upsert_tenant(TenantId::from("tenant"));
        first.upsert_user(
            TenantId::from("tenant"),
            UserId::from("user"),
            CredentialKind::CliDeviceSession,
        );
        first.upsert_project(TenantId::from("tenant"), ProjectId::from("project"), "demo");
        first.enroll_node(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
            "public-key",
            "node:attach",
        );
        first.upsert_source_provider_config(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            SourceProviderKind::Git,
            Digest::sha256("git-manifest"),
        );
        first.start_process(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            clusterflux_core::ProcessId::from("process"),
        );
        first.try_persist(&mut store).unwrap();

        let restarted = Coordinator::try_boot(&mut store, 2).unwrap();

        assert!(restarted.project(&ProjectId::from("project")).is_some());
        assert!(restarted
            .node_identity(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &NodeId::from("node"),
            )
            .is_some());
        assert_eq!(restarted.active_process_count(), 0);
    }

    #[test]
    fn postgres_round_trip_runs_when_dsn_is_configured() {
        let Ok(dsn) = std::env::var("CLUSTERFLUX_TEST_POSTGRES") else {
            return;
        };

        let mut store = PostgresDurableStore::connect(&dsn).unwrap();
        let mut state = DurableState::default();
        state.tenants.insert(
            TenantId::from("tenant"),
            TenantRecord {
                id: TenantId::from("tenant"),
            },
        );
        state.projects.insert(
            ProjectId::from("project"),
            ProjectRecord {
                id: ProjectId::from("project"),
                tenant: TenantId::from("tenant"),
                name: "demo".to_owned(),
            },
        );
        state.users.insert(
            UserId::from("user"),
            UserRecord {
                id: UserId::from("user"),
                tenant: TenantId::from("tenant"),
                credential_kind: CredentialKind::CliDeviceSession,
            },
        );
        let session_digests = [
            Digest::sha256("postgres-round-trip-session-one"),
            Digest::sha256("postgres-round-trip-session-two"),
        ];
        for session_digest in &session_digests {
            state.cli_sessions.insert(
                session_digest.clone(),
                CliSessionRecord {
                    session_digest: session_digest.clone(),
                    tenant: TenantId::from("tenant"),
                    project: ProjectId::from("project"),
                    user: UserId::from("user"),
                    credential_kind: CredentialKind::CliDeviceSession,
                    expires_at_epoch_seconds: None,
                    revoked: false,
                },
            );
            let subject = format!("cli-session:{}", session_digest.as_str());
            state.credentials.insert(
                subject.clone(),
                CredentialRecord {
                    subject,
                    tenant: TenantId::from("tenant"),
                    project: Some(ProjectId::from("project")),
                    kind: CredentialKind::CliDeviceSession,
                    public_key_fingerprint: None,
                },
            );
        }
        store.save_state(&state).unwrap();
        let loaded = store.load_state().unwrap();

        assert!(loaded.projects.contains_key(&ProjectId::from("project")));
        assert!(session_digests
            .iter()
            .all(|session_digest| loaded.cli_sessions.contains_key(session_digest)));
        assert_eq!(loaded.credentials.len(), 2);
    }
}
