use std::collections::BTreeMap;

use clusterflux_core::{LimitError, LimitKind, ProjectId, ResourceLimits, ResourceMeter, TenantId};
use serde::{Deserialize, Serialize};

use crate::TenantQuotaOverrideValues;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionQuotaLimits {
    pub max_projects: u64,
    pub max_nodes: u64,
    pub max_active_processes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorQuotaConfiguration {
    pub limits: ResourceLimits,
    pub window_seconds: BTreeMap<LimitKind, u64>,
    pub policy_label: Option<String>,
    pub max_projects_per_tenant: usize,
    pub max_nodes_per_tenant: usize,
    pub max_active_processes_per_tenant: usize,
}

pub(super) struct CoordinatorQuotaStatus {
    pub(super) policy_label: Option<String>,
    pub(super) limits: ResourceLimits,
    pub(super) window_seconds: BTreeMap<LimitKind, u64>,
    pub(super) usage: BTreeMap<LimitKind, u64>,
    pub(super) window_started_epoch_seconds: BTreeMap<LimitKind, u64>,
}

impl CoordinatorQuotaConfiguration {
    pub fn new(
        limits: ResourceLimits,
        window_seconds: impl IntoIterator<Item = (LimitKind, u64)>,
    ) -> Result<Self, String> {
        let window_seconds = window_seconds.into_iter().collect::<BTreeMap<_, _>>();
        if window_seconds.values().any(|seconds| *seconds == 0) {
            return Err("quota windows must be at least one second".to_owned());
        }
        Ok(Self {
            limits,
            window_seconds,
            policy_label: None,
            max_projects_per_tenant: usize::MAX,
            max_nodes_per_tenant: usize::MAX,
            max_active_processes_per_tenant: usize::MAX,
        })
    }

    pub fn with_policy_label(mut self, label: impl Into<String>) -> Self {
        let label = label.into();
        self.policy_label = (!label.trim().is_empty()).then_some(label);
        self
    }

    pub fn with_admission_limits(
        mut self,
        max_projects_per_tenant: usize,
        max_nodes_per_tenant: usize,
        max_active_processes_per_tenant: usize,
    ) -> Self {
        self.max_projects_per_tenant = max_projects_per_tenant;
        self.max_nodes_per_tenant = max_nodes_per_tenant;
        self.max_active_processes_per_tenant = max_active_processes_per_tenant;
        self
    }

    pub fn unlimited() -> Self {
        Self {
            limits: ResourceLimits::unlimited(),
            window_seconds: LimitKind::ALL
                .into_iter()
                .map(|kind| (kind, u64::MAX))
                .collect(),
            policy_label: None,
            max_projects_per_tenant: usize::MAX,
            max_nodes_per_tenant: usize::MAX,
            max_active_processes_per_tenant: usize::MAX,
        }
    }

    pub fn window_seconds(&self, kind: LimitKind) -> u64 {
        self.window_seconds
            .get(&kind)
            .copied()
            .unwrap_or(u64::MAX)
            .max(1)
    }
}

impl Default for CoordinatorQuotaConfiguration {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectQuotaScope {
    tenant: TenantId,
    project: ProjectId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MeterKey {
    scope: ProjectQuotaScope,
    kind: LimitKind,
    window: u64,
}

#[derive(Clone, Debug)]
pub(super) struct CoordinatorQuota {
    configuration: CoordinatorQuotaConfiguration,
    meters: BTreeMap<MeterKey, ResourceMeter>,
}

impl Default for CoordinatorQuota {
    fn default() -> Self {
        Self::new(CoordinatorQuotaConfiguration::default())
    }
}

impl CoordinatorQuota {
    pub(super) fn new(configuration: CoordinatorQuotaConfiguration) -> Self {
        Self {
            configuration,
            meters: BTreeMap::new(),
        }
    }

    pub(super) fn ensure_project_admission(
        &self,
        _tenant: &TenantId,
        current: usize,
        tenant_override: Option<&TenantQuotaOverrideValues>,
    ) -> Result<(), super::CoordinatorServiceError> {
        let maximum = self
            .effective_admission_limits(tenant_override)
            .max_projects;
        if u64::try_from(current).unwrap_or(u64::MAX) >= maximum {
            return Err(super::CoordinatorServiceError::ProjectQuota {
                current: u64::try_from(current).unwrap_or(u64::MAX),
                maximum,
            });
        }
        Ok(())
    }

    pub(super) fn ensure_node_admission(
        &self,
        _tenant: &TenantId,
        current: usize,
        tenant_override: Option<&TenantQuotaOverrideValues>,
    ) -> Result<(), super::CoordinatorServiceError> {
        let maximum = self.effective_admission_limits(tenant_override).max_nodes;
        if u64::try_from(current).unwrap_or(u64::MAX) >= maximum {
            return Err(super::CoordinatorServiceError::NodeIdentityQuota {
                current: u64::try_from(current).unwrap_or(u64::MAX),
                maximum,
            });
        }
        Ok(())
    }

    pub(super) fn ensure_process_admission(
        &self,
        _tenant: &TenantId,
        current: usize,
        tenant_override: Option<&TenantQuotaOverrideValues>,
    ) -> Result<(), super::CoordinatorServiceError> {
        let maximum = self
            .effective_admission_limits(tenant_override)
            .max_active_processes;
        if u64::try_from(current).unwrap_or(u64::MAX) >= maximum {
            return Err(super::CoordinatorServiceError::ActiveProcessQuota {
                current: u64::try_from(current).unwrap_or(u64::MAX),
                maximum,
            });
        }
        Ok(())
    }

    pub fn default_admission_limits(&self) -> AdmissionQuotaLimits {
        AdmissionQuotaLimits {
            max_projects: u64::try_from(self.configuration.max_projects_per_tenant)
                .unwrap_or(u64::MAX),
            max_nodes: u64::try_from(self.configuration.max_nodes_per_tenant).unwrap_or(u64::MAX),
            max_active_processes: u64::try_from(self.configuration.max_active_processes_per_tenant)
                .unwrap_or(u64::MAX),
        }
    }

    pub fn effective_admission_limits(
        &self,
        tenant_override: Option<&TenantQuotaOverrideValues>,
    ) -> AdmissionQuotaLimits {
        let defaults = self.default_admission_limits();
        AdmissionQuotaLimits {
            max_projects: tenant_override
                .and_then(|values| values.max_projects)
                .unwrap_or(defaults.max_projects),
            max_nodes: tenant_override
                .and_then(|values| values.max_nodes)
                .unwrap_or(defaults.max_nodes),
            max_active_processes: tenant_override
                .and_then(|values| values.max_active_processes)
                .unwrap_or(defaults.max_active_processes),
        }
    }

    fn key(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        now_epoch_seconds: u64,
    ) -> MeterKey {
        MeterKey {
            scope: ProjectQuotaScope {
                tenant: tenant.clone(),
                project: project.clone(),
            },
            kind,
            window: now_epoch_seconds / self.configuration.window_seconds(kind),
        }
    }

    fn meter(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        now_epoch_seconds: u64,
    ) -> Option<&ResourceMeter> {
        self.meters
            .get(&self.key(tenant, project, kind, now_epoch_seconds))
    }

    fn meter_mut(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        now_epoch_seconds: u64,
    ) -> &mut ResourceMeter {
        let key = self.key(tenant, project, kind, now_epoch_seconds);
        self.meters.retain(|existing, _| {
            existing.scope != key.scope || existing.kind != kind || existing.window == key.window
        });
        self.meters.entry(key).or_default()
    }

    fn can_charge(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        amount: u64,
        now_epoch_seconds: u64,
    ) -> Result<(), LimitError> {
        self.meter(tenant, project, kind, now_epoch_seconds)
            .cloned()
            .unwrap_or_default()
            .can_charge(&self.configuration.limits, kind, amount)
    }

    fn charge(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        amount: u64,
        now_epoch_seconds: u64,
    ) -> Result<u64, LimitError> {
        let limits = self.configuration.limits.clone();
        let meter = self.meter_mut(tenant, project, kind, now_epoch_seconds);
        meter.charge(&limits, kind, amount)?;
        Ok(meter.used(&kind))
    }

    fn used(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        kind: LimitKind,
        now_epoch_seconds: u64,
    ) -> u64 {
        self.meter(tenant, project, kind, now_epoch_seconds)
            .map_or(0, |meter| meter.used(&kind))
    }

    pub(super) fn can_charge_workflow_spawn(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> Result<(), LimitError> {
        self.can_charge(tenant, project, LimitKind::Spawn, 1, now_epoch_seconds)
    }

    pub(super) fn charge_api_call(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> Result<u64, LimitError> {
        self.charge(tenant, project, LimitKind::ApiCall, 1, now_epoch_seconds)
    }

    pub(super) fn charge_log_bytes(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        bytes: u64,
        now_epoch_seconds: u64,
    ) -> Result<u64, LimitError> {
        self.charge(
            tenant,
            project,
            LimitKind::LogBytes,
            bytes,
            now_epoch_seconds,
        )
    }

    pub(super) fn charge_workflow_spawn(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> Result<u64, LimitError> {
        self.charge(tenant, project, LimitKind::Spawn, 1, now_epoch_seconds)
    }

    #[cfg(test)]
    pub(super) fn used_workflow_spawns(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> u64 {
        self.used(tenant, project, LimitKind::Spawn, now_epoch_seconds)
    }

    #[cfg(test)]
    pub(super) fn used_api_calls(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> u64 {
        self.used(tenant, project, LimitKind::ApiCall, now_epoch_seconds)
    }

    #[cfg(test)]
    pub(super) fn used_log_bytes(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> u64 {
        self.used(tenant, project, LimitKind::LogBytes, now_epoch_seconds)
    }

    #[cfg(test)]
    pub(super) fn active_meter_count(&self) -> usize {
        self.meters.len()
    }

    pub(super) fn charge_debug_read(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        bytes: u64,
        now_epoch_seconds: u64,
    ) -> Result<u64, LimitError> {
        self.charge(
            tenant,
            project,
            LimitKind::DebugReadBytes,
            bytes,
            now_epoch_seconds,
        )
    }

    pub(super) fn used_debug_read_bytes(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> u64 {
        self.used(
            tenant,
            project,
            LimitKind::DebugReadBytes,
            now_epoch_seconds,
        )
    }

    pub(super) fn project_status(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        now_epoch_seconds: u64,
    ) -> CoordinatorQuotaStatus {
        let mut usage = BTreeMap::new();
        let mut window_starts = BTreeMap::new();
        for kind in LimitKind::ALL {
            let seconds = self.configuration.window_seconds(kind);
            usage.insert(kind, self.used(tenant, project, kind, now_epoch_seconds));
            window_starts.insert(kind, (now_epoch_seconds / seconds).saturating_mul(seconds));
        }
        CoordinatorQuotaStatus {
            policy_label: self.configuration.policy_label.clone(),
            limits: self.configuration.limits.clone(),
            window_seconds: self.configuration.window_seconds.clone(),
            usage,
            window_started_epoch_seconds: window_starts,
        }
    }

    #[cfg(test)]
    pub(super) fn set_workflow_limits(&mut self, limits: ResourceLimits) {
        self.configuration
            .limits
            .limits
            .insert(LimitKind::Spawn, limits.limit(&LimitKind::Spawn));
        self.meters.clear();
    }
}
