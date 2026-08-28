use std::collections::BTreeMap;

use clusterflux_core::{
    Actor, DownloadPolicy, PanelEvent, PanelEventKind, PanelState, PanelWidget, PanelWidgetKind,
    ProcessId, ProjectId, RateLimit, TenantId, UserId,
};

use crate::CoordinatorError;

use super::artifact_id_from_path;
use super::keys::{panel_stop_key, PanelStopKey};
use super::{CoordinatorResponse, CoordinatorService, CoordinatorServiceError};

const PANEL_SNAPSHOT_TTL_SECONDS: u64 = 24 * 60 * 60;
const PANEL_RATE_WINDOW_SECONDS: u64 = 60;
const MAX_PANEL_SNAPSHOTS_PER_TENANT: usize = 4_096;
const MAX_PANEL_SNAPSHOTS_TOTAL: usize = 1_000_000;
const MAX_PANEL_UPDATES_PER_PROCESS_PER_WINDOW: u64 = 600;
const MAX_PANEL_EVENT_RECORDS_PER_PROCESS: usize = 4_096;
const MAX_PANEL_EVENT_RECORDS_PER_TENANT: usize = 262_144;
const MAX_PANEL_EVENT_RECORDS_TOTAL: usize = 1_000_000;
const MAX_PANEL_EVENTS_PER_USER_PER_WINDOW: u64 = 600;

#[derive(Clone, Debug)]
struct StoredPanelSnapshot {
    panel: PanelState,
    stopped: bool,
    expires_at: u64,
}

#[derive(Clone, Debug)]
struct WindowRateLimit {
    limit: RateLimit,
    expires_at: u64,
}

/// Owns bounded, process-scoped panel snapshots and event/update admission.
///
/// Snapshots expire after a day and are also removed synchronously when their process
/// terminates. Event/update counters use one-minute windows. Large global ceilings are
/// defense-in-depth only; per-tenant and per-process ceilings prevent one tenant from
/// consuming them.
#[derive(Default)]
pub(super) struct PanelRegistry {
    snapshots: BTreeMap<PanelStopKey, StoredPanelSnapshot>,
    update_limits: BTreeMap<PanelStopKey, WindowRateLimit>,
    event_limits: BTreeMap<(PanelStopKey, UserId, String), WindowRateLimit>,
}

impl PanelRegistry {
    fn cleanup_expired(&mut self, now: u64) {
        self.snapshots
            .retain(|_, snapshot| snapshot.expires_at > now);
        self.update_limits.retain(|_, limit| limit.expires_at > now);
        self.event_limits.retain(|_, limit| limit.expires_at > now);
    }

    fn clear_process(&mut self, key: &PanelStopKey) {
        self.snapshots.remove(key);
        self.update_limits.remove(key);
        self.event_limits
            .retain(|(event_key, _, _), _| event_key != key);
    }

    fn snapshot(&self, key: &PanelStopKey) -> Option<PanelState> {
        self.snapshots.get(key).map(|value| value.panel.clone())
    }

    fn is_stopped(&self, key: &PanelStopKey) -> bool {
        self.snapshots
            .get(key)
            .is_some_and(|snapshot| snapshot.stopped)
    }

    pub(super) fn store_snapshot(
        &mut self,
        key: PanelStopKey,
        panel: PanelState,
        stopped: bool,
        now: u64,
    ) -> Result<(), clusterflux_core::PanelError> {
        if panel.tenant != key.0 || panel.project != key.1 || panel.process != key.2 {
            return Err(clusterflux_core::PanelError::ScopeMismatch);
        }
        self.cleanup_expired(now);
        self.admit_update(&key, now)?;
        if !self.snapshots.contains_key(&key) {
            let tenant_snapshots = self
                .snapshots
                .keys()
                .filter(|(tenant, _, _)| tenant == &key.0)
                .count();
            if tenant_snapshots >= MAX_PANEL_SNAPSHOTS_PER_TENANT {
                return Err(clusterflux_core::PanelError::LimitExceeded(format!(
                    "tenant may retain at most {MAX_PANEL_SNAPSHOTS_PER_TENANT} panel snapshots"
                )));
            }
            if self.snapshots.len() >= MAX_PANEL_SNAPSHOTS_TOTAL {
                return Err(clusterflux_core::PanelError::LimitExceeded(format!(
                    "service may retain at most {MAX_PANEL_SNAPSHOTS_TOTAL} panel snapshots"
                )));
            }
        }
        self.snapshots.insert(
            key,
            StoredPanelSnapshot {
                panel,
                stopped,
                expires_at: now.saturating_add(PANEL_SNAPSHOT_TTL_SECONDS),
            },
        );
        Ok(())
    }

    fn admit_update(
        &mut self,
        key: &PanelStopKey,
        now: u64,
    ) -> Result<(), clusterflux_core::PanelError> {
        let limit = self
            .update_limits
            .entry(key.clone())
            .or_insert_with(|| WindowRateLimit {
                limit: RateLimit {
                    max_events: MAX_PANEL_UPDATES_PER_PROCESS_PER_WINDOW,
                    used_events: 0,
                },
                expires_at: now.saturating_add(PANEL_RATE_WINDOW_SECONDS),
            });
        if limit.expires_at <= now {
            limit.limit.used_events = 0;
            limit.expires_at = now.saturating_add(PANEL_RATE_WINDOW_SECONDS);
        }
        if limit.limit.used_events >= limit.limit.max_events {
            return Err(clusterflux_core::PanelError::RateLimited);
        }
        limit.limit.used_events += 1;
        Ok(())
    }

    fn accept_event(
        &mut self,
        panel: &PanelState,
        event: &PanelEvent,
        actor: UserId,
        requested_max_events: u64,
        now: u64,
    ) -> Result<RateLimit, clusterflux_core::PanelError> {
        self.cleanup_expired(now);
        let process_key = panel_stop_key(&event.tenant, &event.project, &event.process);
        let key = (process_key.clone(), actor, event.widget_id.clone());
        if !self.event_limits.contains_key(&key) {
            let process_records = self
                .event_limits
                .keys()
                .filter(|(candidate, _, _)| candidate == &process_key)
                .count();
            if process_records >= MAX_PANEL_EVENT_RECORDS_PER_PROCESS {
                return Err(clusterflux_core::PanelError::LimitExceeded(format!(
                    "process may retain at most {MAX_PANEL_EVENT_RECORDS_PER_PROCESS} panel event counters"
                )));
            }
            let tenant_records = self
                .event_limits
                .keys()
                .filter(|((tenant, _, _), _, _)| tenant == &process_key.0)
                .count();
            if tenant_records >= MAX_PANEL_EVENT_RECORDS_PER_TENANT {
                return Err(clusterflux_core::PanelError::LimitExceeded(format!(
                    "tenant may retain at most {MAX_PANEL_EVENT_RECORDS_PER_TENANT} panel event counters"
                )));
            }
            if self.event_limits.len() >= MAX_PANEL_EVENT_RECORDS_TOTAL {
                return Err(clusterflux_core::PanelError::LimitExceeded(format!(
                    "service may retain at most {MAX_PANEL_EVENT_RECORDS_TOTAL} panel event counters"
                )));
            }
        }
        let max_events = requested_max_events.clamp(1, MAX_PANEL_EVENTS_PER_USER_PER_WINDOW);
        let window = self
            .event_limits
            .entry(key)
            .or_insert_with(|| WindowRateLimit {
                limit: RateLimit {
                    max_events,
                    used_events: 0,
                },
                expires_at: now.saturating_add(PANEL_RATE_WINDOW_SECONDS),
            });
        if window.expires_at <= now {
            window.limit.used_events = 0;
            window.expires_at = now.saturating_add(PANEL_RATE_WINDOW_SECONDS);
        }
        window.limit.max_events = max_events;
        let mut admitted = window.limit.clone();
        panel.accept_event(event, &mut admitted)?;
        window.limit = admitted.clone();
        Ok(admitted)
    }

    #[cfg(test)]
    pub(super) fn contains_snapshot(&self, key: &PanelStopKey) -> bool {
        self.snapshots.contains_key(key)
    }
}

impl CoordinatorService {
    pub(super) fn clear_operator_panel_state(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        let stop_key = panel_stop_key(tenant, project, process);
        self.panel_registry.clear_process(&stop_key);
    }

    pub(super) fn handle_render_operator_panel(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        max_download_bytes: u64,
        stopped: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let stop_key = panel_stop_key(&tenant, &project, &process);
        let now = self.current_epoch_seconds()?;
        self.panel_registry.cleanup_expired(now);

        let panel = if stopped {
            self.ensure_operator_panel_scope(&tenant, &project, &process)?;
            let panel = match self.panel_registry.snapshot(&stop_key) {
                Some(panel) => stopped_panel_snapshot(panel),
                None => self.render_operator_panel(
                    tenant.clone(),
                    project.clone(),
                    process.clone(),
                    UserId::new(actor_user),
                    max_download_bytes,
                    true,
                )?,
            };
            self.panel_registry
                .store_snapshot(stop_key, panel.clone(), true, now)?;
            panel
        } else {
            let panel = self.render_operator_panel(
                tenant.clone(),
                project.clone(),
                process.clone(),
                UserId::new(actor_user),
                max_download_bytes,
                false,
            )?;
            self.panel_registry
                .store_snapshot(stop_key, panel.clone(), false, now)?;
            panel
        };
        Ok(CoordinatorResponse::OperatorPanel { panel })
    }

    pub(super) fn handle_submit_panel_event(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        actor_user: Option<String>,
        widget_id: String,
        kind: PanelEventKind,
        max_events: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let stop_key = panel_stop_key(&tenant, &project, &process);
        let now = self.current_epoch_seconds()?;
        self.panel_registry.cleanup_expired(now);
        let stopped = self.panel_registry.is_stopped(&stop_key);
        let panel = if stopped {
            match self.panel_registry.snapshot(&stop_key) {
                Some(panel) => stopped_panel_snapshot(panel),
                None => {
                    let panel = self.render_operator_panel(
                        tenant.clone(),
                        project.clone(),
                        process.clone(),
                        UserId::from("panel-user"),
                        u64::MAX,
                        true,
                    )?;
                    self.panel_registry.store_snapshot(
                        stop_key.clone(),
                        panel.clone(),
                        true,
                        now,
                    )?;
                    panel
                }
            }
        } else {
            let panel = self.render_operator_panel(
                tenant.clone(),
                project.clone(),
                process.clone(),
                UserId::from("panel-user"),
                u64::MAX,
                false,
            )?;
            self.panel_registry
                .store_snapshot(stop_key, panel.clone(), false, now)?;
            panel
        };
        let event = PanelEvent {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            widget_id: widget_id.clone(),
            kind,
        };
        let actor = UserId::try_new(actor_user.unwrap_or_else(|| "panel-user".to_owned()))
            .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?;
        let limit = self
            .panel_registry
            .accept_event(&panel, &event, actor, max_events, now)?;
        Ok(CoordinatorResponse::PanelEventAccepted {
            used_events: limit.used_events,
            max_events: limit.max_events,
        })
    }

    fn render_operator_panel(
        &self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        actor_user: UserId,
        max_download_bytes: u64,
        stopped: bool,
    ) -> Result<PanelState, CoordinatorServiceError> {
        self.ensure_operator_panel_scope(&tenant, &project, &process)?;

        let events = self
            .task_registry
            .events()
            .filter(|event| {
                event.tenant == tenant && event.project == project && event.process == process
            })
            .collect::<Vec<_>>();
        let completed = events
            .iter()
            .filter(|event| event.status_code == Some(0))
            .count() as u64;
        let total = events.len().max(1) as u64;
        let stdout_bytes = events.iter().map(|event| event.stdout_bytes).sum::<u64>();
        let stderr_bytes = events.iter().map(|event| event.stderr_bytes).sum::<u64>();
        let last_task = events.last().map(|event| event.task.clone());

        let mut panel = PanelState::new(tenant.clone(), project.clone(), process.clone());
        if stopped {
            panel.freeze_program_ui_events();
        }
        panel.add_widget(PanelWidget {
            id: "process-status".to_owned(),
            label: "Process Status".to_owned(),
            kind: PanelWidgetKind::Text {
                value: if stopped {
                    "stopped".to_owned()
                } else {
                    "running".to_owned()
                },
            },
        })?;
        panel.add_widget(PanelWidget {
            id: "task-progress".to_owned(),
            label: "Tasks".to_owned(),
            kind: PanelWidgetKind::Progress {
                current: completed,
                total,
            },
        })?;
        panel.add_widget(PanelWidget {
            id: "task-summary".to_owned(),
            label: "Task Summary".to_owned(),
            kind: PanelWidgetKind::Text {
                value: if events.is_empty() {
                    "no task events recorded".to_owned()
                } else {
                    events
                        .iter()
                        .map(|event| {
                            format!(
                                "{} [{}]:{:?}:{}",
                                event.task_definition, event.task, event.status_code, event.node
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            },
        })?;
        panel.add_widget(PanelWidget {
            id: "recent-logs".to_owned(),
            label: "Recent Logs".to_owned(),
            kind: PanelWidgetKind::Text {
                value: format!("stdout={stdout_bytes} stderr={stderr_bytes}"),
            },
        })?;
        panel.add_widget(PanelWidget {
            id: "debug-process".to_owned(),
            label: "Debug Process".to_owned(),
            kind: PanelWidgetKind::Button {
                action: "debug-process".to_owned(),
            },
        })?;
        panel.add_widget(PanelWidget {
            id: "cancel-process".to_owned(),
            label: "Cancel Process".to_owned(),
            kind: PanelWidgetKind::Button {
                action: "cancel-process".to_owned(),
            },
        })?;
        if last_task.is_some() {
            panel.add_widget(PanelWidget {
                id: "restart-selected-task".to_owned(),
                label: "Restart Selected Task".to_owned(),
                kind: PanelWidgetKind::Button {
                    action: "restart-task".to_owned(),
                },
            })?;
        }

        let mut actions = vec![
            clusterflux_core::ControlPlaneAction::DebugProcess,
            clusterflux_core::ControlPlaneAction::CancelProcess,
        ];
        if let Some(task) = last_task.clone() {
            actions.push(clusterflux_core::ControlPlaneAction::RestartTask(task));
        }
        panel.set_control_plane_actions(actions)?;

        if let Some(path) = events
            .iter()
            .rev()
            .find_map(|event| event.artifact_path.as_ref())
        {
            let artifact = artifact_id_from_path(path)
                .map_err(|error| CoordinatorServiceError::InvalidArtifactPath(error.to_string()))?;
            let context = clusterflux_core::AuthContext {
                tenant,
                project,
                actor: Actor::User(actor_user),
            };
            panel.add_download_widget_from_action(
                "download-artifact",
                "Download Artifact",
                self.artifact_registry.download_action(
                    &context,
                    &artifact,
                    &DownloadPolicy {
                        max_bytes: max_download_bytes,
                    },
                ),
            )?;
        }

        Ok(panel)
    }

    fn ensure_operator_panel_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<(), CoordinatorServiceError> {
        let active = self
            .coordinator
            .active_process(tenant, project, process)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "operator panel requires an active virtual process".to_owned(),
                )
            })?;
        debug_assert_eq!(active.tenant, *tenant);
        debug_assert_eq!(active.project, *project);
        Ok(())
    }
}

fn stopped_panel_snapshot(mut panel: PanelState) -> PanelState {
    panel.freeze_program_ui_events();
    if let Some(status) = panel.widgets.get_mut("process-status") {
        status.kind = PanelWidgetKind::Text {
            value: "stopped".to_owned(),
        };
    }
    panel
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn panel(tenant: &str, project: &str, process: &str) -> PanelState {
        let mut panel = PanelState::new(
            TenantId::from(tenant),
            ProjectId::from(project),
            ProcessId::from(process),
        );
        panel
            .add_widget(PanelWidget {
                id: "button".to_owned(),
                label: "Button".to_owned(),
                kind: PanelWidgetKind::Button {
                    action: "continue".to_owned(),
                },
            })
            .unwrap();
        panel
    }

    #[test]
    fn snapshots_expire_and_terminal_cleanup_removes_every_owned_record() {
        let mut registry = PanelRegistry::default();
        let key = panel_stop_key(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &ProcessId::from("process"),
        );
        registry
            .store_snapshot(key.clone(), panel("tenant", "project", "process"), true, 10)
            .unwrap();
        assert!(registry.contains_snapshot(&key));
        assert!(registry.is_stopped(&key));

        registry.cleanup_expired(10 + PANEL_SNAPSHOT_TTL_SECONDS);
        assert!(!registry.contains_snapshot(&key));

        registry
            .store_snapshot(
                key.clone(),
                panel("tenant", "project", "process"),
                false,
                100_000,
            )
            .unwrap();
        registry.clear_process(&key);
        assert!(!registry.contains_snapshot(&key));
        assert!(!registry.update_limits.contains_key(&key));
        assert!(registry
            .event_limits
            .keys()
            .all(|(event_key, _, _)| event_key != &key));
    }

    #[test]
    fn tenant_snapshot_ceiling_does_not_consume_another_tenants_capacity() {
        let mut registry = PanelRegistry::default();
        for index in 0..MAX_PANEL_SNAPSHOTS_PER_TENANT {
            let project = format!("project-{index}");
            let process = format!("process-{index}");
            registry
                .store_snapshot(
                    panel_stop_key(
                        &TenantId::from("noisy-tenant"),
                        &ProjectId::from(project.as_str()),
                        &ProcessId::from(process.as_str()),
                    ),
                    panel("noisy-tenant", &project, &process),
                    false,
                    10,
                )
                .unwrap();
        }
        let error = registry
            .store_snapshot(
                panel_stop_key(
                    &TenantId::from("noisy-tenant"),
                    &ProjectId::from("overflow"),
                    &ProcessId::from("overflow"),
                ),
                panel("noisy-tenant", "overflow", "overflow"),
                false,
                10,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            clusterflux_core::PanelError::LimitExceeded(_)
        ));

        registry
            .store_snapshot(
                panel_stop_key(
                    &TenantId::from("other-tenant"),
                    &ProjectId::from("project"),
                    &ProcessId::from("process"),
                ),
                panel("other-tenant", "project", "process"),
                false,
                10,
            )
            .unwrap();
    }

    #[test]
    fn user_event_windows_are_bounded_capped_and_expire() {
        let mut registry = PanelRegistry::default();
        let panel = panel("tenant", "project", "process");
        let event = PanelEvent {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            widget_id: "button".to_owned(),
            kind: PanelEventKind::ButtonClicked,
        };
        let first = registry
            .accept_event(&panel, &event, UserId::from("user"), u64::MAX, 10)
            .unwrap();
        assert_eq!(first.max_events, MAX_PANEL_EVENTS_PER_USER_PER_WINDOW);

        for _ in 1..MAX_PANEL_EVENTS_PER_USER_PER_WINDOW {
            registry
                .accept_event(&panel, &event, UserId::from("user"), u64::MAX, 10)
                .unwrap();
        }
        assert_eq!(
            registry.accept_event(&panel, &event, UserId::from("user"), u64::MAX, 10),
            Err(clusterflux_core::PanelError::RateLimited)
        );
        let renewed = registry
            .accept_event(
                &panel,
                &event,
                UserId::from("user"),
                1,
                10 + PANEL_RATE_WINDOW_SECONDS,
            )
            .unwrap();
        assert_eq!(renewed.used_events, 1);
        assert_eq!(renewed.max_events, 1);
    }
}
