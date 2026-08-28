use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ArtifactId, DownloadAction, DownloadError, ProcessId, ProjectId, TaskInstanceId, TenantId,
};

pub const MAX_PANEL_WIDGETS: usize = 64;
pub const MAX_PANEL_SELECT_OPTIONS: usize = 128;
pub const MAX_PANEL_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_PANEL_EVENT_PAYLOAD_BYTES: usize = 4 * 1024;
pub const MAX_PANEL_STATE_BYTES: usize = 256 * 1024;
pub const MAX_PANEL_CONTROL_ACTIONS: usize = MAX_PANEL_WIDGETS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PanelWidgetKind {
    Text {
        value: String,
    },
    Progress {
        current: u64,
        total: u64,
    },
    Button {
        action: String,
    },
    Toggle {
        value: bool,
    },
    Select {
        options: Vec<String>,
        selected: String,
    },
    ArtifactDownload {
        artifact: ArtifactId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelWidget {
    pub id: String,
    pub label: String,
    pub kind: PanelWidgetKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlPlaneAction {
    RestartTask(TaskInstanceId),
    CancelProcess,
    DebugProcess,
    DownloadArtifact(ArtifactId),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelState {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub widgets: BTreeMap<String, PanelWidget>,
    pub program_ui_events_enabled: bool,
    pub control_plane_actions: Vec<ControlPlaneAction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PanelEventKind {
    ButtonClicked,
    ToggleChanged(bool),
    SelectChanged(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelEvent {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub widget_id: String,
    pub kind: PanelEventKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_events: u64,
    pub used_events: u64,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PanelError {
    #[error("custom HTML or JavaScript is not supported in operator panels")]
    CustomContentDenied,
    #[error(
        "operator panel widget `{0}` is not allowed to collect secrets or OAuth-like credentials"
    )]
    CredentialCollectionDenied(String),
    #[error("panel event scope does not match tenant/project/process")]
    ScopeMismatch,
    #[error("program UI events are disabled while debug process is stopped")]
    ProgramEventsDisabled,
    #[error("panel event rate limit exceeded")]
    RateLimited,
    #[error("unknown panel widget `{0}`")]
    UnknownWidget(String),
    #[error("artifact download action is unavailable: {0}")]
    DownloadUnavailable(String),
    #[error("operator panel limit exceeded: {0}")]
    LimitExceeded(String),
}

impl PanelState {
    pub fn new(tenant: TenantId, project: ProjectId, process: ProcessId) -> Self {
        Self {
            tenant,
            project,
            process,
            widgets: BTreeMap::new(),
            program_ui_events_enabled: true,
            control_plane_actions: Vec::new(),
        }
    }

    pub fn add_widget(&mut self, widget: PanelWidget) -> Result<(), PanelError> {
        validate_widget(&widget)?;
        if !self.widgets.contains_key(&widget.id) && self.widgets.len() >= MAX_PANEL_WIDGETS {
            return Err(PanelError::LimitExceeded(format!(
                "at most {MAX_PANEL_WIDGETS} widgets are allowed"
            )));
        }
        let replaced_bytes = self
            .widgets
            .get(&widget.id)
            .map(widget_size_bytes)
            .unwrap_or_default();
        let projected_bytes = self
            .encoded_size_bytes()
            .saturating_sub(replaced_bytes)
            .saturating_add(widget_size_bytes(&widget));
        if projected_bytes > MAX_PANEL_STATE_BYTES {
            return Err(PanelError::LimitExceeded(format!(
                "serialized state may not exceed {MAX_PANEL_STATE_BYTES} bytes"
            )));
        }
        self.widgets.insert(widget.id.clone(), widget);
        Ok(())
    }

    pub fn add_download_widget_from_action(
        &mut self,
        widget_id: impl Into<String>,
        label: impl Into<String>,
        action: Result<DownloadAction, DownloadError>,
    ) -> Result<(), PanelError> {
        let action = action.map_err(|err| PanelError::DownloadUnavailable(err.to_string()))?;
        let artifact = action.artifact;
        self.add_widget(PanelWidget {
            id: widget_id.into(),
            label: label.into(),
            kind: PanelWidgetKind::ArtifactDownload {
                artifact: artifact.clone(),
            },
        })?;
        self.control_plane_actions
            .push(ControlPlaneAction::DownloadArtifact(artifact));
        Ok(())
    }

    pub fn reject_custom_content(_html_or_js: &str) -> Result<(), PanelError> {
        Err(PanelError::CustomContentDenied)
    }

    pub fn freeze_program_ui_events(&mut self) {
        self.program_ui_events_enabled = false;
    }

    pub fn set_control_plane_actions(
        &mut self,
        actions: Vec<ControlPlaneAction>,
    ) -> Result<(), PanelError> {
        if actions.len() > MAX_PANEL_CONTROL_ACTIONS {
            return Err(PanelError::LimitExceeded(format!(
                "at most {MAX_PANEL_CONTROL_ACTIONS} control-plane actions are allowed"
            )));
        }
        self.control_plane_actions = actions;
        Ok(())
    }

    pub fn accept_event(
        &self,
        event: &PanelEvent,
        limit: &mut RateLimit,
    ) -> Result<(), PanelError> {
        validate_panel_event(event)?;
        if !self.program_ui_events_enabled {
            return Err(PanelError::ProgramEventsDisabled);
        }
        if self.tenant != event.tenant
            || self.project != event.project
            || self.process != event.process
        {
            return Err(PanelError::ScopeMismatch);
        }
        if !self.widgets.contains_key(&event.widget_id) {
            return Err(PanelError::UnknownWidget(event.widget_id.clone()));
        }
        if limit.used_events >= limit.max_events {
            return Err(PanelError::RateLimited);
        }
        limit.used_events += 1;
        Ok(())
    }

    pub fn control_plane_actions_available(&self) -> &[ControlPlaneAction] {
        &self.control_plane_actions
    }

    fn encoded_size_bytes(&self) -> usize {
        self.tenant
            .as_str()
            .len()
            .saturating_add(self.project.as_str().len())
            .saturating_add(self.process.as_str().len())
            .saturating_add(self.widgets.values().map(widget_size_bytes).sum::<usize>())
            .saturating_add(
                self.control_plane_actions
                    .iter()
                    .map(control_plane_action_size_bytes)
                    .sum::<usize>(),
            )
    }
}

fn validate_widget(widget: &PanelWidget) -> Result<(), PanelError> {
    validate_bounded_text("widget id", &widget.id, MAX_PANEL_TEXT_BYTES)?;
    validate_bounded_text("widget label", &widget.label, MAX_PANEL_TEXT_BYTES)?;
    let mut checked_text = vec![widget.id.as_str(), widget.label.as_str()];
    match &widget.kind {
        PanelWidgetKind::Text { value } => {
            validate_bounded_text("text widget value", value, MAX_PANEL_TEXT_BYTES)?;
        }
        PanelWidgetKind::Button { action } => {
            validate_bounded_text("button action", action, MAX_PANEL_TEXT_BYTES)?;
            checked_text.push(action);
        }
        PanelWidgetKind::Select { options, selected } => {
            if options.len() > MAX_PANEL_SELECT_OPTIONS {
                return Err(PanelError::LimitExceeded(format!(
                    "at most {MAX_PANEL_SELECT_OPTIONS} select options are allowed"
                )));
            }
            validate_bounded_text("selected option", selected, MAX_PANEL_TEXT_BYTES)?;
            for option in options {
                validate_bounded_text("select option", option, MAX_PANEL_TEXT_BYTES)?;
            }
            checked_text.push(selected);
            checked_text.extend(options.iter().map(String::as_str));
        }
        PanelWidgetKind::Progress { .. }
        | PanelWidgetKind::Toggle { .. }
        | PanelWidgetKind::ArtifactDownload { .. } => {}
    }

    let combined = checked_text.join(" ").to_ascii_lowercase();
    if combined.contains("password")
        || combined.contains("token")
        || combined.contains("oauth")
        || combined.contains("secret")
    {
        return Err(PanelError::CredentialCollectionDenied(widget.id.clone()));
    }
    Ok(())
}

fn validate_panel_event(event: &PanelEvent) -> Result<(), PanelError> {
    validate_bounded_text(
        "event widget id",
        &event.widget_id,
        MAX_PANEL_EVENT_PAYLOAD_BYTES,
    )?;
    if let PanelEventKind::SelectChanged(value) = &event.kind {
        validate_bounded_text("selected event value", value, MAX_PANEL_EVENT_PAYLOAD_BYTES)?;
    }
    Ok(())
}

fn validate_bounded_text(name: &str, value: &str, maximum: usize) -> Result<(), PanelError> {
    if value.len() > maximum {
        return Err(PanelError::LimitExceeded(format!(
            "{name} may not exceed {maximum} bytes"
        )));
    }
    Ok(())
}

fn widget_size_bytes(widget: &PanelWidget) -> usize {
    let kind_bytes = match &widget.kind {
        PanelWidgetKind::Text { value } => value.len(),
        PanelWidgetKind::Progress { .. } => std::mem::size_of::<u64>() * 2,
        PanelWidgetKind::Button { action } => action.len(),
        PanelWidgetKind::Toggle { .. } => 1,
        PanelWidgetKind::Select { options, selected } => options
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(selected.len()),
        PanelWidgetKind::ArtifactDownload { artifact } => artifact.as_str().len(),
    };
    widget
        .id
        .len()
        .saturating_add(widget.label.len())
        .saturating_add(kind_bytes)
}

fn control_plane_action_size_bytes(action: &ControlPlaneAction) -> usize {
    match action {
        ControlPlaneAction::RestartTask(task) => task.as_str().len(),
        ControlPlaneAction::DownloadArtifact(artifact) => artifact.as_str().len(),
        ControlPlaneAction::CancelProcess | ControlPlaneAction::DebugProcess => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel() -> PanelState {
        PanelState::new(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            ProcessId::from("process"),
        )
    }

    #[test]
    fn panel_uses_typed_widgets_and_rejects_custom_content() {
        let mut panel = panel();
        panel
            .add_widget(PanelWidget {
                id: "progress".to_owned(),
                label: "Build".to_owned(),
                kind: PanelWidgetKind::Progress {
                    current: 1,
                    total: 2,
                },
            })
            .unwrap();

        assert!(PanelState::reject_custom_content("<script>alert(1)</script>").is_err());
        assert!(panel.widgets.contains_key("progress"));
    }

    #[test]
    fn panel_rejects_password_or_oauth_collection_widgets() {
        let mut panel = panel();
        let error = panel
            .add_widget(PanelWidget {
                id: "oauth_token".to_owned(),
                label: "OAuth Token".to_owned(),
                kind: PanelWidgetKind::Text {
                    value: String::new(),
                },
            })
            .unwrap_err();

        assert!(matches!(error, PanelError::CredentialCollectionDenied(_)));
    }

    #[test]
    fn panel_rejects_credential_collection_in_interactive_fields() {
        let mut panel = panel();
        let button_error = panel
            .add_widget(PanelWidget {
                id: "continue".to_owned(),
                label: "Continue".to_owned(),
                kind: PanelWidgetKind::Button {
                    action: "collect-secret".to_owned(),
                },
            })
            .unwrap_err();
        assert!(matches!(
            button_error,
            PanelError::CredentialCollectionDenied(_)
        ));

        let select_error = panel
            .add_widget(PanelWidget {
                id: "auth-mode".to_owned(),
                label: "Auth Mode".to_owned(),
                kind: PanelWidgetKind::Select {
                    options: vec!["password".to_owned(), "public key".to_owned()],
                    selected: "public key".to_owned(),
                },
            })
            .unwrap_err();
        assert!(matches!(
            select_error,
            PanelError::CredentialCollectionDenied(_)
        ));
    }

    #[test]
    fn panel_events_are_scoped_and_rate_limited() {
        let mut panel = panel();
        panel
            .add_widget(PanelWidget {
                id: "restart".to_owned(),
                label: "Restart".to_owned(),
                kind: PanelWidgetKind::Button {
                    action: "restart".to_owned(),
                },
            })
            .unwrap();
        let event = PanelEvent {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            widget_id: "restart".to_owned(),
            kind: PanelEventKind::ButtonClicked,
        };
        let mut limit = RateLimit {
            max_events: 1,
            used_events: 0,
        };

        panel.accept_event(&event, &mut limit).unwrap();
        assert_eq!(
            panel.accept_event(&event, &mut limit),
            Err(PanelError::RateLimited)
        );
    }

    #[test]
    fn stopped_debug_process_keeps_control_plane_actions_available() {
        let mut panel = panel();
        panel.freeze_program_ui_events();
        panel
            .set_control_plane_actions(vec![
                ControlPlaneAction::RestartTask(TaskInstanceId::from("task")),
                ControlPlaneAction::DownloadArtifact(ArtifactId::from("artifact")),
            ])
            .unwrap();

        let event = PanelEvent {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            widget_id: "missing".to_owned(),
            kind: PanelEventKind::ButtonClicked,
        };
        let mut limit = RateLimit {
            max_events: 1,
            used_events: 0,
        };

        assert_eq!(
            panel.accept_event(&event, &mut limit),
            Err(PanelError::ProgramEventsDisabled)
        );
        assert_eq!(panel.control_plane_actions_available().len(), 2);
    }

    #[test]
    fn download_widget_is_only_created_from_available_action() {
        let mut panel = panel();
        let action = Ok(DownloadAction {
            artifact: ArtifactId::from("artifact"),
            source: crate::StorageLocation::RetainedNode(crate::NodeId::from("node")),
            scoped_token_subject: "tenant/project/process/artifact".to_owned(),
        });

        panel
            .add_download_widget_from_action("download-artifact", "Download", action)
            .unwrap();

        assert!(matches!(
            panel.widgets["download-artifact"].kind,
            PanelWidgetKind::ArtifactDownload { .. }
        ));
        assert!(matches!(
            panel.control_plane_actions_available()[0],
            ControlPlaneAction::DownloadArtifact(_)
        ));

        let before = panel.widgets.len();
        let error = panel
            .add_download_widget_from_action(
                "missing-download",
                "Download",
                Err(DownloadError::Unavailable),
            )
            .unwrap_err();

        assert_eq!(panel.widgets.len(), before);
        assert!(matches!(error, PanelError::DownloadUnavailable(_)));
    }

    #[test]
    fn panel_rejects_oversized_state_widgets_and_events() {
        let mut panel = panel();
        let oversized_text = "x".repeat(MAX_PANEL_TEXT_BYTES + 1);
        let error = panel
            .add_widget(PanelWidget {
                id: "oversized".to_owned(),
                label: "Oversized".to_owned(),
                kind: PanelWidgetKind::Text {
                    value: oversized_text,
                },
            })
            .unwrap_err();
        assert!(matches!(error, PanelError::LimitExceeded(_)));

        for index in 0..MAX_PANEL_WIDGETS {
            panel
                .add_widget(PanelWidget {
                    id: format!("widget-{index}"),
                    label: "Bounded".to_owned(),
                    kind: PanelWidgetKind::Toggle { value: false },
                })
                .unwrap();
        }
        let error = panel
            .add_widget(PanelWidget {
                id: "one-too-many".to_owned(),
                label: "Bounded".to_owned(),
                kind: PanelWidgetKind::Toggle { value: false },
            })
            .unwrap_err();
        assert!(matches!(error, PanelError::LimitExceeded(_)));

        let event = PanelEvent {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            widget_id: "x".repeat(MAX_PANEL_EVENT_PAYLOAD_BYTES + 1),
            kind: PanelEventKind::ButtonClicked,
        };
        let mut limit = RateLimit {
            max_events: 1,
            used_events: 0,
        };
        assert!(matches!(
            panel.accept_event(&event, &mut limit),
            Err(PanelError::LimitExceeded(_))
        ));
        assert_eq!(limit.used_events, 0);
    }
}
