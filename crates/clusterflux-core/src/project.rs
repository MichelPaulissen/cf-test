use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use syn::{punctuated::Punctuated, Expr, Item, Lit, Meta, Token};
use thiserror::Error;

use crate::{discover_environments, Digest, EnvironmentResource};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entrypoint {
    pub name: String,
    pub function: String,
    pub is_default: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectModel {
    pub root: PathBuf,
    pub workflow_root: PathBuf,
    pub manifest_digest: Digest,
    pub environments: Vec<EnvironmentResource>,
    pub entrypoints: BTreeMap<String, Entrypoint>,
    pub default_entrypoint: String,
    pub required_config_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProjectModelError {
    #[error("environment discovery failed: {0}")]
    Environment(String),
    #[error("Clusterflux entrypoint discovery failed: {0}")]
    EntrypointDiscovery(String),
    #[error(
        "no Clusterflux entrypoint is declared; add `#[clusterflux::main]` to a function under .clusterflux/"
    )]
    NoEntrypoints,
    #[error("unknown Clusterflux entrypoint `{name}`; available entrypoints: {available:?}")]
    UnknownEntrypoint {
        name: String,
        available: Vec<String>,
    },
    #[error("Clusterflux entrypoint is ambiguous; choose one explicitly from {available:?}")]
    AmbiguousEntrypoint { available: Vec<String> },
}

impl ProjectModel {
    pub fn discover_without_config(root: &Path) -> Result<Self, ProjectModelError> {
        let workflow_root = root.join(".clusterflux");
        let manifest_path = workflow_root.join("Cargo.toml");
        let manifest_bytes = fs::read(&manifest_path).map_err(|error| {
            ProjectModelError::EntrypointDiscovery(format!(
                "failed to read {}: {error}",
                manifest_path.display()
            ))
        })?;
        // Locally Cargo owns manifest semantics. Clusterflux only records the
        // bytes for source identity and never applies the hosted-safe subset.
        let manifest_digest = Digest::sha256(&manifest_bytes);
        let environments = discover_environments(root)
            .map_err(|error| ProjectModelError::Environment(error.to_string()))?;
        // This recursive scan is deliberately approximate. Cargo's compiled module
        // graph and the shared bundle finalizer are the only runnable authority;
        // unreadable, invalid, or duplicate annotations in files Cargo does not
        // compile must not prevent check/build/run.
        let entrypoints = discover_entrypoint_candidates(&workflow_root);
        let default_entrypoint = source_default_entrypoint(&entrypoints).unwrap_or_default();
        Ok(Self {
            root: root.to_path_buf(),
            workflow_root,
            manifest_digest,
            environments,
            entrypoints,
            default_entrypoint,
            required_config_file: None,
        })
    }

    pub fn select_entrypoint(&self, name: Option<&str>) -> Result<&Entrypoint, ProjectModelError> {
        if self.entrypoints.is_empty() {
            return Err(ProjectModelError::NoEntrypoints);
        }
        let name = match name {
            Some(name) => name,
            None if !self.default_entrypoint.is_empty() => &self.default_entrypoint,
            None => {
                return Err(ProjectModelError::AmbiguousEntrypoint {
                    available: self.entrypoints.keys().cloned().collect(),
                })
            }
        };
        self.entrypoints
            .get(name)
            .ok_or_else(|| ProjectModelError::UnknownEntrypoint {
                name: name.to_owned(),
                available: self.entrypoints.keys().cloned().collect(),
            })
    }
}

fn discover_entrypoint_candidates(root: &Path) -> BTreeMap<String, Entrypoint> {
    if !root.is_dir() {
        return BTreeMap::new();
    }

    let mut source_files = Vec::new();
    collect_rust_sources(root, &mut source_files);
    source_files.sort();

    let mut entrypoints = BTreeMap::new();
    for path in source_files {
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(syntax) = syn::parse_file(&source) else {
            continue;
        };
        collect_entrypoint_candidate_items(&syntax.items, &mut entrypoints);
    }
    entrypoints
}

fn collect_rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_rust_sources(&path, files);
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn collect_entrypoint_candidate_items(
    items: &[Item],
    entrypoints: &mut BTreeMap<String, Entrypoint>,
) {
    for item in items {
        match item {
            Item::Fn(function) => {
                let Some(attribute) = function.attrs.iter().find(|attribute| {
                    let segments = attribute
                        .path()
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>();
                    segments.as_slice() == ["clusterflux", "main"]
                }) else {
                    continue;
                };
                let function_name = function.sig.ident.to_string();
                let default_name = function_name
                    .strip_suffix("_main")
                    .unwrap_or(&function_name);
                let (name, is_default) = entrypoint_options(attribute, default_name);
                let entrypoint = Entrypoint {
                    name: name.clone(),
                    function: function_name,
                    is_default,
                };
                entrypoints.entry(name).or_insert(entrypoint);
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_entrypoint_candidate_items(nested, entrypoints);
                }
            }
            _ => {}
        }
    }
}

fn entrypoint_options(attribute: &syn::Attribute, default: &str) -> (String, bool) {
    let Meta::List(_) = &attribute.meta else {
        return (default.to_owned(), false);
    };
    let Ok(arguments) = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
    else {
        return (default.to_owned(), false);
    };
    let mut name = default.to_owned();
    let mut is_default = false;
    for meta in arguments {
        let Meta::NameValue(name_value) = meta else {
            continue;
        };
        let Expr::Lit(expression) = name_value.value else {
            continue;
        };
        match expression.lit {
            Lit::Str(value) if name_value.path.is_ident("name") => name = value.value(),
            Lit::Bool(value) if name_value.path.is_ident("default") => is_default = value.value,
            _ => {}
        }
    }
    (name, is_default)
}

fn source_default_entrypoint(entrypoints: &BTreeMap<String, Entrypoint>) -> Option<String> {
    let explicit = entrypoints
        .values()
        .filter(|entrypoint| entrypoint.is_default)
        .collect::<Vec<_>>();
    if explicit.len() == 1 {
        return Some(explicit[0].name.clone());
    }
    if explicit.len() > 1 {
        return None;
    }
    if entrypoints.contains_key("main") {
        return Some("main".to_owned());
    }
    if entrypoints.len() == 1 {
        return entrypoints.keys().next().cloned();
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write_manifest(root: &Path) {
        fs::create_dir_all(root.join(".clusterflux")).unwrap();
        fs::write(
            root.join(".clusterflux/Cargo.toml"),
            "[package]\nname='test-workflow'\nversion='0.0.0'\nedition='2024'\npublish=false\n[lib]\npath='main.rs'\ncrate-type=['cdylib']\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0'}\n[workspace]\nresolver='3'\n",
        )
        .unwrap();
    }

    #[test]
    fn project_works_without_hand_written_configuration_file() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path());
        fs::create_dir_all(temp.path().join("envs/linux")).unwrap();
        fs::write(
            temp.path().join("envs/linux/Containerfile"),
            "FROM alpine\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".clusterflux/main.rs"),
            "#[clusterflux::main]\npub fn build_main() {}\n",
        )
        .unwrap();

        let model = ProjectModel::discover_without_config(temp.path()).unwrap();

        assert_eq!(model.required_config_file, None);
        assert_eq!(model.environments[0].name, "linux");
        assert_eq!(model.select_entrypoint(None).unwrap().name, "build");
    }

    #[test]
    fn project_can_define_multiple_default_entrypoints() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path());
        fs::create_dir_all(temp.path().join(".clusterflux/nested")).unwrap();
        fs::write(
            temp.path().join(".clusterflux/main.rs"),
            "#[clusterflux::main(name = \"check\")]\npub fn test_main() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".clusterflux/nested/release.rs"),
            "#[clusterflux::main]\npub fn release_main() {}\n",
        )
        .unwrap();
        let model = ProjectModel::discover_without_config(temp.path()).unwrap();

        assert_eq!(
            model.select_entrypoint(Some("check")).unwrap().function,
            "test_main"
        );
        assert_eq!(
            model.select_entrypoint(Some("release")).unwrap().function,
            "release_main"
        );
    }

    #[test]
    fn unknown_entrypoint_lists_available_choices() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path());
        fs::write(
            temp.path().join(".clusterflux/main.rs"),
            "#[clusterflux::main]\npub fn build_main() {}\n",
        )
        .unwrap();
        let model = ProjectModel::discover_without_config(temp.path()).unwrap();
        let error = model.select_entrypoint(Some("deploy")).unwrap_err();

        assert!(matches!(error, ProjectModelError::UnknownEntrypoint { .. }));
    }

    #[test]
    fn project_without_declared_entrypoint_does_not_invent_product_surfaces() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path());
        fs::write(temp.path().join(".clusterflux/main.rs"), "fn main() {}\n").unwrap();

        let model = ProjectModel::discover_without_config(temp.path()).unwrap();

        assert!(model.entrypoints.is_empty());
        assert_eq!(model.default_entrypoint, "");
        assert_eq!(
            model.select_entrypoint(None).unwrap_err(),
            ProjectModelError::NoEntrypoints
        );
    }

    #[test]
    fn duplicate_and_invalid_uncompiled_files_are_nonblocking_source_candidates() {
        let temp = tempfile::tempdir().unwrap();
        write_manifest(temp.path());
        fs::write(
            temp.path().join(".clusterflux/main.rs"),
            "#[clusterflux::main]\npub fn build_main() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".clusterflux/unused_duplicate.rs"),
            "#[clusterflux::main(name = \"build\")]\npub fn ignored_main() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join(".clusterflux/unused_invalid.rs"),
            "#[clusterflux::main( this is not valid Rust",
        )
        .unwrap();

        let model = ProjectModel::discover_without_config(temp.path()).unwrap();

        assert_eq!(model.entrypoints.len(), 1);
        assert_eq!(model.entrypoints["build"].function, "build_main");
    }
}
