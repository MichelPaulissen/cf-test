const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");
const crypto = require("crypto");


let vscode = null;
try {
  vscode = require("vscode");
} catch (_) {
  vscode = null;
}

const rustAnalyzerEntriesAdded = new Map();

function discoverEnvironmentNames(projectRoot) {
  const envsDir = path.join(projectRoot, "envs");
  if (!fs.existsSync(envsDir)) return [];

  return fs
    .readdirSync(envsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => {
      const dir = path.join(envsDir, name);
      return (
        fs.existsSync(path.join(dir, "Containerfile")) ||
        fs.existsSync(path.join(dir, "Dockerfile"))
      );
    })
    .sort();
}

function findEnvReferences(text) {
  const references = [];
  const pattern = /env!\(\s*"([^"]+)"\s*\)/g;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    references.push({
      name: match[1],
      start: match.index,
      end: pattern.lastIndex
    });
  }
  return references;
}

function diagnoseEnvReferences(text, environmentNames) {
  const known = new Set(environmentNames);
  return findEnvReferences(text)
    .filter((reference) => !known.has(reference.name))
    .map((reference) => ({
      ...reference,
      message: `Missing Clusterflux environment "${reference.name}". Add envs/${reference.name}/Containerfile or envs/${reference.name}/Dockerfile.`
    }));
}

function binaryCandidates(projectRoot, name) {
  const names = process.platform === "win32" ? [name, `${name}.exe`] : [name];
  return names.map((candidate) => path.join(projectRoot, candidate));
}

function executableWorkspaceBinary(projectRoot, name) {
  if (!projectRoot) return null;
  return binaryCandidates(projectRoot, name).find((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch (_) {
      return false;
    }
  }) || null;
}

function hasCargoWorkspace(root) {
  return fs.existsSync(path.join(root, "Cargo.toml"));
}

async function configureRustAnalyzerProjects(workspaceRoot) {
  if (!vscode || !workspaceRoot) return [];
  const projects = ["Cargo.toml", path.join(".clusterflux", "Cargo.toml")]
    .map((relative) => path.join(workspaceRoot, relative))
    .filter((manifest) => fs.existsSync(manifest));
  if (projects.length === 0) return [];
  const configuration = vscode.workspace.getConfiguration(
    "rust-analyzer",
    vscode.Uri.file(workspaceRoot)
  );
  const existing = configuration.get("linkedProjects", []);
  const linked = Array.from(new Set([...existing, ...projects]));
  rustAnalyzerEntriesAdded.set(
    workspaceRoot,
    projects.filter((project) => !existing.includes(project))
  );
  if (JSON.stringify(existing) !== JSON.stringify(linked)) {
    await configuration.update(
      "linkedProjects",
      linked,
      vscode.ConfigurationTarget.WorkspaceFolder
    );
  }
  return linked;
}

function parseRustcDiagnostics(output, workspaceRoot) {
  const diagnostics = [];
  for (const line of String(output || "").split(/\r?\n/)) {
    const start = line.indexOf("{");
    if (start < 0) continue;
    let message;
    try {
      message = JSON.parse(line.slice(start));
    } catch (_) {
      continue;
    }
    if (message && message.reason === "compiler-message" && message.message) {
      message = message.message;
    }
    if (!message || !Array.isArray(message.spans)) continue;
    for (const span of message.spans.filter((item) => item && item.is_primary)) {
      const file = path.isAbsolute(span.file_name)
        ? span.file_name
        : path.join(workspaceRoot, span.file_name);
      diagnostics.push({
        file,
        message: message.message || "Clusterflux compiler diagnostic",
        level: message.level || "error",
        lineStart: Math.max(0, Number(span.line_start || 1) - 1),
        columnStart: Math.max(0, Number(span.column_start || 1) - 1),
        lineEnd: Math.max(0, Number(span.line_end || span.line_start || 1) - 1),
        columnEnd: Math.max(0, Number(span.column_end || span.column_start || 1) - 1)
      });
    }
  }
  return diagnostics;
}

function registerWorkflowCommands(context, workspaceRoot, compilerDiagnostics) {
  if (!workspaceRoot) return;
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  const askEntrypoint = () => vscode.window.showInputBox({
    prompt: "Clusterflux entrypoint",
    value: "main"
  });
  context.subscriptions.push(
    vscode.commands.registerCommand("clusterflux.workflow.check", async () => {
      try {
        const invocation = clusterfluxCliCommand(workspaceRoot, [
          "check", "--project", workspaceRoot, "--message-format", "rustc-json", "--json"
        ]);
        const result = childProcess.spawnSync(invocation.command, invocation.args, invocation.options);
        const parsed = parseRustcDiagnostics(
          `${String(result.stdout || "")}\n${String(result.stderr || "")}`,
          workspaceRoot
        );
        compilerDiagnostics.clear();
        const byFile = new Map();
        for (const diagnostic of parsed) {
          const uri = vscode.Uri.file(diagnostic.file);
          const key = uri.toString();
          if (!byFile.has(key)) byFile.set(key, { uri, diagnostics: [] });
          const severity = diagnostic.level === "warning"
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Error;
          byFile.get(key).diagnostics.push(new vscode.Diagnostic(
            new vscode.Range(
              diagnostic.lineStart,
              diagnostic.columnStart,
              diagnostic.lineEnd,
              diagnostic.columnEnd
            ),
            diagnostic.message,
            severity
          ));
        }
        for (const { uri, diagnostics } of byFile.values()) {
          compilerDiagnostics.set(uri, diagnostics);
        }
        if (result.error) throw result.error;
        if (result.status !== 0) {
          throw new Error(String(result.stderr || result.stdout || "workflow check failed").trim());
        }
        vscode.window.showInformationMessage("Clusterflux workflow check passed.");
      } catch (error) {
        vscode.window.showErrorMessage(`Clusterflux workflow check failed: ${error.message}`);
      }
    }),
    vscode.commands.registerCommand("clusterflux.workflow.run", async () => {
      const entry = await askEntrypoint();
      if (!entry) return;
      const terminal = vscode.window.createTerminal("Clusterflux Workflow");
      terminal.sendText(`clusterflux run --project ${JSON.stringify(workspaceRoot)} ${JSON.stringify(entry)}`);
      terminal.show();
    }),
    vscode.commands.registerCommand("clusterflux.workflow.debug", async () => {
      const entry = await askEntrypoint();
      if (!entry) return;
      await vscode.debug.startDebugging(folder, {
        type: "clusterflux",
        request: "launch",
        name: `Clusterflux: Debug ${entry}`,
        project: workspaceRoot,
        entry
      });
    })
  );
}

function resolveProjectPath(folder, value) {
  const workspaceRoot = folder && folder.uri && folder.uri.fsPath;
  if (!value || value === "${workspaceFolder}") return workspaceRoot;
  if (workspaceRoot && typeof value === "string") {
    return value.replace(/\$\{workspaceFolder\}/g, workspaceRoot);
  }
  return value;
}

function bundleInspectCommand(projectRoot, adapterWorkspace = path.resolve(__dirname, "..")) {
  const workspaceCli = executableWorkspaceBinary(projectRoot, "clusterflux");
  if (workspaceCli) {
    return {
      command: workspaceCli,
      args: ["bundle", "inspect", "--project", projectRoot, "--json"],
      options: {
        cwd: projectRoot,
        encoding: "utf8"
      }
    };
  }

  return {
    command: "cargo",
    args: [
      "run",
      "-q",
      "-p",
      "clusterflux-cli",
      "--bin",
      "clusterflux",
      "--",
      "bundle",
      "inspect",
      "--project",
      projectRoot,
      "--json"
    ],
    options: {
      cwd: adapterWorkspace,
      encoding: "utf8"
    }
  };
}

function clusterfluxCliCommand(
  projectRoot,
  args,
  adapterWorkspace = path.resolve(__dirname, "..")
) {
  const workspaceCli = executableWorkspaceBinary(projectRoot, "clusterflux");
  if (workspaceCli) {
    return {
      command: workspaceCli,
      args,
      options: { cwd: projectRoot, encoding: "utf8" }
    };
  }
  if (!hasCargoWorkspace(adapterWorkspace)) {
    return {
      command: "clusterflux",
      args,
      options: { cwd: projectRoot, encoding: "utf8" }
    };
  }
  return {
    command: "cargo",
    args: ["run", "-q", "-p", "clusterflux-cli", "--bin", "clusterflux", "--", ...args],
    options: { cwd: adapterWorkspace, encoding: "utf8" }
  };
}

function runClusterfluxCliJson(
  projectRoot,
  args,
  adapterWorkspace = path.resolve(__dirname, ".."),
  runner = childProcess.spawnSync
) {
  const invocation = clusterfluxCliCommand(projectRoot, [...args, "--json"], adapterWorkspace);
  const result = runner(invocation.command, invocation.args, invocation.options);
  if (result.error) {
    throw new Error(`Clusterflux CLI failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "").trim();
    throw new Error(detail || `Clusterflux CLI exited with status ${result.status}`);
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`Clusterflux CLI returned invalid JSON: ${error.message}`);
  }
}

function loadLiveProcesses(
  projectRoot,
  adapterWorkspace = path.resolve(__dirname, ".."),
  runner = childProcess.spawnSync
) {
  try {
    const report = runClusterfluxCliJson(
      projectRoot,
      ["process", "list"],
      adapterWorkspace,
      runner
    );
    return {
      processes: asArray(report.processes),
      coordinator: report.coordinator || null,
      tenant: report.tenant || null,
      project: report.project || null,
      user: report.user || null,
      error: null
    };
  } catch (error) {
    return {
      processes: [],
      coordinator: null,
      tenant: null,
      project: null,
      user: null,
      error: error.message
    };
  }
}

function digestFromParts(parts) {
  const hasher = crypto.createHash("sha256");
  for (const value of parts) {
    const part = Buffer.from(value);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(part.length));
    hasher.update(length);
    hasher.update(part);
  }
  return hasher.digest("hex");
}

function clusterfluxProcessId(projectRoot, entry) {
  if (!entry) throw new Error("entrypoint must be selected before deriving a process id");
  return `vp-${digestFromParts(["dap-process:v1", projectRoot, entry]).slice(0, 12)}`;
}

function refreshBundleBeforeLaunch(
  projectRoot,
  adapterWorkspace = path.resolve(__dirname, ".."),
  runner = childProcess.spawnSync
) {
  const command = bundleInspectCommand(projectRoot, adapterWorkspace);
  const result = runner(command.command, command.args, command.options);
  if (result.error) {
    throw new Error(`Clusterflux bundle refresh failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    throw new Error(
      `Clusterflux bundle refresh failed before debug launch${detail ? `: ${detail}` : "."}`
    );
  }

  let inspection;
  try {
    inspection = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`Clusterflux bundle refresh returned invalid metadata: ${error.message}`);
  }
  if (!inspection.metadata || !inspection.metadata.identity) {
    throw new Error("Clusterflux bundle refresh did not return a bundle identity.");
  }
  return inspection;
}

function clusterfluxViewDescriptors() {
  return [
    { id: "clusterflux.nodes", emptyLabel: "No attached nodes" },
    { id: "clusterflux.processes", emptyLabel: "No virtual processes" },
    { id: "clusterflux.logs", emptyLabel: "No log streams" },
    { id: "clusterflux.artifacts", emptyLabel: "No artifacts" },
    { id: "clusterflux.inspector", emptyLabel: "No inspector state" }
  ];
}

function clusterfluxViewStatePath(projectRoot) {
  return path.join(projectRoot, ".clusterflux-state", "views.json");
}

function emptyClusterfluxViewState() {
  return {
    nodes: [],
    processes: [],
    logs: [],
    artifacts: [],
    inspector: []
  };
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function loadClusterfluxViewState(projectRoot, reader = fs.readFileSync) {
  const statePath = clusterfluxViewStatePath(projectRoot);
  if (!fs.existsSync(statePath)) {
    return emptyClusterfluxViewState();
  }

  let parsed;
  try {
    parsed = JSON.parse(reader(statePath, "utf8"));
  } catch (error) {
    return {
      ...emptyClusterfluxViewState(),
      inspector: [
        {
          label: "View state error",
          value: error.message
        }
      ]
    };
  }

  return {
    nodes: asArray(parsed.nodes),
    processes: asArray(parsed.processes),
    logs: asArray(parsed.logs),
    artifacts: asArray(parsed.artifacts),
    inspector: asArray(parsed.inspector)
  };
}

function item(label, description = "", options = {}) {
  return {
    label: String(label || ""),
    description: String(description || ""),
    ...options
  };
}

function clusterfluxViewItems(state, viewId) {
  switch (viewId) {
    case "clusterflux.nodes":
      return state.nodes.map((node) =>
        item(node.id || node.name || "node", [node.status, node.capabilities].filter(Boolean).join(" "))
      );
    case "clusterflux.processes":
      return state.processes.map((process) =>
        item(
          process.id || process.process || "process",
          [process.state || process.status, process.entry].filter(Boolean).join(" "),
          {
            processId: process.id || process.process,
            processState: process.state || process.status || "unknown",
            contextValue: "clusterflux.virtualProcess",
            command: {
              command: "clusterflux.process.attach",
              title: "Attach to Virtual Process",
              arguments: [process.id || process.process]
            }
          }
        )
      );
    case "clusterflux.logs":
      return state.logs.map((log) =>
        item(log.task || log.stream || "log", [log.message, log.bytes].filter(Boolean).join(" "))
      );
    case "clusterflux.artifacts":
      return state.artifacts.map((artifact) =>
        item(artifact.path || artifact.id || "artifact", [artifact.status, artifact.size].filter(Boolean).join(" "))
      );
    case "clusterflux.inspector":
      return state.inspector.map((entry) =>
        item(entry.label || entry.name || "inspector", entry.value || entry.detail || "")
      );
    default:
      return [];
  }
}

function treeItemsForView(projectRoot, descriptor, liveProcesses = null) {
  const state = projectRoot ? loadClusterfluxViewState(projectRoot) : emptyClusterfluxViewState();
  if (descriptor.id === "clusterflux.processes" && liveProcesses) {
    if (liveProcesses.error) {
      return [
        item("Live process state unavailable", liveProcesses.error, {
          contextValue: "clusterflux.processError"
        })
      ];
    }
    state.processes = liveProcesses.processes;
  }
  const items = clusterfluxViewItems(state, descriptor.id);
  return items.length > 0 ? items : [item(descriptor.emptyLabel)];
}

function toVsCodeTreeItem(viewItem) {
  const treeItem = new vscode.TreeItem(
    viewItem.label,
    vscode.TreeItemCollapsibleState.None
  );
  treeItem.description = viewItem.description;
  treeItem.tooltip = viewItem.description || viewItem.label;
  treeItem.contextValue = viewItem.contextValue;
  treeItem.command = viewItem.command;
  return treeItem;
}

function resolveClusterfluxDebugConfiguration(folder, config = {}) {
  const project = resolveProjectPath(folder, config.project);
  return {
    ...config,
    name:
      config.name ||
      (config.request === "attach"
        ? "Clusterflux: Attach to Virtual Process"
        : "Clusterflux: Launch Virtual Process"),
    type: "clusterflux",
    request: config.request || "launch",
    project,
    runtimeBackend: config.runtimeBackend || "local-services"
  };
}

function debugAdapterExecutableSpec(
  projectRoot,
  adapterWorkspace = path.resolve(__dirname, "..")
) {
  const workspaceAdapter = executableWorkspaceBinary(projectRoot, "clusterflux-debug-dap");
  if (workspaceAdapter) {
    return {
      command: workspaceAdapter,
      args: [],
      options: { cwd: projectRoot }
    };
  }

  if (!hasCargoWorkspace(adapterWorkspace)) {
    return {
      command: "clusterflux-debug-dap",
      args: [],
      options: { cwd: projectRoot || process.cwd() }
    };
  }

  return {
    command: "cargo",
    args: ["run", "-q", "-p", "clusterflux-dap", "--bin", "clusterflux-debug-dap"],
    options: { cwd: adapterWorkspace }
  };
}

function registerClusterfluxViews(context) {
  if (!vscode) return null;
  const workspaceRoot =
    vscode.workspace.workspaceFolders &&
    vscode.workspace.workspaceFolders[0] &&
    vscode.workspace.workspaceFolders[0].uri.fsPath;
  const emitters = new Map();
  let liveProcesses = null;
  const refreshProcesses = () => {
    liveProcesses = workspaceRoot ? loadLiveProcesses(workspaceRoot) : null;
    const emitter = emitters.get("clusterflux.processes");
    if (emitter) emitter.fire();
    return liveProcesses;
  };
  for (const descriptor of clusterfluxViewDescriptors()) {
    const emitter = new vscode.EventEmitter();
    emitters.set(descriptor.id, emitter);
    context.subscriptions.push(
      vscode.window.registerTreeDataProvider(descriptor.id, {
        onDidChangeTreeData: emitter.event,
        getTreeItem(item) {
          return item;
        },
        getChildren() {
          if (descriptor.id === "clusterflux.processes" && liveProcesses === null) {
            refreshProcesses();
          }
          return treeItemsForView(workspaceRoot, descriptor, liveProcesses).map(toVsCodeTreeItem);
        }
      }),
      emitter
    );
  }
  if (workspaceRoot && vscode.workspace.createFileSystemWatcher) {
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(workspaceRoot, ".clusterflux-state/views.json")
    );
    const refresh = () => emitters.forEach((emitter) => emitter.fire());
    context.subscriptions.push(
      watcher,
      watcher.onDidChange(refresh),
      watcher.onDidCreate(refresh),
      watcher.onDidDelete(refresh)
    );
  }
  context.subscriptions.push(
    vscode.commands.registerCommand("clusterflux.refreshProcesses", refreshProcesses)
  );
  return { workspaceRoot, refreshProcesses, getLiveProcesses: () => liveProcesses };
}

function commandProcessId(value) {
  if (typeof value === "string") return value;
  return value && (value.processId || value.label);
}

function liveDebugConfiguration(workspaceRoot, processId, liveProcesses) {
  return {
    type: "clusterflux",
    request: "attach",
    name: `Clusterflux: Attach to ${processId}`,
    project: workspaceRoot,
    runtimeBackend: "live-services",
    processId
  };
}

function processAction(projectRoot, action, processId) {
  return runClusterfluxCliJson(projectRoot, ["process", action, "--process", processId, "--yes"]);
}

function registerProcessCommands(context, viewController) {
  if (!viewController || !viewController.workspaceRoot) return;
  const projectRoot = viewController.workspaceRoot;
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];

  context.subscriptions.push(
    vscode.commands.registerCommand("clusterflux.process.attach", async (value) => {
      const processId = commandProcessId(value);
      if (!processId) return;
      const live = viewController.refreshProcesses();
      if (live.error) {
        vscode.window.showErrorMessage(`Unable to load Clusterflux process state: ${live.error}`);
        return;
      }
      await vscode.debug.startDebugging(
        folder,
        liveDebugConfiguration(projectRoot, processId, live)
      );
    }),
    vscode.commands.registerCommand("clusterflux.process.cancel", async (value) => {
      const processId = commandProcessId(value);
      if (!processId) return;
      const selected = await vscode.window.showWarningMessage(
        `Request cooperative cancellation of ${processId}? The process remains active until its code exits.`,
        { modal: true },
        "Request Cancellation"
      );
      if (selected !== "Request Cancellation") return;
      try {
        processAction(projectRoot, "cancel", processId);
        viewController.refreshProcesses();
        vscode.window.showInformationMessage(`Cancellation requested for ${processId}.`);
      } catch (error) {
        vscode.window.showErrorMessage(`Clusterflux cancellation failed: ${error.message}`);
      }
    }),
    vscode.commands.registerCommand("clusterflux.process.abort", async (value) => {
      const processId = commandProcessId(value);
      if (!processId) return;
      const selected = await vscode.window.showWarningMessage(
        `Abort ${processId}? This forcibly terminates the virtual process and releases the project slot.`,
        { modal: true },
        "Abort Process"
      );
      if (selected !== "Abort Process") return;
      try {
        processAction(projectRoot, "abort", processId);
        viewController.refreshProcesses();
        vscode.window.showInformationMessage(`Aborted ${processId}.`);
      } catch (error) {
        vscode.window.showErrorMessage(`Clusterflux abort failed: ${error.message}`);
      }
    })
  );
}

function existingProcessRelationship(activeProcess, intendedProcessId) {
  return activeProcess && activeProcess.process === intendedProcessId
    ? "same_launch_target"
    : "different_launch_target";
}

async function resolveExistingProcessBeforeLaunch(folder, config) {
  if (
    !folder ||
    config.request !== "launch" ||
    config.runtimeBackend !== "live-services" ||
    !config.project
  ) {
    return config;
  }
  const live = loadLiveProcesses(config.project);
  if (live.error || live.processes.length === 0) return config;

  const active = live.processes[0];
  const intendedProcessId =
    config.processId || (config.entry ? clusterfluxProcessId(config.project, config.entry) : null);
  const relationship = existingProcessRelationship(active, intendedProcessId);
  const runningId = active.process;
  const detail = `${runningId} is ${active.state || "running"} in Coordinator Project ${
    live.project || "selected by the authenticated CLI session"
  }.`;

  const choices =
    relationship === "same_launch_target"
      ? [
          { label: "Attach", description: "Debug the existing virtual process.", action: "attach" },
          { label: "Restart", description: "Restart this virtual process with the current launch.", action: "restart" },
          ...(active.state === "cancelling"
            ? []
            : [{ label: "Request cancellation", description: "Let the process handle cancellation and exit.", action: "cancel" }]),
          { label: "Abort and launch", description: "Forcibly terminate it, then start this launch.", action: "abort_launch" },
          { label: "Show details", description: detail, action: "details" },
          { label: "Cancel launch", description: "Leave the running process unchanged.", action: "dismiss" }
        ]
      : [
          { label: "Show running process", description: detail, action: "details" },
          ...(active.state === "cancelling"
            ? []
            : [{ label: "Request cancellation", description: "Ask the other process to exit cooperatively.", action: "cancel" }]),
          { label: "Abort it and launch this workspace", description: "Forcibly free this Coordinator Project slot.", action: "abort_launch" },
          { label: "Use another Coordinator Project", description: "Keep the other process and select a different authenticated project.", action: "other_project" },
          { label: "Cancel launch", description: "Leave the running process unchanged.", action: "dismiss" }
        ];

  const selected = await vscode.window.showQuickPick(choices, {
    title:
      relationship === "same_launch_target"
        ? "This Clusterflux virtual process is already running"
        : "Another launch is using this Coordinator Project",
    placeHolder: detail,
    ignoreFocusOut: true
  });
  if (!selected || selected.action === "dismiss") return undefined;
  if (selected.action === "details") {
    await vscode.window.showInformationMessage(detail, { modal: true });
    return undefined;
  }
  if (selected.action === "other_project") {
    await vscode.window.showInformationMessage(
      `Choose or create another Coordinator Project with the Clusterflux CLI, then run \`clusterflux project select\` from this workspace. The current project is ${
        live.project || "the project in the authenticated CLI session"
      }.`,
      { modal: true }
    );
    return undefined;
  }
  if (selected.action === "cancel") {
    processAction(config.project, "cancel", runningId);
    vscode.commands.executeCommand("clusterflux.refreshProcesses");
    return undefined;
  }
  if (selected.action === "abort_launch") {
    processAction(config.project, "abort", runningId);
    vscode.commands.executeCommand("clusterflux.refreshProcesses");
    return config;
  }
  if (selected.action === "attach") {
    return {
      ...config,
      request: "attach",
      name: `Clusterflux: Attach to ${runningId}`,
      processId: runningId
    };
  }
  if (selected.action === "restart") {
    return { ...config, processId: runningId, restartExisting: true };
  }
  return undefined;
}

function activate(context) {
  if (!vscode) return;

  const diagnostics = vscode.languages.createDiagnosticCollection("clusterflux");
  const compilerDiagnostics = vscode.languages.createDiagnosticCollection("clusterflux-compiler");
  context.subscriptions.push(diagnostics, compilerDiagnostics);
  const viewController = registerClusterfluxViews(context);
  registerProcessCommands(context, viewController);
  const workspaceRoot = viewController && viewController.workspaceRoot;
  configureRustAnalyzerProjects(workspaceRoot).catch((error) => {
    vscode.window.showWarningMessage(`Clusterflux could not configure rust-analyzer projects: ${error.message}`);
  });
  registerWorkflowCommands(context, workspaceRoot, compilerDiagnostics);

  const refresh = (document) => {
    if (document.languageId !== "rust") return;
    const folder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!folder) return;
    const environmentNames = discoverEnvironmentNames(folder.uri.fsPath);
    const items = diagnoseEnvReferences(document.getText(), environmentNames).map((diagnostic) => {
      const start = document.positionAt(diagnostic.start);
      const end = document.positionAt(diagnostic.end);
      return new vscode.Diagnostic(
        new vscode.Range(start, end),
        diagnostic.message,
        vscode.DiagnosticSeverity.Error
      );
    });
    diagnostics.set(document.uri, items);
  };

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(refresh),
    vscode.workspace.onDidChangeTextDocument((event) => refresh(event.document)),
    vscode.workspace.onDidSaveTextDocument(refresh),
    vscode.debug.registerDebugAdapterDescriptorFactory("clusterflux", {
      createDebugAdapterDescriptor(session) {
        const folder = session.workspaceFolder;
        const project = session.configuration.project || (folder && folder.uri.fsPath);
        if (!project) {
          throw new Error("Clusterflux debug launch requires a workspace folder or project path.");
        }
        const adapterWorkspace = path.resolve(__dirname, "..");
        refreshBundleBeforeLaunch(project, adapterWorkspace);
        const spec = debugAdapterExecutableSpec(project, adapterWorkspace);
        return new vscode.DebugAdapterExecutable(
          spec.command,
          spec.args,
          spec.options
        );
      }
    }),
    vscode.debug.registerDebugConfigurationProvider("clusterflux", {
      async resolveDebugConfiguration(folder, config) {
        const resolved = resolveClusterfluxDebugConfiguration(folder, config);
        return resolveExistingProcessBeforeLaunch(folder, resolved);
      }
    })
  );

  for (const document of vscode.workspace.textDocuments) {
    refresh(document);
  }
}

async function deactivate() {
  if (!vscode) return;
  for (const [workspaceRoot, added] of rustAnalyzerEntriesAdded) {
    if (added.length === 0) continue;
    const configuration = vscode.workspace.getConfiguration(
      "rust-analyzer",
      vscode.Uri.file(workspaceRoot)
    );
    const existing = configuration.get("linkedProjects", []);
    const cleaned = existing.filter((project) => !added.includes(project));
    if (JSON.stringify(existing) !== JSON.stringify(cleaned)) {
      await configuration.update(
        "linkedProjects",
        cleaned,
        vscode.ConfigurationTarget.WorkspaceFolder
      );
    }
  }
  rustAnalyzerEntriesAdded.clear();
}

module.exports = {
  activate,
  deactivate,
  bundleInspectCommand,
  debugAdapterExecutableSpec,
  diagnoseEnvReferences,
  configureRustAnalyzerProjects,
  clusterfluxCliCommand,
  clusterfluxProcessId,
  clusterfluxViewDescriptors,
  clusterfluxViewItems,
  clusterfluxViewStatePath,
  discoverEnvironmentNames,
  findEnvReferences,
  existingProcessRelationship,
  loadLiveProcesses,
  loadClusterfluxViewState,
  parseRustcDiagnostics,
  registerClusterfluxViews,
  refreshBundleBeforeLaunch,
  runClusterfluxCliJson,
  resolveClusterfluxDebugConfiguration
};
