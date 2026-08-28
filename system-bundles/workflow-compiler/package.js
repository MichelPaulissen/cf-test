#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");

const repo = path.resolve(__dirname, "../..");
const containerfile = path.join(
  repo,
  "system-bundles/workflow-compiler/envs/compiler/Containerfile"
);
const tag =
  process.env.CLUSTERFLUX_SYSTEM_COMPILER_TAG ||
  "localhost/clusterflux-system-compiler:release";

const environmentInputRoots = [
  "Cargo.toml",
  "Cargo.lock",
  "compiler-toolchain.json",
  "crates/clusterflux-core/Cargo.toml",
  "crates/clusterflux-core/build.rs",
  "crates/clusterflux-core/src",
  "crates/clusterflux-macros",
  "crates/clusterflux-sdk",
  "system-bundles/workflow-compiler/driver",
  "system-bundles/workflow-compiler/envs/compiler",
  "system-bundles/workflow-compiler/package.js",
];

function digestParts(parts) {
  const hash = crypto.createHash("sha256");
  for (const part of parts) {
    const bytes = Buffer.isBuffer(part) ? part : Buffer.from(part);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
  }
  return `sha256:${hash.digest("hex")}`;
}

function filesBelow(input) {
  const absolute = path.join(repo, input);
  if (fs.statSync(absolute).isFile()) return [input];
  return fs
    .readdirSync(absolute, { withFileTypes: true })
    .flatMap((entry) =>
      filesBelow(path.posix.join(input.replaceAll(path.sep, "/"), entry.name))
    );
}

const environmentInputs = environmentInputRoots
  .flatMap(filesBelow)
  .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
const environmentDigest = digestParts([
  "clusterflux-system-compiler-environment:v2",
  ...environmentInputs.flatMap((input) => [
    input,
    fs.readFileSync(path.join(repo, input)),
  ]),
]);
const compilerToolchain = JSON.parse(
  fs.readFileSync(path.join(repo, "compiler-toolchain.json"), "utf8")
);

if (process.argv.includes("--print-environment-digest")) {
  process.stdout.write(`${environmentDigest}\n`);
  process.exit(0);
}

const archiveOverride = process.env.CLUSTERFLUX_SYSTEM_COMPILER_IMAGE_ARCHIVE;
const packageDirOverride = process.env.CLUSTERFLUX_SYSTEM_COMPILER_PACKAGE_DIR;
if (!archiveOverride && !packageDirOverride) {
  throw new Error(
    "set CLUSTERFLUX_SYSTEM_COMPILER_PACKAGE_DIR or CLUSTERFLUX_SYSTEM_COMPILER_IMAGE_ARCHIVE"
  );
}
const archive = path.resolve(
  archiveOverride || path.join(packageDirOverride, "system-compiler-image.oci.tar")
);
const shareDir = path.dirname(archive);
const podman = process.env.CLUSTERFLUX_PODMAN || "podman";
const packageWriter = path.resolve(
  process.env.CLUSTERFLUX_SYSTEM_PACKAGE_WRITER ||
    path.join(repo, "target/release/clusterflux-system-package")
);
fs.mkdirSync(shareDir, { recursive: true });
fs.rmSync(archive, { force: true });
const rootfs = process.env.CLUSTERFLUX_SYSTEM_COMPILER_ROOTFS_DIR;
const imageId = rootfs
  ? assembleOciArchive(path.resolve(rootfs), archive, environmentDigest)
  : buildAndSaveWithPodman(archive, environmentDigest);
if (!fs.existsSync(packageWriter)) {
  throw new Error(`system package manifest writer is missing: ${packageWriter}`);
}
cp.execFileSync(
  packageWriter,
  ["write", "--share-dir", shareDir, "--image-digest", imageId],
  { cwd: repo, stdio: "inherit" }
);
cp.execFileSync(packageWriter, ["verify", "--share-dir", shareDir], {
  cwd: repo,
  stdio: "inherit",
});

process.stdout.write(
  `${JSON.stringify({
    tag,
    image_id: imageId,
    environment_digest: environmentDigest,
    archive,
    share_dir: shareDir,
  })}\n`
);

function buildAndSaveWithPodman(output, exactEnvironmentDigest) {
  cp.execFileSync(
    podman,
    [
      "build",
      "--build-arg",
      `CLUSTERFLUX_ENVIRONMENT_DIGEST=${exactEnvironmentDigest}`,
      "--build-arg",
      `CLUSTERFLUX_RUST_RELEASE=${compilerToolchain.rust_release}`,
      "--build-arg",
      `CLUSTERFLUX_WASM_TARGET=${compilerToolchain.wasm_target}`,
      "--tag",
      tag,
      "--file",
      containerfile,
      repo,
    ],
    { cwd: repo, stdio: "inherit" }
  );
  const inspected = cp
    .execFileSync(podman, ["image", "inspect", "--format", "{{.Id}}", tag], {
      cwd: repo,
      encoding: "utf8",
    })
    .trim();
  const imageId = inspected.startsWith("sha256:")
    ? inspected
    : `sha256:${inspected}`;
  cp.execFileSync(
    podman,
    ["save", "--format", "oci-archive", "--output", output, tag],
    { cwd: repo, stdio: "inherit" }
  );
  return imageId;
}

function assembleOciArchive(rootfs, output, exactEnvironmentDigest) {
  if (!fs.statSync(rootfs).isDirectory()) {
    throw new Error(`compiler rootfs is not a directory: ${rootfs}`);
  }
  const temporary = fs.mkdtempSync(
    path.join(path.dirname(output), ".compiler-oci-layout-")
  );
  try {
    const layout = path.join(temporary, "layout");
    const blobs = path.join(layout, "blobs", "sha256");
    fs.mkdirSync(blobs, { recursive: true });
    const layer = path.join(temporary, "layer.tar");
    deterministicTar(rootfs, layer);
    const layerHex = sha256File(layer);
    fs.renameSync(layer, path.join(blobs, layerHex));

    const architecture = { x64: "amd64", arm64: "arm64" }[process.arch];
    if (!architecture || process.platform !== "linux") {
      throw new Error(`unsupported compiler appliance host ${process.platform}/${process.arch}`);
    }
    const config = {
      created: "1970-01-01T00:00:00Z",
      architecture,
      os: "linux",
      config: {
        User: "65532:65532",
        WorkingDir: "/workspace",
        Labels: {
          "org.clusterflux.environment-digest": exactEnvironmentDigest,
          "org.clusterflux.package-contract": "system-bundles.json",
        },
      },
      rootfs: { type: "layers", diff_ids: [`sha256:${layerHex}`] },
      history: [{ created: "1970-01-01T00:00:00Z", created_by: "Clusterflux self-build" }],
    };
    const configBytes = Buffer.from(JSON.stringify(config));
    const configHex = sha256Bytes(configBytes);
    fs.writeFileSync(path.join(blobs, configHex), configBytes);
    const manifest = {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      config: {
        mediaType: "application/vnd.oci.image.config.v1+json",
        digest: `sha256:${configHex}`,
        size: configBytes.length,
      },
      layers: [
        {
          mediaType: "application/vnd.oci.image.layer.v1.tar",
          digest: `sha256:${layerHex}`,
          size: fs.statSync(path.join(blobs, layerHex)).size,
        },
      ],
    };
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    const manifestHex = sha256Bytes(manifestBytes);
    fs.writeFileSync(path.join(blobs, manifestHex), manifestBytes);
    fs.writeFileSync(
      path.join(layout, "oci-layout"),
      `${JSON.stringify({ imageLayoutVersion: "1.0.0" })}\n`
    );
    fs.writeFileSync(
      path.join(layout, "index.json"),
      `${JSON.stringify({
        schemaVersion: 2,
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: `sha256:${manifestHex}`,
            size: manifestBytes.length,
            annotations: { "org.opencontainers.image.ref.name": "release" },
          },
        ],
      })}\n`
    );
    deterministicTar(layout, output);
    return `sha256:${configHex}`;
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function deterministicTar(directory, output) {
  cp.execFileSync(
    "tar",
    [
      "--sort=name",
      "--mtime=@0",
      "--owner=0",
      "--group=0",
      "--numeric-owner",
      "-C",
      directory,
      "-cf",
      output,
      ".",
    ],
    { stdio: "inherit" }
  );
}

function sha256File(file) {
  return sha256Bytes(fs.readFileSync(file));
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}
