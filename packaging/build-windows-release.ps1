param(
    [Parameter(Mandatory = $true)][string]$Commit,
    [Parameter(Mandatory = $true)][string]$SourceSnapshot,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

if ($Commit -cnotmatch '^[0-9a-f]{40}$') { throw 'invalid source commit' }
if ($SourceSnapshot -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'invalid source snapshot digest' }
if ($Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'invalid release version' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x86-64 is required' }

$manifestVersion = Select-String -LiteralPath 'crates\clusterflux-node\Cargo.toml' `
    -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if ($null -eq $manifestVersion -or $manifestVersion.Matches[0].Groups[1].Value -ne $Version) {
    throw 'Windows node manifest version does not match the release version'
}

& cargo build --locked --release -p clusterflux-node `
    --bin clusterflux-node --bin clusterflux-environment-setup
if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }

$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'target' }
$nodeSource = Join-Path $targetRoot 'release\clusterflux-node.exe'
$setupSource = Join-Path $targetRoot 'release\clusterflux-environment-setup.exe'
foreach ($binary in @($nodeSource, $setupSource)) {
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "missing Windows release binary: $binary"
    }
}

$nodeVersion = (& $nodeSource --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $nodeVersion -notmatch [regex]::Escape($Version)) {
    throw 'clusterflux-node.exe reported the wrong version'
}
$setupVersion = (& $setupSource --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $setupVersion -notmatch [regex]::Escape($Version)) {
    throw 'clusterflux-environment-setup.exe reported the wrong version'
}

$outputPath = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputPath
[IO.Directory]::CreateDirectory($outputParent) | Out-Null
$stage = Join-Path $outputParent 'windows-package-stage'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
[IO.Directory]::CreateDirectory($stage) | Out-Null

try {
    Copy-Item -LiteralPath $nodeSource -Destination (Join-Path $stage 'clusterflux-node.exe')
    Copy-Item -LiteralPath $setupSource -Destination (Join-Path $stage 'clusterflux-environment-setup.exe')
    Copy-Item -LiteralPath 'LICENSE-APACHE' -Destination $stage
    Copy-Item -LiteralPath 'LICENSE-MIT' -Destination $stage

    $readme = @"
Clusterflux $Version for Windows x86-64.

This package installs a user-attached execution-only node and the environment
setup helper. Install and start containerd, BuildKit, nerdctl, and the Windows
nat CNI network separately. Allow inbound UDP for clusterflux-node.exe so
authenticated peers can transfer artifacts. Native host commands remain
disabled by default.

Documentation: https://github.com/lesstuff/clusterflux/blob/main/docs/windows-nodes.md
"@
    [IO.File]::WriteAllText(
        (Join-Path $stage 'README-install.txt'),
        $readme.Replace("`r`n", "`n"),
        [Text.UTF8Encoding]::new($false)
    )

    $nodeDigest = (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'clusterflux-node.exe')).Hash.ToLowerInvariant()
    $setupDigest = (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'clusterflux-environment-setup.exe')).Hash.ToLowerInvariant()
    $rustToolchain = (& rustc --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rustToolchain)) {
        throw 'rustc did not report its toolchain identity'
    }
    $manifest = [ordered]@{
        format_version = 1
        kind = 'clusterflux-windows-package'
        version = $Version
        source_commit = $Commit
        source_snapshot = $SourceSnapshot
        architecture = 'x86_64-windows'
        rust_toolchain = $rustToolchain
        binaries = [ordered]@{
            'clusterflux-environment-setup.exe' = "sha256:$setupDigest"
            'clusterflux-node.exe' = "sha256:$nodeDigest"
        }
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(
        (Join-Path $stage 'package-manifest.json'),
        $manifestJson.Replace("`r`n", "`n") + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    $archiveStream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $archiveStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true
        )
        try {
            $epoch = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            foreach ($name in @(
                'LICENSE-APACHE',
                'LICENSE-MIT',
                'README-install.txt',
                'clusterflux-environment-setup.exe',
                'clusterflux-node.exe',
                'package-manifest.json'
            )) {
                $entry = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $epoch
                $entryStream = $entry.Open()
                $inputStream = [IO.File]::OpenRead((Join-Path $stage $name))
                try { $inputStream.CopyTo($entryStream) }
                finally {
                    $inputStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $archiveStream.Dispose() }

    if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf) -or (Get-Item $outputPath).Length -eq 0) {
        throw 'Windows release package was not created'
    }
}
finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}

Write-Output "VERSION=$Version"
Write-Output "COMMIT=$Commit"
Write-Output "SOURCE_SNAPSHOT=$SourceSnapshot"
