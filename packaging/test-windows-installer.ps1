param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$Package,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [string]$Report = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$installerPath = [IO.Path]::GetFullPath($Installer)
$packagePath = [IO.Path]::GetFullPath($Package)
$work = Join-Path ([IO.Path]::GetTempPath()) "clusterflux-installer-test-$PID-$([Guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($work) | Out-Null
$jobs = @()

function Start-PackageServer([string]$File, [long]$Limit = -1) {
    $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
    $probe.Stop()
    $job = Start-Job -ArgumentList $File, $Limit, $port -ScriptBlock {
        param($File, $Limit, $Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object Collections.Generic.List[byte]
                $tail = ''
                while ($tail -notlike "*`r`n`r`n") {
                    $value = $stream.ReadByte()
                    if ($value -lt 0) { break }
                    $request.Add([byte]$value)
                    $tail = [Text.Encoding]::ASCII.GetString($request.ToArray())
                }
                $bytes = [IO.File]::ReadAllBytes($File)
                $length = if ($Limit -ge 0 -and $Limit -lt $bytes.Length) { [int]$Limit } else { $bytes.Length }
                $header = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: $length`r`nConnection: close`r`n`r`n")
                $stream.Write($header, 0, $header.Length)
                $stream.Write($bytes, 0, $length)
                $stream.Flush()
            }
            finally { $client.Dispose() }
        }
        finally { $listener.Stop() }
    }
    $script:jobs += $job
    Start-Sleep -Milliseconds 500
    return "http://127.0.0.1:$port/clusterflux-windows-x86_64.zip"
}

try {
    $prefix = Join-Path $work 'install'
    $goodUri = Start-PackageServer $packagePath
    $output = @(& $installerPath -Prefix $prefix -DownloadUri $goodUri -NoPathUpdate)
    if (-not ($output -join "`n").Contains("Installed Clusterflux $ExpectedVersion")) {
        throw 'installer did not report the installed version'
    }
    if (-not ($output -join "`n").Contains("Add $prefix to your user PATH")) {
        throw 'installer did not report the PATH action'
    }
    foreach ($name in @('clusterflux-node.exe', 'clusterflux-environment-setup.exe', 'package-manifest.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $prefix $name) -PathType Leaf)) {
            throw "installer omitted $name"
        }
    }

    [IO.File]::WriteAllText((Join-Path $prefix 'old-install-sentinel'), 'old')
    $goodUri = Start-PackageServer $packagePath
    & $installerPath -Prefix $prefix -DownloadUri $goodUri -NoPathUpdate | Out-Null
    if (Test-Path -LiteralPath (Join-Path $prefix 'old-install-sentinel')) {
        throw 'installer did not atomically replace the previous installation'
    }

    $corrupt = Join-Path $work 'corrupt.zip'
    [IO.File]::WriteAllBytes($corrupt, [byte[]](1, 2, 3, 4))
    $badUri = Start-PackageServer $corrupt
    $rejected = $false
    try { & $installerPath -Prefix $prefix -DownloadUri $badUri -NoPathUpdate | Out-Null }
    catch { $rejected = $_.Exception.Message -like '*digest mismatch*' }
    if (-not $rejected -or -not (Test-Path -LiteralPath (Join-Path $prefix 'clusterflux-node.exe'))) {
        throw 'installer did not safely reject a wrong package digest'
    }

    $partialUri = Start-PackageServer $packagePath 1024
    $partialRejected = $false
    try { & $installerPath -Prefix $prefix -DownloadUri $partialUri -NoPathUpdate | Out-Null }
    catch { $partialRejected = $_.Exception.Message -like '*digest mismatch*' }
    if (-not $partialRejected -or -not (Test-Path -LiteralPath (Join-Path $prefix 'clusterflux-node.exe'))) {
        throw 'installer did not safely reject a partial package download'
    }

    $result = [ordered]@{
        kind = 'clusterflux-windows-installer-smoke'
        passed = $true
        version = $ExpectedVersion
        correct_zip_accepted = $true
        wrong_digest_rejected = $true
        partial_download_rejected = $true
        existing_install_replaced_atomically = $true
        path_action_reported = $true
    }
    $json = $result | ConvertTo-Json
    if ($Report) {
        [IO.File]::WriteAllText([IO.Path]::GetFullPath($Report), $json + "`n", [Text.UTF8Encoding]::new($false))
    }
    Write-Output $json
}
finally {
    foreach ($job in $jobs) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
