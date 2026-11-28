# Installs BlazeServe on Windows from the latest release, or updates it.
#
#   irm https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.ps1 | iex
#
# Downloads the Windows build, checks it against the published SHA256SUMS, puts
# blaze.exe in %LOCALAPPDATA%\Programs\BlazeServe, and adds that folder to your
# user PATH. No administrator rights required, and it does not auto-update.
# Remove it: $env:BLAZE_UNINSTALL = 1; irm https://raw.githubusercontent.com/whoisjayd/blazeserve/main/install.ps1 | iex
#
# To verify release provenance before trusting an archive, download it and run:
#   gh attestation verify <archive> --repo whoisjayd/blazeserve
#
# Environment:
#   BLAZE_VERSION       a release tag like v1.1.0 (default: the latest)
#   BLAZE_INSTALL_DIR   override install directory (default: %LOCALAPPDATA%\Programs\BlazeServe)
#   BLAZE_BASE_URL      override download base URL (for mirrors or local testing)
#   BLAZE_UNINSTALL     set to 1 to remove BlazeServe and its PATH entry

# `irm | iex` runs in the caller's session; the child scope keeps preferences and helpers out of it.
& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'whoisjayd/blazeserve'

function Get-InstallDir {
    if ($env:BLAZE_INSTALL_DIR) {
        return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:BLAZE_INSTALL_DIR)
    }
    return Join-Path $env:LOCALAPPDATA 'Programs\BlazeServe'
}

# The registry is used directly because [Environment] expands %VARIABLES% when it reads PATH
# and stores the result as plain text, which would permanently rewrite the user's entries.
function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $key.Dispose()
    }
    return @($raw -split ';' | Where-Object { $_ })
}

function Set-UserPath {
    param([string[]]$Entries)
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $key.SetValue('Path', ($Entries -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally {
        $key.Dispose()
    }
    # A registry write is silent; removing an unset variable tells programs to reread them all.
    [Environment]::SetEnvironmentVariable('BLAZE_PATH_CHANGED', $null, 'User')
}

function Test-SameDir {
    param([string]$Entry, [string]$Dir)
    [Environment]::ExpandEnvironmentVariables($Entry).TrimEnd('\') -ieq $Dir.TrimEnd('\')
}

function Get-ReleaseBaseUrl {
    if ($env:BLAZE_BASE_URL) {
        return $env:BLAZE_BASE_URL.TrimEnd('/')
    }
    if ($env:BLAZE_VERSION) {
        $tag = if ($env:BLAZE_VERSION.StartsWith('v')) { $env:BLAZE_VERSION } else { "v$($env:BLAZE_VERSION)" }
        return "https://github.com/$Repo/releases/download/$tag"
    }
    return "https://github.com/$Repo/releases/latest/download"
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($LiteralPath)
    try {
        $bytes = $sha.ComputeHash($stream)
        return ([BitConverter]::ToString($bytes) -replace '-', '').ToUpperInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Get-ReleaseAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $parsed = [Uri]$Uri
    if ($parsed.Scheme -eq 'file') {
        if (-not $env:BLAZE_BASE_URL) {
            throw 'file:// URLs require BLAZE_BASE_URL.'
        }
        $localPath = $parsed.LocalPath
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) {
            throw "Download failed: $Uri"
        }
        Copy-Item -LiteralPath $localPath -Destination $OutFile -Force
        return
    }
    if ($parsed.Scheme -ne 'https') {
        throw "Refusing non-HTTPS URL: $Uri"
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile
}

function Uninstall-BlazeServe {
    param([string]$Dir)
    Remove-Item Env:\BLAZE_UNINSTALL -ErrorAction SilentlyContinue
    # The folder may be one the user shares with other tools: remove only what we put there.
    foreach ($file in 'blaze.exe', 'blaze.new.exe') {
        $path = Join-Path $Dir $file
        if (Test-Path -LiteralPath $path) { Remove-Item -Force -LiteralPath $path }
    }
    if (Test-Path -LiteralPath $Dir) {
        if (Get-ChildItem -Force -LiteralPath $Dir | Select-Object -First 1) {
            Write-Host "Removed blaze from $Dir. The folder holds other files, so it stays on PATH."
            return
        }
        Remove-Item -Force -LiteralPath $Dir
    }
    $entries = @(Get-UserPath)
    $remaining = @($entries | Where-Object { -not (Test-SameDir $_ $Dir) })
    if ($remaining.Count -ne $entries.Count) { Set-UserPath $remaining }
    Write-Host "Removed BlazeServe from $Dir."
}

function Install-BlazeServe {
    param([string]$Dir)
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq 'x86' -and $env:PROCESSOR_ARCHITEW6432) {
        $arch = $env:PROCESSOR_ARCHITEW6432
    }
    if ($arch -ne 'AMD64') {
        throw "BlazeServe's Windows build is x86_64; this is $arch."
    }

    $base = Get-ReleaseBaseUrl
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("blaze-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        $sums = Join-Path $tmp 'SHA256SUMS'
        Get-ReleaseAsset -Uri "$base/SHA256SUMS" -OutFile $sums

        $target = 'x86_64-pc-windows-msvc'
        $expected = $null
        $name = $null
        foreach ($rawLine in (Get-Content -LiteralPath $sums)) {
            $line = $rawLine.Trim()
            if (-not $line -or $line.StartsWith('#')) { continue }
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?([^\s/\\]+)$') {
                $hash = $Matches[1].ToUpperInvariant()
                $file = $Matches[2]
                if ($env:BLAZE_VERSION) {
                    $tag = if ($env:BLAZE_VERSION.StartsWith('v')) { $env:BLAZE_VERSION } else { "v$($env:BLAZE_VERSION)" }
                    if ($file -eq "blazeserve-$tag-$target.zip") {
                        $expected = $hash
                        $name = $file
                        break
                    }
                } elseif ($file -like "blazeserve-v*-$target.zip") {
                    $expected = $hash
                    $name = $file
                    break
                }
            }
        }
        if (-not $expected -or -not $name) {
            throw 'No Windows build in this release.'
        }

        $zip = Join-Path $tmp $name
        Get-ReleaseAsset -Uri "$base/$name" -OutFile $zip
        $actual = Get-Sha256Hex -LiteralPath $zip
        if ($actual -ne $expected) {
            throw 'The download does not match its checksum; nothing was installed.'
        }

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $extractRoot = Join-Path $tmp 'extracted'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $extractRoot)
        $extractedDir = Join-Path $extractRoot ($name -replace '\.zip$', '')
        $exeSrc = Join-Path $extractedDir 'blaze.exe'
        if (-not (Test-Path -LiteralPath $exeSrc -PathType Leaf)) {
            throw "Archive $name does not contain blaze.exe."
        }

        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
        $exeDst = Join-Path $Dir 'blaze.exe'
        $exeNew = Join-Path $Dir 'blaze.new.exe'
        try {
            Copy-Item -Force -LiteralPath $exeSrc -Destination $exeNew
            Unblock-File -LiteralPath $exeNew
            $version = & $exeNew --version
            if ($LASTEXITCODE -ne 0) {
                throw 'The downloaded blaze.exe does not run on this system; nothing was installed.'
            }
            try {
                Move-Item -Force -LiteralPath $exeNew -Destination $exeDst
            } catch {
                throw "Cannot replace $exeDst. Stop any running blaze and run the installer again. $_"
            }
        } finally {
            if (Test-Path -LiteralPath $exeNew) { Remove-Item -Force -LiteralPath $exeNew }
        }

        $userPath = @(Get-UserPath)
        if (-not ($userPath | Where-Object { Test-SameDir $_ $Dir })) {
            Set-UserPath ($userPath + $Dir)
            $env:Path = "$env:Path;$Dir"
        }

        Write-Host "$version installed in $Dir"
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

$installDir = Get-InstallDir
if ($env:BLAZE_UNINSTALL) {
    Uninstall-BlazeServe -Dir $installDir
} else {
    Install-BlazeServe -Dir $installDir
}
}
