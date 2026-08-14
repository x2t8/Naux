param(
    [Parameter(Mandatory = $true)]
    [string]$Archive,
    [Parameter(Mandatory = $true)]
    [string]$Checksum,
    [Parameter(Mandatory = $false)]
    [string]$Bootstrap
)

$ErrorActionPreference = "Stop"
$archivePath = (Resolve-Path $Archive).Path
$checksumPath = (Resolve-Path $Checksum).Path
$bootstrapPath = if ($Bootstrap) { (Resolve-Path $Bootstrap).Path } else { $null }
$archiveName = [System.IO.Path]::GetFileName($archivePath)

if ($archiveName -notmatch '^naux-learn-([0-9]+\.[0-9]+\.[0-9]+)-windows-x86_64-gnu\.zip$') {
    throw "noncanonical NAUX Windows archive name"
}
$version = $Matches[1]
$line = [System.IO.File]::ReadAllText($checksumPath)
$expectedLine = $line.TrimEnd("`r", "`n")
if ($line -ne "$expectedLine`n" -or
    $expectedLine -notmatch '^([0-9a-f]{64})  ([^\\/]+\.zip)$' -or
    $Matches[2] -ne $archiveName) {
    throw "noncanonical NAUX Windows checksum file"
}
$expectedHash = $Matches[1]
$actualHash = (Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "NAUX Windows archive checksum mismatch"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("naux-s1-windows-runtime-" + [guid]::NewGuid())
$extract = Join-Path $tempRoot "extract"
$prefix = Join-Path $tempRoot "installed"
$state = Join-Path $tempRoot "state"
try {
    New-Item -ItemType Directory -Path $extract | Out-Null
    New-Item -ItemType Directory -Path $state | Out-Null

    if ($bootstrapPath) {
        $parseTokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $bootstrapPath,
            [ref]$parseTokens,
            [ref]$parseErrors
        ) | Out-Null
        if (@($parseErrors).Count -ne 0) {
            throw "Windows bootstrap parser gate failed: $($parseErrors[0].Message)"
        }

        $releaseDirectory = Split-Path -Parent $archivePath
        function Invoke-WebRequest {
            param(
                [switch]$UseBasicParsing,
                [Parameter(Mandatory = $true)]
                [string]$Uri,
                [Parameter(Mandatory = $true)]
                [string]$OutFile
            )
            $requestUri = [uri]$Uri
            $asset = [System.IO.Path]::GetFileName($requestUri.AbsolutePath)
            if ($asset -notin @($archiveName, "$archiveName.sha256")) {
                throw "bootstrap requested an unexpected release asset: $asset"
            }
            $expectedPathPrefix = "/x2t8/Naux/releases/download/v$version-learn/"
            if ($requestUri.Host -cne 'github.com' -or
                -not $requestUri.AbsolutePath.StartsWith(
                    $expectedPathPrefix,
                    [System.StringComparison]::Ordinal
                )) {
                throw "bootstrap requested an unpinned release URL: $Uri"
            }
            Copy-Item -LiteralPath (Join-Path $releaseDirectory $asset) -Destination $OutFile
        }

        $savedLocalAppData = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path $tempRoot 'bootstrap-local-app-data'
        $env:NAUX_LEARN_INSTALL_YES = '1'
        $env:NAUX_LEARN_INSTALL_LANGUAGE = 'en-US'
        try {
            & $bootstrapPath | Out-Null
            $bootstrapInstalled = Join-Path $env:LOCALAPPDATA (
                "Programs\NAUX\Learn\$version\bin\naux.exe"
            )
            if (-not (Test-Path -LiteralPath $bootstrapInstalled -PathType Leaf)) {
                throw 'Windows bootstrap did not publish the expected installed executable'
            }
            $bootstrapVersion = (& $bootstrapInstalled --version | Out-String).TrimEnd("`r", "`n")
            if ($LASTEXITCODE -ne 0 -or $bootstrapVersion -ne "naux $version") {
                throw 'Windows bootstrap installed executable version mismatch'
            }
        }
        finally {
            $env:LOCALAPPDATA = $savedLocalAppData
            Remove-Item Env:NAUX_LEARN_INSTALL_YES -ErrorAction SilentlyContinue
            Remove-Item Env:NAUX_LEARN_INSTALL_LANGUAGE -ErrorAction SilentlyContinue
            Remove-Item Function:Invoke-WebRequest -ErrorAction SilentlyContinue
        }
        Write-Output "S1 Windows pinned-bootstrap install: PASS"
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $extract
    $bundle = Join-Path $extract "naux-learn-$version-windows-x86_64-gnu"
    $binary = Join-Path $bundle "bin\naux.exe"
    $setup = Join-Path $bundle "NAUX-Learn-Setup.exe"
    $brand = Join-Path $bundle "assets\langnaux-learn.png"
    $brandRow = Get-Content (Join-Path $bundle "BUILD-SEED.tsv") |
        Where-Object { $_ -like "brand-source-sha256`t*" }
    if (@($brandRow).Count -ne 1) { throw "Windows brand seed is noncanonical" }
    $expectedBrandHash = ($brandRow -split "`t", 2)[1]
    $actualBrandHash = (Get-FileHash $brand -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualBrandHash -ne $expectedBrandHash) {
        throw "Windows bundle logo identity mismatch"
    }
    $versionOutput = (& $binary --version | Out-String).TrimEnd("`r", "`n")
    if ($LASTEXITCODE -ne 0 -or $versionOutput -ne "naux $version") {
        throw "naux.exe version gate failed"
    }
    & $binary bundle verify $bundle | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows bundle verification failed" }
    $localeGate = @(& $binary welcome --validate-locales)
    if ($LASTEXITCODE -ne 0 -or $localeGate.Count -ne 2 -or
        $localeGate[0] -ne "NAUX installer locales: verified" -or
        $localeGate[1] -ne "catalogs: 9") {
        throw "Windows localized-disclosure catalog gate failed"
    }

    $savedPath = $env:PATH
    $env:PATH = "$env:SystemRoot\System32"
    try {
        & $setup --yes --language vi-VN --prefix $prefix --state-directory $state | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Windows native Setup installation failed" }
        $receipts = @(Get-ChildItem -LiteralPath $state -File -Filter "*.tsv")
        if ($receipts.Count -ne 1) { throw "Windows lifecycle receipt inventory mismatch" }
        $installed = Join-Path $prefix "bin\naux.exe"
        $installedBrand = Join-Path $prefix "assets\langnaux-learn.png"
        $installedBrandHash = (Get-FileHash $installedBrand -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($installedBrandHash -ne $expectedBrandHash) {
            throw "Windows installed logo identity mismatch"
        }
        & $installed installation uninstall --receipt $receipts[0].FullName --dry-run | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Windows lifecycle uninstall dry-run failed" }
        $program = Join-Path $prefix "examples\hello.nx"
        $actualOutput = Join-Path $tempRoot "hello.actual"
        $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $processInfo.FileName = $installed
        $processInfo.ArgumentList.Add("run")
        $processInfo.ArgumentList.Add($program)
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($processInfo)
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "Windows first program failed: $stderr" }
        [System.IO.File]::WriteAllText(
            $actualOutput,
            $stdout,
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    finally {
        $env:PATH = $savedPath
    }
    $expectedBytes = [System.IO.File]::ReadAllBytes((Join-Path $prefix "examples\hello.out"))
    $actualBytes = [System.IO.File]::ReadAllBytes($actualOutput)
    if (-not [System.Linq.Enumerable]::SequenceEqual($expectedBytes, $actualBytes)) {
        throw "Windows first-program output mismatch"
    }
    Write-Output "S1 Windows real-host version/verify/install/run: PASS"
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
