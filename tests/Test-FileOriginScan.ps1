#Requires -Version 5.1
<#
.SYNOPSIS
    Integration tests for FileOriginScan.ps1.

.DESCRIPTION
    Black-box tests. The script builds a throwaway folder tree plus a temporary
    uninstall-registry entry, runs the tool the same way a user would, then
    asserts on the JSON / HTML / CSV it produced.

    Written in ASCII only so it behaves identically under Windows PowerShell 5.1
    and PowerShell 7, regardless of console code page.

.EXAMPLE
    ./tests/Test-FileOriginScan.ps1

.EXAMPLE
    ./tests/Test-FileOriginScan.ps1 -KeepTemp
#>
[CmdletBinding()]
param(
    [string]$ToolPath,
    [switch]$KeepTemp
)

$ErrorActionPreference = 'Stop'

$script:Pass = 0
$script:Fail = 0
$script:Skipped = 0

# U+9AD8 "high" - the tool's top confidence label. Kept as a code point so this
# file stays ASCII-only and survives any encoding round trip.
$HighConfidence = [string][char]0x9AD8

function Write-Check {
    param([bool]$Ok, [string]$Name, [string]$Detail)
    if ($Ok) {
        $script:Pass++
        Write-Host ('  [PASS] ' + $Name) -ForegroundColor Green
    } else {
        $script:Fail++
        Write-Host ('  [FAIL] ' + $Name) -ForegroundColor Red
        if ($Detail) { Write-Host ('         ' + $Detail) -ForegroundColor DarkYellow }
    }
}

function Test-Equal {
    param($Expected, $Actual, [string]$Name)
    $ok = ($Expected -eq $Actual)
    $detail = ''
    if (-not $ok) { $detail = 'expected [' + $Expected + '] but got [' + $Actual + ']' }
    Write-Check -Ok $ok -Name $Name -Detail $detail
}

function Test-Skip {
    param([string]$Name, [string]$Reason)
    $script:Skipped++
    Write-Host ('  [SKIP] ' + $Name + ' (' + $Reason + ')') -ForegroundColor DarkGray
}

function New-DummyFile {
    param([string]$Path, [int]$Size = 1024, [int]$Seed = 42)
    $bytes = New-Object byte[] $Size
    (New-Object System.Random $Seed).NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function New-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    return $Path
}

function Get-Json {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# ---------------------------------------------------------------- setup

if ([string]::IsNullOrWhiteSpace($ToolPath)) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $ToolPath = Join-Path $repoRoot 'FileOriginScan.ps1'
}
if (-not (Test-Path -LiteralPath $ToolPath)) {
    Write-Host ('Tool not found: ' + $ToolPath) -ForegroundColor Red
    exit 1
}
$ToolPath = (Resolve-Path -LiteralPath $ToolPath).ProviderPath
$PowerShellExe = (Get-Process -Id $PID).Path

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('file-origin-scan-test-' + [guid]::NewGuid().ToString('N'))
$fixture = New-Dir (Join-Path $tempRoot 'loose')
$appDir = New-Dir (Join-Path $tempRoot 'app')
$nestedDir = New-Dir (Join-Path $fixture 'nested\deeper')
$emptyDir = New-Dir (Join-Path $tempRoot 'empty')
$outDir = New-Dir (Join-Path $tempRoot 'reports')
$regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FileOriginScanSelfTest'

function Invoke-Tool {
    param([string[]]$ToolArgs)
    $raw = & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $ToolPath @ToolArgs 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = (($raw | Out-String).Trim())
    }
}

Write-Host ''
Write-Host 'FileOriginScan integration tests' -ForegroundColor Cyan
Write-Host ('  tool      : ' + $ToolPath)
Write-Host ('  powershell: ' + $PowerShellExe)
Write-Host ('  temp      : ' + $tempRoot)
Write-Host ''

try {
    # ---- fixture: loose junk of every category
    New-DummyFile -Path (Join-Path $fixture 'vcruntime140.dll') -Size 2048 -Seed 1
    New-DummyFile -Path (Join-Path $fixture 'mystery.dll') -Size 2048 -Seed 2
    New-DummyFile -Path (Join-Path $fixture 'pagefile.sys') -Size 512 -Seed 3
    Set-Content -LiteralPath (Join-Path $fixture 'notes.txt') -Value 'personal notes' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $nestedDir 'deep.txt') -Value 'nested' -Encoding UTF8

    # ---- fixture: files living inside a registered install location
    New-DummyFile -Path (Join-Path $appDir 'main.exe') -Size 4096 -Seed 4
    New-DummyFile -Path (Join-Path $appDir 'core.dll') -Size 4096 -Seed 5

    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name DisplayName -Value 'File Origin Scan Self Test'
    Set-ItemProperty -Path $regPath -Name DisplayVersion -Value '1.0.0'
    Set-ItemProperty -Path $regPath -Name Publisher -Value 'File Origin Scan Test Publisher'
    Set-ItemProperty -Path $regPath -Name InstallLocation -Value $appDir

    # ---- run 1: the main path, loose directory
    $report1 = Join-Path $outDir 'loose.html'
    $run1 = Invoke-Tool -ToolArgs @('-Path', $fixture, '-OutFile', $report1, '-Quiet')
    Test-Equal 0 $run1.ExitCode 'loose scan exits with code 0'
    Write-Host ('         ' + $run1.Output) -ForegroundColor DarkGray

    $jsonPath1 = [System.IO.Path]::ChangeExtension($report1, '.json')
    $csvPath1 = [System.IO.Path]::ChangeExtension($report1, '.csv')
    Test-Equal $true (Test-Path -LiteralPath $jsonPath1) 'JSON report written'
    Test-Equal $true (Test-Path -LiteralPath $csvPath1) 'CSV report written'
    Test-Equal $true (Test-Path -LiteralPath $report1) 'HTML report written'

    if (Test-Path -LiteralPath $jsonPath1) {
        $doc = Get-Json -Path $jsonPath1
        $byName = @{}
        foreach ($f in $doc.Files) { $byName[$f.Name] = $f }

        Test-Equal 4 $doc.FileCount 'loose scan sees exactly the 4 top-level files'
        Test-Equal 'Component' $byName['vcruntime140.dll'].Kind 'vcruntime140.dll hits the known-component table'
        Test-Equal 'System' $byName['pagefile.sys'].Kind 'pagefile.sys is flagged as a Windows system file'
        Test-Equal 'Suspicious' $byName['mystery.dll'].Kind 'unsigned binary without version info is flagged as unknown origin'
        Test-Equal 'Unknown' $byName['notes.txt'].Kind 'plain text file stays unattributed'

        $appJson = Join-Path $outDir 'app.json'
        $run2 = Invoke-Tool -ToolArgs @('-Path', $appDir, '-OutFile', (Join-Path $outDir 'app.html'), '-Quiet')
        Test-Equal 0 $run2.ExitCode 'install-location scan exits with code 0'
        $appDoc = Get-Json -Path $appJson
        $appByName = @{}
        foreach ($f in $appDoc.Files) { $appByName[$f.Name] = $f }
        Test-Equal 'App' $appByName['main.exe'].Kind 'file inside a registered install location is attributed to the app'
        Test-Equal $HighConfidence $appByName['main.exe'].Confidence 'install-location match reports the top confidence'
        Test-Equal 'File Origin Scan Self Test' $appByName['main.exe'].Product 'attributed product name comes from the uninstall registry'

        $csvLines = @(Get-Content -LiteralPath $csvPath1 -Encoding UTF8)
        Test-Equal 5 $csvLines.Count 'CSV has a header row plus one row per file'

        $html = Get-Content -LiteralPath $report1 -Raw -Encoding UTF8
        Test-Equal $true ($html.Contains('</html>')) 'HTML report is complete'
        Test-Equal $true ($html.Contains((Split-Path -Leaf $fixture))) 'HTML report mentions the scanned folder'

        # ---- run 3: recursion is off by default and on with -Recurse
        $recurseOut = Join-Path $outDir 'recurse.html'
        Invoke-Tool -ToolArgs @('-Path', $fixture, '-OutFile', $recurseOut, '-Quiet') | Out-Null
        $flatDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($recurseOut, '.json'))
        $flatNames = @($flatDoc.Files | ForEach-Object { $_.Name })
        Test-Equal $false ($flatNames -contains 'deep.txt') 'nested file is ignored without -Recurse'

        Invoke-Tool -ToolArgs @('-Path', $fixture, '-Recurse', '-OutFile', $recurseOut, '-Quiet') | Out-Null
        $deepDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($recurseOut, '.json'))
        $deepNames = @($deepDoc.Files | ForEach-Object { $_.Name })
        Test-Equal $true ($deepNames -contains 'deep.txt') 'nested file is found with -Recurse'

        # ---- run 4: -MaxFiles caps the work and says so
        $capDir = New-Dir (Join-Path $tempRoot 'many')
        1..5 | ForEach-Object { Set-Content -LiteralPath (Join-Path $capDir ('file' + $_ + '.txt')) -Value 'x' -Encoding UTF8 }
        $capOut = Join-Path $outDir 'cap.html'
        Invoke-Tool -ToolArgs @('-Path', $capDir, '-MaxFiles', '2', '-OutFile', $capOut, '-Quiet') | Out-Null
        $capDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($capOut, '.json'))
        Test-Equal 2 $capDoc.FileCount '-MaxFiles limits the number of analysed files'

        # ---- run 5: -SkipSignature turns signature checking off cleanly
        $skipOut = Join-Path $outDir 'nosig.html'
        Invoke-Tool -ToolArgs @('-Path', $appDir, '-SkipSignature', '-OutFile', $skipOut, '-Quiet') | Out-Null
        $skipDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($skipOut, '.json'))
        Test-Equal $false $skipDoc.Signed '-SkipSignature is reported in the JSON payload'

        # ---- run 6: empty folder is a normal, non-fatal outcome
        $emptyOut = Join-Path $outDir 'empty.html'
        $run6 = Invoke-Tool -ToolArgs @('-Path', $emptyDir, '-OutFile', $emptyOut, '-Quiet')
        Test-Equal 0 $run6.ExitCode 'empty folder still exits with code 0'
        $emptyDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($emptyOut, '.json'))
        Test-Equal 0 $emptyDoc.FileCount 'empty folder reports zero files'
    }

    # ---- PE architecture detection against a real system binary
    $peSource = Join-Path $env:SystemRoot 'System32\notepad.exe'
    if (Test-Path -LiteralPath $peSource) {
        $peDir = New-Dir (Join-Path $tempRoot 'pe')
        Copy-Item -LiteralPath $peSource -Destination (Join-Path $peDir 'notepad.exe') -Force
        $peOut = Join-Path $outDir 'pe.html'
        Invoke-Tool -ToolArgs @('-Path', $peDir, '-OutFile', $peOut, '-Quiet') | Out-Null
        $peDoc = Get-Json -Path ([System.IO.Path]::ChangeExtension($peOut, '.json'))
        $expectedArch = 'x86'
        if ([Environment]::Is64BitOperatingSystem) { $expectedArch = 'x64' }
        Test-Equal $expectedArch $peDoc.Files[0].Arch 'PE header reveals the real architecture'
    } else {
        Test-Skip 'PE header reveals the real architecture' 'notepad.exe not available on this system'
    }
} finally {
    if (Test-Path -LiteralPath $regPath) {
        Remove-Item -LiteralPath $regPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($KeepTemp) {
        Write-Host ('Temp kept: ' + $tempRoot) -ForegroundColor DarkGray
    } elseif (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ('Result: ' + $script:Pass + ' passed, ' + $script:Fail + ' failed, ' + $script:Skipped + ' skipped') -ForegroundColor Cyan
if ($script:Fail -gt 0) { exit 1 }
exit 0
