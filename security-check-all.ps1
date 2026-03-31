#requires -Version 5.1
<#
  Script unique de verification "post-incident" pour Windows.
  Objectif: reproduire automatiquement les controles effectues dans cette session.

  Ce script:
  1) verifie Node/npm et peut mettre npm a jour
  2) lance le scan Python axios1.py sur un dossier racine
  3) controle des IoC Windows simples (%PROGRAMDATA%\wt.exe, startup, Run keys)
  4) lance un Quick Scan Microsoft Defender (optionnel)
  5) produit un rapport texte + JSON, facile a versionner dans Git
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RootPath = $env:USERPROFILE,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ".\reports",

    [Parameter(Mandatory = $false)]
    [switch]$UpdateNpm,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDefender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ("`n=== {0} ===" -f $Message) -ForegroundColor Cyan
}

function Test-CommandExists {
    param([string]$CommandName)
    return [bool](Get-Command $CommandName -ErrorAction SilentlyContinue)
}

function Invoke-SafeCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $PWD.Path
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $quotedArgs = @()
    foreach ($arg in $Arguments) {
        if ($arg -match '\s') {
            $quotedArgs += ('"{0}"' -f ($arg -replace '"', '\"'))
        } else {
            $quotedArgs += $arg
        }
    }
    $psi.Arguments = ($quotedArgs -join " ")

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

function Get-RunKeys {
    $items = @()
    $paths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    continue
                }
                $items += [pscustomobject]@{
                    RegistryPath = $path
                    Name         = $p.Name
                    Value        = [string]$p.Value
                }
            }
        }
    }
    return $items
}

function Get-StartupEntries {
    $entries = @()
    $startupFolders = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup")
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $entries += Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    Folder = $folder
                    Name   = $_.Name
                    FullName = $_.FullName
                }
            }
        }
    }
    return $entries
}

function Get-SuspiciousMatches {
    param([object[]]$Items)
    $pattern = "(wt\.exe|ld\.py|plain-crypto-js|axios)"
    return $Items | Where-Object {
        ($_ | Out-String) -match $pattern
    }
}

function Get-DefenderSummary {
    try {
        $status = Get-MpComputerStatus
        $threats = @(Get-MpThreatDetection)
        return [pscustomobject]@{
            Available                  = $true
            AntivirusEnabled           = [bool]$status.AntivirusEnabled
            RealTimeProtectionEnabled  = [bool]$status.RealTimeProtectionEnabled
            QuickScanStartTime         = $status.QuickScanStartTime
            QuickScanEndTime           = $status.QuickScanEndTime
            ThreatCount                = $threats.Count
            Threats                    = $threats | Select-Object ThreatName, SeverityID, InitialDetectionTime, Resources
        }
    } catch {
        return [pscustomobject]@{
            Available = $false
            Error     = $_.Exception.Message
        }
    }
}

if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$txtReportPath = Join-Path $OutputDir ("security-report-{0}.txt" -f $timestamp)
$jsonReportPath = Join-Path $OutputDir ("security-report-{0}.json" -f $timestamp)

$report = [ordered]@{
    Metadata = [ordered]@{
        GeneratedAt = (Get-Date).ToString("o")
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        RootPath = $RootPath
    }
    NodeNpm = $null
    AxiosScan = $null
    WindowsIoC = $null
    Defender = $null
    DefenderAssessment = $null
    FinalVerdict = $null
}

Write-Step "Verification Node/npm"
$hasNode = Test-CommandExists -CommandName "node"
$hasNpm = (Test-CommandExists -CommandName "npm") -or (Test-CommandExists -CommandName "npm.cmd")

$nodeVersion = if ($hasNode) { (& node -v) } else { "absent" }
$npmVersionBefore = if ($hasNpm) { (& npm -v) } else { "absent" }
$npmVersionAfter = $npmVersionBefore
$npmUpdateOutput = ""

if ($UpdateNpm -and $hasNpm) {
    Write-Step "Mise a jour npm"
    try {
        $updateResult = Invoke-SafeCommand -FilePath "npm" -Arguments @("install", "-g", "npm@latest")
        $npmUpdateOutput = ($updateResult.StdOut + "`n" + $updateResult.StdErr).Trim()
        $npmVersionAfter = (& npm -v)
    } catch {
        $npmUpdateOutput = "Erreur mise a jour npm: $($_.Exception.Message)"
    }
}

$report.NodeNpm = [ordered]@{
    NodeInstalled = $hasNode
    NpmInstalled = $hasNpm
    NodeVersion = $nodeVersion
    NpmVersionBefore = $npmVersionBefore
    NpmVersionAfter = $npmVersionAfter
    NpmUpdateOutput = $npmUpdateOutput
}

Write-Step "Scan Axios supply-chain"
$axiosScriptPath = Join-Path $PSScriptRoot "axios1.py"
if (-not (Test-Path $axiosScriptPath)) {
    throw "Impossible de trouver axios1.py a cote du script: $axiosScriptPath"
}

$pythonCandidates = @("python", "py")
$pythonCmd = $null
foreach ($candidate in $pythonCandidates) {
    if (Test-CommandExists -CommandName $candidate) {
        $pythonCmd = $candidate
        break
    }
}
if (-not $pythonCmd) {
    throw "Python introuvable dans le PATH."
}

$axiosResult = Invoke-SafeCommand -FilePath $pythonCmd -Arguments @($axiosScriptPath, "--root", $RootPath, "--json")
$axiosJson = $null
try {
    $axiosJson = $axiosResult.StdOut | ConvertFrom-Json -ErrorAction Stop
} catch {
    $axiosJson = [pscustomobject]@{
        parseError = "Impossible de parser la sortie JSON de axios1.py"
        rawStdOut = $axiosResult.StdOut
        rawStdErr = $axiosResult.StdErr
    }
}

$report.AxiosScan = [ordered]@{
    ExitCode = $axiosResult.ExitCode
    Parsed = $axiosJson
}

Write-Step "Controle IoC Windows"
$wtPath = Join-Path $env:ProgramData "wt.exe"
$runKeys = Get-RunKeys
$startupEntries = Get-StartupEntries
$suspiciousRunKeys = Get-SuspiciousMatches -Items $runKeys
$suspiciousStartup = Get-SuspiciousMatches -Items $startupEntries

$report.WindowsIoC = [ordered]@{
    ProgramDataWtExists = (Test-Path $wtPath)
    ProgramDataWtPath = $wtPath
    SuspiciousRunKeys = $suspiciousRunKeys
    SuspiciousStartupEntries = $suspiciousStartup
}

if (-not $SkipDefender) {
    Write-Step "Quick Scan Microsoft Defender"
    try {
        Start-MpScan -ScanType QuickScan
    } catch {
        # On n'interrompt pas l'analyse si le scan ne demarre pas.
    }
}

$report.Defender = Get-DefenderSummary

# Verdict simple: tout indicateur fort doit declencher une alerte
$hasAxiosSuspicion = $false
if ($report.AxiosScan.Parsed -and $report.AxiosScan.Parsed.projects) {
    foreach ($project in $report.AxiosScan.Parsed.projects) {
        if ($project.compromised_versions_found.Count -gt 0 -or $project.plain_crypto_js_found -eq $true) {
            $hasAxiosSuspicion = $true
            break
        }
    }
}
$hasWindowsIoC = [bool]$report.WindowsIoC.ProgramDataWtExists
$hasDefenderThreat = $false
if ($report.Defender -and $report.Defender.Available -eq $true) {
    $hasDefenderThreat = ([int]$report.Defender.ThreatCount -gt 0)
}

# Le verdict principal ne couvre que les IoC Axios/Windows actuels.
$overallSafe = -not ($hasAxiosSuspicion -or $hasWindowsIoC)
$report.DefenderAssessment = [ordered]@{
    HasThreatHistory = $hasDefenderThreat
    Message = if ($hasDefenderThreat) {
        "Des detections Defender existent dans l'historique; a traiter separablement des IoC Axios/Windows."
    } else {
        "Aucune detection Defender dans l'historique."
    }
}
$report.FinalVerdict = [ordered]@{
    Safe = $overallSafe
    HasAxiosSuspicion = $hasAxiosSuspicion
    HasWindowsIoC = $hasWindowsIoC
    HasDefenderThreat = $hasDefenderThreat
    Message = if ($overallSafe) {
        "Aucun indicateur direct Axios/Windows detecte."
    } else {
        "Indicateur(s) Axios/Windows detecte(s). Isoler la machine et lancer une reponse a incident."
    }
}

$jsonText = $report | ConvertTo-Json -Depth 8
$jsonText | Set-Content -Path $jsonReportPath -Encoding UTF8

$txt = @()
$txt += "Security check report"
$txt += "Generated at: $($report.Metadata.GeneratedAt)"
$txt += "Computer: $($report.Metadata.ComputerName)"
$txt += "User: $($report.Metadata.UserName)"
$txt += "RootPath: $($report.Metadata.RootPath)"
$txt += ""
$txt += "Node/npm:"
$txt += " - Node: $($report.NodeNpm.NodeVersion)"
$txt += " - npm before: $($report.NodeNpm.NpmVersionBefore)"
$txt += " - npm after:  $($report.NodeNpm.NpmVersionAfter)"
$txt += ""
$txt += "Final verdict: $($report.FinalVerdict.Message)"
$txt += "Flags: AxiosSuspicion=$($report.FinalVerdict.HasAxiosSuspicion), WindowsIoC=$($report.FinalVerdict.HasWindowsIoC)"
$txt += "Defender history: HasThreatHistory=$($report.DefenderAssessment.HasThreatHistory)"
$txt += "Defender note: $($report.DefenderAssessment.Message)"
$txt += ""
$txt += "JSON report: $jsonReportPath"
$txt -join "`r`n" | Set-Content -Path $txtReportPath -Encoding UTF8

Write-Step "Rapport genere"
Write-Host "TXT  : $txtReportPath"
Write-Host "JSON : $jsonReportPath"
Write-Host ""
Write-Host $report.FinalVerdict.Message -ForegroundColor $(if ($overallSafe) { "Green" } else { "Yellow" })

if (-not $overallSafe) {
    exit 2
}
exit 0
