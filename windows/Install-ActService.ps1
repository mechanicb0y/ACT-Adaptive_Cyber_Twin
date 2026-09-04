<#
.SYNOPSIS
    Install / uninstall ACT as a Windows service (via NSSM) or a Scheduled Task.

.DESCRIPTION
    Windows has no systemd. Two supported options:

      -Method NSSM   (recommended) wraps `python -m app.main --mode service` in a
                     real Windows service with automatic restart. Requires NSSM
                     (https://nssm.cc, or `winget install NSSM.NSSM`).

      -Method Task   registers a Scheduled Task that runs at boot as SYSTEM and
                     restarts on failure. No extra software.

    Config is read from backend\.env as usual. Set at least ACT_JWT_SECRET and
    DATABASE_URL there.

.EXAMPLE
    # from the repo root, in an elevated PowerShell
    .\windows\Install-ActService.ps1 -Method NSSM
    .\windows\Install-ActService.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [ValidateSet("NSSM", "Task")] [string] $Method = "NSSM",
    [string] $ServiceName = "ACT",
    [string] $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [switch] $Uninstall
)

$ErrorActionPreference = "Stop"
$backend = Join-Path $RepoRoot "backend"
$venvPy  = Join-Path $backend ".venv\Scripts\python.exe"
$python  = if (Test-Path $venvPy) { $venvPy } else { (Get-Command python).Source }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this in an elevated PowerShell (Administrator)."
    }
}
Assert-Admin

if ($Uninstall) {
    Write-Host "Removing $ServiceName ..."
    if (Get-Command nssm -ErrorAction SilentlyContinue) {
        & nssm stop $ServiceName 2>$null; & nssm remove $ServiceName confirm 2>$null
    }
    sc.exe delete $ServiceName 2>$null | Out-Null
    schtasks /Delete /TN $ServiceName /F 2>$null | Out-Null
    Write-Host "Done."
    return
}

if ($Method -eq "NSSM") {
    if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
        throw "NSSM not found. Install it (winget install NSSM.NSSM) or use -Method Task."
    }
    & nssm install $ServiceName $python "-m" "app.main" "--mode" "service"
    & nssm set $ServiceName AppDirectory $backend
    & nssm set $ServiceName AppStdout (Join-Path $backend "logs\service.out.log")
    & nssm set $ServiceName AppStderr (Join-Path $backend "logs\service.err.log")
    & nssm set $ServiceName AppRotateFiles 1
    & nssm set $ServiceName AppRotateBytes 10485760
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm set $ServiceName AppExit Default Restart
    & nssm set $ServiceName AppRestartDelay 3000
    & nssm set $ServiceName AppEnvironmentExtra "ACT_LOG_FORMAT=json"
    & nssm start $ServiceName
    Write-Host "Service '$ServiceName' installed and started. Logs: $backend\logs\"
}
else {
    $action  = New-ScheduledTaskAction -Execute $python `
        -Argument "-m app.main --mode service" -WorkingDirectory $backend
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force
    Start-ScheduledTask -TaskName $ServiceName
    Write-Host "Scheduled task '$ServiceName' registered (runs at boot as SYSTEM)."
}
