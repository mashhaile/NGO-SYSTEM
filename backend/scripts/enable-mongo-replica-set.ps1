# =====================================================
# ENABLE MONGODB REPLICA SET (local Windows service)
# =====================================================
#
# Turns the local standalone MongoDB service into a
# single-node replica set so the backend can use
# transactions. Existing data is kept.
#
# Run ONCE in PowerShell **as Administrator**, from the
# backend folder:
#
#     powershell -ExecutionPolicy Bypass -File scripts\enable-mongo-replica-set.ps1
#
# What it does:
#   1. Backs up mongod.cfg (mongod.cfg.bak-<timestamp>)
#   2. Adds  replication: replSetName: rs0
#   3. Restarts the MongoDB service
#   4. Runs scripts/initReplicaSet.js (rs.initiate)
#
# Undo: restore the .bak file and restart the service.
# =====================================================

param(
    [string]$ConfigPath = "C:\Program Files\MongoDB\Server\8.3\bin\mongod.cfg",
    [string]$ServiceName = "MongoDB",
    [string]$ReplSetName = "rs0"
)

$ErrorActionPreference = "Stop"


# ---- Administrator check ----------------------------

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script in PowerShell as Administrator."
}

if (-not (Test-Path $ConfigPath)) {
    Write-Error "mongod.cfg not found at $ConfigPath. Pass -ConfigPath."
}


# ---- 1. Backup + 2. Edit config ---------------------

$config = Get-Content $ConfigPath -Raw

if ($config -match "(?m)^\s*replSetName\s*:") {

    Write-Host "replication.replSetName is already set in mongod.cfg."

}
else {

    $backup = "$ConfigPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"

    Copy-Item $ConfigPath $backup

    Write-Host "Backed up config to $backup"

    if ($config -match "(?m)^#replication:[ \t]*\r?$") {
        $config = $config -replace "(?m)^#replication:[ \t]*\r?$", "replication:`r`n  replSetName: $ReplSetName`r"
    }
    else {
        $config = $config.TrimEnd() + "`r`n`r`nreplication:`r`n  replSetName: $ReplSetName`r`n"
    }

    Set-Content -Path $ConfigPath -Value $config -Encoding ascii

    Write-Host "Added replication.replSetName: $ReplSetName"

}


# ---- 3. Restart service -----------------------------

Write-Host "Restarting $ServiceName service..."

Restart-Service -Name $ServiceName -Force

(Get-Service -Name $ServiceName).WaitForStatus("Running", "00:00:30")


# ---- 4. Initiate replica set ------------------------

$backendDir = Split-Path -Parent $PSScriptRoot

Push-Location $backendDir

try {
    node scripts/initReplicaSet.js $ReplSetName "127.0.0.1:27017"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "initReplicaSet.js failed. Config backup is next to mongod.cfg."
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Done. Restart the backend (npm start / nodemon) so it detects transactions."
