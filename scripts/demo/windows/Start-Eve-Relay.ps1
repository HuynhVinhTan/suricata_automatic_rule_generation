[CmdletBinding()]
param(
    [string]$LogPath=(Join-Path ([IO.Path]::GetTempPath()) 'suricata-showcase-eve-relay.log'),
    [string]$RelayPidPath=(Join-Path ([IO.Path]::GetTempPath()) 'suricata-showcase-eve-relay.pid'),
    [string]$SinkRoot='/home/tanhv/suricata-ai-showcase/eve-shadow'
)
$ErrorActionPreference='Stop'
& "$PSScriptRoot/Connect-ThreeVMs.ps1"
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 "mkdir -p /home/tanhv/suricata-ai-showcase/runtime '$SinkRoot'"
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare VM3 relay sink.' }
$relay=Join-Path $PSScriptRoot 'Eve-Relay.cmd'
$proc=Start-Process cmd.exe -ArgumentList @('/d','/c',$relay,$SinkRoot) -RedirectStandardError $LogPath -PassThru
Set-Content -LiteralPath $RelayPidPath -Value $proc.Id -NoNewline
Write-Host "Relay PID=$($proc.Id)"
Write-Host "Relay PID file=$RelayPidPath"
Write-Host "Relay log=$LogPath"
Write-Host 'Source is read-only VM1 EVE; sink is bounded VM3 showcase storage.'
