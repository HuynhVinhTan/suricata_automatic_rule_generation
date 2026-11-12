[CmdletBinding()] param([string]$LogPath=(Join-Path ([IO.Path]::GetTempPath()) 'suricata-showcase-eve-relay.log'))
$ErrorActionPreference='Stop'
& "$PSScriptRoot/Connect-ThreeVMs.ps1"
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 "mkdir -p /home/tanhv/suricata-ai-showcase/runtime /home/tanhv/suricata-ai-showcase/eve-shadow"
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare VM3 relay sink.' }
$command="ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm1 'tail -F -n 0 /var/log/suricata/eve.json' | ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 '/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-relay-sink.py --root /home/tanhv/suricata-ai-showcase/eve-shadow'"
$proc=Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$command) -RedirectStandardError $LogPath -PassThru
Write-Host "Relay PID=$($proc.Id)"; Write-Host "Relay log=$LogPath"; Write-Host 'Source is read-only VM1 EVE; sink is bounded VM3 showcase storage.'
