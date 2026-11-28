[CmdletBinding()] param()
$ErrorActionPreference='Stop'
& "$PSScriptRoot/Connect-ThreeVMs.ps1"
foreach ($pair in @(@('suricata-vm1','vm1-status.sh'),@('suricata-vm2','vm2-status.sh'),@('suricata-vm3','vm3-status.sh'))) {
    Write-Host "--- $($pair[0]) ---"
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $pair[0] "`$HOME/suricata-ai-showcase/current/scripts/demo/$($pair[1])"
    if ($LASTEXITCODE -ne 0) { throw "Status failed for $($pair[0])" }
}
