[CmdletBinding()]
param([switch]$OpenTerminals)
$ErrorActionPreference = 'Stop'
$aliases = @('suricata-vm1','suricata-vm2','suricata-vm3')
$agent = Get-Service ssh-agent -ErrorAction Stop
if ($agent.Status -ne 'Running') { try { Start-Service ssh-agent -ErrorAction Stop } catch { throw 'ssh-agent is stopped; ask the owner to start the existing OpenSSH Authentication Agent.' } }
Write-Host "ssh-agent: $((Get-Service ssh-agent).Status)"
ssh-add -l
if ($LASTEXITCODE -ne 0) { throw 'No usable SSH identity is loaded in ssh-agent.' }
foreach ($alias in $aliases) {
    $effective = ssh -G $alias 2>$null
    if ($LASTEXITCODE -ne 0) { throw "ssh -G failed for $alias" }
    Write-Host "$alias :: $(($effective | Where-Object { $_ -match '^hostname ' } | Select-Object -First 1)) :: $(($effective | Where-Object { $_ -match '^user ' } | Select-Object -First 1))"
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=5 $alias 'hostname; id -un'
    if ($LASTEXITCODE -ne 0) { throw "Strict non-interactive SSH failed for $alias" }
}
if ($OpenTerminals) { foreach ($alias in $aliases) { Start-Process powershell.exe -ArgumentList @('-NoExit','-NoProfile','-Command',"ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $alias") } }
