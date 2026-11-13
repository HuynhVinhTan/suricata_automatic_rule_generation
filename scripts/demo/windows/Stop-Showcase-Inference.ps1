[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 '/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-stop-worker.sh'
if ($LASTEXITCODE -ne 0) { throw 'Showcase inference worker failed to stop.' }
