[CmdletBinding()]
param([string]$Model='/home/tanhv/suricata-ai-showcase/models/showcase_demo')
$ErrorActionPreference='Stop'
ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 "'/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-start-worker.sh' '$Model' '/home/tanhv/suricata-ai-showcase/eve-shadow/eve-shadow.jsonl' 'showcase_demo'"
if ($LASTEXITCODE -ne 0) { throw 'Showcase inference worker failed to start.' }
Write-Host 'SHOWCASE_INFERENCE_PROFILE=showcase_demo'
Write-Host 'SHOWCASE_INFERENCE_REVIEW_ONLY=YES'
