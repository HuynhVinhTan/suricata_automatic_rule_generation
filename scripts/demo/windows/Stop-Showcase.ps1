[CmdletBinding()] param()
$ErrorActionPreference='Stop'
foreach ($alias in @('suricata-vm1','suricata-vm2','suricata-vm3')) {
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $alias "if test -f '$HOME/suricata-ai-showcase/runtime/worker.pid'; then p=$(cat '$HOME/suricata-ai-showcase/runtime/worker.pid'); if test -r /proc/$p/cmdline && tr '\0' ' ' < /proc/$p/cmdline | grep -q 'suricata-ai-showcase'; then kill -TERM $p 2>/dev/null || true; fi; rm -f '$HOME/suricata-ai-showcase/runtime/worker.pid'; fi"
    Write-Host "$alias demo worker stop requested."
}
Write-Host 'Stop the Windows relay process using its printed PID, if running.'
