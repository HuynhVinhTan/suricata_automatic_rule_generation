[CmdletBinding()]
param([string]$RelayPidPath = (Join-Path ([IO.Path]::GetTempPath()) 'suricata-showcase-eve-relay.pid'))
$ErrorActionPreference = 'Stop'

$remote = @'
set -eu
ROOT='__ROOT__'
stop_owned_pid() {
  file="$1"
  [ -f "$file" ] || return 0
  pid=$(cat "$file")
  if printf '%s' "$pid" | grep -Eq '^[0-9]+$' && [ -r "/proc/$pid/cmdline" ]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$ROOT" || { echo "refusing non-showcase PID $pid" >&2; return 1; }
    kill -TERM "$pid" 2>/dev/null || true
  fi
  rm -f -- "$file"
}
stop_owned_pid "$ROOT/runtime/worker.pid"
stop_owned_pid "$ROOT/runtime/isolated.pid"
stop_owned_pid "$ROOT/runtime/http-server.pid"
echo 'SHOWCASE_PROCESSES_STOP_REQUESTED=YES'
'@

$targets = @(
    @{ Alias = 'suricata-vm1'; Root = '/home/tanhv/suricata-ai-showcase' },
    @{ Alias = 'suricata-vm2'; Root = '/home/kali/suricata-ai-showcase' },
    @{ Alias = 'suricata-vm3'; Root = '/home/tanhv/suricata-ai-showcase' }
)
foreach ($target in $targets) {
    $command = $remote.Replace('__ROOT__', $target.Root)
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $target.Alias $command
    if ($LASTEXITCODE -ne 0) { throw "Failed to stop showcase processes on $($target.Alias)" }
}

if (Test-Path -LiteralPath $RelayPidPath) {
    $relayPid = (Get-Content -Raw -LiteralPath $RelayPidPath).Trim()
    if ($relayPid -match '^[0-9]+$') {
        $process = Get-Process -Id ([int]$relayPid) -ErrorAction SilentlyContinue
        if ($process) { Stop-Process -Id $process.Id -Force -ErrorAction Stop }
    }
    Remove-Item -LiteralPath $RelayPidPath -Force
    Write-Host "Windows EVE relay stopped (PID $relayPid)."
} else {
    Write-Host 'Windows EVE relay PID file not found; nothing to stop.'
}
Write-Host 'Production Suricata, Filebeat and ELK were not targeted.'
