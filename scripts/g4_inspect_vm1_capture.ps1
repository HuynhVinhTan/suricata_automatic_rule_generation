[CmdletBinding()]
param(
    [string]$Vm1Target = 'tanhv@192.168.10.10'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$payload = @'
set -eu
UNIT=/etc/systemd/system/suricata-ai-capture.service
SERVICE=suricata-ai-capture.service
ROOT=/home/tanhv/suricata-ai-showcase
EXPECTED_RELEASE="$ROOT/releases/08174bf8a9af83c588b48f1c95f7647c22db5118"
EXPECTED_CAPTURE_SHA256=1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3
EXPECTED_HANDOFF_SHA256=0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de
EXPECTED_UNIT=42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de
test -f "$UNIT"
test ! -L "$UNIT"
printf '%s\n' '--- systemctl cat ---'
systemctl cat "$SERVICE"
printf '%s\n' '--- effective properties ---'
systemctl show --all "$SERVICE" \
  -p ExecStart -p ExecStartPre -p ExecStartPost -p User -p Group \
  -p CapabilityBoundingSet -p AmbientCapabilities -p NoNewPrivileges \
  -p ProtectSystem -p ProtectHome -p PrivateTmp -p RestrictAddressFamilies \
  -p FragmentPath -p DropInPaths -p WorkingDirectory -p ActiveState \
  -p SubState -p MainPID -p TimeoutStartUSec
printf 'ExecStartPre=%s\n' "$(systemctl show --all -p ExecStartPre --value "$SERVICE")"
printf 'ExecStartPost=%s\n' "$(systemctl show --all -p ExecStartPost --value "$SERVICE")"
printf '%s\n' '--- unit SHA256 ---'
unit_sha=$(sha256sum "$UNIT" | awk '{print $1}')
printf 'unit_sha256=%s\n' "$unit_sha"
printf 'expected_unit_sha256=%s\n' "$EXPECTED_UNIT"
test "$unit_sha" = "$EXPECTED_UNIT"
printf '%s\n' '--- current and rollback target ---'
if [ -L "$ROOT/current" ]; then
  current_target=$(readlink -e "$ROOT/current")
  printf 'current_target=%s\n' "$current_target"
  printf 'rollback_target=%s\n' "$current_target"
elif [ -e "$ROOT/current" ]; then
  printf '%s\n' 'current_target=UNSAFE_NON_SYMLINK'
  exit 75
else
  printf '%s\n' 'current_target=ABSENT'
  printf '%s\n' 'rollback_target=NONE'
fi
wd=$(systemctl show -p WorkingDirectory --value "$SERVICE")
test -n "$wd"
printf 'effective_working_directory=%s\n' "$wd"
module_path=$(cd -- "$wd" && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$wd" /usr/bin/python3 -c 'import backend.pcap_capture as m; print(m.__file__)')
module_path=$(readlink -e "$module_path")
test -f "$module_path"
printf 'source_module_path=%s\n' "$module_path"
printf 'source_module_sha256=%s\n' "$(sha256sum "$module_path" | awk '{print $1}')"
test -d "$EXPECTED_RELEASE"
test ! -L "$EXPECTED_RELEASE"
test -f "$EXPECTED_RELEASE/backend/pcap_capture.py"
test -f "$EXPECTED_RELEASE/backend/pcap_handoff.py"
published_capture_sha=$(sha256sum "$EXPECTED_RELEASE/backend/pcap_capture.py" | awk '{print $1}')
published_handoff_sha=$(sha256sum "$EXPECTED_RELEASE/backend/pcap_handoff.py" | awk '{print $1}')
printf 'published_release_path=%s\n' "$EXPECTED_RELEASE"
printf 'published_capture_sha256=%s\n' "$published_capture_sha"
printf 'published_handoff_sha256=%s\n' "$published_handoff_sha"
test "$published_capture_sha" = "$EXPECTED_CAPTURE_SHA256"
test "$published_handoff_sha" = "$EXPECTED_HANDOFF_SHA256"
printf '%s\n' 'published_release_hashes_pass=TRUE'
printf '%s\n' '--- service state and capture process ---'
printf 'capture_active_state=%s\n' "$(systemctl show -p ActiveState --value "$SERVICE")"
printf 'capture_sub_state=%s\n' "$(systemctl show -p SubState --value "$SERVICE")"
if pgrep -af '[/]tcpdump' >/dev/null; then printf '%s\n' 'tcpdump_process=present'; else printf '%s\n' 'tcpdump_process=absent'; fi
'@

$normalized = $payload -replace "`r`n", "`n"
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($normalized))
& ssh -o BatchMode=yes -o StrictHostKeyChecking=yes $Vm1Target `
    ("printf %s '{0}' | base64 -d | bash" -f $encoded)
if ($LASTEXITCODE -ne 0) { throw "Read-only VM1 inspection failed with exit code $LASTEXITCODE." }
