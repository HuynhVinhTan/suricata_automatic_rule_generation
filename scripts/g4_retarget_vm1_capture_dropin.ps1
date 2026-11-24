[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Rollback,
    [switch]$Execute,
    [string]$Vm1Target = 'tanhv@192.168.10.10'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ($Install -and $Rollback) { throw 'Choose -Install or -Rollback, not both.' }
if (-not $Install -and -not $Rollback) { throw 'Choose -Install or -Rollback.' }

$ReleaseCommit = '08174bf8a9af83c588b48f1c95f7647c22db5118'
$ReleaseRoot = "/home/tanhv/suricata-ai-showcase/releases/$ReleaseCommit"
$Unit = '/etc/systemd/system/suricata-ai-capture.service'
$Service = 'suricata-ai-capture.service'
$DropIn = '/etc/systemd/system/suricata-ai-capture.service.d/10-g4-release.conf'
$ExpectedUnitSha256 = '42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de'
$ExpectedCaptureSha256 = '1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3'
$ExpectedHandoffSha256 = '0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de'
$OriginalWorkingDirectory = '/home/tanhv/suricata-ai-tools'
$ExpectedBpf = 'tcp and host 192.168.10.20 and host 192.168.10.10 and (port 18080 or portrange 18100-18123)'

function Get-Payload {
    param([ValidateSet('install', 'rollback')][string]$Action)
    $template = @'
set -eu
umask 077
ACTION='__ACTION__'
SERVICE=suricata-ai-capture.service
UNIT=/etc/systemd/system/suricata-ai-capture.service
DROPIN=/etc/systemd/system/suricata-ai-capture.service.d/10-g4-release.conf
RELEASE='__RELEASE__'
EXPECTED_UNIT='__UNIT_SHA256__'
EXPECTED_CAPTURE='__CAPTURE_SHA256__'
EXPECTED_HANDOFF='__HANDOFF_SHA256__'
EXPECTED_WD='__ORIGINAL_WD__'
TARGET_WD='__RELEASE__'
EXPECTED_BPF='__BPF__'

test -f "$UNIT"
test ! -L "$UNIT"
test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT"
test "$(systemctl show -p ActiveState --value "$SERVICE")" = inactive
test "$(systemctl show -p SubState --value "$SERVICE")" = dead
test "$(systemctl show -p ActiveState --value suricata-ai-send.service)" = inactive
test "$(systemctl show -p ActiveState --value suricata-ai-send.timer)" = inactive
if pgrep -af '[/]tcpdump' >/dev/null; then exit 75; fi

before_exec=$(systemctl show -p ExecStart --value "$SERVICE")
before_pre=$(systemctl show -p ExecStartPre --value "$SERVICE")
before_post=$(systemctl show -p ExecStartPost --value "$SERVICE")
before_user=$(systemctl show -p User --value "$SERVICE")
before_group=$(systemctl show -p Group --value "$SERVICE")
before_caps=$(systemctl show -p CapabilityBoundingSet --value "$SERVICE")
before_ambient=$(systemctl show -p AmbientCapabilities --value "$SERVICE")
before_nnp=$(systemctl show -p NoNewPrivileges --value "$SERVICE")
before_protect_system=$(systemctl show -p ProtectSystem --value "$SERVICE")
before_protect_home=$(systemctl show -p ProtectHome --value "$SERVICE")
before_private_tmp=$(systemctl show -p PrivateTmp --value "$SERVICE")
before_families=$(systemctl show -p RestrictAddressFamilies --value "$SERVICE")
before_readwrite=$(systemctl show -p ReadWritePaths --value "$SERVICE")
before_timeout=$(systemctl show -p TimeoutStartUSec --value "$SERVICE")
before_wd=$(systemctl show -p WorkingDirectory --value "$SERVICE")
if [ "$ACTION" = install ]; then
  test -z "$(systemctl show -p DropInPaths --value "$SERVICE")"
  test "$before_wd" = "$EXPECTED_WD"
else
  test "$before_wd" = "$TARGET_WD"
  test -f "$DROPIN"
  test ! -L "$DROPIN"
  test "$(stat -c '%a' "$DROPIN")" = 644
  grep -Fxq '[Service]' "$DROPIN"
  grep -Fxq 'WorkingDirectory=__RELEASE__' "$DROPIN"
fi

test -d "$RELEASE"
test ! -L "$RELEASE"
test -f "$RELEASE/backend/pcap_capture.py"
test -f "$RELEASE/backend/pcap_handoff.py"
test ! -L "$RELEASE/backend/pcap_capture.py"
test ! -L "$RELEASE/backend/pcap_handoff.py"
test "$(sha256sum "$RELEASE/backend/pcap_capture.py" | awk '{print $1}')" = "$EXPECTED_CAPTURE"
test "$(sha256sum "$RELEASE/backend/pcap_handoff.py" | awk '{print $1}')" = "$EXPECTED_HANDOFF"
module_path=$(cd -- "$RELEASE" && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$RELEASE" /usr/bin/python3 -c 'import backend.pcap_capture as m; print(m.__file__)')
module_path=$(readlink -e "$module_path")
test "$module_path" = "$RELEASE/backend/pcap_capture.py"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$RELEASE" /usr/bin/python3 - "$EXPECTED_BPF" <<'PY'
import sys
import backend.pcap_capture as capture
assert capture.INTERFACE == "ens33"
assert capture.DEFAULT_DURATION_SECONDS == 60
assert capture.MAX_DURATION_SECONDS == 60
assert capture.SNAPLEN == 262144
assert capture.MAX_PCAP_BYTES == 64 * 1024 * 1024
assert capture.BPF_FILTER == sys.argv[1]
PY

if [ "$ACTION" = install ]; then
  test ! -e "$DROPIN"
  test ! -L /etc/systemd/system/suricata-ai-capture.service.d
  mkdir -m 755 /etc/systemd/system/suricata-ai-capture.service.d
  tmp="$DROPIN.tmp.$$"
  umask 022
  printf '%s\n' '[Service]' 'WorkingDirectory=__RELEASE__' > "$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -- "$tmp" "$DROPIN"
  systemctl daemon-reload
  test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT"
  test "$(systemctl show -p ExecStart --value "$SERVICE")" = "$before_exec"
  test "$(systemctl show -p ExecStartPre --value "$SERVICE")" = "$before_pre"
  test "$(systemctl show -p ExecStartPost --value "$SERVICE")" = "$before_post"
  test "$(systemctl show -p User --value "$SERVICE")" = "$before_user"
  test "$(systemctl show -p Group --value "$SERVICE")" = "$before_group"
  test "$(systemctl show -p CapabilityBoundingSet --value "$SERVICE")" = "$before_caps"
  test "$(systemctl show -p AmbientCapabilities --value "$SERVICE")" = "$before_ambient"
  test "$(systemctl show -p NoNewPrivileges --value "$SERVICE")" = "$before_nnp"
  test "$(systemctl show -p ProtectSystem --value "$SERVICE")" = "$before_protect_system"
  test "$(systemctl show -p ProtectHome --value "$SERVICE")" = "$before_protect_home"
  test "$(systemctl show -p PrivateTmp --value "$SERVICE")" = "$before_private_tmp"
  test "$(systemctl show -p RestrictAddressFamilies --value "$SERVICE")" = "$before_families"
  test "$(systemctl show -p ReadWritePaths --value "$SERVICE")" = "$before_readwrite"
  test "$(systemctl show -p TimeoutStartUSec --value "$SERVICE")" = "$before_timeout"
  test "$(systemctl show -p WorkingDirectory --value "$SERVICE")" = "$TARGET_WD"
  test "$(systemctl show -p ActiveState --value "$SERVICE")" = inactive
  test "$(systemctl show -p SubState --value "$SERVICE")" = dead
  test "$(systemctl show -p ActiveState --value suricata-ai-send.timer)" = inactive
  printf '%s\n' VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE
else
  rm -- "$DROPIN"
  rmdir -- /etc/systemd/system/suricata-ai-capture.service.d
  systemctl daemon-reload
  test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT"
  test "$(systemctl show -p ExecStart --value "$SERVICE")" = "$before_exec"
  test "$(systemctl show -p ExecStartPre --value "$SERVICE")" = "$before_pre"
  test "$(systemctl show -p ExecStartPost --value "$SERVICE")" = "$before_post"
  test "$(systemctl show -p WorkingDirectory --value "$SERVICE")" = "$EXPECTED_WD"
  test "$(systemctl show -p User --value "$SERVICE")" = "$before_user"
  test "$(systemctl show -p Group --value "$SERVICE")" = "$before_group"
  test "$(systemctl show -p CapabilityBoundingSet --value "$SERVICE")" = "$before_caps"
  test "$(systemctl show -p AmbientCapabilities --value "$SERVICE")" = "$before_ambient"
  test "$(systemctl show -p NoNewPrivileges --value "$SERVICE")" = "$before_nnp"
  test "$(systemctl show -p ProtectSystem --value "$SERVICE")" = "$before_protect_system"
  test "$(systemctl show -p ProtectHome --value "$SERVICE")" = "$before_protect_home"
  test "$(systemctl show -p PrivateTmp --value "$SERVICE")" = "$before_private_tmp"
  test "$(systemctl show -p RestrictAddressFamilies --value "$SERVICE")" = "$before_families"
  test "$(systemctl show -p ReadWritePaths --value "$SERVICE")" = "$before_readwrite"
  test "$(systemctl show -p TimeoutStartUSec --value "$SERVICE")" = "$before_timeout"
  test -z "$(systemctl show -p DropInPaths --value "$SERVICE")"
  test "$(systemctl show -p ActiveState --value "$SERVICE")" = inactive
  test "$(systemctl show -p SubState --value "$SERVICE")" = dead
  test "$(systemctl show -p ActiveState --value suricata-ai-send.timer)" = inactive
  printf '%s\n' VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE
fi
'@
    return $template.Replace('__ACTION__', $Action).Replace('__RELEASE__', $ReleaseRoot).Replace('__UNIT_SHA256__', $ExpectedUnitSha256).Replace('__CAPTURE_SHA256__', $ExpectedCaptureSha256).Replace('__HANDOFF_SHA256__', $ExpectedHandoffSha256).Replace('__ORIGINAL_WD__', $OriginalWorkingDirectory).Replace('__BPF__', $ExpectedBpf)
}

if (-not $Execute) {
    Write-Output 'Plan only. Re-run with -Execute after the separately approved VM1 release and drop-in scope.'
    Write-Output ("action={0}; release={1}; dropin={2}" -f ($(if ($Install) { 'install' } else { 'rollback' }), $ReleaseRoot, $DropIn))
    exit 0
}

$payload = Get-Payload -Action $(if ($Install) { 'install' } else { 'rollback' })
$normalized = $payload -replace "`r`n", "`n"
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($normalized))
& ssh -tt -o StrictHostKeyChecking=yes $Vm1Target ("sudo -v && printf %s '{0}' | base64 -d | sudo -n bash -s --" -f $encoded)
if ($LASTEXITCODE -ne 0) { throw "VM1 drop-in workflow failed with exit code $LASTEXITCODE." }
