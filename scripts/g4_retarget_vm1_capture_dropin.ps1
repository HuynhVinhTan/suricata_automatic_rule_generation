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
$DropInDir = '/etc/systemd/system/suricata-ai-capture.service.d'
$DropIn = "$DropInDir/10-g4-release.conf"
$ExpectedUnitSha256 = '42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de'
$ExpectedCaptureSha256 = '1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3'
$ExpectedHandoffSha256 = '0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de'
$ExpectedDropInSha256 = 'ad0f18078ce09e38a7b8eade105bfe48d6539d7faca6b775a41b8dc7aca8b074'
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
DROPIN_DIR=/etc/systemd/system/suricata-ai-capture.service.d
DROPIN=/etc/systemd/system/suricata-ai-capture.service.d/10-g4-release.conf
RELEASE='__RELEASE__'
EXPECTED_UNIT='__UNIT_SHA256__'
EXPECTED_CAPTURE='__CAPTURE_SHA256__'
EXPECTED_HANDOFF='__HANDOFF_SHA256__'
EXPECTED_DROPIN='__DROPIN_SHA256__'
EXPECTED_WD='__ORIGINAL_WD__'
TARGET_WD='__RELEASE__'
EXPECTED_BPF='__BPF__'
dropin_created=0
dropin_dir_created=0
before_state_ready=0
temporary_file=''
created_dropin_identity=''
created_dropin_dir_identity=''
before_dropin_dir_identity=''
before_exec=''
before_pre=''
before_post=''
before_user=''
before_group=''
before_caps=''
before_ambient=''
before_nnp=''
before_protect_system=''
before_protect_home=''
before_private_tmp=''
before_families=''
before_readwrite=''
before_timeout=''
before_wd=''
current_checkpoint=initialization

remote_checkpoint() {
  current_checkpoint=$1
  printf 'VM1_REMOTE_CHECKPOINT=%s\n' "$current_checkpoint"
}

verify_properties() {
  expected_wd=$1
  ok=0
  test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT" || ok=1
  test "$(systemctl show -p ExecStart --value "$SERVICE")" = "$before_exec" || ok=1
  test "$(systemctl show -p ExecStartPre --value "$SERVICE")" = "$before_pre" || ok=1
  test "$(systemctl show -p ExecStartPost --value "$SERVICE")" = "$before_post" || ok=1
  test "$(systemctl show -p User --value "$SERVICE")" = "$before_user" || ok=1
  test "$(systemctl show -p Group --value "$SERVICE")" = "$before_group" || ok=1
  test "$(systemctl show -p CapabilityBoundingSet --value "$SERVICE")" = "$before_caps" || ok=1
  test "$(systemctl show -p AmbientCapabilities --value "$SERVICE")" = "$before_ambient" || ok=1
  test "$(systemctl show -p NoNewPrivileges --value "$SERVICE")" = "$before_nnp" || ok=1
  test "$(systemctl show -p ProtectSystem --value "$SERVICE")" = "$before_protect_system" || ok=1
  test "$(systemctl show -p ProtectHome --value "$SERVICE")" = "$before_protect_home" || ok=1
  test "$(systemctl show -p PrivateTmp --value "$SERVICE")" = "$before_private_tmp" || ok=1
  test "$(systemctl show -p RestrictAddressFamilies --value "$SERVICE")" = "$before_families" || ok=1
  test "$(systemctl show -p ReadWritePaths --value "$SERVICE")" = "$before_readwrite" || ok=1
  test "$(systemctl show -p TimeoutStartUSec --value "$SERVICE")" = "$before_timeout" || ok=1
  test "$(systemctl show -p WorkingDirectory --value "$SERVICE")" = "$expected_wd" || ok=1
  test "$(systemctl show -p ActiveState --value "$SERVICE")" = inactive || ok=1
  test "$(systemctl show -p SubState --value "$SERVICE")" = dead || ok=1
  test "$(systemctl show -p ActiveState --value suricata-ai-send.timer)" = inactive || ok=1
  return "$ok"
}

verify_dropin_identity() {
  ok=0
  test -f "$DROPIN" || ok=1
  test ! -L "$DROPIN" || ok=1
  test "$(sha256sum "$DROPIN" | awk '{print $1}')" = "$EXPECTED_DROPIN" || ok=1
  test "$(stat -c '%U:%G %a' "$DROPIN")" = 'root:root 644' || ok=1
  return "$ok"
}

rollback_reject() {
  printf '%s\n' VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE >&2
  exit 1
}

remove_created_dropin() {
  ok=0
  test "$dropin_created" = 1 || ok=1
  test -n "$created_dropin_identity" || ok=1
  test "$(stat -c '%d:%i:%U:%G:%a' "$DROPIN")" = "$created_dropin_identity" || ok=1
  verify_dropin_identity || ok=1
  if [ "$ok" -ne 0 ]; then
    return 1
  fi
  sudo -n rm -- "$DROPIN"
  test ! -e "$DROPIN"
  test ! -L "$DROPIN"
}

rollback_install() {
  status=$?
  set +e
  rm -f -- "$temporary_file" 2>/dev/null
  if [ "$status" -ne 0 ]; then
    printf 'VM1_REMOTE_FAILURE_CHECKPOINT=%s\n' "$current_checkpoint" >&2
    printf 'VM1_REMOTE_FAILURE_EXIT=%s\n' "$status" >&2
  fi
  if [ "$ACTION" = install ] && [ "$status" -ne 0 ]; then
    rollback_failed=0
    if [ "$dropin_created" = 1 ]; then
      if remove_created_dropin; then
        sudo -n systemctl daemon-reload || rollback_failed=1
      else
        rollback_failed=1
      fi
    fi
    if [ "$dropin_dir_created" = 1 ]; then
      current_dir_identity=$(stat -c '%d:%i:%U:%G:%a' "$DROPIN_DIR" 2>/dev/null)
      remaining=$(find "$DROPIN_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)
      if [ -d "$DROPIN_DIR" ] && [ "$current_dir_identity" = "$created_dropin_dir_identity" ] && [ -z "$remaining" ]; then
        sudo -n rmdir -- "$DROPIN_DIR" || rollback_failed=1
      else
        rollback_failed=1
      fi
    fi
    if [ -e "$DROPIN" ] || [ -L "$DROPIN" ]; then rollback_failed=1; fi
    if [ "$before_state_ready" = 1 ]; then
      verify_properties "$EXPECTED_WD" || rollback_failed=1
    fi
    if [ "$rollback_failed" = 0 ]; then
      printf '%s\n' VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE
    else
      printf '%s\n' VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE >&2
    fi
  fi
  exit "$status"
}
trap rollback_install EXIT

remote_checkpoint preflight-unit-identity
test -f "$UNIT"
test ! -L "$UNIT"
test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT"
remote_checkpoint preflight-service-state
test "$(systemctl show -p ActiveState --value "$SERVICE")" = inactive
test "$(systemctl show -p SubState --value "$SERVICE")" = dead
test "$(systemctl show -p ActiveState --value suricata-ai-send.service)" = inactive
test "$(systemctl show -p ActiveState --value suricata-ai-send.timer)" = inactive
if pgrep -af '[/]tcpdump' >/dev/null; then exit 75; fi

remote_checkpoint preflight-security-properties
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
before_state_ready=1

if [ "$ACTION" = install ]; then
  remote_checkpoint install-scope-preflight
  test -z "$(systemctl show -p DropInPaths --value "$SERVICE")"
  test "$before_wd" = "$EXPECTED_WD"
  remote_checkpoint install-release-preflight
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

  remote_checkpoint install-dropin-preflight
  test ! -e "$DROPIN"
  test ! -L "$DROPIN"
  if [ -L "$DROPIN_DIR" ]; then exit 1; fi
  if [ -e "$DROPIN_DIR" ]; then
    test -d "$DROPIN_DIR"
    before_dropin_dir_identity=$(stat -c '%d:%i:%U:%G:%a' "$DROPIN_DIR")
  else
    dropin_dir_created=1
  fi
  remote_checkpoint install-dropin-write
  tmp=$(mktemp)
  temporary_file=$tmp
  umask 022
  printf '%s\n' '[Service]' "WorkingDirectory=$RELEASE" > "$tmp"
  chmod 0644 "$tmp"
  if [ "$dropin_dir_created" = 1 ]; then
    sudo -n install -d -o root -g root -m 0755 "$DROPIN_DIR"
    created_dropin_dir_identity=$(stat -c '%d:%i:%U:%G:%a' "$DROPIN_DIR")
    test "$(stat -c '%U:%G %a' "$DROPIN_DIR")" = 'root:root 755'
  fi
  sudo -n install -o root -g root -m 0644 "$tmp" "$DROPIN"
  dropin_created=1
  created_dropin_identity=$(stat -c '%d:%i:%U:%G:%a' "$DROPIN")
  rm -f -- "$tmp"
  temporary_file=''
  remote_checkpoint install-dropin-identity
  verify_dropin_identity
  if [ "$dropin_dir_created" = 0 ]; then
    test "$(stat -c '%d:%i:%U:%G:%a' "$DROPIN_DIR")" = "$before_dropin_dir_identity"
  fi
  remote_checkpoint install-daemon-reload
  sudo -n systemctl daemon-reload
  remote_checkpoint install-post-verification
  verify_properties "$TARGET_WD"
  verify_dropin_identity
  trap - EXIT
  remote_checkpoint install-success
  printf '%s\n' VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE
else
  remote_checkpoint rollback-scope-preflight
  if [ "$before_wd" != "$TARGET_WD" ] && [ "$before_wd" != "$EXPECTED_WD" ]; then
    rollback_reject
  fi
  if [ -L "$DROPIN_DIR" ]; then
    rollback_reject
  fi
  remote_checkpoint rollback-dropin-identity
  if ! verify_dropin_identity; then
    rollback_reject
  fi
  remote_checkpoint rollback-dropin-removal
  if ! sudo -n rm -- "$DROPIN"; then
    rollback_reject
  fi
  if [ -e "$DROPIN" ] || [ -L "$DROPIN" ]; then
    rollback_reject
  fi
  remote_checkpoint rollback-daemon-reload
  if ! sudo -n systemctl daemon-reload; then
    rollback_reject
  fi
  remote_checkpoint rollback-post-verification
  if ! verify_properties "$EXPECTED_WD"; then
    rollback_reject
  fi
  remote_checkpoint rollback-success
  printf '%s\n' VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE
fi
'@
    return $template.Replace('__ACTION__', $Action).Replace('__RELEASE__', $ReleaseRoot).Replace('__UNIT_SHA256__', $ExpectedUnitSha256).Replace('__CAPTURE_SHA256__', $ExpectedCaptureSha256).Replace('__HANDOFF_SHA256__', $ExpectedHandoffSha256).Replace('__DROPIN_SHA256__', $ExpectedDropInSha256).Replace('__ORIGINAL_WD__', $OriginalWorkingDirectory).Replace('__BPF__', $ExpectedBpf)
}

if (-not $Execute) {
    Write-Output 'Plan only. Re-run with -Execute after the separately approved VM1 release and drop-in scope.'
    Write-Output ("action={0}; release={1}; dropin={2}" -f ($(if ($Install) { 'install' } else { 'rollback' }), $ReleaseRoot, $DropIn))
    exit 0
}

$payload = Get-Payload -Action $(if ($Install) { 'install' } else { 'rollback' })
$normalized = $payload -replace "`r`n?", "`n"
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($normalized))
& ssh -tt -o StrictHostKeyChecking=yes $Vm1Target ("sudo -v && printf %s '{0}' | base64 -d | bash -s --" -f $encoded)
if ($LASTEXITCODE -ne 0) { throw "VM1 drop-in workflow failed with exit code $LASTEXITCODE." }
