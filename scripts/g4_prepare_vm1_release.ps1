[CmdletBinding()]
param(
    [string]$RepositoryRoot = 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e',
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$PinnedReleaseCommit = '08174bf8a9af83c588b48f1c95f7647c22db5118'
$VerifiedControllerHead = '624858968e0528c58d6e4284394d0932cf8bd7cb'
$ExpectedBranch = 'feat/complete-suricata-ai-e2e'
$ExpectedArchiveSha256 = '8cc7905d4632c0cbcfdad474f2cc61a2e138c8f46e14771594eb245a18a32005'
$ExpectedUnitSha256 = '42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de'
$Vm1Target = 'tanhv@192.168.10.10'
$ShowcaseRoot = '/home/tanhv/suricata-ai-showcase'
$ReleasePath = "$ShowcaseRoot/releases/$PinnedReleaseCommit"
$RemoteStageName = 'g4-vm1-' + ([Guid]::NewGuid().ToString('N'))
$RemoteStagePath = "$ShowcaseRoot/.runtime-staging/$RemoteStageName"

function Invoke-RemoteBash {
    param([string]$Payload)
    $normalized = $Payload -replace "`r`n", "`n"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($normalized))
    & ssh -o BatchMode=yes -o StrictHostKeyChecking=yes $Vm1Target `
        ("printf %s '{0}' | base64 -d | bash" -f $encoded)
    if ($LASTEXITCODE -ne 0) { throw "Remote VM1 command failed with exit code $LASTEXITCODE." }
}

function Assert-LocalPinnedState {
    $branch = (& git -C $RepositoryRoot branch --show-current).Trim()
    if ($branch -ne $ExpectedBranch) { throw "Unexpected branch '$branch'." }
    $head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    & git -C $RepositoryRoot merge-base --is-ancestor $VerifiedControllerHead $head
    if ($LASTEXITCODE -ne 0) { throw "HEAD '$head' does not descend from verified state '$VerifiedControllerHead'." }
    & git -C $RepositoryRoot cat-file -e "$PinnedReleaseCommit^{commit}"
    if ($LASTEXITCODE -ne 0) { throw 'Pinned release commit is unavailable.' }
    & git -C $RepositoryRoot merge-base --is-ancestor $PinnedReleaseCommit $head
    if ($LASTEXITCODE -ne 0) { throw 'Pinned release is not an ancestor of HEAD.' }
    & git -C $RepositoryRoot merge-base --is-ancestor $PinnedReleaseCommit $VerifiedControllerHead
    if ($LASTEXITCODE -ne 0) { throw 'Pinned ancestry does not match the verified state.' }
}

function New-PinnedArchive {
    $archive = Join-Path ([IO.Path]::GetTempPath()) ("suricata-ai-vm1-{0}.tar" -f $PinnedReleaseCommit)
    if (Test-Path -LiteralPath $archive) { throw "Refusing existing archive '$archive'." }
    & git -C $RepositoryRoot archive --format=tar --output=$archive $PinnedReleaseCommit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $ExpectedArchiveSha256) {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        throw "Archive SHA256 mismatch: $actual"
    }
    return $archive
}

function Get-RemoteStagePayload {
    return @'
set -eu
umask 077
ROOT=__ROOT__
RELEASE=__RELEASE__
STAGE=__STAGE__
UNIT=/etc/systemd/system/suricata-ai-capture.service
EXPECTED_UNIT=__UNIT__
test -d "$ROOT"
test ! -L "$ROOT"
test -d "$ROOT/releases"
test ! -L "$ROOT/releases"
test ! -e "$RELEASE"
test ! -L "$ROOT/.runtime-staging"
if [ -e "$ROOT/.runtime-staging" ]; then test -d "$ROOT/.runtime-staging"; fi
test -f "$UNIT"
test ! -L "$UNIT"
test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$EXPECTED_UNIT"
test "$(systemctl show -p ActiveState --value suricata-ai-capture.service)" = inactive
test "$(systemctl show -p SubState --value suricata-ai-capture.service)" = dead
if pgrep -af '[/]tcpdump' >/dev/null; then exit 75; fi
if [ ! -e "$ROOT/.runtime-staging" ]; then mkdir -m 700 "$ROOT/.runtime-staging"; fi
test "$(stat -c '%a' "$ROOT/.runtime-staging")" = 700
test ! -e "$STAGE"
mkdir -m 700 "$STAGE"
stage_device=$(stat -c '%d' "$STAGE")
releases_device=$(stat -c '%d' "$ROOT/releases")
test "$stage_device" = "$releases_device"
printf 'stage_device=%s releases_device=%s\n' "$stage_device" "$releases_device"
printf '%s\n' VM1_STAGE_READY=TRUE
'@.Replace('__ROOT__', $ShowcaseRoot).Replace('__RELEASE__', $ReleasePath).Replace('__STAGE__', $RemoteStagePath).Replace('__UNIT__', $ExpectedUnitSha256)
}

function Get-RemotePublishPayload {
    return @'
set -eu
umask 077
ROOT=__ROOT__
RELEASE=__RELEASE__
STAGE=__STAGE__
ARCHIVE="$STAGE/source.tar"
EXTRACTED="$STAGE/extracted"
EXPECTED_ARCHIVE=__ARCHIVE__
EXPECTED_UNIT=__UNIT__
UNIT=/etc/systemd/system/suricata-ai-capture.service
on_exit() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then printf 'VM1_RELEASE_FAIL=TRUE staging=%s\n' "$STAGE" >&2; fi
  exit "$status"
}
trap on_exit EXIT
test -f "$ARCHIVE"
test -d "$ROOT"
test ! -L "$ROOT"
test -d "$ROOT/releases"
test ! -L "$ROOT/releases"
test "$(sha256sum "$ARCHIVE" | awk '{print $1}')" = "$EXPECTED_ARCHIVE"
if tar -tf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then exit 74; fi
mkdir -m 700 "$EXTRACTED"
tar -xf "$ARCHIVE" -C "$EXTRACTED" --no-same-owner --no-same-permissions
test -f "$EXTRACTED/backend/pcap_capture.py"
test -f "$EXTRACTED/backend/pcap_handoff.py"
test ! -L "$EXTRACTED/backend/pcap_capture.py"
test ! -L "$EXTRACTED/backend/pcap_handoff.py"
test "$(sha256sum "$EXTRACTED/backend/pcap_capture.py" | awk '{print $1}')" = 1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3
test "$(sha256sum "$EXTRACTED/backend/pcap_handoff.py" | awk '{print $1}')" = 0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de
current_kind=absent
current_before=
if [ -L "$ROOT/current" ]; then current_kind=symlink; current_before=$(readlink -e "$ROOT/current"); test -n "$current_before"; elif [ -e "$ROOT/current" ]; then exit 75; fi
unit_before=$(sha256sum "$UNIT" | awk '{print $1}')
state_before=$(systemctl show -p ActiveState --value suricata-ai-capture.service)
substate_before=$(systemctl show -p SubState --value suricata-ai-capture.service)
test "$unit_before" = "$EXPECTED_UNIT"
test "$state_before" = inactive
test "$substate_before" = dead
if pgrep -af '[/]tcpdump' >/dev/null; then exit 75; fi
test ! -e "$RELEASE"
stage_device=$(stat -c '%d' "$STAGE")
releases_device=$(stat -c '%d' "$ROOT/releases")
test "$stage_device" = "$releases_device"
printf 'publish_stage_device=%s publish_releases_device=%s\n' "$stage_device" "$releases_device"
mv -- "$EXTRACTED" "$RELEASE"
test "$(sha256sum "$RELEASE/backend/pcap_capture.py" | awk '{print $1}')" = 1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3
test "$(sha256sum "$RELEASE/backend/pcap_handoff.py" | awk '{print $1}')" = 0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de
test "$(sha256sum "$UNIT" | awk '{print $1}')" = "$unit_before"
test "$(systemctl show -p ActiveState --value suricata-ai-capture.service)" = "$state_before"
test "$(systemctl show -p SubState --value suricata-ai-capture.service)" = "$substate_before"
if [ "$current_kind" = symlink ]; then test -L "$ROOT/current"; test "$(readlink -e "$ROOT/current")" = "$current_before"; else test ! -e "$ROOT/current"; fi
rm -f -- "$ARCHIVE"
rmdir -- "$STAGE"
printf '%s\n' VM1_RELEASE_PASS=TRUE
'@.Replace('__ROOT__', $ShowcaseRoot).Replace('__RELEASE__', $ReleasePath).Replace('__STAGE__', $RemoteStagePath).Replace('__ARCHIVE__', $ExpectedArchiveSha256).Replace('__UNIT__', $ExpectedUnitSha256)
}

if (-not $Execute) {
    Write-Output 'Plan only. Re-run with -Execute after owner authorization.'
    Write-Output ("branch={0}; verified_head={1}; release_commit={2}" -f $ExpectedBranch, $VerifiedControllerHead, $PinnedReleaseCommit)
    exit 0
}

Assert-LocalPinnedState
$archive = $null
try {
    $archive = New-PinnedArchive
    Invoke-RemoteBash (Get-RemoteStagePayload)
    & scp -B -o BatchMode=yes -o StrictHostKeyChecking=yes $archive "$Vm1Target`:$RemoteStagePath/source.tar"
    if ($LASTEXITCODE -ne 0) { throw "Archive transfer failed with exit code $LASTEXITCODE." }
    Invoke-RemoteBash (Get-RemotePublishPayload)
}
finally {
    if ($null -ne $archive -and (Test-Path -LiteralPath $archive)) {
        Remove-Item -LiteralPath $archive -Force
    }
}
