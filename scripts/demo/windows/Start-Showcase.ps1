[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path, [switch]$OpenTerminals, [switch]$AllowDetached)
$ErrorActionPreference = 'Stop'
$branch = (git -C $RepositoryRoot branch --show-current).Trim()
if ($branch -ne 'feat/complete-suricata-ai-e2e' -and -not ($AllowDetached -and [string]::IsNullOrWhiteSpace($branch))) { throw "Refusing deployment from branch '$branch'. Use the exact showcase branch or -AllowDetached for a pinned commit." }
if (git -C $RepositoryRoot status --porcelain) { throw 'Refusing deployment with a dirty worktree.' }
$commit = (git -C $RepositoryRoot rev-parse HEAD).Trim()
$archive = Join-Path ([IO.Path]::GetTempPath()) "suricata-showcase-$commit.tar"
try {
    git -C $RepositoryRoot archive --format=tar --output=$archive HEAD
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    $sha = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    $targets = @(@{Alias='suricata-vm1';Root='/home/tanhv/suricata-ai-showcase'},@{Alias='suricata-vm2';Root='/home/kali/suricata-ai-showcase'},@{Alias='suricata-vm3';Root='/home/tanhv/suricata-ai-showcase'})
    foreach ($target in $targets) {
        $alias=$target.Alias; $root=$target.Root
        ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $alias "mkdir -p '$root/releases/$commit' '$root/runtime' '$root/evidence'"
        if ($LASTEXITCODE -ne 0) { throw "Cannot prepare $alias" }
        scp -q -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $archive "$alias`:/tmp/suricata-showcase-$commit.tar"
        if ($LASTEXITCODE -ne 0) { throw "Cannot transfer source to $alias" }
        $remoteCommand = @'
set -eu
archive='__ARCHIVE__'
root='__ROOT__'
expected_commit='__COMMIT__'
expected_sha='__SHA__'
tar -xf "$archive" -C "$root/releases/$expected_commit"
actual_sha=$(sha256sum "$archive" | awk '{print $1}')
test "$actual_sha" = "$expected_sha"
test -f "$root/releases/$expected_commit/pyproject.toml"
printf '%s\n' "$expected_commit" > "$root/runtime/source-commit.txt"
printf '%s\n' "$actual_sha" > "$root/runtime/source-archive-sha256.txt"
ln -sfn "$root/releases/$expected_commit" "$root/current"
test "$(cat "$root/runtime/source-commit.txt")" = "$expected_commit"
rm -f "$archive"
'@
        $remoteCommand = $remoteCommand.Replace('__ARCHIVE__', "/tmp/suricata-showcase-$commit.tar").Replace('__ROOT__', $root).Replace('__COMMIT__', $commit).Replace('__SHA__', $sha)
        ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $alias $remoteCommand
        if ($LASTEXITCODE -ne 0) { throw "Cannot verify source on $alias" }
        Write-Host "$alias deployed commit $commit; archive SHA256 $sha"
    }
    & "$PSScriptRoot/Connect-ThreeVMs.ps1" -OpenTerminals:$OpenTerminals
} finally { if (Test-Path -LiteralPath $archive) { [IO.File]::Delete($archive) } }
