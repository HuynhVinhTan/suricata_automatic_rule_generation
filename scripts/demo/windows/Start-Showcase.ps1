[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path, [switch]$OpenTerminals)
$ErrorActionPreference = 'Stop'
$branch = (git -C $RepositoryRoot branch --show-current).Trim()
if ($branch -ne 'feat/complete-suricata-ai-e2e') { throw "Refusing deployment from branch '$branch'." }
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
        ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $alias "tar -xf '/tmp/suricata-showcase-$commit.tar' -C '$root/releases/$commit'; sha256sum '/tmp/suricata-showcase-$commit.tar'; rm -f '/tmp/suricata-showcase-$commit.tar'; printf '%s\n' '$commit' > '$root/runtime/source-commit.txt'; printf '%s\n' '$sha' > '$root/runtime/source-archive-sha256.txt'; ln -sfn '$root/releases/$commit' '$root/current'; test -f '$root/current/pyproject.toml'"
        if ($LASTEXITCODE -ne 0) { throw "Cannot verify source on $alias" }
        Write-Host "$alias deployed commit $commit; archive SHA256 $sha"
    }
    & "$PSScriptRoot/Connect-ThreeVMs.ps1" -OpenTerminals:$OpenTerminals
} finally { if (Test-Path -LiteralPath $archive) { [IO.File]::Delete($archive) } }
