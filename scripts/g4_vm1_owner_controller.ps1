[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ApprovedHead,
    [switch]$ResumeRetargetOnly,
    [string]$RepositoryRoot = 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ExpectedBranch = 'feat/complete-suricata-ai-e2e'
$Vm1Target = 'tanhv@192.168.10.10'
$ExpectedUnitSha256 = '42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de'
$OriginalWorkingDirectory = '/home/tanhv/suricata-ai-tools'
$TargetWorkingDirectory = '/home/tanhv/suricata-ai-showcase/releases/08174bf8a9af83c588b48f1c95f7647c22db5118'
$ExpectedCaptureSha256 = '1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3'

$Prepare = Join-Path $RepositoryRoot 'scripts/g4_prepare_vm1_release.ps1'
$Inspect = Join-Path $RepositoryRoot 'scripts/g4_inspect_vm1_capture.ps1'
$Retarget = Join-Path $RepositoryRoot 'scripts/g4_retarget_vm1_capture_dropin.ps1'

$ExpectedHashes = @{
    'scripts/g4_inspect_vm1_capture.ps1' = 'a237c6e544786db8400506d4c14a7ec385700a6aa90039bf361db631999774ec'
    'scripts/g4_prepare_vm1_release.ps1' = 'e7b800d02a96002959e7aef060d9556d1a150fca8764dae79bed132199a32ff6'
    'scripts/g4_retarget_vm1_capture_dropin.ps1' = 'e275be2abd363a791ca5c703fa94aad6e0225c80965675b1b3a0a87f6ae99284'
}

$SecurityFields = @(
    'ExecStart', 'ExecStartPre', 'ExecStartPost', 'User', 'Group',
    'CapabilityBoundingSet', 'AmbientCapabilities', 'NoNewPrivileges',
    'ProtectSystem', 'ProtectHome', 'PrivateTmp',
    'RestrictAddressFamilies', 'TimeoutStartUSec', 'FragmentPath'
)

function Get-ReportField {
    param(
        [object[]]$Lines,
        [string]$Name
    )

    $Prefix = "$Name="
    foreach ($Line in $Lines) {
        $Text = [string]$Line
        if ($Text.StartsWith($Prefix)) {
            return $Text.Substring($Prefix.Length)
        }
    }

    throw "Missing inspection field: $Name"
}

function Require-Marker {
    param(
        [object[]]$Lines,
        [string]$Marker
    )

    $Normalized = ($Lines -join "`n") -replace "`r`n?", "`n"
    if (-not ($Normalized -match "(?m)^$([regex]::Escape($Marker))$")) {
        throw "Required marker was not observed: $Marker"
    }
}

function Show-Output {
    param([object[]]$Lines)
    $Lines | ForEach-Object { Write-Host $_ }
}

Push-Location $RepositoryRoot
try {
    if ((git branch --show-current) -ne $ExpectedBranch) {
        throw "Wrong repository branch."
    }
    if ((git rev-parse HEAD) -ne $ApprovedHead) {
        throw "HEAD is not the approved controller commit."
    }

    git status --short | Write-Host

    foreach ($RelativePath in $ExpectedHashes.Keys) {
        $ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $RepositoryRoot $RelativePath)).Hash.ToLowerInvariant()
        if ($ActualHash -ne $ExpectedHashes[$RelativePath]) {
            throw "Script hash mismatch: $RelativePath"
        }
    }

    if ($ResumeRetargetOnly) {
        Write-Host 'Resume-retarget-only mode: VM1 release publication is skipped.'
    }
    else {
        $PlanOutput = & $Prepare -RepositoryRoot $RepositoryRoot 2>&1
        $PlanExit = $LASTEXITCODE
        Show-Output $PlanOutput
        if ($PlanExit -ne 0) {
            throw 'VM1 release plan failed.'
        }

        if ((Read-Host 'Type VM1_RELEASE_APPROVE=YES to publish the prepared release') -ne 'YES') {
            throw 'VM1 release publication was not approved.'
        }

        $ReleaseOutput = & $Prepare -RepositoryRoot $RepositoryRoot -Execute 2>&1
        $ReleaseExit = $LASTEXITCODE
        Show-Output $ReleaseOutput
        if ($ReleaseExit -ne 0) {
            throw 'VM1 release publication command failed.'
        }
        Require-Marker $ReleaseOutput 'VM1_RELEASE_PASS=TRUE'
        Write-Host 'VM1_RELEASE_PASS=TRUE'
    }

    $BeforeOutput = & $Inspect -Vm1Target $Vm1Target 2>&1
    $BeforeExit = $LASTEXITCODE
    Show-Output $BeforeOutput
    if ($BeforeExit -ne 0) {
        throw 'Pre-install VM1 inspection failed.'
    }
    if ((Get-ReportField $BeforeOutput 'published_release_hashes_pass') -ne 'TRUE') {
        throw 'Published VM1 release hash verification failed.'
    }
    if ((Get-ReportField $BeforeOutput 'published_release_path') -ne $TargetWorkingDirectory) {
        throw 'Published VM1 release path mismatch.'
    }
    if ((Get-ReportField $BeforeOutput 'published_capture_sha256') -ne $ExpectedCaptureSha256 -or
        (Get-ReportField $BeforeOutput 'published_handoff_sha256') -ne '0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de') {
        throw 'Published VM1 release module hash mismatch.'
    }
    if ($ResumeRetargetOnly) {
        Write-Host 'VM1_RELEASE_RESUME_PASS=TRUE'
    }

    if ((Get-ReportField $BeforeOutput 'unit_sha256') -ne $ExpectedUnitSha256) {
        throw 'Original unit hash mismatch.'
    }
    if ((Get-ReportField $BeforeOutput 'effective_working_directory') -ne $OriginalWorkingDirectory) {
        throw 'Original WorkingDirectory mismatch.'
    }
    if ((Get-ReportField $BeforeOutput 'DropInPaths') -ne '') {
        throw 'Unexpected pre-existing drop-in.'
    }
    if ((Get-ReportField $BeforeOutput 'capture_active_state') -ne 'inactive' -or
        (Get-ReportField $BeforeOutput 'capture_sub_state') -ne 'dead') {
        throw 'Capture service is not inactive/dead.'
    }
    if ((Get-ReportField $BeforeOutput 'tcpdump_process') -ne 'absent') {
        throw 'tcpdump is running.'
    }

    $BeforeCurrentTarget = Get-ReportField $BeforeOutput 'current_target'
    $BeforeSecurity = @{}
    foreach ($Field in $SecurityFields) {
        $BeforeSecurity[$Field] = Get-ReportField $BeforeOutput $Field
    }

    if ((Read-Host 'Type VM1_CAPTURE_DROPIN_INSTALL_APPROVE=YES to install the reviewed drop-in') -ne 'YES') {
        throw 'VM1 drop-in installation was not approved.'
    }

    $InstallOutput = & $Retarget -Vm1Target $Vm1Target -Install -Execute 2>&1
    $InstallExit = $LASTEXITCODE
    Show-Output $InstallOutput
    if ($InstallExit -ne 0) {
        throw 'VM1 drop-in installation command failed.'
    }
    Require-Marker $InstallOutput 'VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE'
    Write-Host 'VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE'

    $AfterOutput = & $Inspect -Vm1Target $Vm1Target 2>&1
    $AfterExit = $LASTEXITCODE
    Show-Output $AfterOutput
    if ($AfterExit -ne 0) {
        throw 'Post-install VM1 inspection failed.'
    }

    if ((Get-ReportField $AfterOutput 'unit_sha256') -ne $ExpectedUnitSha256) {
        throw 'Original unit changed.'
    }
    if ((Get-ReportField $AfterOutput 'current_target') -ne $BeforeCurrentTarget) {
        throw 'Current pointer changed.'
    }
    if ((Get-ReportField $AfterOutput 'effective_working_directory') -ne $TargetWorkingDirectory) {
        throw 'Effective WorkingDirectory does not target the approved release.'
    }
    if ((Get-ReportField $AfterOutput 'source_module_path') -ne "$TargetWorkingDirectory/backend/pcap_capture.py") {
        throw 'Effective module path mismatch.'
    }
    if ((Get-ReportField $AfterOutput 'source_module_sha256') -ne $ExpectedCaptureSha256) {
        throw 'Effective module hash mismatch.'
    }
    if ((Get-ReportField $AfterOutput 'capture_active_state') -ne 'inactive' -or
        (Get-ReportField $AfterOutput 'capture_sub_state') -ne 'dead' -or
        (Get-ReportField $AfterOutput 'tcpdump_process') -ne 'absent') {
        throw 'Post-install service state is unsafe.'
    }

    foreach ($Field in $SecurityFields) {
        if ((Get-ReportField $AfterOutput $Field) -ne $BeforeSecurity[$Field]) {
            throw "Security property changed: $Field"
        }
    }

    Write-Host 'VM1_EFFECTIVE_MODULE_PASS=TRUE'
    Write-Host 'VM1_SECURITY_PROPERTIES_UNCHANGED=TRUE'
    Write-Host 'VM1_READY_FOR_G4=TRUE'
}
finally {
    Pop-Location
}
