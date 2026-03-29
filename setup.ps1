[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$KEY_NAME,

    [Parameter(Mandatory = $true)]
    [string]$IP_ADDRESS,

    [Parameter(Mandatory = $true)]
    [string]$VM_USER
)

$ErrorActionPreference = 'Stop'

$HOST_ALIAS = if ($KEY_NAME -match '_key$') { $KEY_NAME -replace '_key$', '' } else { $KEY_NAME }

function Set-RestrictedDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$User
    )

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $User,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.SetAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}

function Set-RestrictedFileAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$User
    )

    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $User,
        [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.SetAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}

function Test-HostAliasLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Line,

        [Parameter(Mandatory = $true)]
        [string]$Alias
    )

    if ($Line -notmatch '^\s*Host\s+') {
        return $false
    }

    $tokens = ($Line -replace '^\s*Host\s+', '').Trim() -split '\s+'
    foreach ($token in $tokens) {
        if ($token -ieq $Alias) {
            return $true
        }
    }

    return $false
}

$homeDir = [Environment]::GetFolderPath('UserProfile')
$downloadsDir = Join-Path $homeDir 'Downloads'
$sshDir = Join-Path $homeDir '.ssh'
$provisionedDir = Join-Path $sshDir 'provisioned_keys'
$sourceKeyPath = Join-Path $downloadsDir $KEY_NAME
$destinationKeyPath = Join-Path $provisionedDir $KEY_NAME
$configPath = Join-Path $sshDir 'config'
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
New-Item -ItemType Directory -Path $provisionedDir -Force | Out-Null

Set-RestrictedDirectoryAcl -Path $sshDir -User $currentUser
Set-RestrictedDirectoryAcl -Path $provisionedDir -User $currentUser

if (Test-Path -LiteralPath $sourceKeyPath -PathType Leaf) {
    Move-Item -LiteralPath $sourceKeyPath -Destination $destinationKeyPath -Force
}
elseif (-not (Test-Path -LiteralPath $destinationKeyPath -PathType Leaf)) {
    throw "Key not found at '$sourceKeyPath' or '$destinationKeyPath'."
}

Set-RestrictedFileAcl -Path $destinationKeyPath -User $currentUser

if (-not (Test-Path -LiteralPath $configPath)) {
    New-Item -ItemType File -Path $configPath -Force | Out-Null
}

$configLines = @(Get-Content -LiteralPath $configPath -ErrorAction SilentlyContinue)
$hostStartIndexes = @()

for ($i = 0; $i -lt $configLines.Count; $i++) {
    if ($configLines[$i] -match '^\s*Host\s+') {
        $hostStartIndexes += $i
    }
}

$targetStart = -1
$targetEnd = -1

for ($j = 0; $j -lt $hostStartIndexes.Count; $j++) {
    $start = $hostStartIndexes[$j]
    $end = if ($j -lt ($hostStartIndexes.Count - 1)) { $hostStartIndexes[$j + 1] - 1 } else { $configLines.Count - 1 }

    if (Test-HostAliasLine -Line $configLines[$start] -Alias $HOST_ALIAS) {
        $targetStart = $start
        $targetEnd = $end
        break
    }
}

if ($targetStart -ge 0) {
    $hostnameUpdated = $false

    for ($k = $targetStart + 1; $k -le $targetEnd; $k++) {
        if ($configLines[$k] -match '^\s*HostName\s+') {
            $configLines[$k] = "    HostName $IP_ADDRESS"
            $hostnameUpdated = $true
            break
        }
    }

    if (-not $hostnameUpdated) {
        $before = @()
        $after = @()

        if ($targetStart -ge 0) {
            $before = $configLines[0..$targetStart]
        }
        if (($targetStart + 1) -le ($configLines.Count - 1)) {
            $after = $configLines[($targetStart + 1)..($configLines.Count - 1)]
        }

        $configLines = @($before + "    HostName $IP_ADDRESS" + $after)
    }
}
else {
    $newBlock = @(
        "Host $HOST_ALIAS",
        "    HostName $IP_ADDRESS",
        "    User $VM_USER",
        "    IdentityFile $destinationKeyPath",
        "    IdentitiesOnly yes"
    )

    if ($configLines.Count -gt 0 -and $configLines[-1].Trim() -ne '') {
        $configLines += ''
    }

    $configLines += $newBlock
}

$configLines | Set-Content -LiteralPath $configPath -Encoding ascii

Write-Host "SSH key setup complete. Connect with: ssh $HOST_ALIAS"
