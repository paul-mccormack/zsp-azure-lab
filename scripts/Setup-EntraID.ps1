#Requires -Version 7.0
<#
.SYNOPSIS
    Creates Entra ID objects for Zero Standing Privilege lab.

.DESCRIPTION
    Creates the following Entra ID objects with retry logic for eventual consistency:
    - SG-Intune-Admins-ZSP: Security group for Intune Administrator role
    - SG-Security-Reader-ZSP: Security group for Security Reader role
    - Activates and assigns directory roles to groups
    - Backup service principal with zero initial permissions

.PARAMETER ProjectName
    Project name for resource naming.

.PARAMETER MaxRetries
    Maximum retry attempts for propagation delays. Default: 10

.PARAMETER RetryDelaySeconds
    Seconds to wait between retries. Default: 10

.OUTPUTS
    Key=Value pairs for use by other scripts:
    - INTUNE_ADMIN_GROUP_ID
    - SECURITY_READER_GROUP_ID
    - BACKUP_SP_OBJECT_ID
    - BACKUP_SP_CLIENT_ID
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProjectName,

    [Parameter()]
    [int]$MaxRetries = 10,

    [Parameter()]
    [int]$RetryDelaySeconds = 10
)

$ErrorActionPreference = 'Stop'

# Well-known directory role template IDs
$IntuneAdminRoleTemplateId = '3a2c62db-5318-420d-8d74-23affee5d9d5'
$SecurityReaderRoleTemplateId = '5d6b6bb7-de71-4623-b4af-96380a352509'

function Wait-ForObject {
    param(
        [string]$ObjectType,
        [string]$ObjectId,
        [int]$MaxRetries,
        [int]$RetryDelaySeconds
    )

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            switch ($ObjectType) {
                'group' {
                    $result = az ad group show --group $ObjectId --output json 2>$null | ConvertFrom-Json
                }
                'sp' {
                    $result = az ad sp show --id $ObjectId --output json 2>$null | ConvertFrom-Json
                }
                'app' {
                    $result = az ad app show --id $ObjectId --output json 2>$null | ConvertFrom-Json
                }
            }
            if ($result) {
                return $true
            }
        }
        catch {
            # Object not yet available
        }

        if ($i -lt $MaxRetries) {
            Write-Host "    Waiting for $ObjectType to propagate (attempt $i/$MaxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    return $false
}

Write-Host "Creating Entra ID objects..." -ForegroundColor Yellow

# Create Intune Admins ZSP Group
Write-Host "  Creating SG-Intune-Admins-ZSP group..." -ForegroundColor Cyan
$intuneGroupName = "SG-Intune-Admins-ZSP"
$existingIntuneGroup = az ad group list --display-name $intuneGroupName --output json 2>$null | ConvertFrom-Json

if ($existingIntuneGroup -and $existingIntuneGroup.Count -gt 0) {
    $intuneGroupId = $existingIntuneGroup[0].id
    Write-Host "    Group already exists: $intuneGroupId" -ForegroundColor Green
}
else {
    $intuneGroup = az ad group create `
        --display-name $intuneGroupName `
        --description "ZSP group for Intune administration. Members are added/removed automatically by ZSP Gateway. Do not modify manually." `
        --mail-nickname "SG-Intune-Admins-ZSP" `
        --is-assignable-to-role true `
        --output json 2>&1 | ConvertFrom-Json

    if (-not $intuneGroup.id) {
        throw "Failed to create Intune Admins group"
    }
    $intuneGroupId = $intuneGroup.id
    Write-Host "    Created: $intuneGroupId" -ForegroundColor Green

    # Wait for propagation
    if (-not (Wait-ForObject -ObjectType 'group' -ObjectId $intuneGroupId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Group failed to propagate: $intuneGroupId"
    }
}

# Create Security Reader ZSP Group
Write-Host "  Creating SG-Security-Reader-ZSP group..." -ForegroundColor Cyan
$securityGroupName = "SG-Security-Reader-ZSP"
$existingSecurityGroup = az ad group list --display-name $securityGroupName --output json 2>$null | ConvertFrom-Json

if ($existingSecurityGroup -and $existingSecurityGroup.Count -gt 0) {
    $securityGroupId = $existingSecurityGroup[0].id
    Write-Host "    Group already exists: $securityGroupId" -ForegroundColor Green
}
else {
    $securityGroup = az ad group create `
        --display-name $securityGroupName `
        --description "ZSP group for Security Reader access. Members are added/removed automatically by ZSP Gateway." `
        --mail-nickname "SG-Security-Reader-ZSP" `
        --is-assignable-to-role true `
        --output json 2>&1 | ConvertFrom-Json

    if (-not $securityGroup.id) {
        throw "Failed to create Security Reader group"
    }
    $securityGroupId = $securityGroup.id
    Write-Host "    Created: $securityGroupId" -ForegroundColor Green

    # Wait for propagation
    if (-not (Wait-ForObject -ObjectType 'group' -ObjectId $securityGroupId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Group failed to propagate: $securityGroupId"
    }
}

# Activate and assign Intune Administrator role
Write-Host "  Activating Intune Administrator role..." -ForegroundColor Cyan
$intuneRole = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$IntuneAdminRoleTemplateId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $intuneRole.value -or $intuneRole.value.Count -eq 0) {
    # Activate the role
    $activateBody = @{ roleTemplateId = $IntuneAdminRoleTemplateId } | ConvertTo-Json -Compress
    $intuneRole = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        --headers "Content-Type=application/json" `
        --body $activateBody `
        --output json 2>&1 | ConvertFrom-Json

    if (-not $intuneRole.id) {
        throw "Failed to activate Intune Administrator role"
    }
    $intuneRoleId = $intuneRole.id
    Write-Host "    Activated role: $intuneRoleId" -ForegroundColor Green
}
else {
    $intuneRoleId = $intuneRole.value[0].id
    Write-Host "    Role already active: $intuneRoleId" -ForegroundColor Green
}

# Assign group to Intune Administrator role
Write-Host "  Assigning group to Intune Administrator role..." -ForegroundColor Cyan
$existingIntuneMember = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles/$intuneRoleId/members?`$filter=id eq '$intuneGroupId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $existingIntuneMember.value -or $existingIntuneMember.value.Count -eq 0) {
    $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$intuneGroupId" } | ConvertTo-Json -Compress
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles/$intuneRoleId/members/`$ref" `
        --headers "Content-Type=application/json" `
        --body $memberBody `
        --output none 2>&1
    Write-Host "    Assignment created" -ForegroundColor Green
}
else {
    Write-Host "    Already assigned" -ForegroundColor Green
}

# Activate and assign Security Reader role
Write-Host "  Activating Security Reader role..." -ForegroundColor Cyan
$securityRole = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$SecurityReaderRoleTemplateId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $securityRole.value -or $securityRole.value.Count -eq 0) {
    # Activate the role
    $activateBody = @{ roleTemplateId = $SecurityReaderRoleTemplateId } | ConvertTo-Json -Compress
    $securityRole = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        --headers "Content-Type=application/json" `
        --body $activateBody `
        --output json 2>&1 | ConvertFrom-Json

    if (-not $securityRole.id) {
        throw "Failed to activate Security Reader role"
    }
    $securityRoleId = $securityRole.id
    Write-Host "    Activated role: $securityRoleId" -ForegroundColor Green
}
else {
    $securityRoleId = $securityRole.value[0].id
    Write-Host "    Role already active: $securityRoleId" -ForegroundColor Green
}

# Assign group to Security Reader role
Write-Host "  Assigning group to Security Reader role..." -ForegroundColor Cyan
$existingSecurityMember = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/directoryRoles/$securityRoleId/members?`$filter=id eq '$securityGroupId'" `
    --output json 2>$null | ConvertFrom-Json

if (-not $existingSecurityMember.value -or $existingSecurityMember.value.Count -eq 0) {
    $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$securityGroupId" } | ConvertTo-Json -Compress
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/directoryRoles/$securityRoleId/members/`$ref" `
        --headers "Content-Type=application/json" `
        --body $memberBody `
        --output none 2>&1
    Write-Host "    Assignment created" -ForegroundColor Green
}
else {
    Write-Host "    Already assigned" -ForegroundColor Green
}

# Create Backup Service Principal
Write-Host "  Creating backup service principal..." -ForegroundColor Cyan
$backupAppName = "$ProjectName-backup-sp"
$existingBackupApp = az ad app list --display-name $backupAppName --output json 2>$null | ConvertFrom-Json

if ($existingBackupApp -and $existingBackupApp.Count -gt 0) {
    $backupAppId = $existingBackupApp[0].appId
    $backupSp = az ad sp show --id $backupAppId --output json 2>$null | ConvertFrom-Json
    $backupSpObjectId = $backupSp.id
    Write-Host "    App already exists: $backupAppId" -ForegroundColor Green
    Write-Host "    SP object ID: $backupSpObjectId" -ForegroundColor Green
}
else {
    # Create application registration
    $backupApp = az ad app create `
        --display-name $backupAppName `
        --output json 2>&1 | ConvertFrom-Json

    if (-not $backupApp.appId) {
        throw "Failed to create backup application"
    }
    $backupAppId = $backupApp.appId
    Write-Host "    Created app: $backupAppId" -ForegroundColor Green

    # Wait for app to propagate
    if (-not (Wait-ForObject -ObjectType 'app' -ObjectId $backupAppId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Application failed to propagate: $backupAppId"
    }

    # Create service principal
    $backupSp = az ad sp create --id $backupAppId --output json 2>&1 | ConvertFrom-Json

    if (-not $backupSp.id) {
        throw "Failed to create backup service principal"
    }
    $backupSpObjectId = $backupSp.id
    Write-Host "    Created SP: $backupSpObjectId" -ForegroundColor Green

    # Wait for SP to propagate
    if (-not (Wait-ForObject -ObjectType 'sp' -ObjectId $backupSpObjectId -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds)) {
        throw "Service principal failed to propagate: $backupSpObjectId"
    }
}

Write-Host "Entra ID objects created successfully" -ForegroundColor Green

# Output configuration for other scripts
Write-Output "INTUNE_ADMIN_GROUP_ID=$intuneGroupId"
Write-Output "SECURITY_READER_GROUP_ID=$securityGroupId"
Write-Output "BACKUP_SP_OBJECT_ID=$backupSpObjectId"
Write-Output "BACKUP_SP_CLIENT_ID=$backupAppId"

exit 0
