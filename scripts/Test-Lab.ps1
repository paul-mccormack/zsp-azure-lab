#Requires -Version 7.0
<#
.SYNOPSIS
    Runs smoke tests on the deployed ZSP lab.

.DESCRIPTION
    Tests the following functionality:
    1. Health endpoint returns 200
    2. NHI access endpoint grants temporary access
    3. Role assignment is created on target resource
    4. (Optional) Wait for expiry and verify revocation

.PARAMETER FunctionAppUrl
    Base URL of the Function App.

.PARAMETER BackupSpObjectId
    Object ID of the backup service principal for testing.

.PARAMETER KeyVaultResourceId
    Resource ID of the Key Vault for testing access grants.

.PARAMETER WaitForRevocation
    Wait for access to expire and verify revocation (adds delay).

.PARAMETER TestDurationMinutes
    Duration in minutes for test access grant. Default: 2

.EXAMPLE
    ./Test-Lab.ps1 -FunctionAppUrl "https://zsp-lab-gateway.azurewebsites.net" `
                   -BackupSpObjectId "abc123" `
                   -KeyVaultResourceId "/subscriptions/.../Microsoft.KeyVault/vaults/..."
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FunctionAppUrl,

    [Parameter(Mandatory)]
    [string]$BackupSpObjectId,

    [Parameter(Mandatory)]
    [string]$KeyVaultResourceId,

    [Parameter()]
    [switch]$WaitForRevocation,

    [Parameter()]
    [int]$TestDurationMinutes = 2
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== ZSP Lab Smoke Tests ===" -ForegroundColor Cyan

$passed = 0
$failed = 0

# Test 1: Health endpoint
Write-Host "`nTest 1: Health endpoint" -ForegroundColor Yellow
try {
    $healthUrl = "$FunctionAppUrl/api/health"
    $healthResponse = Invoke-RestMethod -Uri $healthUrl -Method GET -TimeoutSec 30

    if ($healthResponse.status -eq 'healthy') {
        Write-Host "  PASSED: Health check returned healthy" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host "  FAILED: Unexpected health status: $($healthResponse.status)" -ForegroundColor Red
        $failed++
    }
}
catch {
    Write-Host "  FAILED: Health check error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Test 2: NHI Access endpoint
Write-Host "`nTest 2: NHI Access grant" -ForegroundColor Yellow
$assignmentId = $null
try {
    $nhiUrl = "$FunctionAppUrl/api/nhi-access"
    $body = @{
        sp_object_id = $BackupSpObjectId
        scope = $KeyVaultResourceId
        role = "Key Vault Secrets User"
        duration_minutes = $TestDurationMinutes
        workflow_id = "smoke-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    } | ConvertTo-Json

    $nhiResponse = Invoke-RestMethod -Uri $nhiUrl -Method POST -Body $body -ContentType "application/json" -TimeoutSec 60

    if ($nhiResponse.status -eq 'granted') {
        Write-Host "  PASSED: Access granted" -ForegroundColor Green
        Write-Host "    Assignment ID: $($nhiResponse.assignment_id)" -ForegroundColor Gray
        Write-Host "    Expires at: $($nhiResponse.expires_at)" -ForegroundColor Gray
        $assignmentId = $nhiResponse.assignment_id
        $passed++
    }
    else {
        Write-Host "  FAILED: Unexpected status: $($nhiResponse.status)" -ForegroundColor Red
        $failed++
    }
}
catch {
    Write-Host "  FAILED: NHI access error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Test 3: Verify role assignment exists
Write-Host "`nTest 3: Verify role assignment" -ForegroundColor Yellow
try {
    $assignments = az role assignment list `
        --assignee $BackupSpObjectId `
        --scope $KeyVaultResourceId `
        --output json 2>$null | ConvertFrom-Json

    $kvSecretUser = $assignments | Where-Object { $_.roleDefinitionName -eq 'Key Vault Secrets User' }

    if ($kvSecretUser) {
        Write-Host "  PASSED: Role assignment found" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host "  FAILED: Role assignment not found" -ForegroundColor Red
        Write-Host "    Assignments: $($assignments | ConvertTo-Json -Compress)" -ForegroundColor Gray
        $failed++
    }
}
catch {
    Write-Host "  FAILED: Role verification error: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Test 4: Wait for revocation (optional)
if ($WaitForRevocation) {
    Write-Host "`nTest 4: Wait for revocation" -ForegroundColor Yellow
    $waitSeconds = ($TestDurationMinutes * 60) + 30  # Add 30 seconds buffer
    Write-Host "  Waiting $waitSeconds seconds for access to expire..." -ForegroundColor Gray

    Start-Sleep -Seconds $waitSeconds

    try {
        $assignments = az role assignment list `
            --assignee $BackupSpObjectId `
            --scope $KeyVaultResourceId `
            --output json 2>$null | ConvertFrom-Json

        $kvSecretUser = $assignments | Where-Object { $_.roleDefinitionName -eq 'Key Vault Secrets User' }

        if (-not $kvSecretUser) {
            Write-Host "  PASSED: Role assignment revoked" -ForegroundColor Green
            $passed++
        }
        else {
            Write-Host "  FAILED: Role assignment still exists after expiry" -ForegroundColor Red
            $failed++
        }
    }
    catch {
        Write-Host "  FAILED: Revocation verification error: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}
else {
    Write-Host "`nTest 4: Skipped (use -WaitForRevocation to test)" -ForegroundColor Gray
}

# Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })

if ($failed -gt 0) {
    exit 1
}
exit 0
