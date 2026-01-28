// Zero Standing Privilege Lab - Parameters
// Copy this file and customize for your environment

using './main.bicep'

// Required: Deployer's Entra ID object ID (az ad signed-in-user show --query id -o tsv)
param deployerPrincipalId = ''

// Project naming (must be lowercase alphanumeric with hyphens, 3-20 chars)
param projectName = 'zsp-lab'

// Azure region
param location = 'eastus'

// Maximum access duration in minutes (5-1440)
param maxAccessDurationMinutes = 480

// Optional: Additional tags
param tags = {
  owner: ''
  costCenter: ''
}
