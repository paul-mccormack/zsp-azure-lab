// Zero Standing Privilege Lab - Monitoring Infrastructure
// Deploys: Log Analytics Workspace, Data Collection Endpoint

targetScope = 'resourceGroup'

@description('Project name for resource naming')
param projectName string

@description('Azure region')
param location string

@description('Tags for all resources')
param tags object = {}

// Merge default tags
var resourceTags = union({
  project: projectName
  environment: 'lab'
  purpose: 'zero-standing-privilege-demo'
}, tags)

// Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${projectName}-logs'
  location: location
  tags: resourceTags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Data Collection Endpoint
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: '${projectName}-dce'
  location: location
  tags: resourceTags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// Outputs
output logAnalyticsWorkspaceId string = logAnalytics.id
output logAnalyticsWorkspaceCustomerId string = logAnalytics.properties.customerId
output logAnalyticsWorkspaceName string = logAnalytics.name
output dataCollectionEndpointId string = dataCollectionEndpoint.id
output dataCollectionEndpointUrl string = dataCollectionEndpoint.properties.logsIngestion.endpoint
