<#
.SYNOPSIS
    Creates Azure AD B2C app registrations for implicit and authorization code with PKCE demos.

.DESCRIPTION
    Creates or updates separate implicit and PKCE clients plus a shared demo
    API, exposes a delegated demo.read scope, pre-authorizes both clients,
    grants tenant-wide delegated consent, and writes demo-settings.js. The B2C
    user flow or custom policy must already exist.

.EXAMPLE
    .\Setup-B2CAuthCodeDemo.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -PolicyId "B2C_1_susi"

.NOTES
    Requires Microsoft.Graph.Authentication:
      Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$PolicyId,

    [string]$TenantDomain,

    [string]$PkceClientDisplayName = 'B2C PKCE Visual Demo',

    [string]$ImplicitClientDisplayName = 'B2C Implicit Visual Demo',

    [string]$ApiDisplayName = 'B2C PKCE Visual Demo API',

    [ValidatePattern('^http://localhost(:\d+)?(/.*)?$')]
    [string]$RedirectUri = 'http://localhost:8400/index.html',

    [bool]$RequestRefreshToken = $true,

    [switch]$Recreate
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$scopeId = [guid]::NewGuid().ToString()
$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphOidcScopes = @{
    openid = '37f7f235-527c-4136-accd-4a02d197296e'
    profile = '14dad69e-099b-42c9-810b-d002981feec1'
    offline_access = '7427e0e9-2fba-42fe-b0c0-848c9e6a8182'
}

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host "    $Message" -ForegroundColor Green }

function Escape-ODataString {
    param([string]$Value)
    return $Value.Replace("'", "''")
}

function Get-AppByDisplayName {
    param([string]$DisplayName)
    $escapedName = Escape-ODataString $DisplayName
    $filter = [uri]::EscapeDataString("displayName eq '$escapedName'")
    $result = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter&`$select=id,appId,displayName"
    return @($result.value) | Select-Object -First 1
}

function Ensure-ServicePrincipal {
    param(
        [string]$AppId,
        [string]$SignInAudience
    )
    $filter = [uri]::EscapeDataString("appId eq '$AppId'")
    $result = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=id,appId,signInAudience"
    $servicePrincipal = @($result.value) | Select-Object -First 1
    if ($servicePrincipal -and $servicePrincipal.signInAudience -ne $SignInAudience) {
        Write-Step "Replacing service principal for $AppId to apply B2C sign-in audience"
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)"
        $servicePrincipal = $null
    }
    if (-not $servicePrincipal) {
        $servicePrincipal = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body @{ appId = $AppId }
    }
    return $servicePrincipal
}

function Invoke-GraphJson {
    param(
        [ValidateSet('POST', 'PATCH')]
        [string]$Method,
        [string]$Uri,
        [hashtable]$Body
    )
    $json = $Body | ConvertTo-Json -Depth 20
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType 'application/json'
}

function Grant-DelegatedConsent {
    param(
        [string]$ClientServicePrincipalId,
        [string]$ResourceServicePrincipalId,
        [string]$Scopes
    )
    $grantFilter = [uri]::EscapeDataString("clientId eq '$ClientServicePrincipalId' and resourceId eq '$ResourceServicePrincipalId'")
    $grantResult = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$grantFilter&`$select=id,scope"
    $permissionGrant = @($grantResult.value) | Select-Object -First 1
    if ($permissionGrant) {
        Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($permissionGrant.id)" -Body @{ scope = $Scopes } | Out-Null
    } else {
        Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body @{
            clientId = $ClientServicePrincipalId
            consentType = 'AllPrincipals'
            resourceId = $ResourceServicePrincipalId
            scope = $Scopes
        } | Out-Null
    }
}

function Ensure-ClientApplication {
    param(
        [string]$DisplayName,
        [ValidateSet('Implicit', 'Pkce')]
        [string]$Flow,
        [string]$ApiAppId,
        [string]$ApiScopeId,
        [string]$RedirectUri
    )

    $isImplicit = $Flow -eq 'Implicit'
    $requiredResourceAccess = @(
        @{
            resourceAppId = $ApiAppId
            resourceAccess = @(@{ id = $ApiScopeId; type = 'Scope' })
        }
    )
    if ($isImplicit) {
        $requiredResourceAccess += @{
            resourceAppId = $graphAppId
            resourceAccess = @(
                @{ id = $graphOidcScopes.openid; type = 'Scope' }
                @{ id = $graphOidcScopes.profile; type = 'Scope' }
            )
        }
    } else {
        $requiredResourceAccess += @{
            resourceAppId = $graphAppId
            resourceAccess = @(
                @{ id = $graphOidcScopes.offline_access; type = 'Scope' }
            )
        }
    }

    $body = @{
        displayName = $DisplayName
        signInAudience = 'AzureADandPersonalMicrosoftAccount'
        spa = @{ redirectUris = @($(if ($isImplicit) { @() } else { $RedirectUri })) }
        web = @{
            redirectUris = @($(if ($isImplicit) { $RedirectUri } else { @() }))
            implicitGrantSettings = @{
                enableAccessTokenIssuance = $isImplicit
                enableIdTokenIssuance = $isImplicit
            }
        }
        api = @{ requestedAccessTokenVersion = 2 }
        requiredResourceAccess = $requiredResourceAccess
    }

    $application = Get-AppByDisplayName $DisplayName
    if ($application) {
        Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($application.id)" -Body $body | Out-Null
    } else {
        $application = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $body
    }

    return [pscustomobject]@{
        Application = $application
        ServicePrincipal = Ensure-ServicePrincipal -AppId $application.appId -SignInAudience $body.signInAudience
    }
}

Write-Step 'Checking Microsoft Graph PowerShell support'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is required. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}

Write-Step "Connecting to tenant $TenantId"
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Organization.Read.All' -ContextScope Process -NoWelcome

try {
    if (-not $TenantDomain) {
        Write-Step 'Resolving the tenant initial domain'
        $organization = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,verifiedDomains'
        $TenantDomain = @($organization.value[0].verifiedDomains | Where-Object { $_.isInitial })[0].name
    }

    if (-not $TenantDomain -or -not $TenantDomain.EndsWith('.onmicrosoft.com')) {
        throw "TenantDomain must be the tenant's initial domain, for example contoso.onmicrosoft.com. Resolved value: '$TenantDomain'"
    }

    $tenantSubdomain = $TenantDomain.Substring(0, $TenantDomain.Length - '.onmicrosoft.com'.Length)
    if ($Recreate) {
        Write-Step 'Removing existing demo registrations so B2C can classify their initial manifests correctly'
        foreach ($displayName in @($PkceClientDisplayName, $ImplicitClientDisplayName, $ApiDisplayName)) {
            $existingApp = Get-AppByDisplayName $displayName
            if (-not $existingApp) { continue }

            $filter = [uri]::EscapeDataString("appId eq '$($existingApp.appId)'")
            $servicePrincipals = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter&`$select=id"
            foreach ($servicePrincipal in @($servicePrincipals.value)) {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)"
            }
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/applications/$($existingApp.id)"
            Write-Ok "Removed '$displayName' ($($existingApp.appId))"
        }
    }

    Write-Step "Creating or updating API registration '$ApiDisplayName'"
    $apiApp = Get-AppByDisplayName $ApiDisplayName
    if (-not $apiApp) {
        $apiApp = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body @{
            displayName = $ApiDisplayName
            signInAudience = 'AzureADandPersonalMicrosoftAccount'
            api = @{ requestedAccessTokenVersion = 2 }
        }
    }

    $apiScopeUri = "https://$TenantDomain/$($apiApp.appId)/demo.read"
    $apiUpdate = @{
        signInAudience = 'AzureADandPersonalMicrosoftAccount'
        identifierUris = @("https://$TenantDomain/$($apiApp.appId)")
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @(
                @{
                    id = $scopeId
                    adminConsentDescription = 'Read data from the PKCE protocol demonstration API.'
                    adminConsentDisplayName = 'Read PKCE demo data'
                    isEnabled = $true
                    type = 'User'
                    userConsentDescription = 'Allow the demo to obtain an access token for its sample API.'
                    userConsentDisplayName = 'Access the PKCE demo API'
                    value = 'demo.read'
                }
            )
        }
    }

    $existingApi = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApp.id)?`$select=api"
    $existingScope = @($existingApi.api.oauth2PermissionScopes | Where-Object { $_.value -eq 'demo.read' }) | Select-Object -First 1
    if ($existingScope) {
        $scopeId = $existingScope.id
        $apiUpdate.api.oauth2PermissionScopes[0].id = $scopeId
    }
    Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApp.id)" -Body $apiUpdate | Out-Null
    $apiServicePrincipal = Ensure-ServicePrincipal -AppId $apiApp.appId -SignInAudience $apiUpdate.signInAudience
    Write-Ok "API appId: $($apiApp.appId)"

    Write-Step "Creating or updating PKCE SPA registration '$PkceClientDisplayName'"
    $pkceClient = Ensure-ClientApplication -DisplayName $PkceClientDisplayName -Flow Pkce -ApiAppId $apiApp.appId -ApiScopeId $scopeId -RedirectUri $RedirectUri
    Write-Ok "PKCE SPA appId: $($pkceClient.Application.appId)"

    Write-Step "Creating or updating implicit registration '$ImplicitClientDisplayName'"
    $implicitClient = Ensure-ClientApplication -DisplayName $ImplicitClientDisplayName -Flow Implicit -ApiAppId $apiApp.appId -ApiScopeId $scopeId -RedirectUri $RedirectUri
    Write-Ok "Implicit appId: $($implicitClient.Application.appId)"

    Write-Step 'Pre-authorizing both clients for the demo API scope'
    $apiUpdate.api.preAuthorizedApplications = @(
        @{
            appId = $pkceClient.Application.appId
            delegatedPermissionIds = @($scopeId)
        }
        @{
            appId = $implicitClient.Application.appId
            delegatedPermissionIds = @($scopeId)
        }
    )
    Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($apiApp.id)" -Body @{ api = $apiUpdate.api } | Out-Null

    Write-Step 'Granting tenant-wide delegated consent'
    $graphFilter = [uri]::EscapeDataString("appId eq '$graphAppId'")
    $graphServicePrincipal = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$graphFilter&`$select=id").value) | Select-Object -First 1
    if (-not $graphServicePrincipal) { throw 'Microsoft Graph service principal was not found in the tenant.' }
    Grant-DelegatedConsent -ClientServicePrincipalId $pkceClient.ServicePrincipal.id -ResourceServicePrincipalId $apiServicePrincipal.id -Scopes 'demo.read'
    Grant-DelegatedConsent -ClientServicePrincipalId $pkceClient.ServicePrincipal.id -ResourceServicePrincipalId $graphServicePrincipal.id -Scopes 'offline_access'
    Grant-DelegatedConsent -ClientServicePrincipalId $implicitClient.ServicePrincipal.id -ResourceServicePrincipalId $apiServicePrincipal.id -Scopes 'demo.read'
    Grant-DelegatedConsent -ClientServicePrincipalId $implicitClient.ServicePrincipal.id -ResourceServicePrincipalId $graphServicePrincipal.id -Scopes 'openid profile'
    Write-Ok 'Admin consent granted for both clients'

    $settings = [ordered]@{
        tenantId = $TenantId
        tenantDomain = $TenantDomain
        tenantSubdomain = $tenantSubdomain
        policyId = $PolicyId
        pkceClientId = $pkceClient.Application.appId
        implicitClientId = $implicitClient.Application.appId
        redirectUri = $RedirectUri
        apiScope = $apiScopeUri
        requestRefreshToken = $RequestRefreshToken
    }
    $settingsJson = $settings | ConvertTo-Json -Depth 5
    $settingsPath = Join-Path $scriptRoot 'demo-settings.js'
    "window.DEMO_SETTINGS = $settingsJson;" | Set-Content -Path $settingsPath -Encoding utf8
    Write-Ok "Wrote browser settings to $settingsPath"

    Write-Host ''
    Write-Host 'Setup complete.' -ForegroundColor Yellow
    Write-Host "Run: .\Start-B2CAuthCodeDemo.ps1"
    Write-Host "Then open: $RedirectUri"
} finally {
    & { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } 3>$null
}