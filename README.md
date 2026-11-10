# Azure AD B2C OAuth Flow Visual Demo

A dependency-free protocol workbench that compares the implicit flow with the authorization code flow with PKCE. It begins with a flow choice, pauses before each protocol message, and decodes returned JWTs locally.

- The implicit flow requests `openid profile demo.read` and returns an ID token and API access token in the redirect fragment.
- The PKCE flow requests `demo.read` and optional `offline_access`. It returns a code, then obtains an API access token and optional refresh token from the token endpoint. It does not request an ID token.

## Prerequisites

- An existing Azure AD B2C tenant and user flow or custom policy.
- PowerShell 7 or Windows PowerShell 5.1.
- The Microsoft Graph authentication module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.
- A tenant administrator who can grant `Application.ReadWrite.All` and `DelegatedPermissionGrant.ReadWrite.All` while running setup.

## Set up the tenant

```powershell
cd B2CAuthCodeDemo
.\Setup-B2CAuthCodeDemo.ps1 `
  -TenantId '<tenant-guid>' `
  -PolicyId 'B2C_1_susi'
```

The script creates or updates three Azure AD B2C registrations:

- **B2C PKCE Visual Demo**: a public SPA client with `http://localhost:8400/index.html` as its redirect URI.
- **B2C Implicit Visual Demo**: a web client with implicit ID and access token issuance enabled and the same redirect URI.
- **B2C PKCE Visual Demo API**: a shared resource app exposing `demo.read` and pre-authorizing both clients.

The script grants both clients tenant-wide delegated consent for `demo.read`, and grants the implicit client the standard `openid` and `profile` permissions. It then writes both client IDs to `demo-settings.js`. This file contains IDs and endpoint inputs, never a client secret. Use `-RequestRefreshToken:$false` to omit `offline_access` from the PKCE flow, or override names, tenant domain, and redirect URI with the script parameters.

Both registrations use the B2C account type **Accounts in any identity provider or organizational directory (for authenticating users with user flows)** and v2 access tokens. A normal rerun updates their visible manifests without changing application IDs.

The PKCE registration disables implicit issuance. The separate implicit registration enables both ID and access token issuance.

If a registration was originally created with the wrong account type, B2C can retain that original classification even after its visible manifest is corrected. Recreate only these demo registrations when B2C returns `AADB2C90068`:

```powershell
.\Setup-B2CAuthCodeDemo.ps1 -TenantId '<tenant-guid>' -PolicyId 'B2C_1_susi' -Recreate
```

Recreation generates new application IDs for all three registrations and rewrites `demo-settings.js`.

The script does not create the B2C user flow/custom policy. The value passed to `-PolicyId` must already exist.

## Run the demo

```powershell
.\Start-B2CAuthCodeDemo.ps1
```

The script serves the folder at <http://localhost:8400/index.html> and opens the browser. A web server is required because OAuth redirect URIs and browser security rules do not support running this flow directly from a `file://` URL.

## Security notes

- This is an educational protocol inspector, not a production token handler.
- Tokens stay in the current browser tab and `sessionStorage`; they are never sent anywhere except the configured B2C token endpoint.
- Close the tab or use **Reset demo** when finished. Refresh tokens are opaque and are displayed, not decoded.
- PKCE protects authorization-code redemption. It does not make browser storage suitable for production token persistence.