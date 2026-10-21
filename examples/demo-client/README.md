# soauth Demo Client & Testing Guide

This directory provides a standalone reference implementation demonstrating how to integrate any frontend or backend application with **soauth** using standard **OAuth 2.0 Authorization Code Flow + PKCE (S256)**.

---

## 🚀 30-Second Quickstart

### 1. Start soauth Backend & Frontend
In terminal 1:
```bash
cd backend
npm run dev
```

In terminal 2:
```bash
cd frontend
npm run dev
```

### 2. Run the Interactive Flow
You have two instant options:

#### Option A: Built-in Interactive Browser Tester
Open your browser and navigate directly to:
👉 **`http://localhost:4000/callback`**

1. Click **"Launch Authorization Flow with PKCE"**.
2. Log in using the default developer credentials:
   - **Email**: `admin@soauth.internal`
   - **Password**: `SoAuthAdminPassword!2026`
   *(Or click "Sign up" to create a new user account, or click Google/GitHub social login!)*
3. Review and grant the requested OIDC scopes (`openid`, `profile`, `email`, `offline_access`).
4. You are redirected back to `http://localhost:4000/callback` with a single-use authorization code.
5. Click **"Exchange for Access & ID Tokens"** to immediately invoke `POST /token`.
6. Click **"Call GET /userinfo"** to inspect your verified OIDC user claims!

#### Option B: Standalone Demo Client App
Open `examples/demo-client/index.html` in any web browser or serve it via any static file server:
```bash
npx serve examples/demo-client
```
Navigate to the hosted URL (e.g. `http://localhost:3000` or file).

---

## 💻 Integration with `@soauth/sdk`

```typescript
import {
  createAuthorizationUrl,
  exchangeCodeForTokens,
  fetchUserInfo,
  refreshAccessToken,
  revokeToken,
  buildLogoutUrl
} from '@soauth/sdk';

// 1. Generate standard PKCE authorization URL
const { url, codeVerifier, state } = await createAuthorizationUrl({
  issuerUrl: 'http://localhost:4000',
  clientId: '00000000-0000-4000-8000-000000000001',
  redirectUri: 'http://localhost:4000/callback',
  scope: 'openid profile email offline_access',
});

// Store codeVerifier in sessionStorage for the callback step
sessionStorage.setItem('code_verifier', codeVerifier);
window.location.assign(url);

// 2. On redirect callback (?code=...&state=...):
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code')!;

const tokens = await exchangeCodeForTokens({
  issuerUrl: 'http://localhost:4000',
  clientId: '00000000-0000-4000-8000-000000000001',
  clientSecret: 'soauth-dev-confidential-secret-2026', // omit for public SPAs
  redirectUri: 'http://localhost:4000/callback',
  code,
  codeVerifier: sessionStorage.getItem('code_verifier')!,
});

console.log('Access Token:', tokens.access_token);
console.log('ID Token (OIDC):', tokens.id_token);

// 3. Fetch authenticated user claims
const userInfo = await fetchUserInfo('http://localhost:4000', tokens.access_token);
console.log('User Profile:', userInfo);

// 4. Refresh token before access token expiry
const newTokens = await refreshAccessToken({
  issuerUrl: 'http://localhost:4000',
  clientId: '00000000-0000-4000-8000-000000000001',
  clientSecret: 'soauth-dev-confidential-secret-2026',
  refreshToken: tokens.refresh_token!,
});
```
