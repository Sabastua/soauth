import type { OAuthTransactionContext } from '../types/oauth.types.js';

function resolveBackendUrl(): string {
  if (import.meta.env?.VITE_BACKEND_URL) {
    return import.meta.env.VITE_BACKEND_URL.replace(/\/$/, '');
  }
  if (
    typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
    window.location.port !== '4000'
  ) {
    return 'http://localhost:4000';
  }
  return typeof window !== 'undefined' ? window.location.origin : 'http://localhost:4000';
}

export const BACKEND_URL = resolveBackendUrl();

export async function submitLoginAndConsent(params: {
  context: OAuthTransactionContext;
  email: string;
  password?: string;
  otpCode?: string;
  passkeyCredentialId?: string;
  consentGranted: boolean;
  mfaCode?: string;
}): Promise<{ redirect_to: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/oauth/login-consent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({
      email: params.email,
      ...(params.password ? { password: params.password } : {}),
      ...(params.otpCode ? { otp_code: params.otpCode } : {}),
      ...(params.passkeyCredentialId ? { passkey_credential_id: params.passkeyCredentialId } : {}),
      consent_granted: params.consentGranted,
      ...(params.mfaCode ? { mfa_code: params.mfaCode } : {}),
      response_type: 'code',
      client_id: params.context.clientId,
      redirect_uri: params.context.redirectUri,
      scope: params.context.scope,
      state: params.context.state,
      code_challenge: params.context.codeChallenge,
      code_challenge_method: params.context.codeChallengeMethod,
      ...(params.context.nonce ? { nonce: params.context.nonce } : {}),
    }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Authentication failed');
  }

  return payload as { redirect_to: string };
}

export async function sendPasswordlessOtp(
  email: string,
): Promise<{ message: string; dev_otp_code?: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/passwordless/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to send passwordless sign-in code');
  }

  return payload;
}

export async function submitSignUp(email: string, password: string): Promise<{ message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Registration failed');
  }

  return payload;
}

export async function submitForgotPassword(email: string): Promise<{ message: string; dev_reset_token?: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Password reset request failed');
  }

  return payload;
}

export async function submitResetPassword(token: string, newPassword: string): Promise<{ message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, new_password: newPassword }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Password reset failed');
  }

  return payload;
}

export interface ClientAppItem {
  id: string;
  owner_user_id?: string | null;
  app_name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  is_confidential: boolean;
  require_pkce: boolean;
  logo_url?: string | null;
  primary_color?: string | null;
  app_website_url?: string | null;
  privacy_policy_url?: string | null;
  terms_of_service_url?: string | null;
  webhook_url?: string | null;
  webhook_secret?: string | null;
  custom_claims_template?: string | null;
  created_at: string;
}

export interface ClientBrandingInfo {
  client_id: string;
  app_name: string;
  logo_url: string | null;
  primary_color: string;
  app_website_url: string | null;
  privacy_policy_url: string | null;
  terms_of_service_url: string | null;
}

export interface NewClientResponse {
  client_id: string;
  client_secret?: string;
  client_name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  token_endpoint_auth_method: string;
  webhook_secret?: string;
}

export async function fetchClients(): Promise<ClientAppItem[]> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to fetch registered clients');
  }
  return response.json();
}

export async function fetchClientBranding(clientId: string): Promise<ClientBrandingInfo | null> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/branding`);
  if (!response.ok) return null;
  return response.json();
}

export async function registerClientApp(params: {
  client_name: string;
  redirect_uris: string[];
  allowed_scopes?: string[];
  token_endpoint_auth_method?: 'client_secret_post' | 'none';
  logo_url?: string;
  primary_color?: string;
  webhook_url?: string;
}): Promise<NewClientResponse> {
  const response = await fetch(`${BACKEND_URL}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(params),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Client registration failed');
  }
  return payload;
}

export async function updateClientSettings(
  clientId: string,
  patch: {
    app_name?: string;
    redirect_uris?: string[];
    logo_url?: string | null;
    primary_color?: string | null;
    app_website_url?: string | null;
    privacy_policy_url?: string | null;
    terms_of_service_url?: string | null;
    webhook_url?: string | null;
    webhook_secret?: string | null;
    custom_claims_template?: string | null;
  },
): Promise<ClientAppItem> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(patch),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to update application settings');
  }
  return payload;
}

export interface ScopedApiKeyItem {
  id: string;
  client_id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
}

export async function fetchClientApiKeys(clientId: string): Promise<ScopedApiKeyItem[]> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/api-keys`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load API keys');
  }
  return response.json();
}

export async function createClientApiKey(
  clientId: string,
  params: { name: string; scopes?: string[] },
): Promise<{ api_key: ScopedApiKeyItem; raw_key: string; message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/api-keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to create API key');
  }
  return payload;
}

export async function revokeClientApiKey(clientId: string, keyId: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/api-keys/${keyId}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to revoke API key');
  }
}

export async function triggerTestWebhook(
  clientId: string,
): Promise<{ delivered: boolean; statusCode?: number; error?: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/webhook-test`, {
    method: 'POST',
    credentials: 'include',
  });
  return response.json();
}

export interface AppDirectoryUser {
  id: string;
  email: string;
  email_verified: boolean;
  role: string;
  is_mfa_enabled: boolean;
  created_at: string;
  last_login_at: string | null;
  session_count: number;
  active_sessions: number;
}

export async function fetchClientUsers(clientId: string): Promise<AppDirectoryUser[]> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/users`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load application user directory');
  }
  return response.json();
}

export async function updateClientUser(
  clientId: string,
  userId: string,
  patch: { role?: string; revoke_sessions?: boolean },
): Promise<{ message: string; user_id: string; role: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${clientId}/users/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(patch),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to update user');
  }
  return payload;
}

export interface AuditLogItem {
  id: string;
  event_type: string;
  actor_user_id: string | null;
  actor_email: string | null;
  client_id: string | null;
  ip_address: string | null;
  status: 'success' | 'failure' | 'warning';
  details: string;
  created_at: string;
}

export interface SaasOverviewResponse {
  plan: {
    name: string;
    mau_used: number;
    mau_limit: number;
    total_users: number;
    total_clients: number;
    total_sessions: number;
  };
  audit_logs: AuditLogItem[];
}

export async function fetchSaasOverview(): Promise<SaasOverviewResponse> {
  const response = await fetch(`${BACKEND_URL}/api/v1/saas/overview`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load SaaS analytics overview');
  }
  return response.json();
}

export async function deleteClientApp(id: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${id}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to delete client');
  }
}

export async function regenerateClientSecret(id: string): Promise<{ client_id: string; client_secret: string; message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/clients/${id}/regenerate-secret`, {
    method: 'POST',
    credentials: 'include',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to regenerate client secret');
  }
  return payload;
}

export interface SessionUserInfo {
  id: string;
  email: string;
  email_verified?: boolean;
  role?: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  is_mfa_enabled: boolean;
  created_at?: string;
}

export interface OrganizationMemberItem {
  id: string;
  org_id: string;
  user_id: string | null;
  email: string;
  role: 'org:admin' | 'org:member' | 'org:billing';
  status: 'active' | 'invited';
  joined_at: string;
}

export interface OrganizationItem {
  id: string;
  name: string;
  slug: string;
  created_by_user_id: string;
  created_at: string;
  members: OrganizationMemberItem[];
}

export interface PasskeyItem {
  id: string;
  user_id: string;
  email: string;
  credential_id: string;
  device_name: string;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
}

export async function fetchUserOrganizations(): Promise<{
  organizations: OrganizationItem[];
  active_org_id: string | null;
}> {
  const response = await fetch(`${BACKEND_URL}/api/v1/orgs`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load organizations');
  }
  return response.json();
}

export async function createOrganization(params: {
  name: string;
  slug?: string;
}): Promise<OrganizationItem> {
  const response = await fetch(`${BACKEND_URL}/api/v1/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to create organization');
  }
  return payload;
}

export async function inviteOrganizationMember(
  orgId: string,
  params: { email: string; role: 'org:admin' | 'org:member' | 'org:billing' },
): Promise<OrganizationMemberItem> {
  const response = await fetch(`${BACKEND_URL}/api/v1/orgs/${orgId}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to invite member');
  }
  return payload;
}

export async function removeOrganizationMember(orgId: string, memberId: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/api/v1/orgs/${orgId}/members/${memberId}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to remove member');
  }
}

export async function switchActiveOrganization(orgId: string): Promise<{
  active_org_id: string;
  org_id?: string;
  org_slug?: string;
  org_role?: string;
}> {
  const response = await fetch(`${BACKEND_URL}/api/v1/orgs/${orgId}/switch`, {
    method: 'POST',
    credentials: 'include',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to switch organization');
  }
  return payload;
}

export async function fetchUserPasskeys(): Promise<PasskeyItem[]> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/passkeys`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load passkeys');
  }
  return response.json();
}

export async function registerUserPasskey(params: {
  device_name: string;
  credential_id?: string;
}): Promise<PasskeyItem> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/passkeys/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(params),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to register passkey');
  }
  return payload;
}

export async function deleteUserPasskey(passkeyId: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/passkeys/${passkeyId}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to delete passkey');
  }
}

export interface ActiveSessionInfo {
  id: string;
  client_id: string;
  ip_address: string | null;
  user_agent: string | null;
  auth_time: string;
  expires_at: string;
  is_current: boolean;
}

export async function fetchCurrentSession(): Promise<{
  authenticated: boolean;
  session_id?: string;
  user?: SessionUserInfo;
}> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/session`, {
    credentials: 'include',
  });
  if (!response.ok) return { authenticated: false };
  return response.json();
}

export async function sendEmailVerificationOtp(): Promise<{
  message: string;
  dev_otp_code?: string;
}> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/verify-email/send`, {
    method: 'POST',
    credentials: 'include',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to send verification code');
  }
  return payload;
}

export async function confirmEmailVerificationOtp(
  code: string,
): Promise<{ email_verified: boolean; message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/verify-email/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ code }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Invalid verification code');
  }
  return payload;
}

export async function submitSsoConsent(params: {
  context: OAuthTransactionContext;
  consentGranted: boolean;
}): Promise<{ redirect_to: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/oauth/sso-consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      consent_granted: params.consentGranted,
      response_type: 'code',
      client_id: params.context.clientId,
      redirect_uris: undefined,
      redirect_uri: params.context.redirectUri,
      scope: params.context.scope,
      state: params.context.state,
      code_challenge: params.context.codeChallenge,
      code_challenge_method: params.context.codeChallengeMethod,
      ...(params.context.nonce ? { nonce: params.context.nonce } : {}),
    }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'SSO authorization failed');
  }
  return payload as { redirect_to: string };
}

export async function submitPortalLogin(params: {
  email: string;
  password?: string;
  otpCode?: string;
  passkeyCredentialId?: string;
  mfaCode?: string;
}): Promise<{ authenticated: boolean; session_id: string; user: SessionUserInfo }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({
      email: params.email,
      ...(params.password ? { password: params.password } : {}),
      ...(params.otpCode ? { otp_code: params.otpCode } : {}),
      ...(params.passkeyCredentialId ? { passkey_credential_id: params.passkeyCredentialId } : {}),
      ...(params.mfaCode ? { mfa_code: params.mfaCode } : {}),
    }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Login failed');
  }
  return payload;
}

export async function submitPortalLogout(): Promise<void> {
  await fetch(`${BACKEND_URL}/api/v1/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
}

export async function fetchUserSessions(): Promise<ActiveSessionInfo[]> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/sessions`, {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to load active sessions');
  }
  return response.json();
}

export async function revokeUserSession(sessionId: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/sessions/${sessionId}`, {
    method: 'DELETE',
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error('Failed to revoke session');
  }
}

export async function setupMfa(): Promise<{
  secret: string;
  otpauth_uri: string;
  current_test_code?: string;
}> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/mfa/setup`, {
    method: 'POST',
    credentials: 'include',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to initialize MFA setup');
  }
  return payload;
}

export async function enableMfa(secret: string, code: string): Promise<{ is_mfa_enabled: boolean; message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/mfa/enable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ secret, code }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to enable MFA');
  }
  return payload;
}

export async function disableMfa(): Promise<{ is_mfa_enabled: boolean; message: string }> {
  const response = await fetch(`${BACKEND_URL}/api/v1/auth/mfa/disable`, {
    method: 'POST',
    credentials: 'include',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error_description ?? 'Failed to disable MFA');
  }
  return payload;
}



