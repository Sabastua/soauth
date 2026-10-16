import type { OAuthTransactionContext } from '../types/oauth.types.js';

const BACKEND_URL = import.meta.env?.VITE_BACKEND_URL ?? 'http://localhost:4000';

export async function submitLoginAndConsent(params: {
  context: OAuthTransactionContext;
  email: string;
  password: string;
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
      password: params.password,
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
