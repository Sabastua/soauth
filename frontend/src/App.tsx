import React, { useEffect, useMemo, useState } from 'react';
import { LoginView } from './views/Login.js';
import { ConsentView } from './views/Consent.js';
import { SignUpView } from './views/SignUp.js';
import { ForgotPasswordView } from './views/ForgotPassword.js';
import { DevPortal } from './views/DevPortal.js';
import {
  submitForgotPassword,
  submitLoginAndConsent,
  submitResetPassword,
  submitSignUp,
  submitSsoConsent,
} from './services/api.js';
import type { AuthFlowStep, OAuthTransactionContext } from './types/oauth.types.js';

function parseOAuthQueryContext(search: string): OAuthTransactionContext | null {
  const params = new URLSearchParams(search);
  const clientId = params.get('client_id');
  const appName = params.get('app_name') ?? 'Registered Application';
  const redirectUri = params.get('redirect_uri');
  const scope = params.get('scope') ?? 'openid';
  const state = params.get('state');
  const codeChallenge = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method');
  const nonce = params.get('nonce') ?? undefined;

  if (
    !clientId ||
    !redirectUri ||
    !state ||
    !codeChallenge ||
    codeChallengeMethod !== 'S256'
  ) {
    return null;
  }

  return {
    clientId,
    appName,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod: 'S256',
    ...(nonce !== undefined ? { nonce } : {}),
  };
}

export const App: React.FC = () => {
  const initialContext = useMemo(
    () => parseOAuthQueryContext(window.location.search),
    [],
  );

  const [flowState, setFlowState] = useState<AuthFlowStep>(() => {
    if (window.location.hash === '#portal' || !initialContext) {
      return { step: 'DEV_PORTAL', ...(initialContext ? { context: initialContext } : {}) };
    }
    return { step: 'LOGIN', context: initialContext };
  });

  useEffect(() => {
    const handleHash = () => {
      if (window.location.hash === '#portal') {
        setFlowState({ step: 'DEV_PORTAL', ...(initialContext ? { context: initialContext } : {}) });
      }
    };
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, [initialContext]);

  if (flowState.step === 'DEV_PORTAL') {
    return (
      <DevPortal
        onBackToLogin={
          initialContext
            ? () => {
                window.location.hash = '';
                setFlowState({ step: 'LOGIN', context: initialContext });
              }
            : undefined
        }
      />
    );
  }

  if (flowState.step === 'LOGIN') {
    return (
      <LoginView
        context={flowState.context}
        {...(flowState.error !== undefined ? { error: flowState.error } : {})}
        {...(flowState.requireMfa !== undefined ? { requireMfa: flowState.requireMfa } : {})}
        onCredentialsCaptured={(email, password, mfaCode, otpCode, passkeyCredentialId) => {
          setFlowState({
            step: 'CONSENT',
            context: flowState.context,
            credentials: {
              email,
              ...(password ? { password } : {}),
              ...(otpCode ? { otpCode } : {}),
              ...(passkeyCredentialId ? { passkeyCredentialId } : {}),
              ...(mfaCode ? { mfaCode } : {}),
            },
          });
        }}
        onSsoContinue={(email) => {
          setFlowState({
            step: 'CONSENT',
            context: flowState.context,
            credentials: { email, useSsoCookie: true },
          });
        }}
        onNavigateToSignUp={() => {
          setFlowState({ step: 'SIGNUP', context: flowState.context });
        }}
        onNavigateToForgotPassword={() => {
          setFlowState({ step: 'FORGOT_PASSWORD', context: flowState.context });
        }}
        onNavigateToPortal={() => {
          window.location.hash = '#portal';
          setFlowState({ step: 'DEV_PORTAL', context: flowState.context });
        }}
      />
    );
  }

  if (flowState.step === 'SIGNUP') {
    return (
      <SignUpView
        context={flowState.context}
        onSignUp={async (email, password) => {
          await submitSignUp(email, password);
          // Transition directly to consent with newly created account
          setFlowState({
            step: 'CONSENT',
            context: flowState.context,
            credentials: { email, password },
          });
        }}
        onNavigateToLogin={() => {
          setFlowState({ step: 'LOGIN', context: flowState.context });
        }}
      />
    );
  }

  if (flowState.step === 'FORGOT_PASSWORD') {
    return (
      <ForgotPasswordView
        context={flowState.context}
        onRequestReset={async (email) => {
          const res = await submitForgotPassword(email);
          return res.dev_reset_token;
        }}
        onResetPassword={async (token, newPassword) => {
          await submitResetPassword(token, newPassword);
        }}
        onNavigateToLogin={() => {
          setFlowState({ step: 'LOGIN', context: flowState.context });
        }}
      />
    );
  }

  if (flowState.step === 'CONSENT') {
    return (
      <ConsentView
        context={flowState.context}
        userEmail={flowState.credentials.email}
        onDecision={async (consentGranted) => {
          try {
            const { redirect_to } = flowState.credentials.useSsoCookie
              ? await submitSsoConsent({
                  context: flowState.context,
                  consentGranted,
                })
              : await submitLoginAndConsent({
                  context: flowState.context,
                  email: flowState.credentials.email,
                  ...(flowState.credentials.password
                    ? { password: flowState.credentials.password }
                    : {}),
                  ...(flowState.credentials.otpCode
                    ? { otpCode: flowState.credentials.otpCode }
                    : {}),
                  ...(flowState.credentials.passkeyCredentialId
                    ? { passkeyCredentialId: flowState.credentials.passkeyCredentialId }
                    : {}),
                  consentGranted,
                  ...(flowState.credentials.mfaCode
                    ? { mfaCode: flowState.credentials.mfaCode }
                    : {}),
                });
            setFlowState({ step: 'REDIRECTING', redirectTo: redirect_to });
            window.location.assign(redirect_to);
          } catch (err) {
            const message = err instanceof Error ? err.message : 'Authentication failed';
            const isMfaNeeded = message.includes('MFA_REQUIRED');
            setFlowState({
              step: 'LOGIN',
              context: flowState.context,
              requireMfa: isMfaNeeded,
              error: isMfaNeeded ? 'Please enter your 6-digit MFA authenticator code.' : message,
            });
          }
        }}
      />
    );
  }

  return (
    <div className="auth-stage">
      <main className="oauth-card" style={{ textAlign: 'center' }}>
        <div className="brand-monogram" style={{ margin: '0 auto 0.5rem' }}>
          S
        </div>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Redirecting to application...</h2>
        <p style={{ color: '#64748b', fontSize: '0.88rem' }}>
          Completing OAuth 2.1 PKCE callback handshake.
        </p>
      </main>
    </div>
  );
};
