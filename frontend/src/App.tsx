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
      <main style={{ width: '100%', maxWidth: '900px', padding: '1rem' }}>
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
      </main>
    );
  }

  if (flowState.step === 'LOGIN') {
    return (
      <LoginView
        context={flowState.context}
        {...(flowState.error !== undefined ? { error: flowState.error } : {})}
        {...(flowState.requireMfa !== undefined ? { requireMfa: flowState.requireMfa } : {})}
        onCredentialsCaptured={(email, password, mfaCode) => {
          setFlowState({
            step: 'CONSENT',
            context: flowState.context,
            credentials: { email, password, ...(mfaCode ? { mfaCode } : {}) },
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
            const { redirect_to } = await submitLoginAndConsent({
              context: flowState.context,
              email: flowState.credentials.email,
              password: flowState.credentials.password,
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
    <main className="oauth-card">
      <p>Redirecting back to application callback...</p>
    </main>
  );
};
