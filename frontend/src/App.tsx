import React, { useMemo, useState } from 'react';
import { LoginView } from './views/Login.js';
import { ConsentView } from './views/Consent.js';
import { submitLoginAndConsent } from './services/api.js';
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

  const [flowState, setFlowState] = useState<AuthFlowStep | null>(() =>
    initialContext ? { step: 'LOGIN', context: initialContext } : null,
  );

  if (!flowState) {
    return (
      <main className="oauth-card">
        <h1>Invalid OAuth 2.0 Authorization Request</h1>
        <p>
          Missing required PKCE (<code>S256</code>) or client parameters. Initiate login via{' '}
          <code>GET /authorize</code>.
        </p>
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
