import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface ConsentViewProps {
  context: OAuthTransactionContext;
  userEmail: string;
  onDecision: (consentGranted: boolean) => Promise<void>;
}

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your unique digital identity (Subject ID)',
  profile: 'Read your basic profile metadata',
  email: 'Read your verified email address',
  offline_access: 'Maintain access via rotating refresh tokens while you are offline',
};

export const ConsentView: React.FC<ConsentViewProps> = ({
  context,
  userEmail,
  onDecision,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const scopes = context.scope.split(' ').filter(Boolean);

  const handleClick = async (granted: boolean) => {
    setSubmitting(true);
    try {
      await onDecision(granted);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="oauth-card">
      <header>
        <h1>{context.appName} wants to access your account</h1>
        <p>Signed in as {userEmail}</p>
      </header>

      <section>
        <h2>Requested Permissions (OIDC Scopes)</h2>
        <ul>
          {scopes.map((scope) => (
            <li key={scope}>
              <strong>{scope}</strong>: {SCOPE_DESCRIPTIONS[scope] ?? `Access scope "${scope}"`}
            </li>
          ))}
        </ul>
      </section>

      <footer>
        <p>
          Callback destination: <code>{context.redirectUri}</code>
        </p>
        <div className="actions">
          <button
            type="button"
            disabled={submitting}
            onClick={() => handleClick(false)}
          >
            Deny
          </button>
          <button
            type="button"
            disabled={submitting}
            onClick={() => handleClick(true)}
          >
            Allow &amp; Issue Code
          </button>
        </div>
      </footer>
    </main>
  );
};
