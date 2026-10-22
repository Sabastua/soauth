import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface ConsentViewProps {
  context: OAuthTransactionContext;
  userEmail: string;
  onDecision: (consentGranted: boolean) => Promise<void>;
}

const SCOPE_DESCRIPTIONS: Record<string, { title: string; desc: string }> = {
  openid: {
    title: 'Verify Digital Identity',
    desc: 'Share your unique OpenID Subject identifier (sub) with this application.',
  },
  profile: {
    title: 'Profile & RBAC Role Claims',
    desc: 'Read your account role, permissions, and profile update timestamp.',
  },
  email: {
    title: 'Verified Email Address',
    desc: 'Read your primary email address and verification status.',
  },
  offline_access: {
    title: 'Offline Session Renewal',
    desc: 'Maintain seamless access using rotating refresh tokens.',
  },
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
    <div className="auth-stage">
      <main className="oauth-card">
        <header>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.65rem',
              marginBottom: '0.85rem',
            }}
          >
            <div className="brand-monogram" style={{ marginBottom: 0, width: '42px', height: '42px', fontSize: '1.05rem' }}>
              {context.appName.charAt(0).toUpperCase()}
            </div>
            <span style={{ color: '#94a3b8', fontWeight: 700 }}>⇄</span>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '50%',
                background: '#eef2ff',
                border: '2px solid #c7d2fe',
                color: '#4338ca',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 800,
                fontSize: '1rem',
              }}
            >
              {userEmail.charAt(0).toUpperCase()}
            </div>
          </div>

          <h1>Authorize {context.appName}</h1>
          <p>
            Signed in as <strong style={{ color: '#0f172a' }}>{userEmail}</strong>
          </p>
        </header>

        <section>
          <div
            style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: '#64748b',
              marginBottom: '0.6rem',
            }}
          >
            Permissions Requested ({scopes.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
            {scopes.map((scope) => {
              const info = SCOPE_DESCRIPTIONS[scope] ?? {
                title: `Scope: ${scope}`,
                desc: `Grant access to "${scope}" resource scope.`,
              };
              return (
                <div
                  key={scope}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.7rem',
                    padding: '0.75rem 0.85rem',
                    background: '#f8fafc',
                    border: '1px solid #e2e8f0',
                    borderRadius: '10px',
                  }}
                >
                  <span
                    style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: '50%',
                      background: '#dcfce7',
                      color: '#15803d',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.72rem',
                      fontWeight: 800,
                      flexShrink: 0,
                      marginTop: '0.1rem',
                    }}
                  >
                    ✓
                  </span>
                  <div>
                    <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#0f172a' }}>
                      {info.title}{' '}
                      <code style={{ fontSize: '0.72rem', marginLeft: '0.25rem' }}>{scope}</code>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.15rem' }}>
                      {info.desc}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <div
          style={{
            background: '#f8fafc',
            border: '1px dashed #cbd5e1',
            borderRadius: '8px',
            padding: '0.6rem 0.8rem',
            fontSize: '0.76rem',
            color: '#64748b',
            wordBreak: 'break-all',
          }}
        >
          Redirecting after consent to: <code>{context.redirectUri}</code>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            type="button"
            className="btn-secondary"
            style={{ flex: 1 }}
            disabled={submitting}
            onClick={() => handleClick(false)}
          >
            Deny
          </button>
          <button
            type="button"
            style={{ flex: 1.4 }}
            disabled={submitting}
            onClick={() => handleClick(true)}
          >
            {submitting ? 'Authorizing...' : 'Allow Access →'}
          </button>
        </div>

        <footer className="trust-footer">
          <span className="trust-badge">🔒 OAuth 2.1 + PKCE S256 Verified</span>
        </footer>
      </main>
    </div>
  );
};
