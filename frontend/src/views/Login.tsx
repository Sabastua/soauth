import React, { useEffect, useState } from 'react';
import {
  BACKEND_URL,
  fetchClientBranding,
  fetchCurrentSession,
  submitPortalLogout,
  type ClientBrandingInfo,
  type SessionUserInfo,
} from '../services/api.js';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface LoginViewProps {
  context: OAuthTransactionContext;
  error?: string;
  requireMfa?: boolean;
  onCredentialsCaptured: (email: string, password: string, mfaCode?: string) => void;
  onSsoContinue?: (email: string) => void;
  onNavigateToSignUp?: () => void;
  onNavigateToForgotPassword?: () => void;
  onNavigateToPortal?: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  context,
  error,
  requireMfa = false,
  onCredentialsCaptured,
  onSsoContinue,
  onNavigateToSignUp,
  onNavigateToForgotPassword,
  onNavigateToPortal,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [ssoUser, setSsoUser] = useState<SessionUserInfo | null>(null);
  const [useDifferentAccount, setUseDifferentAccount] = useState(false);
  const [branding, setBranding] = useState<ClientBrandingInfo | null>(null);

  useEffect(() => {
    fetchCurrentSession()
      .then((res) => {
        if (res.authenticated && res.user) {
          setSsoUser(res.user);
        }
      })
      .catch(() => {
        // Ignore session check errors
      });

    if (context.clientId) {
      fetchClientBranding(context.clientId)
        .then((data) => {
          if (data) setBranding(data);
        })
        .catch(() => {
          // Ignore branding fetch errors
        });
    }
  }, [context.clientId]);

  const brandColor = branding?.primary_color || '#4f46e5';
  const displayAppName = branding?.app_name || context.appName;
  const appInitial = displayAppName.trim().charAt(0).toUpperCase() || 'S';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCredentialsCaptured(email.trim(), password, requireMfa ? mfaCode.trim() : undefined);
  };

  const handleSocialLogin = (provider: 'google' | 'github') => {
    const params = new URLSearchParams({
      client_id: context.clientId,
      redirect_uri: context.redirectUri,
      scope: context.scope,
      state: context.state,
      code_challenge: context.codeChallenge,
      code_challenge_method: context.codeChallengeMethod,
      ...(context.nonce ? { nonce: context.nonce } : {}),
    });
    window.location.assign(`${BACKEND_URL}/api/v1/auth/social/${provider}?${params.toString()}`);
  };

  return (
    <div className="auth-stage">
      <main className="oauth-card" style={{ borderTop: `4px solid ${brandColor}` }}>
        <header>
          {branding?.logo_url ? (
            <img
              src={branding.logo_url}
              alt={`${displayAppName} logo`}
              style={{
                maxHeight: '48px',
                maxWidth: '180px',
                objectFit: 'contain',
                marginBottom: '0.75rem',
              }}
            />
          ) : (
            <div
              className="brand-monogram"
              style={{
                background: `linear-gradient(135deg, ${brandColor}, #0ea5e9)`,
              }}
            >
              {appInitial}
            </div>
          )}
          <h1>Sign in to {displayAppName}</h1>
          <p>Welcome back! Please sign in to continue</p>
        </header>

        {error && (
          <div role="alert" className="oauth-error">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {ssoUser && !useDifferentAccount && !requireMfa && onSsoContinue ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '0.85rem',
                padding: '1rem',
                borderRadius: '12px',
                border: '1px solid #c7d2fe',
                background: 'linear-gradient(135deg, #eef2ff 0%, #f8fafc 100%)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', overflow: 'hidden' }}>
                <div
                  style={{
                    width: '42px',
                    height: '42px',
                    borderRadius: '50%',
                    background: brandColor,
                    color: '#ffffff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '1.05rem',
                    flexShrink: 0,
                    boxShadow: '0 4px 10px rgba(79, 70, 229, 0.25)',
                  }}
                >
                  {ssoUser.email.charAt(0).toUpperCase()}
                </div>
                <div style={{ overflow: 'hidden' }}>
                  <div
                    style={{
                      fontWeight: 700,
                      fontSize: '0.92rem',
                      color: '#0f172a',
                      textOverflow: 'ellipsis',
                      overflow: 'hidden',
                    }}
                  >
                    {ssoUser.email}
                  </div>
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: '#15803d',
                      fontWeight: 600,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                      marginTop: '0.15rem',
                    }}
                  >
                    <span
                      style={{
                        width: '7px',
                        height: '7px',
                        borderRadius: '50%',
                        background: '#22c55e',
                        display: 'inline-block',
                      }}
                    />
                    Active SSO Session
                  </div>
                </div>
              </div>
            </div>

            <button
              type="button"
              style={{ background: brandColor, width: '100%' }}
              onClick={() => onSsoContinue(ssoUser.email)}
            >
              Continue as {ssoUser.email.split('@')[0]} →
            </button>

            <button
              type="button"
              className="btn-secondary"
              style={{ width: '100%' }}
              onClick={async () => {
                await submitPortalLogout();
                setSsoUser(null);
                setUseDifferentAccount(true);
              }}
            >
              Use another account
            </button>
          </div>
        ) : (
          <>
            {!requireMfa && (
              <>
                <div className="social-grid">
                  <button
                    type="button"
                    className="social-btn"
                    onClick={() => handleSocialLogin('google')}
                  >
                    <svg width="17" height="17" viewBox="0 0 24 24">
                      <path
                        fill="#4285F4"
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                      />
                      <path
                        fill="#EA4335"
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                      />
                    </svg>
                    Google
                  </button>

                  <button
                    type="button"
                    className="social-btn"
                    onClick={() => handleSocialLogin('github')}
                  >
                    <svg width="17" height="17" fill="#0f172a" viewBox="0 0 24 24">
                      <path
                        fillRule="evenodd"
                        clipRule="evenodd"
                        d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                      />
                    </svg>
                    GitHub
                  </button>
                </div>

                <div className="divider">or continue with email</div>
              </>
            )}

            <form onSubmit={handleSubmit}>
              <div>
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  type="email"
                  required
                  placeholder="name@company.com"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                  <label htmlFor="password" style={{ margin: 0 }}>
                    Password
                  </label>
                  {onNavigateToForgotPassword && (
                    <a
                      href="#forgot"
                      onClick={(e) => {
                        e.preventDefault();
                        onNavigateToForgotPassword();
                      }}
                      style={{ fontSize: '0.78rem', color: brandColor, fontWeight: 600, textDecoration: 'none' }}
                    >
                      Forgot password?
                    </a>
                  )}
                </div>
                <input
                  id="password"
                  type="password"
                  required
                  minLength={8}
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              {requireMfa && (
                <div>
                  <label htmlFor="mfaCode">6-Digit Authenticator Code (2FA)</label>
                  <input
                    id="mfaCode"
                    type="text"
                    required
                    maxLength={6}
                    pattern="\d{6}"
                    placeholder="123456"
                    autoComplete="one-time-code"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                  />
                </div>
              )}

              <button type="submit" style={{ background: brandColor, width: '100%', marginTop: '0.25rem' }}>
                {requireMfa ? 'Verify 2FA & Continue →' : 'Continue →'}
              </button>

              {onNavigateToSignUp && (
                <p style={{ fontSize: '0.84rem', textAlign: 'center', color: '#64748b', marginTop: '0.25rem' }}>
                  Don't have an account?{' '}
                  <a
                    href="#signup"
                    onClick={(e) => {
                      e.preventDefault();
                      onNavigateToSignUp();
                    }}
                    style={{ color: brandColor, fontWeight: 700, textDecoration: 'none' }}
                  >
                    Sign up
                  </a>
                </p>
              )}
            </form>
          </>
        )}

        {(branding?.terms_of_service_url || branding?.privacy_policy_url) && (
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '1rem',
              fontSize: '0.75rem',
            }}
          >
            {branding.terms_of_service_url && (
              <a
                href={branding.terms_of_service_url}
                target="_blank"
                rel="noreferrer"
                style={{ color: '#64748b', textDecoration: 'none' }}
              >
                Terms of Service
              </a>
            )}
            {branding.privacy_policy_url && (
              <a
                href={branding.privacy_policy_url}
                target="_blank"
                rel="noreferrer"
                style={{ color: '#64748b', textDecoration: 'none' }}
              >
                Privacy Policy
              </a>
            )}
          </div>
        )}

        <footer className="trust-footer">
          <span className="trust-badge">🔒 Secured by soauth</span>
          {onNavigateToPortal && (
            <a
              href="#portal"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToPortal();
              }}
              style={{ color: '#4f46e5', fontWeight: 600, textDecoration: 'none' }}
            >
              Cloud Dashboard →
            </a>
          )}
        </footer>
      </main>
    </div>
  );
};
