import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface LoginViewProps {
  context: OAuthTransactionContext;
  error?: string;
  requireMfa?: boolean;
  onCredentialsCaptured: (email: string, password: string, mfaCode?: string) => void;
  onNavigateToSignUp?: () => void;
  onNavigateToForgotPassword?: () => void;
  onNavigateToPortal?: () => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  context,
  error,
  requireMfa = false,
  onCredentialsCaptured,
  onNavigateToSignUp,
  onNavigateToForgotPassword,
  onNavigateToPortal,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCredentialsCaptured(email.trim(), password, requireMfa ? mfaCode.trim() : undefined);
  };

  return (
    <main className="oauth-card">
      <header>
        <h1>Sign in to {context.appName}</h1>
        <p>Continue with your soauth Identity account</p>
      </header>

      {error && (
        <div role="alert" className="oauth-error">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <label htmlFor="email">Email Address</label>
        <input
          id="email"
          type="email"
          required
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <label htmlFor="password" style={{ margin: 0 }}>Password</label>
          {onNavigateToForgotPassword && (
            <a
              href="#forgot"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToForgotPassword();
              }}
              style={{ fontSize: '0.8rem', color: 'var(--primary)', textDecoration: 'none' }}
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
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {requireMfa && (
          <div>
            <label htmlFor="mfaCode">6-Digit Authenticator Code (MFA)</label>
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

        <button type="submit">
          {requireMfa ? 'Verify & Continue' : 'Continue to Scope Consent'}
        </button>

        {onNavigateToSignUp && (
          <p style={{ fontSize: '0.875rem', textAlign: 'center', marginTop: '0.5rem' }}>
            Don't have an account?{' '}
            <a
              href="#signup"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToSignUp();
              }}
              style={{ color: 'var(--primary)', fontWeight: 500, textDecoration: 'none' }}
            >
              Sign up
            </a>
          </p>
        )}

        {onNavigateToPortal && (
          <p style={{ fontSize: '0.8rem', textAlign: 'center', marginTop: '0.75rem', borderTop: '1px solid #f1f5f9', paddingTop: '0.75rem' }}>
            <a
              href="#portal"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToPortal();
              }}
              style={{ color: '#64748b', textDecoration: 'none' }}
            >
              🛠️ Developer Portal (Manage OAuth Apps)
            </a>
          </p>
        )}
      </form>
    </main>
  );
};
