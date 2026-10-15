import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface LoginViewProps {
  context: OAuthTransactionContext;
  error?: string;
  requireMfa?: boolean;
  onCredentialsCaptured: (email: string, password: string, mfaCode?: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  context,
  error,
  requireMfa = false,
  onCredentialsCaptured,
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

        <label htmlFor="password">Password</label>
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
      </form>
    </main>
  );
};
