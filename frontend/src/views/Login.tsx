import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface LoginViewProps {
  context: OAuthTransactionContext;
  error?: string;
  onCredentialsCaptured: (email: string, password: string) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  context,
  error,
  onCredentialsCaptured,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCredentialsCaptured(email.trim(), password);
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

        <button type="submit">Continue to Scope Consent</button>
      </form>
    </main>
  );
};
