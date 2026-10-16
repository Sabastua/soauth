import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface SignUpViewProps {
  context: OAuthTransactionContext;
  onSignUp: (email: string, password: string) => Promise<void>;
  onNavigateToLogin: () => void;
}

export const SignUpView: React.FC<SignUpViewProps> = ({
  context,
  onSignUp,
  onNavigateToLogin,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      await onSignUp(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="oauth-card">
      <header>
        <h1>Create your soauth Account</h1>
        <p>Register to continue to {context.appName}</p>
      </header>

      {error && (
        <div role="alert" className="oauth-error">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <label htmlFor="signup-email">Email Address</label>
        <input
          id="signup-email"
          type="email"
          required
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <label htmlFor="signup-password">Password (min 8 characters)</label>
        <input
          id="signup-password"
          type="password"
          required
          minLength={8}
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <label htmlFor="confirm-password">Confirm Password</label>
        <input
          id="confirm-password"
          type="password"
          required
          minLength={8}
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />

        <button type="submit" disabled={loading}>
          {loading ? 'Creating Account...' : 'Sign Up & Continue'}
        </button>

        <p style={{ fontSize: '0.875rem', textAlign: 'center', marginTop: '0.5rem' }}>
          Already have an account?{' '}
          <a
            href="#login"
            onClick={(e) => {
              e.preventDefault();
              onNavigateToLogin();
            }}
            style={{ color: 'var(--primary)', fontWeight: 500, textDecoration: 'none' }}
          >
            Sign in
          </a>
        </p>
      </form>
    </main>
  );
};
