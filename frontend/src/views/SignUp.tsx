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
    <div className="auth-stage">
      <main className="oauth-card">
        <header>
          <div className="brand-monogram">
            {context.appName.charAt(0).toUpperCase()}
          </div>
          <h1>Create your account</h1>
          <p>Sign up once to access {context.appName}</p>
        </header>

        {error && (
          <div role="alert" className="oauth-error">
            <span>⚠️</span>
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div>
            <label htmlFor="signup-email">Work or Personal Email</label>
            <input
              id="signup-email"
              type="email"
              required
              placeholder="you@example.com"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div>
            <label htmlFor="signup-password">Password (minimum 8 characters)</label>
            <input
              id="signup-password"
              type="password"
              required
              minLength={8}
              placeholder="Create a strong password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <div>
            <label htmlFor="confirm-password">Confirm Password</label>
            <input
              id="confirm-password"
              type="password"
              required
              minLength={8}
              placeholder="Repeat password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          <button type="submit" disabled={loading} style={{ width: '100%', marginTop: '0.25rem' }}>
            {loading ? 'Creating Account...' : 'Create Account & Continue →'}
          </button>

          <p style={{ fontSize: '0.84rem', textAlign: 'center', color: '#64748b', marginTop: '0.25rem' }}>
            Already have an account?{' '}
            <a
              href="#login"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToLogin();
              }}
              style={{ color: 'var(--primary)', fontWeight: 700, textDecoration: 'none' }}
            >
              Sign in
            </a>
          </p>
        </form>

        <footer className="trust-footer">
          <span className="trust-badge">🔒 Argon2id Password Hashing</span>
        </footer>
      </main>
    </div>
  );
};
