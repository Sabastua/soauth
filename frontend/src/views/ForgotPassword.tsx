import React, { useState } from 'react';
import type { OAuthTransactionContext } from '../types/oauth.types.js';

interface ForgotPasswordViewProps {
  context: OAuthTransactionContext;
  onRequestReset: (email: string) => Promise<string | undefined>;
  onResetPassword: (token: string, newPassword: string) => Promise<void>;
  onNavigateToLogin: () => void;
}

export const ForgotPasswordView: React.FC<ForgotPasswordViewProps> = ({
  context,
  onRequestReset,
  onResetPassword,
  onNavigateToLogin,
}) => {
  const [step, setStep] = useState<'REQUEST' | 'RESET'>('REQUEST');
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const devToken = await onRequestReset(email.trim());
      setMessage('Password reset instructions dispatched.');
      if (devToken) {
        setToken(devToken);
      }
      setStep('RESET');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      await onResetPassword(token.trim(), newPassword);
      setMessage('Password updated! Redirecting to Sign In...');
      setTimeout(() => {
        onNavigateToLogin();
      }, 1600);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-stage">
      <main className="oauth-card">
        <header>
          <div className="brand-monogram">{context.appName.charAt(0).toUpperCase() || 'S'}</div>
          <h1>{step === 'REQUEST' ? 'Reset your password' : 'Set a new password'}</h1>
          <p>Recover access to {context.appName}</p>
        </header>

        {error && (
          <div role="alert" className="oauth-error">
            <span>{error}</span>
          </div>
        )}

        {message && <div className="oauth-success">{message}</div>}

        {step === 'REQUEST' ? (
          <form onSubmit={handleRequest}>
            <div>
              <label htmlFor="reset-email">Account Email Address</label>
              <input
                id="reset-email"
                type="email"
                required
                placeholder="name@company.com"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <button type="submit" disabled={loading} style={{ width: '100%' }}>
              {loading ? 'Sending...' : 'Send Reset Token'}
            </button>

            <p style={{ fontSize: '0.84rem', textAlign: 'center', marginTop: '0.25rem' }}>
              <a
                href="#login"
                onClick={(e) => {
                  e.preventDefault();
                  onNavigateToLogin();
                }}
                style={{ color: 'var(--primary)', fontWeight: 700, textDecoration: 'none' }}
              >
                Back to Sign in
              </a>
            </p>
          </form>
        ) : (
          <form onSubmit={handleReset}>
            <div>
              <label htmlFor="reset-token">One-Time Reset Token</label>
              <input
                id="reset-token"
                type="text"
                required
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="new-password">New Password (min 8 characters)</label>
              <input
                id="new-password"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>

            <div>
              <label htmlFor="confirm-new-password">Confirm New Password</label>
              <input
                id="confirm-new-password"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>

            <button type="submit" disabled={loading} style={{ width: '100%' }}>
              {loading ? 'Updating Password...' : 'Save New Password'}
            </button>
          </form>
        )}

        <footer className="trust-footer">
          <span className="trust-badge">Revokes prior sessions on reset</span>
        </footer>
      </main>
    </div>
  );
};
