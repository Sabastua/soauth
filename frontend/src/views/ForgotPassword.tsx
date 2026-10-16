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
      setMessage('Password reset link dispatched.');
      if (devToken) {
        setToken(devToken);
        setStep('RESET');
      } else {
        setStep('RESET');
      }
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
      setMessage('Password reset successful! You can now log in.');
      setTimeout(() => {
        onNavigateToLogin();
      }, 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="oauth-card">
      <header>
        <h1>{step === 'REQUEST' ? 'Reset Password' : 'Enter New Password'}</h1>
        <p>Access your account for {context.appName}</p>
      </header>

      {error && (
        <div role="alert" className="oauth-error">
          {error}
        </div>
      )}

      {message && (
        <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#16a34a', padding: '0.75rem', borderRadius: 6, fontSize: '0.875rem' }}>
          {message}
        </div>
      )}

      {step === 'REQUEST' ? (
        <form onSubmit={handleRequest}>
          <label htmlFor="reset-email">Account Email Address</label>
          <input
            id="reset-email"
            type="email"
            required
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />

          <button type="submit" disabled={loading}>
            {loading ? 'Sending...' : 'Send Reset Instructions'}
          </button>

          <p style={{ fontSize: '0.875rem', textAlign: 'center', marginTop: '0.5rem' }}>
            <a
              href="#login"
              onClick={(e) => {
                e.preventDefault();
                onNavigateToLogin();
              }}
              style={{ color: 'var(--primary)', fontWeight: 500, textDecoration: 'none' }}
            >
              Back to Sign in
            </a>
          </p>
        </form>
      ) : (
        <form onSubmit={handleReset}>
          <label htmlFor="reset-token">Reset Token</label>
          <input
            id="reset-token"
            type="text"
            required
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />

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

          <button type="submit" disabled={loading}>
            {loading ? 'Updating Password...' : 'Save New Password'}
          </button>
        </form>
      )}
    </main>
  );
};
