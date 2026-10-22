import React, { useEffect, useState } from 'react';
import {
  BACKEND_URL,
  type ActiveSessionInfo,
  type ClientAppItem,
  type NewClientResponse,
  type SessionUserInfo,
  deleteClientApp,
  disableMfa,
  enableMfa,
  fetchClients,
  fetchCurrentSession,
  fetchUserSessions,
  regenerateClientSecret,
  registerClientApp,
  revokeUserSession,
  setupMfa,
  submitPortalLogin,
  submitPortalLogout,
} from '../services/api.js';

interface DevPortalProps {
  onBackToLogin?: () => void;
}

export const DevPortal: React.FC<DevPortalProps> = ({ onBackToLogin }) => {
  // Auth state
  const [authChecking, setAuthChecking] = useState(true);
  const [currentUser, setCurrentUser] = useState<SessionUserInfo | null>(null);
  const [loginEmail, setLoginEmail] = useState('admin@soauth.internal');
  const [loginPassword, setLoginPassword] = useState('SoAuthAdminPassword!2026');
  const [loginMfaCode, setLoginMfaCode] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);

  // Navigation Tabs
  const [activeTab, setActiveTab] = useState<'apps' | 'security'>('apps');

  // Clients & Quickstart state
  const [clients, setClients] = useState<ClientAppItem[]>([]);
  const [selectedClientId, setSelectedClientId] = useState<string>('');
  const [snippetTab, setSnippetTab] = useState<'react' | 'nextjs' | 'vanilla'>('react');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Client Form state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newRedirectUris, setNewRedirectUris] = useState(
    typeof window !== 'undefined' ? `${window.location.origin}/callback` : 'http://localhost:3000/callback',
  );
  const [newScopes, setNewScopes] = useState('openid profile email offline_access');
  const [clientType, setClientType] = useState<'confidential' | 'public'>('public');
  const [createdSecretInfo, setCreatedSecretInfo] = useState<NewClientResponse | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<{ clientId: string; secret: string } | null>(null);

  // Security & Sessions state
  const [sessions, setSessions] = useState<ActiveSessionInfo[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState<{
    secret: string;
    otpauth_uri: string;
    current_test_code?: string;
  } | null>(null);
  const [mfaVerifyCode, setMfaVerifyCode] = useState('');
  const [mfaSubmitting, setMfaSubmitting] = useState(false);

  const loadClients = async () => {
    try {
      setLoading(true);
      const data = await fetchClients();
      setClients(data);
      if (data.length > 0 && !selectedClientId) {
        setSelectedClientId(data[0]!.id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load clients');
    } finally {
      setLoading(false);
    }
  };

  const loadSessions = async () => {
    try {
      setSessionsLoading(true);
      const list = await fetchUserSessions();
      setSessions(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load active sessions');
    } finally {
      setSessionsLoading(false);
    }
  };

  useEffect(() => {
    fetchCurrentSession()
      .then((res) => {
        if (res.authenticated && res.user) {
          setCurrentUser(res.user);
          void loadClients();
          void loadSessions();
        }
      })
      .catch(() => {
        // Not authenticated
      })
      .finally(() => {
        setAuthChecking(false);
      });
  }, []);

  const handlePortalLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoginLoading(true);
    try {
      const res = await submitPortalLogin({
        email: loginEmail,
        password: loginPassword,
        ...(loginMfaCode ? { mfaCode: loginMfaCode } : {}),
      });
      setCurrentUser(res.user);
      setLoginMfaCode('');
      await Promise.all([loadClients(), loadSessions()]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoginLoading(false);
    }
  };

  const handlePortalLogout = async () => {
    await submitPortalLogout();
    setCurrentUser(null);
    setMfaSetupData(null);
    setSuccessMsg('Signed out of Developer Portal.');
  };

  const handleCreateClient = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const uris = newRedirectUris
        .split('\n')
        .map((u) => u.trim())
        .filter(Boolean);
      const scopes = newScopes
        .split(' ')
        .map((s) => s.trim())
        .filter(Boolean);

      const res = await registerClientApp({
        client_name: newAppName,
        redirect_uris: uris,
        allowed_scopes: scopes,
        token_endpoint_auth_method: clientType === 'confidential' ? 'client_secret_post' : 'none',
      });

      setCreatedSecretInfo(res);
      setSelectedClientId(res.client_id);
      setShowCreateModal(false);
      setNewAppName('');
      setSuccessMsg(`Application "${res.client_name}" registered successfully.`);
      await loadClients();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Are you sure you want to delete application "${name}" (${id})?`)) return;
    try {
      await deleteClientApp(id);
      setSuccessMsg(`Application "${name}" deleted.`);
      await loadClients();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete client');
    }
  };

  const handleRegenerate = async (id: string) => {
    if (!window.confirm('Regenerating client secret will immediately invalidate the current secret. Continue?')) return;
    try {
      const res = await regenerateClientSecret(id);
      setRevealedSecret({ clientId: id, secret: res.client_secret });
      setSuccessMsg('Client secret rotated successfully.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to rotate secret');
    }
  };

  const handleStartMfaSetup = async () => {
    setError(null);
    try {
      const data = await setupMfa();
      setMfaSetupData(data);
      if (data.current_test_code) {
        setMfaVerifyCode(data.current_test_code);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start 2FA setup');
    }
  };

  const handleEnableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaSetupData) return;
    setError(null);
    setMfaSubmitting(true);
    try {
      await enableMfa(mfaSetupData.secret, mfaVerifyCode);
      setCurrentUser((prev) => (prev ? { ...prev, is_mfa_enabled: true } : prev));
      setMfaSetupData(null);
      setMfaVerifyCode('');
      setSuccessMsg('Two-Factor Authentication (TOTP) enabled on your account!');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to verify 2FA code');
    } finally {
      setMfaSubmitting(false);
    }
  };

  const handleDisableMfa = async () => {
    if (!window.confirm('Disable Two-Factor Authentication on your account?')) return;
    setError(null);
    try {
      await disableMfa();
      setCurrentUser((prev) => (prev ? { ...prev, is_mfa_enabled: false } : prev));
      setMfaSetupData(null);
      setSuccessMsg('Two-Factor Authentication has been disabled.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disable 2FA');
    }
  };

  const handleRevokeSession = async (sessionId: string, isCurrent: boolean) => {
    try {
      await revokeUserSession(sessionId);
      if (isCurrent) {
        setCurrentUser(null);
        setSuccessMsg('Current session revoked. Please sign in again.');
      } else {
        setSuccessMsg('Session revoked.');
        await loadSessions();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke session');
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setSuccessMsg(`Copied ${label} to clipboard!`);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  if (authChecking) {
    return (
      <div className="oauth-card">
        <p style={{ textAlign: 'center', color: '#64748b' }}>Checking Developer Portal session...</p>
      </div>
    );
  }

  // Unauthenticated Portal Sign-In Gate
  if (!currentUser) {
    return (
      <div className="oauth-card" style={{ maxWidth: '440px', width: '100%' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <span
            style={{
              background: '#e0f2fe',
              color: '#0369a1',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.2rem 0.6rem',
              borderRadius: '999px',
            }}
          >
            soauth Dashboard
          </span>
          {onBackToLogin && (
            <button
              type="button"
              onClick={onBackToLogin}
              style={{
                background: 'none',
                border: 'none',
                color: '#0284c7',
                fontSize: '0.8rem',
                padding: 0,
                cursor: 'pointer',
              }}
            >
              ← Back to OAuth Login
            </button>
          )}
        </div>

        <h1 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: '0.25rem' }}>Developer Portal Sign In</h1>
        <p style={{ fontSize: '0.85rem', color: '#64748b', marginBottom: '1.25rem' }}>
          Sign in to manage OAuth applications, grab Clerk-style SDK snippets, and configure 2FA security.
        </p>

        {error && <div className="oauth-error">{error}</div>}
        {successMsg && (
          <div
            style={{
              background: '#f0fdf4',
              border: '1px solid #bbf7d0',
              color: '#166534',
              padding: '0.65rem 0.85rem',
              borderRadius: '6px',
              marginBottom: '1rem',
              fontSize: '0.85rem',
            }}
          >
            {successMsg}
          </div>
        )}

        <form onSubmit={handlePortalLogin}>
          <div>
            <label htmlFor="portal-email">Email Address</label>
            <input
              id="portal-email"
              type="email"
              required
              value={loginEmail}
              onChange={(e) => setLoginEmail(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="portal-password">Password</label>
            <input
              id="portal-password"
              type="password"
              required
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="portal-mfa">2FA Authenticator Code (if enabled)</label>
            <input
              id="portal-mfa"
              type="text"
              inputMode="numeric"
              placeholder="Optional 6-digit code"
              value={loginMfaCode}
              onChange={(e) => setLoginMfaCode(e.target.value)}
            />
          </div>
          <button type="submit" disabled={loginLoading} style={{ width: '100%' }}>
            {loginLoading ? 'Signing in...' : 'Sign In to Dashboard'}
          </button>
        </form>
      </div>
    );
  }

  const activeClient = clients.find((c) => c.id === selectedClientId) ?? clients[0];
  const sampleClientId = activeClient?.id ?? 'client_default_test';
  const sampleRedirectUri = activeClient?.redirect_uris[0] ?? `${window.location.origin}/callback`;

  const reactSnippet = `import React from 'react';
import { createSoAuthReact } from '@soauth/sdk/react';

export const {
  SoAuthProvider,
  useSoAuth,
  SignedIn,
  SignedOut,
  SignInButton,
  UserButton,
} = createSoAuthReact(React);

export function App() {
  return (
    <SoAuthProvider
      issuerUrl="${BACKEND_URL}"
      clientId="${sampleClientId}"
      redirectUri="${sampleRedirectUri}"
    >
      <header>
        <SignedOut>
          <SignInButton label="Sign in with soauth" />
        </SignedOut>
        <SignedIn>
          <UserButton afterSignOutUrl={window.location.origin} />
        </SignedIn>
      </header>
    </SoAuthProvider>
  );
}`;

  const nextjsSnippet = `// auth.ts (Next.js / Auth.js v5)
import NextAuth from "next-auth";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: "soauth",
      name: "soauth",
      type: "oidc",
      issuer: "${BACKEND_URL}",
      clientId: "${sampleClientId}",
      clientSecret: process.env.SOAUTH_CLIENT_SECRET,
      checks: ["pkce", "state"],
    },
  ],
});`;

  const vanillaSnippet = `import { SoAuthClient } from '@soauth/sdk';

const auth = new SoAuthClient({
  issuerUrl: '${BACKEND_URL}',
  clientId: '${sampleClientId}',
  redirectUri: '${sampleRedirectUri}',
});

// Automatically exchanges ?code=... on redirect or restores session
const state = await auth.initialize();

if (!state.isAuthenticated) {
  await auth.loginWithRedirect();
} else {
  console.log('Logged in as:', state.user?.email);
}`;

  const currentSnippet =
    snippetTab === 'react' ? reactSnippet : snippetTab === 'nextjs' ? nextjsSnippet : vanillaSnippet;

  return (
    <div style={{ maxWidth: '880px', width: '100%', margin: '0 auto' }}>
      {/* Top Header & Account Bar */}
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.25rem',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <h1 style={{ fontSize: '1.55rem', fontWeight: 700, color: '#0f172a' }}>soauth Cloud Dashboard</h1>
            <span
              style={{
                background: currentUser.is_mfa_enabled ? '#dcfce7' : '#f1f5f9',
                color: currentUser.is_mfa_enabled ? '#166534' : '#475569',
                fontSize: '0.72rem',
                fontWeight: 600,
                padding: '0.15rem 0.55rem',
                borderRadius: '999px',
              }}
            >
              {currentUser.is_mfa_enabled ? '🔒 2FA Protected' : '2FA Off'}
            </span>
          </div>
          <p style={{ color: '#64748b', fontSize: '0.85rem' }}>
            Signed in as <strong>{currentUser.email}</strong> · Issuer: <code>{BACKEND_URL}</code>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {onBackToLogin && (
            <button
              type="button"
              onClick={onBackToLogin}
              style={{ background: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1', fontSize: '0.85rem' }}
            >
              OAuth Login View
            </button>
          )}
          <button
            type="button"
            onClick={handlePortalLogout}
            style={{ background: '#fee2e2', color: '#991b1b', border: '1px solid #fca5a5', fontSize: '0.85rem' }}
          >
            Sign Out
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          borderBottom: '1px solid #e2e8f0',
          marginBottom: '1.5rem',
          paddingBottom: '0.5rem',
        }}
      >
        <button
          type="button"
          onClick={() => setActiveTab('apps')}
          style={{
            background: activeTab === 'apps' ? '#0284c7' : '#f8fafc',
            color: activeTab === 'apps' ? '#ffffff' : '#334155',
            border: '1px solid',
            borderColor: activeTab === 'apps' ? '#0284c7' : '#cbd5e1',
            fontSize: '0.85rem',
          }}
        >
          Applications & SDK Quickstart ({clients.length})
        </button>
        <button
          type="button"
          onClick={() => {
            setActiveTab('security');
            void loadSessions();
          }}
          style={{
            background: activeTab === 'security' ? '#0284c7' : '#f8fafc',
            color: activeTab === 'security' ? '#ffffff' : '#334155',
            border: '1px solid',
            borderColor: activeTab === 'security' ? '#0284c7' : '#cbd5e1',
            fontSize: '0.85rem',
          }}
        >
          Account Security & Active Sessions ({sessions.length})
        </button>
      </div>

      {successMsg && (
        <div
          style={{
            background: '#f0fdf4',
            border: '1px solid #bbf7d0',
            color: '#166534',
            padding: '0.75rem 1rem',
            borderRadius: '6px',
            marginBottom: '1rem',
            fontSize: '0.9rem',
          }}
        >
          {successMsg}
        </div>
      )}

      {error && (
        <div className="oauth-error" style={{ marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {activeTab === 'apps' ? (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 600 }}>Registered OAuth 2.0 / OIDC Applications</h2>
            <button
              type="button"
              onClick={() => {
                setShowCreateModal(true);
                setCreatedSecretInfo(null);
              }}
            >
              + Register Application
            </button>
          </div>

          {createdSecretInfo && (
            <div
              style={{
                background: '#eff6ff',
                border: '1px solid #bfdbfe',
                color: '#1e40af',
                padding: '1rem',
                borderRadius: '8px',
                marginBottom: '1.5rem',
              }}
            >
              <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Client Registered: {createdSecretInfo.client_name}
              </h3>
              <p style={{ fontSize: '0.85rem', marginBottom: '0.75rem' }}>
                Store the client credentials safely. The client secret is only shown once!
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                <div>
                  <strong style={{ fontSize: '0.85rem' }}>Client ID: </strong>
                  <code style={{ fontSize: '0.85rem' }}>{createdSecretInfo.client_id}</code>
                  <button
                    type="button"
                    style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                    onClick={() => copyToClipboard(createdSecretInfo.client_id, 'Client ID')}
                  >
                    Copy
                  </button>
                </div>
                {createdSecretInfo.client_secret && (
                  <div>
                    <strong style={{ fontSize: '0.85rem' }}>Client Secret: </strong>
                    <code style={{ fontSize: '0.85rem', background: '#fef08a' }}>
                      {createdSecretInfo.client_secret}
                    </code>
                    <button
                      type="button"
                      style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                      onClick={() => copyToClipboard(createdSecretInfo.client_secret!, 'Client Secret')}
                    >
                      Copy
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {revealedSecret && (
            <div
              style={{
                background: '#fffbeb',
                border: '1px solid #fde68a',
                color: '#92400e',
                padding: '1rem',
                borderRadius: '8px',
                marginBottom: '1.5rem',
              }}
            >
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                Rotated Secret for Client: {revealedSecret.clientId}
              </h3>
              <p style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                New Client Secret:{' '}
                <code style={{ fontSize: '0.85rem', background: '#fef08a' }}>{revealedSecret.secret}</code>
                <button
                  type="button"
                  style={{ marginLeft: '0.5rem', padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                  onClick={() => copyToClipboard(revealedSecret.secret, 'Rotated Secret')}
                >
                  Copy
                </button>
              </p>
            </div>
          )}

          {showCreateModal && (
            <div
              style={{
                background: '#ffffff',
                border: '1px solid #cbd5e1',
                borderRadius: '8px',
                padding: '1.5rem',
                marginBottom: '1.5rem',
                boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
              }}
            >
              <h2 style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '1rem' }}>Register New OAuth Client</h2>
              <form onSubmit={handleCreateClient}>
                <div>
                  <label>Application Name</label>
                  <input
                    type="text"
                    required
                    placeholder="My Production SaaS"
                    value={newAppName}
                    onChange={(e) => setNewAppName(e.target.value)}
                  />
                </div>
                <div>
                  <label>Redirect URIs (one per line)</label>
                  <textarea
                    required
                    rows={3}
                    style={{
                      width: '100%',
                      padding: '0.65rem 0.85rem',
                      border: '1px solid var(--border)',
                      borderRadius: '6px',
                      fontFamily: 'monospace',
                      fontSize: '0.9rem',
                    }}
                    value={newRedirectUris}
                    onChange={(e) => setNewRedirectUris(e.target.value)}
                  />
                </div>
                <div>
                  <label>Allowed Scopes (space separated)</label>
                  <input type="text" value={newScopes} onChange={(e) => setNewScopes(e.target.value)} />
                </div>
                <div>
                  <label>Client Type</label>
                  <div style={{ display: 'flex', gap: '1rem', marginTop: '0.25rem', flexWrap: 'wrap' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="clientType"
                        checked={clientType === 'public'}
                        onChange={() => setClientType('public')}
                        style={{ width: 'auto' }}
                      />
                      Public (React SPA / Mobile App, PKCE S256)
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                      <input
                        type="radio"
                        name="clientType"
                        checked={clientType === 'confidential'}
                        onChange={() => setClientType('confidential')}
                        style={{ width: 'auto' }}
                      />
                      Confidential (Next.js / Backend Server with Client Secret)
                    </label>
                  </div>
                </div>
                <div className="actions" style={{ marginTop: '0.5rem' }}>
                  <button type="button" onClick={() => setShowCreateModal(false)}>
                    Cancel
                  </button>
                  <button type="submit">Create Application</button>
                </div>
              </form>
            </div>
          )}

          <section>
            {loading ? (
              <p style={{ color: '#64748b' }}>Loading client applications...</p>
            ) : clients.length === 0 ? (
              <div
                style={{
                  background: '#ffffff',
                  padding: '2rem',
                  border: '1px dashed #cbd5e1',
                  borderRadius: '8px',
                  textAlign: 'center',
                }}
              >
                <p style={{ color: '#64748b', marginBottom: '0.5rem' }}>No clients registered yet.</p>
                <button type="button" onClick={() => setShowCreateModal(true)}>
                  Register Your First App
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {clients.map((client) => (
                  <div
                    key={client.id}
                    style={{
                      background: '#ffffff',
                      border: selectedClientId === client.id ? '2px solid #0284c7' : '1px solid #e2e8f0',
                      borderRadius: '8px',
                      padding: '1.25rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.75rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>{client.app_name}</h3>
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
                          Registered: {new Date(client.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button
                          type="button"
                          onClick={() => setSelectedClientId(client.id)}
                          style={{
                            background: selectedClientId === client.id ? '#e0f2fe' : '#f8fafc',
                            color: '#0369a1',
                            border: '1px solid #bae6fd',
                            fontSize: '0.8rem',
                            padding: '0.4rem 0.75rem',
                          }}
                        >
                          {selectedClientId === client.id ? '✓ Selected for Quickstart' : 'Use in Quickstart'}
                        </button>
                        {client.is_confidential && (
                          <button
                            type="button"
                            onClick={() => handleRegenerate(client.id)}
                            style={{
                              background: '#f8fafc',
                              color: '#0f172a',
                              border: '1px solid #cbd5e1',
                              fontSize: '0.8rem',
                              padding: '0.4rem 0.75rem',
                            }}
                          >
                            Rotate Secret
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleDelete(client.id, client.app_name)}
                          style={{
                            background: '#fee2e2',
                            color: '#991b1b',
                            border: '1px solid #fca5a5',
                            fontSize: '0.8rem',
                            padding: '0.4rem 0.75rem',
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </div>

                    <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      <div>
                        <span style={{ color: '#64748b' }}>Client ID: </span>
                        <code>{client.id}</code>
                        <button
                          type="button"
                          style={{ marginLeft: '0.5rem', padding: '0.15rem 0.4rem', fontSize: '0.75rem' }}
                          onClick={() => copyToClipboard(client.id, 'Client ID')}
                        >
                          Copy
                        </button>
                      </div>

                      <div>
                        <span style={{ color: '#64748b' }}>Redirect URIs: </span>
                        {client.redirect_uris.map((uri) => (
                          <code key={uri} style={{ marginRight: '0.5rem' }}>
                            {uri}
                          </code>
                        ))}
                      </div>

                      <div>
                        <span style={{ color: '#64748b' }}>Allowed Scopes: </span>
                        {client.allowed_scopes.map((sc) => (
                          <span
                            key={sc}
                            style={{
                              background: '#f1f5f9',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              fontSize: '0.75rem',
                              marginRight: '0.35rem',
                            }}
                          >
                            {sc}
                          </span>
                        ))}
                      </div>

                      <div
                        style={{
                          display: 'flex',
                          gap: '1rem',
                          marginTop: '0.25rem',
                          fontSize: '0.8rem',
                          color: '#64748b',
                        }}
                      >
                        <span>
                          Type: <strong>{client.is_confidential ? 'Confidential' : 'Public (PKCE)'}</strong>
                        </span>
                        <span>
                          PKCE Required: <strong>{client.require_pkce ? 'Yes (S256)' : 'No'}</strong>
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Clerk-style Interactive SDK Quickstart */}
          <section
            style={{
              marginTop: '2rem',
              background: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '1.35rem',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '0.75rem',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
                  Drop-In SDK Quickstart ({activeClient?.app_name ?? 'Default App'})
                </h3>
                <p style={{ fontSize: '0.82rem', color: '#64748b' }}>
                  Pre-configured with <code>clientId="{sampleClientId}"</code> and issuer <code>{BACKEND_URL}</code>
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <button
                  type="button"
                  onClick={() => setSnippetTab('react')}
                  style={{
                    background: snippetTab === 'react' ? '#0f172a' : '#f1f5f9',
                    color: snippetTab === 'react' ? '#ffffff' : '#334155',
                    fontSize: '0.78rem',
                    padding: '0.35rem 0.7rem',
                  }}
                >
                  React (Clerk-style)
                </button>
                <button
                  type="button"
                  onClick={() => setSnippetTab('nextjs')}
                  style={{
                    background: snippetTab === 'nextjs' ? '#0f172a' : '#f1f5f9',
                    color: snippetTab === 'nextjs' ? '#ffffff' : '#334155',
                    fontSize: '0.78rem',
                    padding: '0.35rem 0.7rem',
                  }}
                >
                  Next.js (Auth.js)
                </button>
                <button
                  type="button"
                  onClick={() => setSnippetTab('vanilla')}
                  style={{
                    background: snippetTab === 'vanilla' ? '#0f172a' : '#f1f5f9',
                    color: snippetTab === 'vanilla' ? '#ffffff' : '#334155',
                    fontSize: '0.78rem',
                    padding: '0.35rem 0.7rem',
                  }}
                >
                  Vanilla JS / TS
                </button>
                <button
                  type="button"
                  onClick={() => copyToClipboard(currentSnippet, 'SDK Snippet')}
                  style={{
                    background: '#0284c7',
                    color: '#ffffff',
                    fontSize: '0.78rem',
                    padding: '0.35rem 0.7rem',
                  }}
                >
                  Copy Code
                </button>
              </div>
            </div>

            <pre
              style={{
                background: '#0f172a',
                color: '#f8fafc',
                padding: '1rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                overflowX: 'auto',
                lineHeight: 1.5,
              }}
            >
              {currentSnippet}
            </pre>
          </section>
        </>
      ) : (
        /* Security & Active Sessions Tab */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Two-Factor Authentication Card */}
          <section
            style={{
              background: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '1.35rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>
                  Two-Factor Authentication (TOTP RFC 6238)
                </h2>
                <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
                  Protect your account with Google Authenticator, Authy, or 1Password 6-digit codes.
                </p>
              </div>
              {currentUser.is_mfa_enabled ? (
                <button
                  type="button"
                  onClick={handleDisableMfa}
                  style={{ background: '#fee2e2', color: '#991b1b', border: '1px solid #fca5a5', fontSize: '0.85rem' }}
                >
                  Disable 2FA
                </button>
              ) : (
                !mfaSetupData && (
                  <button type="button" onClick={handleStartMfaSetup} style={{ fontSize: '0.85rem' }}>
                    + Enable 2FA Authenticator
                  </button>
                )
              )}
            </div>

            {mfaSetupData && (
              <div
                style={{
                  background: '#f8fafc',
                  border: '1px solid #cbd5e1',
                  borderRadius: '8px',
                  padding: '1rem',
                  marginTop: '0.75rem',
                }}
              >
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                  Step 1: Add Secret Key to Your Authenticator App
                </h3>
                <p style={{ fontSize: '0.83rem', color: '#334155', marginBottom: '0.5rem' }}>
                  Base32 Secret: <code style={{ fontWeight: 700 }}>{mfaSetupData.secret}</code>
                  <button
                    type="button"
                    style={{ marginLeft: '0.5rem', padding: '0.15rem 0.45rem', fontSize: '0.75rem' }}
                    onClick={() => copyToClipboard(mfaSetupData.secret, 'TOTP Secret')}
                  >
                    Copy
                  </button>
                </p>
                <p style={{ fontSize: '0.78rem', color: '#64748b', marginBottom: '0.75rem', wordBreak: 'break-all' }}>
                  URI: <code>{mfaSetupData.otpauth_uri}</code>
                </p>

                {mfaSetupData.current_test_code && (
                  <p
                    style={{
                      fontSize: '0.8rem',
                      background: '#eff6ff',
                      color: '#1e40af',
                      padding: '0.45rem 0.7rem',
                      borderRadius: '6px',
                      marginBottom: '0.75rem',
                    }}
                  >
                    Current 30s TOTP Code (pre-filled for quick testing):{' '}
                    <strong>{mfaSetupData.current_test_code}</strong>
                  </p>
                )}

                <form onSubmit={handleEnableMfa} style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
                  <div style={{ flex: 1 }}>
                    <label htmlFor="mfa-verify-input">Step 2: Enter 6-Digit Verification Code</label>
                    <input
                      id="mfa-verify-input"
                      type="text"
                      inputMode="numeric"
                      required
                      value={mfaVerifyCode}
                      onChange={(e) => setMfaVerifyCode(e.target.value)}
                      placeholder="123456"
                      style={{ marginBottom: 0 }}
                    />
                  </div>
                  <button type="submit" disabled={mfaSubmitting}>
                    {mfaSubmitting ? 'Verifying...' : 'Verify & Activate'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setMfaSetupData(null)}
                    style={{ background: '#e2e8f0', color: '#334155' }}
                  >
                    Cancel
                  </button>
                </form>
              </div>
            )}
          </section>

          {/* Active Sessions List */}
          <section
            style={{
              background: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '1.35rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700 }}>Active SSO & OAuth Sessions</h2>
                <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
                  Devices currently signed into your account across soauth applications.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void loadSessions()}
                style={{ background: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1', fontSize: '0.8rem' }}
              >
                Refresh
              </button>
            </div>

            {sessionsLoading ? (
              <p style={{ color: '#64748b', fontSize: '0.85rem' }}>Loading sessions...</p>
            ) : sessions.length === 0 ? (
              <p style={{ color: '#64748b', fontSize: '0.85rem' }}>No active sessions found.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {sessions.map((sess) => (
                  <div
                    key={sess.id}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '0.85rem 1rem',
                      border: sess.is_current ? '1px solid #bae6fd' : '1px solid #e2e8f0',
                      background: sess.is_current ? '#f0f9ff' : '#f8fafc',
                      borderRadius: '6px',
                    }}
                  >
                    <div style={{ fontSize: '0.84rem' }}>
                      <div style={{ fontWeight: 600, color: '#0f172a', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span>Client: <code>{sess.client_id}</code></span>
                        {sess.is_current && (
                          <span
                            style={{
                              background: '#0284c7',
                              color: '#ffffff',
                              fontSize: '0.7rem',
                              padding: '0.1rem 0.45rem',
                              borderRadius: '999px',
                            }}
                          >
                            Current Device
                          </span>
                        )}
                      </div>
                      <div style={{ color: '#64748b', fontSize: '0.78rem', marginTop: '0.2rem' }}>
                        IP: {sess.ip_address ?? 'local'} · Signed in: {new Date(sess.auth_time).toLocaleString()} · Expires:{' '}
                        {new Date(sess.expires_at).toLocaleDateString()}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleRevokeSession(sess.id, sess.is_current)}
                      style={{
                        background: '#fee2e2',
                        color: '#991b1b',
                        border: '1px solid #fca5a5',
                        fontSize: '0.78rem',
                        padding: '0.35rem 0.65rem',
                      }}
                    >
                      Revoke
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};
