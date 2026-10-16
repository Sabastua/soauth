import React, { useEffect, useState } from 'react';
import {
  type ClientAppItem,
  type NewClientResponse,
  deleteClientApp,
  fetchClients,
  regenerateClientSecret,
  registerClientApp,
} from '../services/api.js';

interface DevPortalProps {
  onBackToLogin?: () => void;
}

export const DevPortal: React.FC<DevPortalProps> = ({ onBackToLogin }) => {
  const [clients, setClients] = useState<ClientAppItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Client Form state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newRedirectUris, setNewRedirectUris] = useState('http://localhost:3000/callback');
  const [newScopes, setNewScopes] = useState('openid profile email');
  const [clientType, setClientType] = useState<'confidential' | 'public'>('confidential');
  const [createdSecretInfo, setCreatedSecretInfo] = useState<NewClientResponse | null>(null);

  // Regenerated secret notification
  const [revealedSecret, setRevealedSecret] = useState<{ clientId: string; secret: string } | null>(null);

  const loadClients = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchClients();
      setClients(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load clients');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadClients();
  }, []);

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
      setShowCreateModal(false);
      setNewAppName('');
      setNewRedirectUris('http://localhost:3000/callback');
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

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setSuccessMsg(`Copied ${label} to clipboard!`);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  return (
    <div style={{ maxWidth: '840px', width: '100%', margin: '0 auto' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 700, color: '#0f172a' }}>soauth Developer Portal</h1>
          <p style={{ color: '#64748b', fontSize: '0.9rem' }}>Manage your OAuth 2.0 / OIDC clients and integration credentials.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {onBackToLogin && (
            <button
              type="button"
              onClick={onBackToLogin}
              style={{ background: '#f1f5f9', color: '#334155', border: '1px solid #cbd5e1' }}
            >
              Back to Login
            </button>
          )}
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
      </header>

      {successMsg && (
        <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', color: '#166534', padding: '0.75rem 1rem', borderRadius: '6px', marginBottom: '1rem', fontSize: '0.9rem' }}>
          {successMsg}
        </div>
      )}

      {error && (
        <div className="oauth-error" style={{ marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {createdSecretInfo && (
        <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', color: '#1e40af', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            🎉 Client Registered: {createdSecretInfo.client_name}
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
                <code style={{ fontSize: '0.85rem', background: '#fef08a' }}>{createdSecretInfo.client_secret}</code>
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
        <div style={{ background: '#fffbeb', border: '1px solid #fde68a', color: '#92400e', padding: '1rem', borderRadius: '8px', marginBottom: '1.5rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.4rem' }}>
            Rotated Secret for Client: {revealedSecret.clientId}
          </h3>
          <p style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            New Client Secret: <code style={{ fontSize: '0.85rem', background: '#fef08a' }}>{revealedSecret.secret}</code>
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
        <div style={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', padding: '1.5rem', marginBottom: '1.5rem', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}>
          <h2 style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '1rem' }}>Register New OAuth Client</h2>
          <form onSubmit={handleCreateClient}>
            <div>
              <label>Application Name</label>
              <input
                type="text"
                required
                placeholder="My Awesome App"
                value={newAppName}
                onChange={(e) => setNewAppName(e.target.value)}
              />
            </div>
            <div>
              <label>Redirect URIs (one per line)</label>
              <textarea
                required
                rows={3}
                style={{ width: '100%', padding: '0.65rem 0.85rem', border: '1px solid var(--border)', borderRadius: '6px', fontFamily: 'monospace', fontSize: '0.9rem' }}
                value={newRedirectUris}
                onChange={(e) => setNewRedirectUris(e.target.value)}
              />
            </div>
            <div>
              <label>Allowed Scopes (space separated)</label>
              <input
                type="text"
                value={newScopes}
                onChange={(e) => setNewScopes(e.target.value)}
              />
            </div>
            <div>
              <label>Client Type</label>
              <div style={{ display: 'flex', gap: '1rem', marginTop: '0.25rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="clientType"
                    checked={clientType === 'confidential'}
                    onChange={() => setClientType('confidential')}
                    style={{ width: 'auto' }}
                  />
                  Confidential (Backend Service with Client Secret)
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="clientType"
                    checked={clientType === 'public'}
                    onChange={() => setClientType('public')}
                    style={{ width: 'auto' }}
                  />
                  Public (SPA / Mobile App, PKCE only)
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
        <h2 style={{ fontSize: '1.2rem', fontWeight: 600, marginBottom: '1rem' }}>
          Registered Clients ({clients.length})
        </h2>

        {loading ? (
          <p style={{ color: '#64748b' }}>Loading client applications...</p>
        ) : clients.length === 0 ? (
          <div style={{ background: '#ffffff', padding: '2rem', border: '1px dashed #cbd5e1', borderRadius: '8px', textAlign: 'center' }}>
            <p style={{ color: '#64748b', marginBottom: '0.5rem' }}>No clients registered yet.</p>
            <button type="button" onClick={() => setShowCreateModal(true)}>Register Your First App</button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {clients.map((client) => (
              <div
                key={client.id}
                style={{
                  background: '#ffffff',
                  border: '1px solid #e2e8f0',
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
                    {client.is_confidential && (
                      <button
                        type="button"
                        onClick={() => handleRegenerate(client.id)}
                        style={{ background: '#f8fafc', color: '#0f172a', border: '1px solid #cbd5e1', fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
                      >
                        Rotate Secret
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => handleDelete(client.id, client.app_name)}
                      style={{ background: '#fee2e2', color: '#991b1b', border: '1px solid #fca5a5', fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
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

                  <div style={{ display: 'flex', gap: '1rem', marginTop: '0.25rem', fontSize: '0.8rem', color: '#64748b' }}>
                    <span>Type: <strong>{client.is_confidential ? 'Confidential' : 'Public (PKCE)'}</strong></span>
                    <span>PKCE Required: <strong>{client.require_pkce ? 'Yes (S256)' : 'No'}</strong></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section style={{ marginTop: '2rem', background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '8px', padding: '1.25rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>Integration Quick Reference</h3>
        <p style={{ fontSize: '0.85rem', color: '#475569', marginBottom: '0.5rem' }}>
          To start an OAuth 2.0 authorization code flow with PKCE:
        </p>
        <pre style={{ background: '#0f172a', color: '#f8fafc', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem', overflowX: 'auto' }}>
{`GET http://localhost:4000/authorize?
  response_type=code
  &client_id=<YOUR_CLIENT_ID>
  &redirect_uri=<YOUR_REDIRECT_URI>
  &scope=openid profile email
  &state=<RANDOM_CSRF_TOKEN>
  &code_challenge=<BASE64URL_SHA256(code_verifier)>
  &code_challenge_method=S256`}
        </pre>
      </section>
    </div>
  );
};
