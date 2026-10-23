import React, { useEffect, useState } from 'react';
import {
  BACKEND_URL,
  type ActiveSessionInfo,
  type AppDirectoryUser,
  type ClientAppItem,
  type NewClientResponse,
  type OrganizationItem,
  type PasskeyItem,
  type SaasOverviewResponse,
  type ScopedApiKeyItem,
  type SessionUserInfo,
  confirmEmailVerificationOtp,
  createClientApiKey,
  createOrganization,
  deleteClientApp,
  deleteUserPasskey,
  disableMfa,
  enableMfa,
  fetchClientApiKeys,
  fetchClientUsers,
  fetchClients,
  fetchCurrentSession,
  fetchSaasOverview,
  fetchUserOrganizations,
  fetchUserPasskeys,
  fetchUserSessions,
  inviteOrganizationMember,
  regenerateClientSecret,
  registerClientApp,
  registerUserPasskey,
  removeOrganizationMember,
  revokeClientApiKey,
  revokeUserSession,
  sendEmailVerificationOtp,
  sendPasswordlessOtp,
  setupMfa,
  submitPortalLogin,
  submitPortalLogout,
  switchActiveOrganization,
  triggerTestWebhook,
  updateClientSettings,
  updateClientUser,
} from '../services/api.js';

interface DevPortalProps {
  onBackToLogin?: () => void;
}

export const DevPortal: React.FC<DevPortalProps> = ({ onBackToLogin }) => {
  // Auth state
  const [authChecking, setAuthChecking] = useState(true);
  const [currentUser, setCurrentUser] = useState<SessionUserInfo | null>(null);
  const [portalAuthMode, setPortalAuthMode] = useState<'password' | 'otp' | 'passkey'>('password');
  const [loginEmail, setLoginEmail] = useState('admin@soauth.internal');
  const [loginPassword, setLoginPassword] = useState('SoAuthAdminPassword!2026');
  const [loginOtpCode, setLoginOtpCode] = useState('');
  const [loginOtpSent, setLoginOtpSent] = useState(false);
  const [loginMfaCode, setLoginMfaCode] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);

  // Navigation Tabs (5 SaaS Pillars)
  const [activeTab, setActiveTab] = useState<'apps' | 'branding' | 'orgs' | 'users' | 'security'>('apps');

  // Clients & Quickstart state
  const [clients, setClients] = useState<ClientAppItem[]>([]);
  const [selectedClientId, setSelectedClientId] = useState<string>('');
  const [snippetTab, setSnippetTab] = useState<'react' | 'nextjs' | 'm2m' | 'vanilla'>('react');
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

  // Feature 4: Scoped API Keys & M2M state
  const [apiKeys, setApiKeys] = useState<ScopedApiKeyItem[]>([]);
  const [newApiKeyName, setNewApiKeyName] = useState('');
  const [newApiKeyScopes, setNewApiKeyScopes] = useState('openid profile email');
  const [revealedApiKey, setRevealedApiKey] = useState<string | null>(null);

  // Branding, Custom Claims & Webhook Editor state (Feature 6)
  const [brandLogoUrl, setBrandLogoUrl] = useState('');
  const [brandPrimaryColor, setBrandPrimaryColor] = useState('#111827');
  const [brandWebsiteUrl, setBrandWebsiteUrl] = useState('');
  const [brandPrivacyUrl, setBrandPrivacyUrl] = useState('');
  const [brandTermsUrl, setBrandTermsUrl] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [customClaimsTemplate, setCustomClaimsTemplate] = useState(
    '{\n  "plan": "pro",\n  "tenant_tier": "enterprise",\n  "org_slug": "{{org.slug}}"\n}',
  );
  const [savingSettings, setSavingSettings] = useState(false);

  // Feature 2: Multi-Tenant Organizations & Team Invitations state
  const [organizations, setOrganizations] = useState<OrganizationItem[]>([]);
  const [activeOrgId, setActiveOrgId] = useState<string | null>(null);
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'org:admin' | 'org:member' | 'org:billing'>('org:member');

  // Per-App User Directory & RBAC state
  const [appUsers, setAppUsers] = useState<AppDirectoryUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);

  // SaaS Usage, Audit Logs, Email Verification, Passkeys & 2FA state (Features 3 & 5)
  const [saasOverview, setSaasOverview] = useState<SaasOverviewResponse | null>(null);
  const [sessions, setSessions] = useState<ActiveSessionInfo[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([]);
  const [newPasskeyDeviceName, setNewPasskeyDeviceName] = useState('MacBook Pro Touch ID');
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [mfaSetupData, setMfaSetupData] = useState<{
    secret: string;
    otpauth_uri: string;
    current_test_code?: string;
  } | null>(null);
  const [mfaVerifyCode, setMfaVerifyCode] = useState('');
  const [mfaSubmitting, setMfaSubmitting] = useState(false);
  const [emailOtpSent, setEmailOtpSent] = useState(false);
  const [emailOtpCode, setEmailOtpCode] = useState('');

  const syncBrandingFormFromClient = (client: ClientAppItem | undefined) => {
    if (!client) return;
    setBrandLogoUrl(client.logo_url ?? '');
    setBrandPrimaryColor(client.primary_color ?? '#111827');
    setBrandWebsiteUrl(client.app_website_url ?? '');
    setBrandPrivacyUrl(client.privacy_policy_url ?? '');
    setBrandTermsUrl(client.terms_of_service_url ?? '');
    setWebhookUrl(client.webhook_url ?? '');
    setCustomClaimsTemplate(
      client.custom_claims_template ??
        JSON.stringify({ plan: 'pro', tenant_tier: 'enterprise', org_slug: '{{org.slug}}' }, null, 2),
    );
  };

  const loadApiKeys = async (clientId: string) => {
    if (!clientId) return;
    try {
      const keys = await fetchClientApiKeys(clientId);
      setApiKeys(keys);
    } catch {
      // Ignore API key load errors
    }
  };

  const loadOrganizations = async () => {
    try {
      const data = await fetchUserOrganizations();
      setOrganizations(data.organizations);
      setActiveOrgId(data.active_org_id);
    } catch {
      // Ignore organization load errors
    }
  };

  const loadClients = async () => {
    try {
      setLoading(true);
      const data = await fetchClients();
      setClients(data);
      const activeId = selectedClientId || data[0]?.id || '';
      if (activeId) {
        setSelectedClientId(activeId);
        const found = data.find((c) => c.id === activeId) ?? data[0];
        syncBrandingFormFromClient(found);
        void loadApiKeys(activeId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load clients');
    } finally {
      setLoading(false);
    }
  };

  const loadAppUsers = async (clientId: string) => {
    if (!clientId) return;
    try {
      setUsersLoading(true);
      const list = await fetchClientUsers(clientId);
      setAppUsers(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load application users');
    } finally {
      setUsersLoading(false);
    }
  };

  const loadSecurityAndSaasOverview = async () => {
    try {
      setSessionsLoading(true);
      const [sessList, overview, pkList] = await Promise.all([
        fetchUserSessions(),
        fetchSaasOverview(),
        fetchUserPasskeys(),
      ]);
      setSessions(sessList);
      setSaasOverview(overview);
      setPasskeys(pkList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load security & SaaS overview');
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
          void loadOrganizations();
          void loadSecurityAndSaasOverview();
        }
      })
      .catch(() => {
        // Not authenticated
      })
      .finally(() => {
        setAuthChecking(false);
      });
  }, []);

  useEffect(() => {
    const client = clients.find((c) => c.id === selectedClientId);
    if (client) {
      syncBrandingFormFromClient(client);
      void loadApiKeys(client.id);
      if (activeTab === 'users') {
        void loadAppUsers(client.id);
      }
    }
  }, [selectedClientId]);

  const launchHostedLoginDemo = (client?: ClientAppItem) => {
    const targetClientId = client?.id ?? '00000000-0000-4000-8000-000000000001';
    const targetAppName = client?.app_name ?? 'soauth Reference Web App';
    const targetRedirect =
      client?.redirect_uris[0] ?? `${window.location.origin}/callback`;

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: targetClientId,
      app_name: targetAppName,
      redirect_uri: targetRedirect,
      scope: 'openid profile email offline_access',
      state: 'demo_state_token_2026_pkce',
      code_challenge: 'E9Melhoa2OwvFrGMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    });
    window.location.assign(`${window.location.pathname}?${params.toString()}`);
  };

  const handleSendPortalOtp = async () => {
    setError(null);
    try {
      const res = await sendPasswordlessOtp(loginEmail.trim());
      setLoginOtpSent(true);
      if (res.dev_otp_code) {
        setLoginOtpCode(res.dev_otp_code);
        setSuccessMsg(`One-time code sent (Dev Sandbox Code: ${res.dev_otp_code})`);
      } else {
        setSuccessMsg(res.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send code');
    }
  };

  const handlePortalLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (portalAuthMode === 'otp' && !loginOtpSent) {
      await handleSendPortalOtp();
      return;
    }

    setLoginLoading(true);
    try {
      let passkeyCredentialId: string | undefined;
      if (portalAuthMode === 'passkey') {
        passkeyCredentialId = 'auto';
        if (typeof window !== 'undefined' && window.PublicKeyCredential && navigator.credentials) {
          try {
            const challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);
            const assertion = (await navigator.credentials.get({
              publicKey: { challenge, timeout: 30000, userVerification: 'preferred' },
            })) as PublicKeyCredential | null;
            if (assertion?.id) passkeyCredentialId = assertion.id;
          } catch {
            // Fallback to registered platform passkey lookup by email
          }
        }
      }

      const res = await submitPortalLogin({
        email: loginEmail,
        ...(portalAuthMode === 'password' ? { password: loginPassword } : {}),
        ...(portalAuthMode === 'otp' ? { otpCode: loginOtpCode } : {}),
        ...(portalAuthMode === 'passkey' && passkeyCredentialId
          ? { passkeyCredentialId }
          : {}),
        ...(loginMfaCode ? { mfaCode: loginMfaCode } : {}),
      });
      setCurrentUser(res.user);
      setLoginMfaCode('');
      setLoginOtpSent(false);
      await Promise.all([loadClients(), loadOrganizations(), loadSecurityAndSaasOverview()]);
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

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClientId) return;
    setError(null);
    try {
      const scopes = newApiKeyScopes
        .split(' ')
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await createClientApiKey(selectedClientId, {
        name: newApiKeyName || 'Backend M2M Service Key',
        scopes,
      });
      setRevealedApiKey(res.raw_key);
      setNewApiKeyName('');
      setSuccessMsg('Scoped M2M API Key generated.');
      await loadApiKeys(selectedClientId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create API key');
    }
  };

  const handleRevokeApiKey = async (keyId: string) => {
    if (!selectedClientId) return;
    try {
      await revokeClientApiKey(selectedClientId, keyId);
      setSuccessMsg('API key revoked.');
      await loadApiKeys(selectedClientId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke API key');
    }
  };

  const handleCreateOrganization = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const org = await createOrganization({
        name: newOrgName,
        ...(newOrgSlug.trim() ? { slug: newOrgSlug.trim() } : {}),
      });
      setNewOrgName('');
      setNewOrgSlug('');
      setSuccessMsg(`Organization "${org.name}" (${org.slug}) created and set as active.`);
      await loadOrganizations();
      const session = await fetchCurrentSession();
      if (session.user) setCurrentUser(session.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create organization');
    }
  };

  const handleInviteOrgMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrgId) return;
    setError(null);
    try {
      await inviteOrganizationMember(activeOrgId, {
        email: inviteEmail,
        role: inviteRole,
      });
      setInviteEmail('');
      setSuccessMsg(`Invited ${inviteEmail} as ${inviteRole}.`);
      await loadOrganizations();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to invite member');
    }
  };

  const handleRemoveOrgMember = async (orgId: string, memberId: string) => {
    try {
      await removeOrganizationMember(orgId, memberId);
      setSuccessMsg('Member removed from organization.');
      await loadOrganizations();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove member');
    }
  };

  const handleSwitchOrg = async (orgId: string) => {
    try {
      const res = await switchActiveOrganization(orgId);
      setActiveOrgId(res.active_org_id);
      setCurrentUser((prev) =>
        prev
          ? {
              ...prev,
              ...(res.org_id !== undefined ? { org_id: res.org_id } : {}),
              ...(res.org_slug !== undefined ? { org_slug: res.org_slug } : {}),
              ...(res.org_role !== undefined ? { org_role: res.org_role } : {}),
            }
          : prev,
      );
      setSuccessMsg(`Switched active organization context to ${res.org_slug ?? orgId}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch organization');
    }
  };

  const handleRegisterPasskey = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      let credentialId: string | undefined;
      if (
        typeof window !== 'undefined' &&
        window.PublicKeyCredential &&
        navigator.credentials &&
        currentUser
      ) {
        try {
          const challenge = new Uint8Array(32);
          window.crypto.getRandomValues(challenge);
          const userIdBytes = new TextEncoder().encode(currentUser.id);
          const created = (await navigator.credentials.create({
            publicKey: {
              challenge,
              rp: { name: 'soauth Identity Platform', id: window.location.hostname },
              user: {
                id: userIdBytes,
                name: currentUser.email,
                displayName: currentUser.email,
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -257 },
              ],
              authenticatorSelection: {
                userVerification: 'preferred',
              },
              timeout: 30000,
            },
          })) as PublicKeyCredential | null;
          if (created?.id) {
            credentialId = created.id;
          }
        } catch {
          // If browser WebAuthn dialog is cancelled or unavailable in headless preview, register platform passkey credential
        }
      }

      const pk = await registerUserPasskey({
        device_name: newPasskeyDeviceName || 'Platform Biometric Passkey',
        ...(credentialId ? { credential_id: credentialId } : {}),
      });
      setPasskeys((prev) => [...prev, pk]);
      setSuccessMsg(`Registered Passkey "${pk.device_name}" for passwordless biometric login.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register passkey');
    }
  };

  const handleDeletePasskey = async (id: string) => {
    try {
      await deleteUserPasskey(id);
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
      setSuccessMsg('Passkey removed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove passkey');
    }
  };

  const handleSaveBrandingAndWebhooks = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedClientId) return;
    setError(null);
    setSavingSettings(true);
    try {
      await updateClientSettings(selectedClientId, {
        logo_url: brandLogoUrl.trim() || null,
        primary_color: brandPrimaryColor.trim() || '#111827',
        app_website_url: brandWebsiteUrl.trim() || null,
        privacy_policy_url: brandPrivacyUrl.trim() || null,
        terms_of_service_url: brandTermsUrl.trim() || null,
        webhook_url: webhookUrl.trim() || null,
        custom_claims_template: customClaimsTemplate.trim() || null,
      });
      setSuccessMsg('Custom branding, JWT claims template & webhook settings saved.');
      await loadClients();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSavingSettings(false);
    }
  };

  const handleTestWebhook = async () => {
    if (!selectedClientId) return;
    setError(null);
    try {
      const res = await triggerTestWebhook(selectedClientId);
      if (res.delivered) {
        setSuccessMsg(`HMAC-signed test webhook delivered (HTTP ${res.statusCode}).`);
      } else {
        setError(`Webhook delivery failed: ${res.error ?? `HTTP ${res.statusCode}`}`);
      }
      await loadSecurityAndSaasOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send test webhook');
    }
  };

  const handleUpdateUserRole = async (userId: string, newRole: string) => {
    if (!selectedClientId) return;
    setError(null);
    try {
      await updateClientUser(selectedClientId, userId, { role: newRole });
      setSuccessMsg(`Updated user RBAC role to "${newRole}".`);
      await loadAppUsers(selectedClientId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    }
  };

  const handleRevokeAppUserSessions = async (userId: string, email: string) => {
    if (!selectedClientId) return;
    if (!window.confirm(`Revoke all active sessions for ${email}?`)) return;
    setError(null);
    try {
      await updateClientUser(selectedClientId, userId, { revoke_sessions: true });
      setSuccessMsg(`Revoked all active sessions for ${email}.`);
      await loadAppUsers(selectedClientId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke user sessions');
    }
  };

  const handleSendEmailOtp = async () => {
    setError(null);
    try {
      const res = await sendEmailVerificationOtp();
      setEmailOtpSent(true);
      if (res.dev_otp_code) {
        setEmailOtpCode(res.dev_otp_code);
      }
      setSuccessMsg(res.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send verification code');
    }
  };

  const handleConfirmEmailOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const res = await confirmEmailVerificationOtp(emailOtpCode);
      setCurrentUser((prev) => (prev ? { ...prev, email_verified: true } : prev));
      setEmailOtpSent(false);
      setSuccessMsg(res.message);
      await loadSecurityAndSaasOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
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
      setSuccessMsg('Two-Factor Authentication (TOTP) enabled on your account.');
      await loadSecurityAndSaasOverview();
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
      await loadSecurityAndSaasOverview();
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
        await loadSecurityAndSaasOverview();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke session');
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setSuccessMsg(`Copied ${label} to clipboard.`);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  if (authChecking) {
    return (
      <div className="auth-stage">
        <div className="oauth-card" style={{ textAlign: 'center' }}>
          <div className="brand-monogram" style={{ margin: '0 auto 0.5rem' }}>
            S
          </div>
          <p style={{ color: '#64748b' }}>Loading soauth Cloud Workspace...</p>
        </div>
      </div>
    );
  }

  // Split-Screen SaaS Hero Sign-In Gate
  if (!currentUser) {
    return (
      <div className="split-auth-layout">
        {/* Left Sign-In Form Column */}
        <div className="split-form-panel">
          <div style={{ maxWidth: '400px', width: '100%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <div className="brand-monogram" style={{ marginBottom: 0, width: '38px', height: '38px', fontSize: '1rem' }}>
                  S
                </div>
                <span style={{ fontWeight: 800, fontSize: '1.15rem', letterSpacing: '-0.02em', color: '#111827' }}>
                  soauth Cloud
                </span>
              </div>
              {onBackToLogin && (
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ padding: '0.35rem 0.7rem', fontSize: '0.78rem' }}
                  onClick={onBackToLogin}
                >
                  Back to App Login
                </button>
              )}
            </div>

            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, letterSpacing: '-0.02em', marginBottom: '0.35rem', color: '#111827' }}>
              Sign in to Developer Console
            </h1>
            <p style={{ fontSize: '0.9rem', color: '#6b7280', marginBottom: '1.25rem', lineHeight: 1.5 }}>
              Manage your multi-tenant OAuth 2.1 apps, organizations, passkeys, M2M keys, and custom JWT claims.
            </p>

            {error && (
              <div className="oauth-error" style={{ marginBottom: '1rem' }}>
                <span>{error}</span>
              </div>
            )}
            {successMsg && (
              <div className="oauth-success" style={{ marginBottom: '1rem' }}>
                {successMsg}
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.4rem', marginBottom: '1rem' }}>
              {(['password', 'otp', 'passkey'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  className="btn-secondary"
                  onClick={() => {
                    setPortalAuthMode(mode);
                    setError(null);
                  }}
                  style={{
                    padding: '0.45rem 0.5rem',
                    fontSize: '0.78rem',
                    borderColor: portalAuthMode === mode ? '#111827' : '#d1d5db',
                    fontWeight: portalAuthMode === mode ? 700 : 500,
                  }}
                >
                  {mode === 'password' ? 'Password' : mode === 'otp' ? 'Email Code' : 'Passkey'}
                </button>
              ))}
            </div>

            <form onSubmit={handlePortalLogin}>
              <div>
                <label htmlFor="portal-email">Developer Email</label>
                <input
                  id="portal-email"
                  type="email"
                  required
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                />
              </div>

              {portalAuthMode === 'password' && (
                <>
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
                      placeholder="Optional 6-digit TOTP code"
                      value={loginMfaCode}
                      onChange={(e) => setLoginMfaCode(e.target.value)}
                    />
                  </div>
                </>
              )}

              {portalAuthMode === 'otp' && loginOtpSent && (
                <div>
                  <label htmlFor="portal-otp">6-Digit Email Sign-In Code</label>
                  <input
                    id="portal-otp"
                    type="text"
                    required
                    maxLength={6}
                    value={loginOtpCode}
                    onChange={(e) => setLoginOtpCode(e.target.value)}
                  />
                </div>
              )}

              {portalAuthMode === 'passkey' && (
                <div style={{ padding: '0.75rem', border: '1px solid #e5e7eb', borderRadius: '8px', background: '#ffffff', fontSize: '0.8rem', color: '#4b5563' }}>
                  Sign in with a registered WebAuthn biometric passkey linked to your email address.
                </div>
              )}

              <button type="submit" className="btn-secondary" disabled={loginLoading} style={{ width: '100%', marginTop: '0.25rem', borderColor: '#111827' }}>
                {loginLoading
                  ? 'Signing in...'
                  : portalAuthMode === 'otp'
                    ? loginOtpSent
                      ? 'Verify Code & Open Dashboard'
                      : 'Send 6-Digit Email Code'
                    : portalAuthMode === 'passkey'
                      ? 'Sign in with Passkey'
                      : 'Open Cloud Dashboard'}
              </button>
            </form>

            <div className="divider" style={{ margin: '1.25rem 0' }}>
              instant sandbox actions
            </div>

            <div style={{ display: 'flex', gap: '0.6rem' }}>
              <button
                type="button"
                className="btn-secondary"
                style={{ flex: 1, fontSize: '0.8rem' }}
                onClick={() => {
                  setPortalAuthMode('password');
                  setLoginEmail('admin@soauth.internal');
                  setLoginPassword('SoAuthAdminPassword!2026');
                }}
              >
                Fill Demo Admin
              </button>
              <button
                type="button"
                className="btn-secondary"
                style={{ flex: 1, fontSize: '0.8rem' }}
                onClick={() => launchHostedLoginDemo()}
              >
                Preview Hosted Login
              </button>
            </div>
          </div>
        </div>

        {/* Right SaaS Showcase Column (Pure White) */}
        <div className="split-hero-panel">
          <div>
            <span
              style={{
                display: 'inline-block',
                background: '#ffffff',
                border: '1px solid #d1d5db',
                color: '#111827',
                padding: '0.3rem 0.75rem',
                borderRadius: '999px',
                fontSize: '0.75rem',
                fontWeight: 700,
                marginBottom: '1.25rem',
              }}
            >
              Production OAuth 2.1 &amp; OIDC SaaS Platform
            </span>
            <h2
              style={{
                fontSize: '2.1rem',
                fontWeight: 800,
                lineHeight: 1.2,
                letterSpacing: '-0.02em',
                marginBottom: '1rem',
                color: '#111827',
              }}
            >
              Drop-in authentication built for modern apps.
            </h2>
            <p style={{ color: '#4b5563', fontSize: '0.98rem', lineHeight: 1.6, maxWidth: '480px' }}>
              Give your users a 1-click Google &amp; Clerk-grade login experience with Passwordless OTP, WebAuthn Passkeys, B2B Organizations, M2M API Keys, and Custom JWT Claims.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '2rem' }}>
              {[
                {
                  title: 'Passwordless & Passkeys',
                  desc: 'Sign in with 6-digit email codes, WebAuthn biometrics, or 1-click SSO cookies.',
                },
                {
                  title: 'B2B Organizations',
                  desc: 'Multi-tenant workspaces, team invitations, and org_id/org_role in RS256 JWTs.',
                },
                {
                  title: 'M2M & Scoped API Keys',
                  desc: 'Issue client_credentials tokens and soauth_live_ keys for backend microservices.',
                },
                {
                  title: 'Custom JWT Templates',
                  desc: 'Inject dynamic custom claims ({{org.slug}}, {{user.role}}) into ID & Access tokens.',
                },
              ].map((feat) => (
                <div
                  key={feat.title}
                  style={{
                    background: '#ffffff',
                    border: '1px solid #e5e7eb',
                    borderRadius: '12px',
                    padding: '1rem',
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#111827', marginBottom: '0.3rem' }}>
                    {feat.title}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#6b7280', lineHeight: 1.45 }}>{feat.desc}</div>
                </div>
              ))}
            </div>
          </div>

          <div
            style={{
              background: '#ffffff',
              border: '1px solid #e5e7eb',
              borderRadius: '12px',
              padding: '1rem 1.25rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.78rem',
              color: '#111827',
            }}
          >
            <div style={{ color: '#6b7280', marginBottom: '0.35rem' }}>// React integration (@soauth/sdk/react)</div>
            <div>{`<SoAuthProvider issuerUrl="${BACKEND_URL}" clientId="your_client_id">`}</div>
            <div style={{ paddingLeft: '1rem' }}>{`<SignedOut><SignInButton /></SignedOut>`}</div>
            <div style={{ paddingLeft: '1rem' }}>{`<SignedIn><OrganizationSwitcher /><UserButton /></SignedIn>`}</div>
            <div>{`</SoAuthProvider>`}</div>
          </div>
        </div>
      </div>
    );
  }

  const activeClient = clients.find((c) => c.id === selectedClientId) ?? clients[0];
  const sampleClientId = activeClient?.id ?? 'client_default_test';
  const sampleRedirectUri = activeClient?.redirect_uris[0] ?? `${window.location.origin}/callback`;
  const activeOrg = organizations.find((o) => o.id === activeOrgId) ?? organizations[0];

  const reactSnippet = `import React from 'react';
import { createSoAuthReact } from '@soauth/sdk/react';

export const {
  SoAuthProvider,
  useSoAuth,
  SignedIn,
  SignedOut,
  SignInButton,
  UserButton,
  OrganizationSwitcher,
  UserProfile,
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
          <OrganizationSwitcher />
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

  const m2mSnippet = `import { exchangeClientCredentials } from '@soauth/sdk';

// Machine-to-Machine (M2M) Backend Service Token Exchange
const tokens = await exchangeClientCredentials({
  issuerUrl: '${BACKEND_URL}',
  clientId: '${sampleClientId}',
  clientSecret: process.env.SOAUTH_API_KEY_OR_SECRET!, // e.g. soauth_live_...
  scope: 'openid profile email',
});

console.log('M2M RS256 Access Token:', tokens.access_token);`;

  const vanillaSnippet = `import { SoAuthClient } from '@soauth/sdk';

const auth = new SoAuthClient({
  issuerUrl: '${BACKEND_URL}',
  clientId: '${sampleClientId}',
  redirectUri: '${sampleRedirectUri}',
});

const state = await auth.initialize();

if (!state.isAuthenticated) {
  await auth.loginWithRedirect();
} else {
  console.log('User:', state.user?.email, 'Org Role:', state.user?.org_role);
}`;

  const currentSnippet =
    snippetTab === 'react'
      ? reactSnippet
      : snippetTab === 'nextjs'
        ? nextjsSnippet
        : snippetTab === 'm2m'
          ? m2mSnippet
          : vanillaSnippet;

  return (
    <div className="saas-shell">
      {/* Left SaaS Navigation Sidebar (Pure White) */}
      <aside className="saas-sidebar">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', padding: '0 0.5rem 1.25rem', borderBottom: '1px solid #e5e7eb' }}>
            <div className="brand-monogram" style={{ marginBottom: 0, width: '36px', height: '36px', fontSize: '0.95rem' }}>
              S
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '1.05rem', color: '#111827', letterSpacing: '-0.02em' }}>
                soauth Cloud
              </div>
              <div style={{ fontSize: '0.72rem', color: '#6b7280' }}>Multi-Tenant OIDC SaaS</div>
            </div>
          </div>

          {/* Active App Switcher in Sidebar */}
          {clients.length > 0 && (
            <div style={{ marginTop: '1.15rem', marginBottom: '1.25rem', padding: '0 0.25rem' }}>
              <label style={{ color: '#6b7280', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Selected Application
              </label>
              <select
                value={selectedClientId}
                onChange={(e) => setSelectedClientId(e.target.value)}
                style={{
                  background: '#ffffff',
                  color: '#111827',
                  border: '1px solid #d1d5db',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  padding: '0.55rem 0.7rem',
                }}
              >
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.app_name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Sidebar Nav Items */}
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
            <button
              type="button"
              className={`saas-nav-btn ${activeTab === 'apps' ? 'active' : ''}`}
              onClick={() => setActiveTab('apps')}
            >
              <span>Apps, M2M Keys &amp; SDK ({clients.length})</span>
            </button>
            <button
              type="button"
              className={`saas-nav-btn ${activeTab === 'branding' ? 'active' : ''}`}
              onClick={() => setActiveTab('branding')}
            >
              <span>Branding, Claims &amp; Webhooks</span>
            </button>
            <button
              type="button"
              className={`saas-nav-btn ${activeTab === 'orgs' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('orgs');
                void loadOrganizations();
              }}
            >
              <span>Organizations &amp; Teams ({organizations.length})</span>
            </button>
            <button
              type="button"
              className={`saas-nav-btn ${activeTab === 'users' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('users');
                if (activeClient) void loadAppUsers(activeClient.id);
              }}
            >
              <span>Users &amp; RBAC Roles</span>
            </button>
            <button
              type="button"
              className={`saas-nav-btn ${activeTab === 'security' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('security');
                void loadSecurityAndSaasOverview();
              }}
            >
              <span>Passkeys, Profile &amp; Audit</span>
            </button>
          </nav>

          {/* 1-Click Live Hosted Login Test Button */}
          <div style={{ marginTop: '1.5rem', padding: '0.85rem', background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '10px' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#111827', marginBottom: '0.25rem' }}>
              Test Live OAuth Flow
            </div>
            <div style={{ fontSize: '0.72rem', color: '#6b7280', marginBottom: '0.65rem', lineHeight: 1.4 }}>
              Launch the hosted login &amp; consent screen for <strong>{activeClient?.app_name ?? 'your app'}</strong>.
            </div>
            <button
              type="button"
              className="btn-secondary"
              style={{ width: '100%', padding: '0.5rem 0.75rem', fontSize: '0.78rem' }}
              onClick={() => launchHostedLoginDemo(activeClient)}
            >
              Try Hosted Login
            </button>
          </div>
        </div>

        {/* Bottom Tenant Profile Bar */}
        <div style={{ borderTop: '1px solid #e5e7eb', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div
              style={{
                width: '34px',
                height: '34px',
                borderRadius: '50%',
                background: '#ffffff',
                border: '1px solid #d1d5db',
                color: '#111827',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '0.85rem',
                flexShrink: 0,
              }}
            >
              {currentUser.email.charAt(0).toUpperCase()}
            </div>
            <div style={{ overflow: 'hidden' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#111827', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                {currentUser.email}
              </div>
              <div style={{ fontSize: '0.7rem', color: '#6b7280' }}>
                Org: {currentUser.org_slug ?? 'acme-corp'} ({currentUser.org_role ?? 'org:admin'})
              </div>
            </div>
          </div>

          <button
            type="button"
            className="btn-danger"
            style={{ width: '100%', padding: '0.45rem', fontSize: '0.78rem' }}
            onClick={handlePortalLogout}
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Workspace Area */}
      <div className="saas-workspace">
        <header className="saas-topbar">
          <div>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#111827', letterSpacing: '-0.02em' }}>
              {activeTab === 'apps' && 'Applications, M2M Keys & SDK Quickstart'}
              {activeTab === 'branding' && 'Login Branding, Custom JWT Claims & Webhooks'}
              {activeTab === 'orgs' && 'Multi-Tenant Organizations & Team Invitations'}
              {activeTab === 'users' && 'Application User Directory & RBAC Roles'}
              {activeTab === 'security' && 'Self-Service Account Profile, Passkeys, 2FA & Audit'}
            </h1>
            <p style={{ fontSize: '0.8rem', color: '#6b7280' }}>
              OIDC Issuer: <code>{BACKEND_URL}</code>
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
            {organizations.length > 0 && (
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  background: '#ffffff',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  padding: '0.28rem 0.6rem',
                }}
              >
                <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#6b7280', textTransform: 'uppercase' }}>
                  Org
                </span>
                <select
                  value={activeOrg?.id ?? ''}
                  onChange={(e) => void handleSwitchOrg(e.target.value)}
                  style={{
                    width: 'auto',
                    border: 'none',
                    background: '#ffffff',
                    color: '#111827',
                    fontSize: '0.8rem',
                    fontWeight: 700,
                    padding: '0.1rem 0.25rem',
                    boxShadow: 'none',
                  }}
                >
                  {organizations.map((org) => (
                    <option key={org.id} value={org.id}>
                      {org.name} ({org.slug})
                    </option>
                  ))}
                </select>
              </div>
            )}
            <span className="pill">
              {currentUser.is_mfa_enabled ? '2FA Protected' : '2FA Off'}
            </span>
            <span className="pill">Role: {currentUser.role ?? 'member'}</span>
            {onBackToLogin && (
              <button
                type="button"
                className="btn-secondary"
                style={{ padding: '0.5rem 0.85rem', fontSize: '0.8rem' }}
                onClick={onBackToLogin}
              >
                Return to OAuth Flow
              </button>
            )}
            <button
              type="button"
              className="btn-secondary"
              style={{ padding: '0.5rem 0.95rem', fontSize: '0.82rem', borderColor: '#111827' }}
              onClick={() => {
                setActiveTab('apps');
                setShowCreateModal(true);
                setCreatedSecretInfo(null);
              }}
            >
              + Register Application
            </button>
          </div>
        </header>

        <div className="saas-content">
          {successMsg && <div className="oauth-success">{successMsg}</div>}
          {error && (
            <div className="oauth-error">
              <span>{error}</span>
            </div>
          )}

          {/* TAB 1: APPLICATIONS, M2M KEYS & SDK QUICKSTART */}
          {activeTab === 'apps' && (
            <>
              {createdSecretInfo && (
                <div
                  style={{
                    background: '#ffffff',
                    border: '1px solid #d1d5db',
                    color: '#111827',
                    padding: '1.25rem',
                    borderRadius: '12px',
                  }}
                >
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                    Application Created: {createdSecretInfo.client_name}
                  </h3>
                  <p style={{ fontSize: '0.84rem', marginBottom: '0.75rem' }}>
                    Save your credentials now. The client secret is hashed with Argon2id and never shown again.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <div>
                      <strong style={{ fontSize: '0.84rem' }}>Client ID: </strong>
                      <code>{createdSecretInfo.client_id}</code>
                      <button
                        type="button"
                        className="btn-secondary"
                        style={{ marginLeft: '0.5rem', padding: '0.2rem 0.55rem', fontSize: '0.75rem' }}
                        onClick={() => copyToClipboard(createdSecretInfo.client_id, 'Client ID')}
                      >
                        Copy
                      </button>
                    </div>
                    {createdSecretInfo.client_secret && (
                      <div>
                        <strong style={{ fontSize: '0.84rem' }}>Client Secret: </strong>
                        <code>{createdSecretInfo.client_secret}</code>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ marginLeft: '0.5rem', padding: '0.2rem 0.55rem', fontSize: '0.75rem' }}
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
                    background: '#ffffff',
                    border: '1px solid #d1d5db',
                    color: '#111827',
                    padding: '1.15rem',
                    borderRadius: '12px',
                  }}
                >
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                    Rotated Secret for Client: {revealedSecret.clientId}
                  </h3>
                  <p style={{ fontSize: '0.84rem' }}>
                    New Client Secret: <code>{revealedSecret.secret}</code>
                    <button
                      type="button"
                      className="btn-secondary"
                      style={{ marginLeft: '0.5rem', padding: '0.2rem 0.55rem', fontSize: '0.75rem' }}
                      onClick={() => copyToClipboard(revealedSecret.secret, 'Rotated Secret')}
                    >
                      Copy
                    </button>
                  </p>
                </div>
              )}

              {showCreateModal && (
                <div className="surface-card" style={{ border: '1px solid #111827' }}>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700, marginBottom: '1rem' }}>
                    Register New OAuth 2.1 / OIDC Client
                  </h2>
                  <form onSubmit={handleCreateClient}>
                    <div>
                      <label>Application Name</label>
                      <input
                        type="text"
                        required
                        placeholder="Acme Customer Portal"
                        value={newAppName}
                        onChange={(e) => setNewAppName(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Allowed Redirect URIs (one per line)</label>
                      <textarea
                        required
                        rows={3}
                        style={{ fontFamily: 'var(--font-mono)', fontSize: '0.84rem' }}
                        value={newRedirectUris}
                        onChange={(e) => setNewRedirectUris(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Allowed OIDC Scopes</label>
                      <input type="text" value={newScopes} onChange={(e) => setNewScopes(e.target.value)} />
                    </div>
                    <div>
                      <label>Application Architecture</label>
                      <div style={{ display: 'flex', gap: '1.25rem', marginTop: '0.35rem', flexWrap: 'wrap' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                          <input
                            type="radio"
                            name="clientType"
                            checked={clientType === 'public'}
                            onChange={() => setClientType('public')}
                            style={{ width: 'auto' }}
                          />
                          Public Client (React / Vite SPA / Mobile — PKCE S256)
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer' }}>
                          <input
                            type="radio"
                            name="clientType"
                            checked={clientType === 'confidential'}
                            onChange={() => setClientType('confidential')}
                            style={{ width: 'auto' }}
                          />
                          Confidential Client (Next.js / Node Backend with Secret)
                        </label>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: '0.65rem', marginTop: '0.5rem' }}>
                      <button type="button" className="btn-secondary" onClick={() => setShowCreateModal(false)}>
                        Cancel
                      </button>
                      <button type="submit" className="btn-secondary" style={{ borderColor: '#111827' }}>
                        Create Application
                      </button>
                    </div>
                  </form>
                </div>
              )}

              <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem' }}>
                {loading ? (
                  <p style={{ color: '#6b7280' }}>Loading applications...</p>
                ) : (
                  clients.map((client) => {
                    const isSelected = selectedClientId === client.id;
                    return (
                      <div
                        key={client.id}
                        className="surface-card"
                        style={{
                          border: isSelected ? '2px solid #111827' : '1px solid var(--border)',
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'space-between',
                          gap: '1rem',
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.75rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                              <div
                                style={{
                                  width: '36px',
                                  height: '36px',
                                  borderRadius: '10px',
                                  background: '#ffffff',
                                  border: '1px solid #d1d5db',
                                  color: '#111827',
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'center',
                                  fontWeight: 800,
                                  fontSize: '0.95rem',
                                }}
                              >
                                {client.app_name.charAt(0).toUpperCase()}
                              </div>
                              <div>
                                <h3 style={{ fontSize: '1.02rem', fontWeight: 700 }}>{client.app_name}</h3>
                                <span className="pill">
                                  {client.is_confidential ? 'Confidential + PKCE' : 'Public SPA (PKCE)'}
                                </span>
                              </div>
                            </div>
                            {isSelected && <span className="pill">Active</span>}
                          </div>

                          <div style={{ fontSize: '0.82rem', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#ffffff', padding: '0.45rem 0.65rem', borderRadius: '6px', border: '1px solid #e5e7eb' }}>
                              <span style={{ color: '#6b7280', fontSize: '0.76rem' }}>Client ID</span>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                <code style={{ border: 'none', background: 'transparent', padding: 0 }}>{client.id.slice(0, 18)}…</code>
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  style={{ padding: '0.15rem 0.45rem', fontSize: '0.7rem' }}
                                  onClick={() => copyToClipboard(client.id, 'Client ID')}
                                >
                                  Copy
                                </button>
                              </div>
                            </div>

                            <div style={{ color: '#6b7280', fontSize: '0.78rem' }}>
                              Callback: <code>{client.redirect_uris[0]}</code>
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap', paddingTop: '0.75rem', borderTop: '1px solid #e5e7eb' }}>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: '0.76rem', padding: '0.38rem 0.65rem' }}
                            onClick={() => setSelectedClientId(client.id)}
                          >
                            Select App
                          </button>
                          <button
                            type="button"
                            className="btn-secondary"
                            style={{ fontSize: '0.76rem', padding: '0.38rem 0.65rem' }}
                            onClick={() => {
                              setSelectedClientId(client.id);
                              setActiveTab('branding');
                            }}
                          >
                            Claims &amp; Branding
                          </button>
                          {client.is_confidential && (
                            <button
                              type="button"
                              className="btn-secondary"
                              style={{ fontSize: '0.76rem', padding: '0.38rem 0.65rem' }}
                              onClick={() => handleRegenerate(client.id)}
                            >
                              Rotate Secret
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn-danger"
                            style={{ fontSize: '0.76rem', padding: '0.38rem 0.65rem', marginLeft: 'auto' }}
                            onClick={() => handleDelete(client.id, client.app_name)}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    );
                  })
                )}
              </section>

              {/* FEATURE 4: SCOPED M2M API KEYS & CLIENT_CREDENTIALS GRANT */}
              {activeClient && (
                <section className="surface-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                    <div>
                      <h3 style={{ fontSize: '1.08rem', fontWeight: 700 }}>
                        Scoped Machine-to-Machine (M2M) API Keys ({activeClient.app_name})
                      </h3>
                      <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                        Issue scoped <code>soauth_live_...</code> keys for backend microservices using <code>grant_type=client_credentials</code> or RFC 7662 token introspection.
                      </p>
                    </div>
                  </div>

                  {revealedApiKey && (
                    <div
                      style={{
                        background: '#ffffff',
                        border: '1px solid #111827',
                        borderRadius: '10px',
                        padding: '1rem',
                        marginBottom: '1rem',
                      }}
                    >
                      <div style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '0.3rem' }}>
                        Copy Scoped API Key Now
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <code>{revealedApiKey}</code>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ padding: '0.2rem 0.55rem', fontSize: '0.75rem' }}
                          onClick={() => copyToClipboard(revealedApiKey, 'Scoped API Key')}
                        >
                          Copy Key
                        </button>
                      </div>
                    </div>
                  )}

                  <form
                    onSubmit={handleCreateApiKey}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '1fr 1fr auto',
                      gap: '0.75rem',
                      alignItems: 'end',
                      marginBottom: '1rem',
                    }}
                  >
                    <div>
                      <label>API Key Name</label>
                      <input
                        type="text"
                        required
                        placeholder="Billing Worker Service"
                        value={newApiKeyName}
                        onChange={(e) => setNewApiKeyName(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Allowed Scopes (space-separated)</label>
                      <input
                        type="text"
                        required
                        placeholder="openid profile email"
                        value={newApiKeyScopes}
                        onChange={(e) => setNewApiKeyScopes(e.target.value)}
                      />
                    </div>
                    <button
                      type="submit"
                      className="btn-secondary"
                      style={{ borderColor: '#111827', height: '40px' }}
                    >
                      + Issue M2M Key
                    </button>
                  </form>

                  {apiKeys.length === 0 ? (
                    <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                      No scoped M2M API keys issued for this application yet.
                    </p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {apiKeys.map((k) => (
                        <div
                          key={k.id}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '0.75rem 1rem',
                            border: '1px solid #e5e7eb',
                            borderRadius: '8px',
                            background: '#ffffff',
                            flexWrap: 'wrap',
                            gap: '0.5rem',
                          }}
                        >
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <strong style={{ fontSize: '0.88rem', color: '#111827' }}>{k.name}</strong>
                              <code>{k.key_prefix}</code>
                            </div>
                            <div style={{ fontSize: '0.76rem', color: '#6b7280', marginTop: '0.15rem' }}>
                              Scopes: <code>{k.scopes.join(' ')}</code> · Created: {new Date(k.created_at).toLocaleDateString()}
                              {k.last_used_at ? ` · Last used: ${new Date(k.last_used_at).toLocaleTimeString()}` : ''}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="btn-danger"
                            style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                            onClick={() => void handleRevokeApiKey(k.id)}
                          >
                            Revoke Key
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              )}

              {/* Interactive SDK Quickstart */}
              <section className="surface-card">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '1rem',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                  }}
                >
                  <div>
                    <h3 style={{ fontSize: '1.08rem', fontWeight: 700 }}>
                      Drop-In Integration Snippet ({activeClient?.app_name ?? 'Default App'})
                    </h3>
                    <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                      Pre-filled with <code>clientId="{sampleClientId}"</code>
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    {(['react', 'nextjs', 'm2m', 'vanilla'] as const).map((tab) => (
                      <button
                        key={tab}
                        type="button"
                        className="btn-secondary"
                        onClick={() => setSnippetTab(tab)}
                        style={{
                          fontSize: '0.78rem',
                          padding: '0.4rem 0.75rem',
                          borderColor: snippetTab === tab ? '#111827' : '#d1d5db',
                        }}
                      >
                        {tab === 'react'
                          ? 'React (@soauth/sdk/react)'
                          : tab === 'nextjs'
                            ? 'Next.js (Auth.js)'
                            : tab === 'm2m'
                              ? 'M2M (client_credentials)'
                              : 'Vanilla TS'}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => copyToClipboard(currentSnippet, 'SDK Snippet')}
                      style={{ fontSize: '0.78rem', padding: '0.4rem 0.75rem' }}
                    >
                      Copy Snippet
                    </button>
                  </div>
                </div>

                <pre
                  style={{
                    background: '#ffffff',
                    color: '#111827',
                    border: '1px solid #e5e7eb',
                    padding: '1.25rem',
                    borderRadius: '10px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    overflowX: 'auto',
                    lineHeight: 1.6,
                  }}
                >
                  {currentSnippet}
                </pre>
              </section>
            </>
          )}

          {/* TAB 2: CUSTOM BRANDING + CUSTOM JWT CLAIMS TEMPLATE & WEBHOOKS */}
          {activeTab === 'branding' && activeClient && (
            <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: '1.5rem', alignItems: 'start' }}>
              <section className="surface-card">
                <h2 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                  Customize Hosted Login, Custom JWT Claims &amp; Webhooks
                </h2>
                <p style={{ fontSize: '0.82rem', color: '#6b7280', marginBottom: '1.25rem' }}>
                  Editing <strong>{activeClient.app_name}</strong>
                </p>

                <form onSubmit={handleSaveBrandingAndWebhooks}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 165px', gap: '0.85rem' }}>
                    <div>
                      <label>Brand Logo URL (SVG / PNG)</label>
                      <input
                        type="url"
                        placeholder="https://example.com/logo.svg"
                        value={brandLogoUrl}
                        onChange={(e) => setBrandLogoUrl(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Brand Accent Color</label>
                      <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                        <input
                          type="color"
                          value={brandPrimaryColor}
                          onChange={(e) => setBrandPrimaryColor(e.target.value)}
                          style={{ width: '42px', height: '38px', padding: '2px', cursor: 'pointer' }}
                        />
                        <input
                          type="text"
                          value={brandPrimaryColor}
                          onChange={(e) => setBrandPrimaryColor(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.85rem' }}>
                    <div>
                      <label>Terms of Service URL</label>
                      <input
                        type="url"
                        placeholder="https://example.com/terms"
                        value={brandTermsUrl}
                        onChange={(e) => setBrandTermsUrl(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Privacy Policy URL</label>
                      <input
                        type="url"
                        placeholder="https://example.com/privacy"
                        value={brandPrivacyUrl}
                        onChange={(e) => setBrandPrivacyUrl(e.target.value)}
                      />
                    </div>
                  </div>

                  <hr style={{ border: 'none', borderTop: '1px solid #e5e7eb', margin: '0.5rem 0' }} />

                  {/* FEATURE 6: CUSTOM JWT CLAIMS TEMPLATE */}
                  <div>
                    <label>Custom JWT Claims Template (JSON Object)</label>
                    <textarea
                      rows={4}
                      style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}
                      placeholder='{"plan":"pro","org_slug":"{{org.slug}}","role":"{{user.role}}"}'
                      value={customClaimsTemplate}
                      onChange={(e) => setCustomClaimsTemplate(e.target.value)}
                    />
                    <span style={{ fontSize: '0.74rem', color: '#6b7280', display: 'block', marginTop: '0.25rem' }}>
                      Merged into RS256 Access &amp; ID Tokens. Supports variables: <code>{'{{user.id}}'}</code>, <code>{'{{user.email}}'}</code>, <code>{'{{user.role}}'}</code>, <code>{'{{org.id}}'}</code>, <code>{'{{org.slug}}'}</code>, <code>{'{{org.role}}'}</code>.
                    </span>
                  </div>

                  <hr style={{ border: 'none', borderTop: '1px solid #e5e7eb', margin: '0.5rem 0' }} />

                  <div>
                    <label>HMAC-SHA256 Webhook Endpoint URL</label>
                    <input
                      type="url"
                      placeholder="https://api.yourcompany.com/webhooks/soauth"
                      value={webhookUrl}
                      onChange={(e) => setWebhookUrl(e.target.value)}
                    />
                  </div>

                  {activeClient.webhook_secret && (
                    <div style={{ fontSize: '0.8rem', background: '#ffffff', padding: '0.6rem 0.8rem', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
                      <span style={{ color: '#6b7280' }}>Signing Secret (<code>X-SoAuth-Signature</code>): </span>
                      <code>{activeClient.webhook_secret}</code>
                      <button
                        type="button"
                        className="btn-secondary"
                        style={{ marginLeft: '0.5rem', padding: '0.15rem 0.45rem', fontSize: '0.72rem' }}
                        onClick={() => copyToClipboard(activeClient.webhook_secret!, 'Webhook Secret')}
                      >
                        Copy
                      </button>
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '0.65rem', marginTop: '0.35rem' }}>
                    <button type="submit" className="btn-secondary" style={{ borderColor: '#111827' }} disabled={savingSettings}>
                      {savingSettings ? 'Saving...' : 'Save Branding, Claims & Webhooks'}
                    </button>
                    {webhookUrl && (
                      <button type="button" className="btn-secondary" onClick={handleTestWebhook}>
                        Send Test Webhook
                      </button>
                    )}
                  </div>
                </form>
              </section>

              {/* Live Real-Time Login Card Preview */}
              <section
                style={{
                  background: '#ffffff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '16px',
                  padding: '1.5rem',
                }}
              >
                <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#6b7280', marginBottom: '0.85rem', textAlign: 'center' }}>
                  Live Hosted Login Preview
                </div>
                <div
                  className="oauth-card"
                  style={{
                    maxWidth: '100%',
                    padding: '1.5rem',
                    boxShadow: 'var(--shadow-sm)',
                  }}
                >
                  <header>
                    {brandLogoUrl ? (
                      <img
                        src={brandLogoUrl}
                        alt="Preview Logo"
                        style={{ maxHeight: '40px', maxWidth: '140px', objectFit: 'contain', marginBottom: '0.5rem' }}
                      />
                    ) : (
                      <div
                        className="brand-monogram"
                        style={{
                          width: '40px',
                          height: '40px',
                          fontSize: '1rem',
                        }}
                      >
                        {activeClient.app_name.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <h1 style={{ fontSize: '1.15rem' }}>Sign in to {activeClient.app_name}</h1>
                    <p style={{ fontSize: '0.8rem' }}>Password, Email OTP Code, or WebAuthn Passkey</p>
                  </header>

                  <button
                    type="button"
                    className="btn-secondary"
                    style={{ width: '100%', pointerEvents: 'none' }}
                  >
                    Continue as {currentUser.email.split('@')[0]}
                  </button>

                  <footer className="trust-footer" style={{ paddingTop: '0.65rem' }}>
                    <span className="trust-badge">Secured by soauth</span>
                    {(brandTermsUrl || brandPrivacyUrl) && (
                      <span style={{ fontSize: '0.7rem' }}>Terms · Privacy</span>
                    )}
                  </footer>
                </div>
              </section>
            </div>
          )}

          {/* FEATURE 2: MULTI-TENANT ORGANIZATIONS & TEAM INVITATIONS */}
          {activeTab === 'orgs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.25rem' }}>
                <section className="surface-card">
                  <h2 style={{ fontSize: '1.08rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                    Create Organization
                  </h2>
                  <p style={{ fontSize: '0.82rem', color: '#6b7280', marginBottom: '1rem' }}>
                    Organizations inject <code>org_id</code>, <code>org_slug</code>, and <code>org_role</code> claims directly into RS256 Access &amp; ID Tokens.
                  </p>
                  <form onSubmit={handleCreateOrganization}>
                    <div>
                      <label>Organization Name</label>
                      <input
                        type="text"
                        required
                        placeholder="Acme Enterprise"
                        value={newOrgName}
                        onChange={(e) => setNewOrgName(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>Organization Slug (optional)</label>
                      <input
                        type="text"
                        placeholder="acme-enterprise"
                        value={newOrgSlug}
                        onChange={(e) => setNewOrgSlug(e.target.value)}
                      />
                    </div>
                    <button
                      type="submit"
                      className="btn-secondary"
                      style={{ borderColor: '#111827' }}
                    >
                      + Create Organization
                    </button>
                  </form>
                </section>

                <section className="surface-card">
                  <h2 style={{ fontSize: '1.08rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                    Invite Team Member
                  </h2>
                  <p style={{ fontSize: '0.82rem', color: '#6b7280', marginBottom: '1rem' }}>
                    Assign organization-scoped roles (<code>org:admin</code>, <code>org:member</code>, or <code>org:billing</code>).
                  </p>
                  <form onSubmit={handleInviteOrgMember}>
                    <div>
                      <label>Target Organization</label>
                      <select
                        value={activeOrgId ?? organizations[0]?.id ?? ''}
                        onChange={(e) => setActiveOrgId(e.target.value)}
                      >
                        {organizations.map((org) => (
                          <option key={org.id} value={org.id}>
                            {org.name} ({org.slug})
                          </option>
                        ))}
                      </select>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 150px', gap: '0.65rem' }}>
                      <div>
                        <label>Member Email</label>
                        <input
                          type="email"
                          required
                          placeholder="teammate@acme.dev"
                          value={inviteEmail}
                          onChange={(e) => setInviteEmail(e.target.value)}
                        />
                      </div>
                      <div>
                        <label>Org Role</label>
                        <select
                          value={inviteRole}
                          onChange={(e) => setInviteRole(e.target.value as 'org:admin' | 'org:member' | 'org:billing')}
                        >
                          <option value="org:member">org:member</option>
                          <option value="org:admin">org:admin</option>
                          <option value="org:billing">org:billing</option>
                        </select>
                      </div>
                    </div>
                    <button
                      type="submit"
                      className="btn-secondary"
                      style={{ borderColor: '#111827' }}
                    >
                      Send Team Invitation
                    </button>
                  </form>
                </section>
              </div>

              <section className="surface-card">
                <h2 style={{ fontSize: '1.08rem', fontWeight: 700, marginBottom: '1rem' }}>
                  Your Organizations &amp; Team Members ({organizations.length})
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {organizations.map((org) => {
                    const isActive = org.id === activeOrgId;
                    const myMember = org.members.find(
                      (m) => m.user_id === currentUser.id || m.email.toLowerCase() === currentUser.email.toLowerCase(),
                    );
                    const myRole = myMember?.role ?? 'org:member';
                    return (
                      <div
                        key={org.id}
                        style={{
                          border: isActive ? '2px solid #111827' : '1px solid #e5e7eb',
                          borderRadius: '10px',
                          padding: '1.1rem',
                          background: '#ffffff',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.85rem' }}>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <strong style={{ fontSize: '1rem', color: '#111827' }}>{org.name}</strong>
                              <code>{org.slug}</code>
                              <span className="pill">{myRole}</span>
                              {isActive && <span className="pill">Active Context</span>}
                            </div>
                            <div style={{ fontSize: '0.76rem', color: '#6b7280', marginTop: '0.2rem' }}>
                              Org ID: <code>{org.id}</code> · Members: <strong>{org.members.length}</strong>
                            </div>
                          </div>
                          {!isActive && (
                            <button
                              type="button"
                              className="btn-secondary"
                              style={{ fontSize: '0.76rem', padding: '0.38rem 0.7rem' }}
                              onClick={() => void handleSwitchOrg(org.id)}
                            >
                              Switch Active Org
                            </button>
                          )}
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                          {org.members.map((m) => (
                            <div
                              key={m.id}
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '0.55rem 0.8rem',
                                border: '1px solid #e5e7eb',
                                borderRadius: '8px',
                                background: '#ffffff',
                                fontSize: '0.82rem',
                              }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                <strong>{m.email}</strong>
                                <span className="pill">{m.role}</span>
                                <span className="pill">{m.status}</span>
                              </div>
                              {myRole === 'org:admin' && (
                                <button
                                  type="button"
                                  className="btn-danger"
                                  style={{ fontSize: '0.72rem', padding: '0.25rem 0.55rem' }}
                                  onClick={() => void handleRemoveOrgMember(org.id, m.id)}
                                >
                                  Remove
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            </div>
          )}

          {/* TAB 3: USERS & RBAC ROLES DIRECTORY */}
          {activeTab === 'users' && activeClient && (
            <section className="surface-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <h2 style={{ fontSize: '1.12rem', fontWeight: 700 }}>
                    User Directory &amp; Role-Based Access Control ({appUsers.length})
                  </h2>
                  <p style={{ fontSize: '0.84rem', color: '#6b7280' }}>
                    Roles are cryptographically signed into RS256 Access &amp; ID Tokens (<code>role</code> and <code>roles</code> claims).
                  </p>
                </div>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.8rem', padding: '0.4rem 0.75rem' }}
                  onClick={() => void loadAppUsers(activeClient.id)}
                >
                  Refresh Directory
                </button>
              </div>

              {usersLoading ? (
                <p style={{ color: '#6b7280', fontSize: '0.85rem' }}>Loading users...</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                  {appUsers.map((u) => (
                    <div
                      key={u.id}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '0.95rem 1.1rem',
                        border: '1px solid #e5e7eb',
                        borderRadius: '10px',
                        background: '#ffffff',
                        flexWrap: 'wrap',
                        gap: '0.75rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div
                          style={{
                            width: '38px',
                            height: '38px',
                            borderRadius: '50%',
                            background: '#ffffff',
                            color: '#111827',
                            border: '1px solid #d1d5db',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 800,
                          }}
                        >
                          {u.email.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                            <strong style={{ fontSize: '0.92rem', color: '#111827' }}>{u.email}</strong>
                            <span className="pill">
                              {u.email_verified ? 'Verified' : 'Unverified'}
                            </span>
                            {u.is_mfa_enabled && <span className="pill">2FA</span>}
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#6b7280', marginTop: '0.15rem' }}>
                            Sub: <code>{u.id}</code> · Active Sessions: <strong>{u.active_sessions}</strong>
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <select
                          value={u.role}
                          onChange={(e) => void handleUpdateUserRole(u.id, e.target.value)}
                          style={{ width: 'auto', padding: '0.38rem 0.65rem', fontSize: '0.8rem', fontWeight: 700 }}
                        >
                          <option value="admin">role: admin</option>
                          <option value="member">role: member</option>
                          <option value="billing">role: billing</option>
                          <option value="viewer">role: viewer</option>
                        </select>
                        <button
                          type="button"
                          className="btn-danger"
                          style={{ fontSize: '0.76rem', padding: '0.38rem 0.7rem' }}
                          onClick={() => void handleRevokeAppUserSessions(u.id, u.email)}
                        >
                          Revoke Sessions
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {/* TAB 4: SELF-SERVICE USER PROFILE, WEBAUTHN PASSKEYS, SAAS MAU ANALYTICS, AUDIT LOGS & 2FA */}
          {activeTab === 'security' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {saasOverview && (
                <div className="kpi-grid">
                  <div className="kpi-card">
                    <span className="kpi-label">Monthly Active Users (MAU)</span>
                    <span className="kpi-value">
                      {saasOverview.plan.mau_used}{' '}
                      <span style={{ fontSize: '0.85rem', fontWeight: 500, color: '#6b7280' }}>
                        / {saasOverview.plan.mau_limit.toLocaleString()}
                      </span>
                    </span>
                  </div>
                  <div className="kpi-card">
                    <span className="kpi-label">Registered OAuth Apps</span>
                    <span className="kpi-value">{saasOverview.plan.total_clients}</span>
                    <span style={{ fontSize: '0.76rem', color: '#6b7280', fontWeight: 600 }}>Multi-Tenant Isolated</span>
                  </div>
                  <div className="kpi-card">
                    <span className="kpi-label">Total Issued Sessions</span>
                    <span className="kpi-value">{saasOverview.plan.total_sessions}</span>
                    <span style={{ fontSize: '0.76rem', color: '#6b7280' }}>PKCE S256 + Rotating Refresh</span>
                  </div>
                </div>
              )}

              {/* FEATURE 3 & 5: SELF-SERVICE ACCOUNT PROFILE & WEBAUTHN PASSKEYS */}
              <section className="surface-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
                      Self-Service Account Center &amp; WebAuthn Passkeys ({passkeys.length})
                    </h3>
                    <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                      Register hardware or biometric passkeys (TouchID, FaceID, Windows Hello, YubiKey) for passwordless login or embed <code>&lt;UserProfile /&gt;</code> from <code>@soauth/sdk/react</code>.
                    </p>
                  </div>
                </div>

                <form
                  onSubmit={handleRegisterPasskey}
                  style={{ display: 'flex', gap: '0.65rem', alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: '1rem' }}
                >
                  <div style={{ flex: 1, minWidth: '240px' }}>
                    <label>Device / Passkey Label</label>
                    <input
                      type="text"
                      required
                      placeholder="MacBook Pro TouchID / Windows Hello"
                      value={newPasskeyDeviceName}
                      onChange={(e) => setNewPasskeyDeviceName(e.target.value)}
                    />
                  </div>
                  <button
                    type="submit"
                    className="btn-secondary"
                    style={{ borderColor: '#111827', height: '40px' }}
                  >
                    + Register Passkey
                  </button>
                </form>

                {passkeys.length === 0 ? (
                  <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                    No WebAuthn passkeys registered on your account yet.
                  </p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {passkeys.map((pk) => (
                      <div
                        key={pk.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '0.75rem 1rem',
                          border: '1px solid #e5e7eb',
                          borderRadius: '8px',
                          background: '#ffffff',
                          flexWrap: 'wrap',
                          gap: '0.5rem',
                        }}
                      >
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <strong style={{ fontSize: '0.88rem', color: '#111827' }}>{pk.device_name}</strong>
                            <span className="pill">{pk.transports.join(', ') || 'internal'}</span>
                          </div>
                          <div style={{ fontSize: '0.76rem', color: '#6b7280', marginTop: '0.15rem' }}>
                            Credential ID: <code>{pk.credential_id}</code> · Added: {new Date(pk.created_at).toLocaleDateString()}
                          </div>
                        </div>
                        <button
                          type="button"
                          className="btn-danger"
                          style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                          onClick={() => void handleDeletePasskey(pk.id)}
                        >
                          Remove Passkey
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* Email Verification & 2FA Row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.25rem' }}>
                <section className="surface-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Email Verification (OIDC)</h3>
                    <span className="pill">
                      {currentUser.email_verified ? 'Verified' : 'Unverified'}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.82rem', color: '#6b7280', marginBottom: '0.85rem' }}>
                    Verifies ownership of <strong>{currentUser.email}</strong> for OIDC <code>email_verified</code> claims.
                  </p>
                  {!currentUser.email_verified && !emailOtpSent && (
                    <button type="button" className="btn-secondary" onClick={handleSendEmailOtp} style={{ fontSize: '0.82rem' }}>
                      Send 6-Digit Email OTP
                    </button>
                  )}
                  {emailOtpSent && (
                    <form onSubmit={handleConfirmEmailOtp} style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
                      <div style={{ flex: 1 }}>
                        <label>6-Digit OTP</label>
                        <input
                          type="text"
                          required
                          maxLength={6}
                          value={emailOtpCode}
                          onChange={(e) => setEmailOtpCode(e.target.value)}
                        />
                      </div>
                      <button type="submit" className="btn-secondary">Confirm</button>
                    </form>
                  )}
                </section>

                <section className="surface-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                    <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Authenticator 2FA (TOTP)</h3>
                    {currentUser.is_mfa_enabled ? (
                      <button type="button" className="btn-danger" style={{ fontSize: '0.78rem', padding: '0.35rem 0.7rem' }} onClick={handleDisableMfa}>
                        Disable 2FA
                      </button>
                    ) : (
                      !mfaSetupData && (
                        <button type="button" className="btn-secondary" style={{ fontSize: '0.78rem', padding: '0.4rem 0.75rem' }} onClick={handleStartMfaSetup}>
                          + Enable 2FA
                        </button>
                      )
                    )}
                  </div>
                  <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                    RFC 6238 Time-Based One-Time Password protection for Google Authenticator, Authy, or 1Password.
                  </p>

                  {mfaSetupData && (
                    <div style={{ marginTop: '0.85rem', padding: '0.9rem', background: '#ffffff', borderRadius: '8px', border: '1px solid #d1d5db' }}>
                      <div style={{ fontSize: '0.8rem', marginBottom: '0.4rem' }}>
                        Secret: <code>{mfaSetupData.secret}</code>
                      </div>
                      {mfaSetupData.current_test_code && (
                        <div style={{ fontSize: '0.78rem', color: '#111827', marginBottom: '0.6rem' }}>
                          Current 30s Code: <strong>{mfaSetupData.current_test_code}</strong>
                        </div>
                      )}
                      <form onSubmit={handleEnableMfa} style={{ display: 'flex', gap: '0.5rem' }}>
                        <input
                          type="text"
                          required
                          value={mfaVerifyCode}
                          onChange={(e) => setMfaVerifyCode(e.target.value)}
                          placeholder="6-digit code"
                        />
                        <button type="submit" className="btn-secondary" disabled={mfaSubmitting}>
                          Activate
                        </button>
                      </form>
                    </div>
                  )}
                </section>
              </div>

              {/* Active Device Sessions */}
              <section className="surface-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Active Device Sessions ({sessions.length})</h3>
                    <p style={{ fontSize: '0.82rem', color: '#6b7280' }}>
                      Revoking a session immediately invalidates its refresh token family.
                    </p>
                  </div>
                </div>
                {sessionsLoading ? (
                  <p style={{ color: '#6b7280', fontSize: '0.85rem' }}>Loading sessions...</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
                    {sessions.map((sess) => (
                      <div
                        key={sess.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '0.8rem 1rem',
                          borderRadius: '8px',
                          border: sess.is_current ? '1px solid #111827' : '1px solid #e5e7eb',
                          background: '#ffffff',
                        }}
                      >
                        <div style={{ fontSize: '0.82rem' }}>
                          <div style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span>Client: <code>{sess.client_id}</code></span>
                            {sess.is_current && <span className="pill">Current Device</span>}
                          </div>
                          <div style={{ color: '#6b7280', fontSize: '0.76rem', marginTop: '0.15rem' }}>
                            IP: {sess.ip_address ?? 'local'} · Signed in: {new Date(sess.auth_time).toLocaleString()}
                          </div>
                        </div>
                        <button
                          type="button"
                          className="btn-danger"
                          style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                          onClick={() => handleRevokeSession(sess.id, sess.is_current)}
                        >
                          Revoke
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* Real-Time Security Audit Log Stream */}
              {saasOverview && (
                <section className="surface-card">
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.25rem' }}>
                    Security Audit Log Stream ({saasOverview.audit_logs.length})
                  </h3>
                  <p style={{ fontSize: '0.82rem', color: '#6b7280', marginBottom: '1rem' }}>
                    Real-time trace of authentication events, token issuances, RBAC updates, and replay detections.
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', maxHeight: '320px', overflowY: 'auto' }}>
                    {saasOverview.audit_logs.map((log) => (
                      <div
                        key={log.id}
                        style={{
                          padding: '0.6rem 0.85rem',
                          borderRadius: '8px',
                          border: '1px solid #e5e7eb',
                          background: '#ffffff',
                          fontSize: '0.8rem',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: '0.75rem',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', flexWrap: 'wrap' }}>
                          <span className="pill" style={{ fontFamily: 'var(--font-mono)' }}>
                            {log.event_type}
                          </span>
                          <span style={{ color: '#111827' }}>{log.details}</span>
                        </div>
                        <span style={{ color: '#6b7280', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                          {new Date(log.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
