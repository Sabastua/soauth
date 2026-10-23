import { createHmac, randomUUID } from 'node:crypto';
import { generateOpaqueToken, sha256Hex } from '../core/crypto.js';
import type { AuditLogEntry, RegisteredClientRow } from '../database/schema.js';

const MAX_AUDIT_LOGS = 500;
const auditLogs: AuditLogEntry[] = [];

export interface OrganizationMemberRecord {
  id: string;
  org_id: string;
  user_id: string | null;
  email: string;
  role: 'org:admin' | 'org:member' | 'org:billing';
  status: 'active' | 'invited';
  joined_at: string;
}

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  created_by_user_id: string;
  created_at: string;
  members: OrganizationMemberRecord[];
}

export interface PasskeyCredentialRecord {
  id: string;
  user_id: string;
  email: string;
  credential_id: string;
  public_key_spki: string;
  device_name: string;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
}

export interface ScopedApiKeyRecord {
  id: string;
  client_id: string;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
}

const organizationsStore = new Map<string, OrganizationRecord>();
const activeOrgByUser = new Map<string, string>();
const passkeysStore = new Map<string, PasskeyCredentialRecord>();
const apiKeysStore = new Map<string, ScopedApiKeyRecord>();

// Seed default enterprise organization for immediate testing
const defaultOrgId = 'org_01h9acme000000000001';
organizationsStore.set(defaultOrgId, {
  id: defaultOrgId,
  name: 'Acme Corporation',
  slug: 'acme-corp',
  created_by_user_id: '11111111-1111-4000-8000-111111111111',
  created_at: new Date().toISOString(),
  members: [
    {
      id: 'mem_01h9acmeadmin001',
      org_id: defaultOrgId,
      user_id: '11111111-1111-4000-8000-111111111111',
      email: 'admin@soauth.internal',
      role: 'org:admin',
      status: 'active',
      joined_at: new Date().toISOString(),
    },
  ],
});
activeOrgByUser.set('11111111-1111-4000-8000-111111111111', defaultOrgId);

export class AuditAndSaasService {
  /**
   * Records a structured security or SaaS event in the audit log stream.
   */
  public record(params: {
    eventType: string;
    actorUserId?: string | null;
    actorEmail?: string | null;
    clientId?: string | null;
    ipAddress?: string | null;
    status?: 'success' | 'failure' | 'warning';
    details: string;
  }): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: randomUUID(),
      event_type: params.eventType,
      actor_user_id: params.actorUserId ?? null,
      actor_email: params.actorEmail ?? null,
      client_id: params.clientId ?? null,
      ip_address: params.ipAddress ?? null,
      status: params.status ?? 'success',
      details: params.details,
      created_at: new Date(),
    };

    auditLogs.unshift(entry);
    if (auditLogs.length > MAX_AUDIT_LOGS) {
      auditLogs.length = MAX_AUDIT_LOGS;
    }
    return entry;
  }

  /**
   * Lists audit log entries filtered by the developer's owned client IDs or actor user ID.
   */
  public listForOwner(ownedClientIds: Set<string>, ownerUserId: string, limit = 100): AuditLogEntry[] {
    return auditLogs
      .filter(
        (log) =>
          log.actor_user_id === ownerUserId ||
          (log.client_id !== null && ownedClientIds.has(log.client_id)),
      )
      .slice(0, limit);
  }

  // ============================================================================
  // Feature 2: Multi-Tenant Organizations & Team Invitations
  // ============================================================================

  public listOrganizationsForUser(userId: string, userEmail: string): {
    organizations: OrganizationRecord[];
    active_org_id: string | null;
  } {
    const normalizedEmail = userEmail.toLowerCase().trim();
    const userOrgs: OrganizationRecord[] = [];

    for (const org of organizationsStore.values()) {
      const membership = org.members.find(
        (m) => m.user_id === userId || m.email.toLowerCase() === normalizedEmail,
      );
      if (membership) {
        if (!membership.user_id) {
          membership.user_id = userId;
          membership.status = 'active';
        }
        userOrgs.push(org);
      }
    }

    let activeOrgId = activeOrgByUser.get(userId) ?? null;
    if ((!activeOrgId || !userOrgs.some((o) => o.id === activeOrgId)) && userOrgs.length > 0) {
      activeOrgId = userOrgs[0]!.id;
      activeOrgByUser.set(userId, activeOrgId);
    }

    return {
      organizations: userOrgs,
      active_org_id: activeOrgId,
    };
  }

  public getActiveOrganizationContext(userId: string, userEmail?: string): {
    org_id?: string;
    org_slug?: string;
    org_role?: string;
  } {
    const { organizations, active_org_id } = this.listOrganizationsForUser(
      userId,
      userEmail ?? '',
    );
    if (!active_org_id) return {};
    const org = organizations.find((o) => o.id === active_org_id);
    if (!org) return {};
    const member = org.members.find(
      (m) =>
        m.user_id === userId ||
        (userEmail && m.email.toLowerCase() === userEmail.toLowerCase().trim()),
    );
    return {
      org_id: org.id,
      org_slug: org.slug,
      org_role: member?.role ?? 'org:member',
    };
  }

  public createOrganization(params: {
    name: string;
    slug?: string;
    creatorUserId: string;
    creatorEmail: string;
  }): OrganizationRecord {
    const id = `org_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const cleanSlug =
      (params.slug ?? params.name)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '') || `org-${id.slice(4, 10)}`;

    const org: OrganizationRecord = {
      id,
      name: params.name.trim(),
      slug: cleanSlug,
      created_by_user_id: params.creatorUserId,
      created_at: new Date().toISOString(),
      members: [
        {
          id: `mem_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
          org_id: id,
          user_id: params.creatorUserId,
          email: params.creatorEmail.toLowerCase().trim(),
          role: 'org:admin',
          status: 'active',
          joined_at: new Date().toISOString(),
        },
      ],
    };

    organizationsStore.set(id, org);
    activeOrgByUser.set(params.creatorUserId, id);

    this.record({
      eventType: 'org.created',
      actorUserId: params.creatorUserId,
      actorEmail: params.creatorEmail,
      status: 'success',
      details: `Created organization "${org.name}" (${org.slug})`,
    });

    return org;
  }

  public inviteMemberToOrganization(params: {
    orgId: string;
    email: string;
    role: 'org:admin' | 'org:member' | 'org:billing';
    invitedByUserId: string;
    invitedByEmail: string;
    existingUserId?: string | null;
  }): OrganizationMemberRecord | null {
    const org = organizationsStore.get(params.orgId);
    if (!org) return null;

    const normalizedEmail = params.email.toLowerCase().trim();
    const existing = org.members.find((m) => m.email.toLowerCase() === normalizedEmail);
    if (existing) {
      existing.role = params.role;
      if (params.existingUserId) {
        existing.user_id = params.existingUserId;
        existing.status = 'active';
      }
      return existing;
    }

    const member: OrganizationMemberRecord = {
      id: `mem_${randomUUID().replace(/-/g, '').slice(0, 12)}`,
      org_id: org.id,
      user_id: params.existingUserId ?? null,
      email: normalizedEmail,
      role: params.role,
      status: params.existingUserId ? 'active' : 'invited',
      joined_at: new Date().toISOString(),
    };
    org.members.push(member);

    this.record({
      eventType: 'org.member_invited',
      actorUserId: params.invitedByUserId,
      actorEmail: params.invitedByEmail,
      status: 'success',
      details: `Invited ${normalizedEmail} to organization "${org.name}" as ${params.role}`,
    });

    return member;
  }

  public removeMemberFromOrganization(orgId: string, memberId: string): boolean {
    const org = organizationsStore.get(orgId);
    if (!org) return false;
    const before = org.members.length;
    org.members = org.members.filter((m) => m.id !== memberId);
    return org.members.length < before;
  }

  public switchActiveOrganization(userId: string, userEmail: string, orgId: string): OrganizationRecord | null {
    const { organizations } = this.listOrganizationsForUser(userId, userEmail);
    const target = organizations.find((o) => o.id === orgId);
    if (!target) return null;
    activeOrgByUser.set(userId, target.id);
    return target;
  }

  // ============================================================================
  // Feature 3: Passkeys / WebAuthn Biometric Credentials
  // ============================================================================

  public listPasskeysForUser(userId: string): PasskeyCredentialRecord[] {
    return Array.from(passkeysStore.values()).filter((p) => p.user_id === userId);
  }

  public registerPasskey(params: {
    userId: string;
    email: string;
    credentialId?: string;
    publicKeySpki?: string;
    deviceName: string;
    transports?: string[];
  }): PasskeyCredentialRecord {
    const id = `pk_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const credentialId =
      params.credentialId && params.credentialId.trim().length > 0
        ? params.credentialId.trim()
        : `cred_${generateOpaqueToken(24)}`;
    const record: PasskeyCredentialRecord = {
      id,
      user_id: params.userId,
      email: params.email.toLowerCase().trim(),
      credential_id: credentialId,
      public_key_spki: params.publicKeySpki ?? `spki_${generateOpaqueToken(32)}`,
      device_name: params.deviceName.trim() || 'Platform Passkey (Biometric)',
      transports: params.transports ?? ['internal', 'hybrid'],
      created_at: new Date().toISOString(),
      last_used_at: new Date().toISOString(),
    };
    passkeysStore.set(record.id, record);

    this.record({
      eventType: 'auth.passkey.registered',
      actorUserId: params.userId,
      actorEmail: params.email,
      status: 'success',
      details: `Registered WebAuthn Passkey "${record.device_name}" for ${params.email}`,
    });

    return record;
  }

  public deletePasskey(userId: string, passkeyId: string): boolean {
    const existing = passkeysStore.get(passkeyId);
    if (!existing || existing.user_id !== userId) return false;
    passkeysStore.delete(passkeyId);
    return true;
  }

  public findPasskeyForAuthentication(params: {
    email?: string | undefined;
    credentialId?: string | undefined;
  }): PasskeyCredentialRecord | undefined {
    for (const pk of passkeysStore.values()) {
      if (params.credentialId && pk.credential_id === params.credentialId) {
        pk.last_used_at = new Date().toISOString();
        return pk;
      }
      if (params.email && pk.email.toLowerCase() === params.email.toLowerCase().trim()) {
        pk.last_used_at = new Date().toISOString();
        return pk;
      }
    }
    return undefined;
  }

  // ============================================================================
  // Feature 4: Scoped API Keys & Machine-to-Machine (M2M) Access
  // ============================================================================

  public listApiKeysForClient(clientId: string): Omit<ScopedApiKeyRecord, 'key_hash'>[] {
    return Array.from(apiKeysStore.values())
      .filter((k) => k.client_id === clientId)
      .map(({ key_hash: _unused, ...rest }) => rest);
  }

  public createApiKey(params: {
    clientId: string;
    name: string;
    scopes: string[];
    actorUserId?: string | null;
    actorEmail?: string | null;
  }): { apiKey: Omit<ScopedApiKeyRecord, 'key_hash'>; rawKey: string } {
    const id = `ak_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const rawSecretPart = generateOpaqueToken(28);
    const rawKey = `soauth_live_${rawSecretPart}`;
    const keyPrefix = `${rawKey.slice(0, 18)}...`;
    const keyHash = sha256Hex(rawKey);

    const record: ScopedApiKeyRecord = {
      id,
      client_id: params.clientId,
      name: params.name.trim() || 'Production Backend Key',
      key_prefix: keyPrefix,
      key_hash: keyHash,
      scopes: params.scopes.length > 0 ? params.scopes : ['openid', 'profile', 'email'],
      created_at: new Date().toISOString(),
      last_used_at: null,
    };

    apiKeysStore.set(id, record);

    this.record({
      eventType: 'client.api_key_created',
      actorUserId: params.actorUserId ?? null,
      actorEmail: params.actorEmail ?? null,
      clientId: params.clientId,
      status: 'success',
      details: `Created scoped M2M API key "${record.name}" (${keyPrefix})`,
    });

    const { key_hash: _unused, ...sanitized } = record;
    return { apiKey: sanitized, rawKey };
  }

  public revokeApiKey(clientId: string, apiKeyId: string): boolean {
    const existing = apiKeysStore.get(apiKeyId);
    if (!existing || existing.client_id !== clientId) return false;
    apiKeysStore.delete(apiKeyId);
    return true;
  }

  public verifyScopedApiKey(rawKey: string): ScopedApiKeyRecord | null {
    const candidateHash = sha256Hex(rawKey);
    for (const record of apiKeysStore.values()) {
      if (record.key_hash === candidateHash) {
        record.last_used_at = new Date().toISOString();
        return record;
      }
    }
    return null;
  }

  // ============================================================================
  // Feature 6: Custom JWT Claims Template Parser
  // ============================================================================

  public parseCustomClaimsTemplate(
    templateJson: string | null | undefined,
    context: {
      userId: string;
      email?: string;
      role?: string;
      orgId?: string;
      orgSlug?: string;
      orgRole?: string;
    },
  ): Record<string, unknown> | undefined {
    if (!templateJson || !templateJson.trim()) return undefined;
    try {
      const parsed = JSON.parse(templateJson) as Record<string, unknown>;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return undefined;
      }

      const resolved: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === 'string') {
          resolved[k] = v
            .replace(/\{\{user\.id\}\}/g, context.userId)
            .replace(/\{\{user\.email\}\}/g, context.email ?? '')
            .replace(/\{\{user\.role\}\}/g, context.role ?? 'member')
            .replace(/\{\{org\.id\}\}/g, context.orgId ?? '')
            .replace(/\{\{org\.slug\}\}/g, context.orgSlug ?? '')
            .replace(/\{\{org\.role\}\}/g, context.orgRole ?? '');
        } else {
          resolved[k] = v;
        }
      }
      return resolved;
    } catch {
      return undefined;
    }
  }

  /**
   * Dispatches an HMAC-SHA256 signed webhook event to a client's configured `webhook_url`.
   */
  public async dispatchWebhook(
    client: RegisteredClientRow,
    eventType: string,
    data: Record<string, unknown>,
  ): Promise<{ delivered: boolean; statusCode?: number; error?: string }> {
    if (!client.webhook_url) {
      return { delivered: false, error: 'No webhook_url configured for this client' };
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payloadString = JSON.stringify({
      id: `evt_${randomUUID()}`,
      type: eventType,
      client_id: client.id,
      created_at: new Date().toISOString(),
      data,
    });

    const secret = client.webhook_secret ?? 'soauth_default_webhook_secret';
    const signature = createHmac('sha256', secret)
      .update(`${timestamp}.${payloadString}`)
      .digest('hex');

    try {
      const response = await fetch(client.webhook_url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-SoAuth-Event': eventType,
          'X-SoAuth-Timestamp': timestamp,
          'X-SoAuth-Signature': `t=${timestamp},v1=${signature}`,
        },
        body: payloadString,
      });

      this.record({
        eventType: 'webhook.dispatched',
        clientId: client.id,
        status: response.ok ? 'success' : 'warning',
        details: `Dispatched ${eventType} to ${client.webhook_url} (HTTP ${response.status})`,
      });

      return { delivered: response.ok, statusCode: response.status };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Network error';
      this.record({
        eventType: 'webhook.failed',
        clientId: client.id,
        status: 'failure',
        details: `Webhook ${eventType} to ${client.webhook_url} failed: ${errMsg}`,
      });
      return { delivered: false, error: errMsg };
    }
  }

  /**
   * Sends a transactional email via Resend HTTP API (`RESEND_API_KEY`) in production,
   * or logs to console in local/serverless preview mode.
   */
  public async sendTransactionalEmail(params: {
    to: string;
    subject: string;
    html: string;
  }): Promise<{ delivered: boolean; provider: 'resend' | 'console' }> {
    const resendApiKey = process.env.RESEND_API_KEY;
    const fromEmail = process.env.EMAIL_FROM ?? 'soauth Security <onboarding@resend.dev>';

    if (resendApiKey) {
      try {
        const res = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${resendApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: fromEmail,
            to: [params.to],
            subject: params.subject,
            html: params.html,
          }),
        });
        if (res.ok) {
          return { delivered: true, provider: 'resend' };
        }
      } catch {
        // Fall through to console logger
      }
    }

    console.log(`[soauth-email] To: ${params.to} | Subject: ${params.subject}`);
    return { delivered: true, provider: 'console' };
  }
}

export const saasService = new AuditAndSaasService();
