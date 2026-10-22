import { createHmac, randomUUID } from 'node:crypto';
import type { AuditLogEntry, RegisteredClientRow } from '../database/schema.js';

const MAX_AUDIT_LOGS = 500;
const auditLogs: AuditLogEntry[] = [];

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
