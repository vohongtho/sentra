// Channel senders. Each returns a provider receipt; "accepted" means the provider accepted the message,
// which is not proof of inbox delivery. Secrets are resolved server-side and never logged.
import nodemailer from 'nodemailer';
import { safeFetch } from './safe-fetch.mjs';
import { hmacHex } from '../crypto.mjs';
import { getSecretValue } from '../services/secrets.mjs';
import { redactText } from '../log.mjs';

export class DeliveryError extends Error { constructor(msg, retryable = true) { super(msg); this.retryable = retryable; } }

export function renderText(message) {
  const b = message.body || {};
  const lines = [message.title, ''];
  const add = (k, v) => v != null && v !== '' && lines.push(`${k}: ${v}`);
  add('Project', b.project); add('Service', b.service); add('Environment', b.environment); add('Affected deployment', b.deployment);
  add('Observed version', b.observed_version); add('Fixed version', b.fixed_version || 'unknown'); add('Exploitation', b.exploitation);
  add('Priority', b.priority); add('Why this matters', b.why); add('Evidence', b.evidence); add('Recommended action', b.action);
  add('Owner', b.owner); add('Due', b.due); add('Link', b.link);
  if (b.items) { lines.push(''); for (const i of b.items) lines.push(`• ${i}`); }
  if (b.text) { lines.push(''); lines.push(b.text); }
  return redactText(lines.join('\n'));
}

export async function sendViaChannel(app, channel, message, { recipients = [] } = {}) {
  const cfg = app.cfg; const text = renderText(message);
  switch (channel.kind) {
    case 'in_app': {
      const ids = recipients.length ? recipients : [];
      for (const identityId of ids) await app.db.query(`INSERT INTO notifications (id, org_id, identity_id, alert_id, title, link) VALUES ($1,$2,$3,$4,$5,$6)`, ['ntf_' + Math.random().toString(36).slice(2, 12), channel.org_id, identityId, message.alertId || null, message.title, message.body?.link || null]);
      return { provider: 'in_app', status: 'delivered', recipients: ids.length };
    }
    case 'email': {
      const smtp = channel.config?.smtp_host ? { host: channel.config.smtp_host, port: channel.config.smtp_port || 587, secure: !!channel.config.smtp_secure, user: channel.config.smtp_user, pass: channel.secret_id ? await getSecretValue(app.db, channel.org_id, channel.secret_id) : '' } : cfg.smtp;
      if (!smtp.host) throw new DeliveryError('Email channel has no SMTP server configured.', false);
      const to = [...new Set([...(channel.config?.to || []), ...(message.emails || [])])].filter(Boolean);
      if (!to.length) throw new DeliveryError('No email recipients resolved.', false);
      const transport = nodemailer.createTransport({ host: smtp.host, port: smtp.port, secure: smtp.secure, auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000 });
      try {
        const info = await transport.sendMail({ from: channel.config?.from || cfg.smtp.from, to, subject: `[Sentra] ${message.title}`.slice(0, 200), text });
        return { provider: 'smtp', status: 'accepted', message_id: info.messageId, accepted: info.accepted, rejected: info.rejected, note: 'Accepted by SMTP server; inbox delivery is not confirmed.' };
      } catch (e) { throw new DeliveryError(`SMTP error: ${e.code || ''} ${e.message}`.trim(), !['EAUTH', 'EENVELOPE'].includes(e.code)); }
    }
    case 'slack': case 'teams': case 'webhook': {
      if (!channel.secret_id) throw new DeliveryError('Channel has no webhook URL secret reference.', false);
      const secret = JSON.parse(await getSecretValue(app.db, channel.org_id, channel.secret_id));
      const url = secret.url; if (!url) throw new DeliveryError('Webhook secret lacks url.', false);
      let payload;
      if (channel.kind === 'slack') payload = { text: text.slice(0, 3500) };
      else if (channel.kind === 'teams') payload = { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: { type: 'AdaptiveCard', version: '1.4', body: [{ type: 'TextBlock', text: message.title, weight: 'Bolder', wrap: true }, { type: 'TextBlock', text: text.slice(0, 3500), wrap: true }] } }] };
      else payload = { event: message.event || 'alert', alert_id: message.alertId || null, title: message.title, body: message.body, sent_at: new Date().toISOString() };
      const body = JSON.stringify(payload);
      const headers = { 'Content-Type': 'application/json', 'User-Agent': 'Sentra-Webhook/1.0' };
      if (channel.kind === 'webhook' && secret.signing_key) {
        const ts = Math.floor(Date.now() / 1000);
        headers['X-Sentra-Timestamp'] = String(ts);
        headers['X-Sentra-Signature'] = `v1=${hmacHex(secret.signing_key, `${ts}.${body}`)}`;
        headers['X-Sentra-Delivery'] = message.deliveryId || '';
      }
      let res;
      try { res = await safeFetch(url, { method: 'POST', headers, body }, { allowPrivate: cfg.allowPrivateWebhookTargets, allowHttp: cfg.allowPrivateWebhookTargets }); }
      catch (e) { throw new DeliveryError(e.message, e.code !== 'URL_BLOCKED' && e.code !== 'URL_INVALID'); }
      if (res.status === 429 || res.status >= 500) throw new DeliveryError(`Provider responded ${res.status}`, true);
      if (!res.ok) throw new DeliveryError(`Provider rejected message: ${res.status} ${res.text.slice(0, 200)}`, false);
      return { provider: channel.kind, status: 'accepted', http_status: res.status, response: res.text.slice(0, 200) };
    }
    case 'siem': {
      // Splunk HTTP Event Collector (format splunk_hec) or a generic JSON collector with a bearer token (format json).
      if (!channel.secret_id) throw new DeliveryError('SIEM channel has no collector secret reference.', false);
      const secret = JSON.parse(await getSecretValue(app.db, channel.org_id, channel.secret_id));
      const event = { source: 'sentra', type: message.event || 'alert', alert_id: message.alertId || null, delivery_id: message.deliveryId || null, title: message.title, body: message.body, at: new Date().toISOString() };
      const hec = (channel.config?.format || 'splunk_hec') === 'splunk_hec';
      const payload = hec ? { time: Math.floor(Date.now() / 1000), source: 'sentra', sourcetype: channel.config?.sourcetype || 'sentra:alert', ...(channel.config?.index ? { index: channel.config.index } : {}), event } : event;
      let res;
      try { res = await safeFetch(secret.url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: hec ? `Splunk ${secret.token}` : `Bearer ${secret.token}` }, body: JSON.stringify(payload) }, { allowPrivate: cfg.allowPrivateWebhookTargets, allowHttp: cfg.allowPrivateWebhookTargets }); }
      catch (e) { throw new DeliveryError(e.message, e.code !== 'URL_BLOCKED' && e.code !== 'URL_INVALID'); }
      if (res.status === 429 || res.status >= 500) throw new DeliveryError(`SIEM collector responded ${res.status}`, true);
      if (!res.ok) throw new DeliveryError(`SIEM collector rejected event: ${res.status} ${res.text.slice(0, 200)}`, false);
      return { provider: hec ? 'splunk_hec' : 'siem_json', status: 'accepted', http_status: res.status, response: res.text.slice(0, 200) };
    }
    default: throw new DeliveryError(`Unsupported channel kind ${channel.kind}`, false);
  }
}
