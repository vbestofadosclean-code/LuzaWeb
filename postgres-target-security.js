import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';

const DEFAULT_ALLOWED_PORTS = new Set([5432, 6432]);
const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.test', '.example', '.invalid', '.home', '.lan', '.onion', '.svc', '.cluster.local', '.docker.internal', '.corp', '.private', '.intranet', '.home.arpa'];
const BLOCKED_HOSTS = new Set(['metadata', 'metadata.google', 'metadata.google.internal', 'instance-data.ec2.internal', 'host.docker.internal', 'gateway.docker.internal']);
const MAX_DNS_ADDRESSES = 16;

function targetError(reason, message = 'O destino PostgreSQL não é permitido.') {
  const error = new Error(message);
  error.code = 'POSTGRES_TARGET_REJECTED';
  error.reason = reason;
  return error;
}

function ipv4Number(ip) {
  if (net.isIP(ip) !== 4) return null;
  return ip.split('.').reduce((value, part) => (value << 8n) | BigInt(Number(part)), 0n);
}

function inIPv4Range(ip, network, prefix) {
  const value = ipv4Number(ip);
  const base = ipv4Number(network);
  if (value === null || base === null) return false;
  const shift = 32n - BigInt(prefix);
  return (value >> shift) === (base >> shift);
}

function ipv6Number(ip) {
  if (net.isIP(ip) !== 6) return null;
  let value = String(ip).toLowerCase().split('%')[0];
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const embedded = value.slice(lastColon + 1);
    if (net.isIP(embedded) !== 4) return null;
    const octets = embedded.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((result, group) => (result << 16n) | BigInt(parseInt(group, 16)), 0n);
}

function inIPv6Range(ip, network, prefix) {
  const value = ipv6Number(ip);
  const base = ipv6Number(network);
  if (value === null || base === null) return false;
  const shift = 128n - BigInt(prefix);
  return (value >> shift) === (base >> shift);
}

export function isPublicPostgresIp(address) {
  const family = net.isIP(String(address || '').split('%')[0]);
  if (family === 4) {
    const denied = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['192.31.196.0', 24], ['192.52.193.0', 24],
      ['192.175.48.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
      ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return !denied.some(([network, prefix]) => inIPv4Range(address, network, prefix));
  }
  if (family === 6) {
    const ip = String(address).split('%')[0].toLowerCase();
    // Only permit IPv6 global-unicast space and explicitly reject transition,
    // documentation and special-purpose ranges that can encode non-public targets.
    if (!inIPv6Range(ip, '2000::', 3)) return false;
    const denied = [
      ['2001:db8::', 32], // documentation
      ['2001::', 23],     // special-purpose IETF IPv6 assignments and transition space
      ['2002::', 16],     // 6to4 transition
      ['2001:10::', 28],  // ORCHID
      ['2001:20::', 28]   // ORCHIDv2
    ];
    return !denied.some(([network, prefix]) => inIPv6Range(ip, network, prefix));
  }
  return false;
}

export function normalizePostgresHostname(input) {
  if (typeof input !== 'string') throw targetError('hostname_type');
  let host = input.trim();
  if (host.length > 255 || !host || /[\s/@?#\\%\u0000-\u001f\u007f]/.test(host)) throw targetError('hostname_format');
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (net.isIP(host)) {
    if (!isPublicPostgresIp(host)) throw targetError('non_public_ip');
    return host.toLowerCase();
  }
  // Reject numeric/hex IP spellings that some resolver stacks interpret as IPs.
  if (/^[0-9.]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) throw targetError('non_canonical_ip');
  host = host.replace(/\.$/, '').toLowerCase();
  if (host.length < 3 || host.length > 253 || !host.includes('.')) throw targetError('hostname_format');
  if (BLOCKED_HOSTS.has(host) || LOCAL_SUFFIXES.some(suffix => host === suffix.slice(1) || host.endsWith(suffix))) throw targetError('local_hostname');
  const labels = host.split('.');
  if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw targetError('hostname_format');
  if (!/^[a-z0-9-]{2,63}$/.test(labels.at(-1))) throw targetError('hostname_format');
  return host;
}

export function allowedPostgresPorts(envValue = process.env.POSTGRES_ALLOWED_PORTS) {
  if (envValue === undefined || String(envValue).trim() === '') return new Set(DEFAULT_ALLOWED_PORTS);
  const ports = String(envValue).split(',').map(value => Number(value.trim()));
  if (!ports.length || ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw targetError('invalid_allowed_ports', 'A configuração de portas PostgreSQL permitidas é inválida.');
  }
  return new Set(ports);
}

export function validatePostgresPort(input, { ports = allowedPostgresPorts() } = {}) {
  const port = Number(input);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !ports.has(port)) throw targetError('port_not_allowed');
  return port;
}

function withTimeout(promise, timeoutMs) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(targetError('dns_timeout', 'Não foi possível validar o destino PostgreSQL a tempo.')), timeoutMs);
    })
  ]).finally(() => clearTimeout(timer));
}

/** Resolve and pin the database target to a validated public IP. All DNS answers
 * must be public; the caller must connect to connectAddress, not re-resolve host. */
export async function resolvePublicPostgresTarget(hostInput, portInput, {
  lookup = (hostname) => dns.lookup(hostname, { all: true, verbatim: true }),
  ports = allowedPostgresPorts(),
  timeoutMs = 3000
} = {}) {
  const hostname = normalizePostgresHostname(hostInput);
  const port = validatePostgresPort(portInput, { ports });
  const family = net.isIP(hostname);
  if (family) {
    return { hostname, port, connectAddress: hostname, family, tlsServername: undefined, pinned: true };
  }
  let answers;
  try { answers = await withTimeout(Promise.resolve().then(() => lookup(hostname)), timeoutMs); }
  catch (error) {
    if (error?.code === 'POSTGRES_TARGET_REJECTED') throw error;
    throw targetError('dns_resolution_failed', 'O hostname PostgreSQL não pôde ser validado.');
  }
  if (!Array.isArray(answers) || answers.length < 1 || answers.length > MAX_DNS_ADDRESSES) throw targetError('dns_answer_count');
  if (answers.some(answer => !answer || net.isIP(String(answer.address || '')) === 0 || !isPublicPostgresIp(String(answer.address)))) {
    throw targetError('dns_non_public_answer');
  }
  const chosen = answers.find(answer => Number(answer.family) === 4) || answers[0];
  return { hostname, port, connectAddress: String(chosen.address), family: Number(chosen.family) || net.isIP(String(chosen.address)), tlsServername: hostname, pinned: true };
}

export function buildPinnedPostgresClientConfig(target, credentials = {}, { ports = allowedPostgresPorts() } = {}) {
  if (!target || !target.pinned || !isPublicPostgresIp(target.connectAddress)) throw targetError('target_not_pinned');
  validatePostgresPort(target.port, { ports });
  const ssl = { rejectUnauthorized: true };
  if (target.tlsServername && !net.isIP(target.tlsServername)) ssl.servername = target.tlsServername;
  return {
    host: target.connectAddress,
    port: target.port,
    database: credentials.database,
    user: credentials.user,
    password: credentials.password,
    ssl,
    connectionTimeoutMillis: 7000,
    query_timeout: 5000,
    statement_timeout: 5000,
    keepAlive: false,
    ...(credentials.enableChannelBinding ? { enableChannelBinding: true } : {})
  };
}

export async function consumePostgresConnectionTestLimit(executor, { projectId, ip, now = Date.now(), perIpLimit = 5, perProjectLimit = 20, windowMs = 600000 } = {}) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('Rate-limit executor must support query().');
  const project = String(projectId || '').trim();
  if (!project) throw new TypeError('A project ID is required.');
  const normalizedIp = String(ip || 'unknown').slice(0, 100);
  const ipHash = crypto.createHash('sha256').update(normalizedIp).digest('hex');
  const projectHash = crypto.createHash('sha256').update(project).digest('hex');
  const buckets = [
    { key: `pg-test:ip:${projectHash}:${ipHash}`, max: perIpLimit, scope: 'ip' },
    { key: `pg-test:project:${projectHash}`, max: perProjectLimit, scope: 'project' }
  ];
  const decisions = [];
  for (const bucket of buckets) {
    const resetAt = now + windowMs;
    const { rows } = await executor.query(`
      INSERT INTO api_rate_limits(bucket_key,attempts,reset_at) VALUES($1,1,$2)
      ON CONFLICT(bucket_key) DO UPDATE SET
        attempts=CASE WHEN api_rate_limits.reset_at <= $3 THEN 1 ELSE api_rate_limits.attempts+1 END,
        reset_at=CASE WHEN api_rate_limits.reset_at <= $3 THEN $2 ELSE api_rate_limits.reset_at END
      RETURNING attempts, reset_at
    `, [bucket.key, resetAt, now]);
    if (!rows?.[0]) throw new Error('PostgreSQL connection test limiter returned no row.');
    const attempts = Number(rows[0].attempts);
    decisions.push({ allowed: attempts <= bucket.max, attempts, max: bucket.max, scope: bucket.scope, resetAt: Number(rows[0].reset_at) });
  }
  const blocked = decisions.filter(item => !item.allowed).sort((a, b) => a.resetAt - b.resetAt)[0];
  return blocked
    ? { allowed: false, scope: blocked.scope, attempts: blocked.attempts, max: blocked.max, retryAfterMs: Math.max(1, blocked.resetAt - now) }
    : { allowed: true, limits: decisions };
}

export function isPostgresTargetSecurityError(error) {
  return error?.code === 'POSTGRES_TARGET_REJECTED';
}
