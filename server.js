import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'crypto';
import { getRequestClientIp } from './client-ip.js';
import path from 'path';
import fs from 'fs/promises';
import { encryptSecret, decryptSecret, validateSecretConfiguration } from './secret-crypto.js';
import { normalizeApiErrorEnvelope } from './api-errors.js';
import { consumeResourceCreationLimit, parseNeonProjectCount, reserveNeonProvisionSlot, resourceQuotaLimits } from './resource-limits.js';
import { pruneProjectHistory, historyRetentionLimits } from './history-retention.js';
import { classifyLifecycleDeleteOperation, lifecycleOperationBlocksRestore } from './project-lifecycle.js';
import { consumePublicApiRateLimit, pruneExpiredApiRateLimits } from './api-rate-limit.js';
import { claimOperationalAlertCooldown } from './operational-alerts.js';
import { validateSameOriginMutation } from './request-security.js';
import { hardenProjectDatabaseRoles } from './postgres-role-hardening.js';
import { resolvePublicPostgresTarget, buildPinnedPostgresClientConfig, normalizePostgresHostname, validatePostgresPort, allowedPostgresPorts, consumePostgresConnectionTestLimit, isPostgresTargetSecurityError } from './postgres-target-security.js';

const { Pool, Client } = pg;
// Use the deployed project root instead of import.meta.url. Netlify's esbuild
// function bundle may emit CommonJS, where import.meta.url is unavailable.
const __dirname = path.resolve(process.cwd());
const __filename = path.join(__dirname, 'server.js');
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = String(process.env.JWT_SECRET || 'dev-only-change-me').trim();
const COOKIE_NAME = 'luzaweb_token';

const databaseConfigured = Boolean(process.env.DATABASE_URL);
const DEFAULT_POOL_MAX = process.env.NETLIFY ? 1 : 10;
function boundedIntegerEnv(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || '', 10);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}
const PG_POOL_MAX = boundedIntegerEnv('PG_POOL_MAX', DEFAULT_POOL_MAX, 1, 20);
const PG_CONNECTION_TIMEOUT_MS = boundedIntegerEnv('PG_CONNECTION_TIMEOUT_MS', 5000, 1000, 30000);
const PG_STATEMENT_TIMEOUT_MS = boundedIntegerEnv('PG_STATEMENT_TIMEOUT_MS', 15000, 1000, 120000);
const PG_MIGRATION_LOCK_TIMEOUT_MS = boundedIntegerEnv('PG_MIGRATION_LOCK_TIMEOUT_MS', 15000, 1000, 60000);
const PG_MIGRATION_STATEMENT_TIMEOUT_MS = boundedIntegerEnv('PG_MIGRATION_STATEMENT_TIMEOUT_MS', 120000, 10000, 180000);
const PROJECT_POOL_CACHE_MAX = boundedIntegerEnv('PG_PROJECT_POOL_CACHE_MAX', 20, 1, 100);
const PG_POOL_WAITING_LIMIT = boundedIntegerEnv('PG_POOL_WAITING_LIMIT', 10, 1, 1000);
const SLOW_REQUEST_ALERT_MS = boundedIntegerEnv('SLOW_REQUEST_ALERT_MS', 2000, 500, 30000);
const TRUST_PROXY_HOPS = process.env.NETLIFY ? 1 : boundedIntegerEnv('TRUST_PROXY_HOPS', 0, 0, 5);
const HISTORY_RETENTION = historyRetentionLimits(process.env);
const RESOURCE_QUOTAS = resourceQuotaLimits(process.env);
const POSTGRES_ALLOWED_PORTS = allowedPostgresPorts();
const POSTGRES_CONNECTION_TEST_LIMITS = Object.freeze({
  perIp: boundedIntegerEnv('POSTGRES_CONNECTION_TESTS_PER_IP', 5, 1, 100),
  perProject: boundedIntegerEnv('POSTGRES_CONNECTION_TESTS_PER_PROJECT', 20, 1, 500),
  windowMs: boundedIntegerEnv('POSTGRES_CONNECTION_TEST_WINDOW_MS', 600000, 60000, 3600000)
});
const localDatabasePath = path.join(__dirname, '.data', 'luzaweb.sqlite');

// Production uses PostgreSQL. Load the local SQLite adapter lazily only for
// local development, so Netlify's function bundler never tries to package the
// node:sqlite built-in into the production function.
let pool = databaseConfigured
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      // The internal platform database uses public tables; do not let URL options
      // silently redirect unqualified application SQL into another schema.
      options: '-c search_path=public',
      ssl: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false' ? { rejectUnauthorized: false } : undefined,
      max: PG_POOL_MAX,
      idleTimeoutMillis: 15000,
      connectionTimeoutMillis: PG_CONNECTION_TIMEOUT_MS,
      statement_timeout: PG_STATEMENT_TIMEOUT_MS,
      // Keep the client-side timeout longer than the migration block; ordinary
      // queries are still bounded by the server-side PG_STATEMENT_TIMEOUT_MS.
      query_timeout: Math.max(PG_STATEMENT_TIMEOUT_MS, PG_MIGRATION_STATEMENT_TIMEOUT_MS),
      maxUses: 5000,
      keepAlive: true
    })
  : null;

// Separate Neon pools keep each project's data in its own real PostgreSQL database.
const projectDataPools = new Map();
async function evictProjectPoolIfNeeded() {
  while (projectDataPools.size > PROJECT_POOL_CACHE_MAX) {
    const oldestKey = projectDataPools.keys().next().value;
    const oldest = projectDataPools.get(oldestKey);
    projectDataPools.delete(oldestKey);
    if (oldest?.pool) await oldest.pool.end().catch(() => {});
  }
}

if (!databaseConfigured) {
  console.warn(`PostgreSQL não configurado. O LUZAWEB está a usar a base local persistente: ${localDatabasePath}`);
}

const app = express();
app.disable('x-powered-by');
// Trust the Netlify edge hop for protocol handling; self-hosted deployments do not
// trust forwarded headers unless the operator explicitly configures proxy hops.
app.set('trust proxy', TRUST_PROXY_HOPS);
const alertCooldowns = new Map(); // Local fallback only when the shared DB cannot be reached.
const ALERT_COOLDOWN_MS = boundedIntegerEnv('ALERT_COOLDOWN_MS', 5 * 60 * 1000, 1000, 60 * 60 * 1000);
const ALERT_DETAIL_ALLOWLIST = new Set(['request_id','method','route','status','duration_ms','error_code','database_configured','project_id','luza_project_id','provider_project_id','table','action','retry_count','waiting_count']);
function sanitizeAlertDetails(details = {}) {
  const safe = {};
  for (const [key, value] of Object.entries(details || {})) {
    if (!ALERT_DETAIL_ALLOWLIST.has(key) || value === null || value === undefined) continue;
    if (typeof value === 'string') safe[key] = value.slice(0, 160);
    else if (typeof value === 'number' && Number.isFinite(value)) safe[key] = value;
    else if (typeof value === 'boolean') safe[key] = value;
  }
  return safe;
}
function routeLabel(req) {
  if (req?.route?.path) return `${String(req.baseUrl || '')}${String(req.route.path)}`.slice(0, 180);
  if (req?.path?.startsWith('/api/')) return '/api/*';
  if (req?.path?.startsWith('/v1/')) return '/v1/*';
  if (req?.path?.startsWith('/sites/')) return '/sites/*';
  return '/';
}
function localAlertCooldownAvailable(event, now) {
  const previous = alertCooldowns.get(event) || 0;
  if (now - previous < ALERT_COOLDOWN_MS) return false;
  alertCooldowns.set(event, now);
  if (alertCooldowns.size > 200) {
    for (const [key, sentAt] of alertCooldowns) if (now - sentAt > ALERT_COOLDOWN_MS * 10) alertCooldowns.delete(key);
  }
  return true;
}
function logEvent(level, event, fields = {}) {
  // Do not include request bodies, cookies, query strings, credentials or raw IPs.
  const entry = { timestamp: new Date().toISOString(), level, service: 'luzaweb', event, ...fields };
  const line = JSON.stringify(entry);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}
if (pool && typeof pool.on === 'function') {
  pool.on('error', error => {
    const errorCode = String(error?.code || 'unknown').slice(0, 40);
    logEvent('error', 'postgres_pool_idle_client_error', { error_code: errorCode });
    void sendOperationalAlert('database_pool_error', { error_code: errorCode });
  });
}
async function sendOperationalAlert(event, details = {}) {
  const webhook = String(process.env.ALERT_WEBHOOK_URL || '').trim();
  if (!webhook) return false;
  let parsed;
  try { parsed = new URL(webhook); }
  catch {
    logEvent('warn', 'alert_webhook_rejected', { reason: 'invalid URL', alert_event: event });
    return false;
  }
  if (!['https:', 'http:'].includes(parsed.protocol) || (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:')) {
    logEvent('warn', 'alert_webhook_rejected', { reason: 'HTTPS required in production and HTTP(S) only supported', alert_event: event });
    return false;
  }

  const now = Date.now();
  const localPrevious = alertCooldowns.get(event) || 0;
  if (now - localPrevious < ALERT_COOLDOWN_MS) return false;
  let canSend = false;
  if (pool && typeof pool.query === 'function') {
    try {
      canSend = await claimOperationalAlertCooldown(pool, event, now, ALERT_COOLDOWN_MS);
      // Remember even a shared-denied claim locally so a busy instance does not
      // issue another database query for every duplicate alert.
      alertCooldowns.set(event, now);
    } catch (error) {
      // When the internal DB is unavailable, use a process-local fallback so an
      // outage notification can still be attempted. The fallback cannot coordinate
      // multiple serverless instances; the next successful DB query restores it.
      canSend = localAlertCooldownAvailable(event, now);
      if (canSend) logEvent('warn', 'shared_alert_cooldown_unavailable', { alert_event: event, error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    }
  } else canSend = localAlertCooldownAvailable(event, now);
  if (!canSend) return false;

  try {
    const response = await fetch(parsed, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ service: 'LUZAWEB', event, environment: process.env.NODE_ENV || 'development', timestamp: new Date().toISOString(), details: sanitizeAlertDetails(details) }),
      signal: AbortSignal.timeout(3000)
    });
    if (!response.ok) logEvent('warn', 'alert_webhook_failed', { alert_event: event, status: response.status });
    return response.ok;
  } catch (error) {
    // Avoid logging error.message: fetch errors may include the webhook URL/token.
    logEvent('warn', 'alert_webhook_failed', { alert_event: event, error_code: String(error?.cause?.code || error?.code || error?.name || 'request_failed').slice(0, 40) });
    return false;
  }
}

function respondApiError(req, res, error, publicMessage = 'Não foi possível concluir o pedido.', status = 500) {
  const internalCode = String(error?.code || error?.name || 'unknown').slice(0, 48);
  logEvent('error', 'api_request_failed', {
    request_id: req.requestId || null,
    method: req.method,
    route: routeLabel(req),
    status,
    error_code: internalCode
  });
  if (res.headersSent) return res.end();
  return res.status(status).json({
    error: publicMessage,
    request_id: req.requestId || null
  });
}

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  const started = Date.now();
  req.requestId = requestId;
  // Normalize all API error responses centrally. 5xx bodies always receive a
  // safe public message and only a small allowlist of metadata is preserved;
  // raw database/provider exception text can never reach API clients.
  const originalJson = res.json.bind(res);
  res.json = body => {
    const isApi = req.path === '/api' || req.path.startsWith('/api/') || req.path === '/v1' || req.path.startsWith('/v1/');
    const hasErrorBody = body && typeof body === 'object' && typeof body.error === 'string';
    if (isApi && (res.statusCode >= 400 || hasErrorBody)) {
      body = normalizeApiErrorEnvelope(res.statusCode, body, requestId);
    }
    return originalJson(body);
  };
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  res.on('finish', () => {
    const durationMs = Date.now() - started;
    const status = res.statusCode;
    const route = routeLabel(req);
    if (req.path.startsWith('/api/') || status >= 500 || durationMs >= SLOW_REQUEST_ALERT_MS) {
      logEvent(durationMs >= SLOW_REQUEST_ALERT_MS ? 'warn' : status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
        durationMs >= SLOW_REQUEST_ALERT_MS ? 'slow_http_request' : 'http_request', {
          request_id: requestId, method: req.method, route, status, duration_ms: durationMs
        });
    }
    if (status >= 500) void sendOperationalAlert('http_5xx', { request_id: requestId, method: req.method, route, status });
    if (durationMs >= SLOW_REQUEST_ALERT_MS && req.path !== '/api/health/live') {
      void sendOperationalAlert('slow_http_request', { request_id: requestId, method: req.method, route, status, duration_ms: durationMs });
    }
  });
  next();
});
// Cookie-authenticated dashboard mutations are same-origin only. This protects
// login/registration and every state-changing /api route, including deploy and
// snapshot restore. Published user sites are additionally delivered with a CSP
// sandbox that deliberately omits allow-same-origin, so their scripts have an
// opaque origin and cannot pass this check using the dashboard's session cookie.
function enforceSameOriginMutations(req, res, next) {
  const verdict = validateSameOriginMutation(req);
  if (verdict.ok) return next();
  res.setHeader('Cache-Control', 'no-store');
  logEvent('warn', 'csrf_origin_rejected', {
    request_id: req.requestId || null,
    method: req.method,
    route: '/api/*',
    reason: verdict.reason
  });
  return res.status(403).json({
    error: 'Pedido bloqueado por verificação de origem. Atualiza a página e tenta novamente.',
    code: 'CSRF_ORIGIN_REJECTED',
    request_id: req.requestId || null
  });
}
// Reject cross-origin mutations before parsing request bodies to reduce work on blocked requests.
app.use('/api', enforceSameOriginMutations);

// Parse bodies/cookies after request tracking and the early CSRF check so malformed JSON
// errors also receive a request ID and the same safe API error envelope.
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const BINARY_FILE_PREFIX = 'LUZAWEB_BINARY_V1|';
const MAX_FILE_BYTES = 300_000;
const MAX_FILES_PER_PROJECT = 120;
const MAX_FOLDERS_PER_PROJECT = 300;
const MAX_PROJECT_BYTES = 5_000_000;
const DB_COLUMN_TYPES = new Set(['text', 'number', 'boolean', 'date']);

// Shared PostgreSQL/SQLite rate-limit storage. Counters represent failed logins only,
// so a successful login does not consume the user's attempt budget. Hashed bucket keys
// avoid storing raw email addresses or IP addresses in this table.
const authAttempts = new Map(); // fallback only for unusual local DB errors
let authCleanupCounter = 0;
const AUTH_LIMITS = [
  { kind: 'ip', max: 10, windowMs: 10 * 60 * 1000 },
  { kind: 'email', max: 5, windowMs: 15 * 60 * 1000 }
];
function authBucketKey(kind, value) {
  return `auth:${kind}:` + crypto.createHash('sha256').update(String(value || 'unknown').toLowerCase()).digest('hex');
}
function authBuckets(req) {
  const ip = getRequestClientIp(req).slice(0, 100);
  const email = String(req.body?.email || '').trim().toLowerCase().slice(0, 254);
  return [
    { key: authBucketKey('ip', ip), max: AUTH_LIMITS[0].max, windowMs: AUTH_LIMITS[0].windowMs },
    ...(email ? [{ key: authBucketKey('email', email), max: AUTH_LIMITS[1].max, windowMs: AUTH_LIMITS[1].windowMs }] : [])
  ];
}
async function readAuthAttempt(bucket, now) {
  try {
    const { rows } = await pool.query('SELECT attempts, reset_at FROM auth_rate_limits WHERE bucket_key=$1', [bucket.key]);
    if (!rows[0]) return { count: 0, reset: now + bucket.windowMs };
    const reset = Number(rows[0].reset_at);
    if (!Number.isFinite(reset) || reset <= now) return { count: 0, reset: now + bucket.windowMs };
    return { count: Number(rows[0].attempts) || 0, reset };
  } catch (error) {
    // SQLite fallback supports local offline development. In production a failure
    // of the shared limiter must not silently disable protection.
    if (databaseConfigured) throw error;
    const item = authAttempts.get(bucket.key);
    if (!item || item.reset <= now) return { count: 0, reset: now + bucket.windowMs };
    return item;
  }
}
async function recordAuthFailure(req) {
  const now = Date.now();
  for (const bucket of authBuckets(req)) {
    const reset = now + bucket.windowMs;
    try {
      await pool.query(`INSERT INTO auth_rate_limits(bucket_key,attempts,reset_at) VALUES($1,1,$2)
        ON CONFLICT(bucket_key) DO UPDATE SET
          attempts=CASE WHEN auth_rate_limits.reset_at <= $3 THEN 1 ELSE auth_rate_limits.attempts+1 END,
          reset_at=CASE WHEN auth_rate_limits.reset_at <= $3 THEN $2 ELSE auth_rate_limits.reset_at END`,
      [bucket.key, reset, now]);
    } catch (error) {
      if (databaseConfigured) throw error;
      const old = authAttempts.get(bucket.key);
      const item = !old || old.reset <= now ? { count: 1, reset } : { count: old.count + 1, reset: old.reset };
      authAttempts.set(bucket.key, item);
    }
  }
  if (authAttempts.size > 5000) {
    for (const [key, item] of authAttempts) if (item.reset <= now) authAttempts.delete(key);
    while (authAttempts.size > 5000) authAttempts.delete(authAttempts.keys().next().value);
  }
  // Periodically prune expired shared counters so the table cannot grow forever.
  authCleanupCounter += 1;
  if (authCleanupCounter % 50 === 0) {
    try { await pool.query('DELETE FROM auth_rate_limits WHERE reset_at <= $1', [now]); }
    catch (error) { if (databaseConfigured) throw error; }
  }
}
async function clearAuthEmailFailures(req) {
  const email = String(req.body?.email || '').trim().toLowerCase().slice(0, 254);
  if (!email) return;
  const key = authBucketKey('email', email);
  try { await pool.query('DELETE FROM auth_rate_limits WHERE bucket_key=$1', [key]); }
  catch (error) {
    if (databaseConfigured) throw error;
    authAttempts.delete(key);
  }
}
async function authRateLimit(req, res, next) {
  try {
    const now = Date.now();
    for (const bucket of authBuckets(req)) {
      const item = await readAuthAttempt(bucket, now);
      if (item.count >= bucket.max) {
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil((item.reset - now) / 1000))));
        return res.status(429).json({ error: 'Demasiadas tentativas falhadas. Aguarda alguns minutos antes de tentar novamente.' });
      }
    }
    next();
  } catch (error) {
    logEvent('error', 'authentication_rate_limiter_unavailable', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    return res.status(503).json({ error: 'O serviço de autenticação está temporariamente indisponível. Tenta novamente.' });
  }
}

async function registrationRateLimit(req, res, next) {
  const ip = getRequestClientIp(req).slice(0, 100);
  const key = authBucketKey('register-ip', ip);
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const max = 10;
  try {
    const { rows } = await pool.query('SELECT attempts, reset_at FROM auth_rate_limits WHERE bucket_key=$1', [key]);
    const item = rows[0];
    if (item && Number(item.reset_at) > now && Number(item.attempts) >= max) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((Number(item.reset_at) - now) / 1000))));
      return res.status(429).json({ error: 'Demasiadas tentativas de registo a partir desta ligação. Tenta novamente mais tarde.' });
    }
    await pool.query(`INSERT INTO auth_rate_limits(bucket_key,attempts,reset_at) VALUES($1,1,$2)
      ON CONFLICT(bucket_key) DO UPDATE SET
        attempts=CASE WHEN auth_rate_limits.reset_at <= $3 THEN 1 ELSE auth_rate_limits.attempts+1 END,
        reset_at=CASE WHEN auth_rate_limits.reset_at <= $3 THEN $2 ELSE auth_rate_limits.reset_at END`,
    [key, now + windowMs, now]);
    authCleanupCounter += 1;
    if (authCleanupCounter % 50 === 0) await pool.query('DELETE FROM auth_rate_limits WHERE reset_at <= $1', [now]);
    next();
  } catch (error) {
    logEvent('error', 'registration_rate_limiter_unavailable', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    return res.status(503).json({ error: 'O serviço de registo está temporariamente indisponível. Tenta novamente.' });
  }
}

function slugify(value) {
  const slug = String(value || '')
    .trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return slug || `site-${Date.now()}`;
}
function cleanPath(input) {
  if (typeof input !== 'string') return '';
  let value = input.trim().replace(/\\/g, '/');
  // Repository paths are virtual paths, never filesystem paths. Reject traversal
  // instead of silently removing segments, and reject truncation/collision risks.
  if (!value || value.startsWith('/') || /^[a-zA-Z]:/.test(value) || /[\u0000-\u001f\u007f]/.test(value)) return '';
  const rawParts = value.split('/');
  if (rawParts.some(part => part === '.' || part === '..')) return '';
  value = rawParts.filter(Boolean).join('/');
  if (!value || value.length > 180) return '';
  return value;
}
function allowedFile(filePath) { return Boolean(cleanPath(filePath)); }
function parseBinaryContent(content) {
  if (typeof content !== 'string' || !content.startsWith(BINARY_FILE_PREFIX)) return null;
  const rest = content.slice(BINARY_FILE_PREFIX.length);
  const splitAt = rest.indexOf('|');
  if (splitAt < 1) return null;
  const mime = rest.slice(0, splitAt);
  const base64 = rest.slice(splitAt + 1);
  if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(mime) || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) return null;
  return { mime, base64 };
}
function storedContentBytes(content) {
  const binary = parseBinaryContent(String(content ?? ''));
  if (!binary) return Buffer.byteLength(String(content ?? ''), 'utf8');
  return Math.max(0, Math.floor(binary.base64.length * 3 / 4) - (binary.base64.endsWith('==') ? 2 : binary.base64.endsWith('=') ? 1 : 0));
}
function isPrivatePublishedPath(filePath) {
  const parts = cleanPath(filePath).toLowerCase().split('/').filter(Boolean);
  if (parts.some(part => part.startsWith('.') && part !== '.well-known')) return true;
  const name = parts.at(-1) || '';
  return /^(?:\.env(?:\..*)?|\.npmrc|\.yarnrc(?:\.yml)?|id_rsa|id_ed25519|authorized_keys|known_hosts|credentials(?:\..*)?|secrets?(?:\..*)?|service[-_]?account(?:\..*)?)$/i.test(name) ||
    /\.(?:pem|key|p12|pfx|sqlite|sqlite3|db|dump|bak|backup|secret|secrets|keystore|jks|p8)$/i.test(name);
}
function safeName(value, fallback = 'item') {
  const name = String(value || '').trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 50);
  return name || fallback;
}

function projectSchemaName(projectId) {
  const id = Number(projectId);
  if (!Number.isSafeInteger(id) || id < 1) throw new Error('Identificador de projeto inválido.');
  return `luza_project_${id}`;
}
function projectRoleName(projectId) {
  const id = Number(projectId);
  if (!Number.isSafeInteger(id) || id < 1) throw new Error('Identificador de projeto inválido.');
  return `lzw_project_${id}`;
}
function quotePgIdentifier(value) { return `\"${String(value).replace(/\"/g, '\"\"')}\"`; }
function quotePgLiteral(value) { return `'${String(value).replace(/'/g, "''")}'`; }
function parseColumnDefinitions(columns) {
  if (Array.isArray(columns)) return columns;
  if (typeof columns === 'string') { try { const parsed = JSON.parse(columns); return Array.isArray(parsed) ? parsed : []; } catch { return []; } }
  return [];
}
function projectPhysicalTableRef(projectId, tableName) {
  return `${quotePgIdentifier(projectSchemaName(projectId))}.${quotePgIdentifier(safeName(tableName, 'tabela'))}`;
}
function projectPhysicalTableRefFor(projectId, tableName, external = false) {
  if (external) return `${quotePgIdentifier('public')}.${quotePgIdentifier(safeName(tableName, 'tabela'))}`;
  return projectPhysicalTableRef(projectId, tableName);
}
function projectColumnSqlType(type) {
  return ({ text: 'TEXT', number: 'DOUBLE PRECISION', boolean: 'BOOLEAN', date: 'DATE' })[type] || 'TEXT';
}
async function grantProjectRoleOnTable(executor, projectId, tableName, external = false) {
  if (external) return;
  const roleName = projectRoleName(projectId);
  const role = (await executor.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [roleName])).rows[0];
  if (!role) return;
  const ref = projectPhysicalTableRef(projectId, tableName);
  await executor.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ${ref} TO ${quotePgIdentifier(roleName)}`);
  await executor.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${quotePgIdentifier(projectSchemaName(projectId))} TO ${quotePgIdentifier(roleName)}`);
}
async function createPhysicalTable(executor, projectId, tableName, columns, { external = false } = {}) {
  const schemaName = projectSchemaName(projectId);
  const safeTable = safeName(tableName, 'tabela');
  const ref = projectPhysicalTableRefFor(projectId, safeTable, external);
  if (!external) await executor.query(`CREATE SCHEMA IF NOT EXISTS ${quotePgIdentifier(schemaName)}`);
  const definitions = [
    `${quotePgIdentifier('__lzw_id')} BIGSERIAL PRIMARY KEY`,
    ...columns.map(column => `${quotePgIdentifier(safeName(column.name))} ${projectColumnSqlType(column.type)}${column.required ? ' NOT NULL' : ''}`),
    `${quotePgIdentifier('__lzw_created_at')} TIMESTAMPTZ NOT NULL DEFAULT NOW()`,
    `${quotePgIdentifier('__lzw_updated_at')} TIMESTAMPTZ NOT NULL DEFAULT NOW()`
  ];
  await executor.query(`CREATE TABLE IF NOT EXISTS ${ref} (${definitions.join(', ')})`);
  await grantProjectRoleOnTable(executor, projectId, safeTable, external);
  return ref;
}
function physicalRowToRecord(row, columns) {
  const data = {};
  for (const column of columns) data[column.name] = row[column.name] === undefined ? null : row[column.name];
  return { id: row.__lzw_id, data, created_at: row.__lzw_created_at, updated_at: row.__lzw_updated_at };
}
async function insertPhysicalRecord(executor, projectId, table, data, { external = false } = {}) {
  const columns = parseColumnDefinitions(table.columns);
  const ref = projectPhysicalTableRefFor(projectId, table.name, external);
  const names = columns.map(column => column.name);
  const fields = names.map(quotePgIdentifier);
  const values = names.map(name => data[name] ?? null);
  const placeholders = values.map((_, index) => `$${index + 1}`);
  const { rows } = await executor.query(
    `INSERT INTO ${ref} (${fields.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING *`, values
  );
  return physicalRowToRecord(rows[0], columns);
}
async function provisionProjectDbConnection(projectId, databaseRow) {
  if (!databaseConfigured) throw new Error('Configura DATABASE_URL no servidor para criar uma ligação PostgreSQL real.');
  if (databaseRow.db_username && databaseRow.db_password_cipher) return projectDatabaseConnectionDetails(projectId, databaseRow);
  let baseUrl;
  try { baseUrl = new URL(process.env.DATABASE_URL); }
  catch { throw new Error('DATABASE_URL não é uma URL PostgreSQL válida.'); }
  const databaseName = decodeURIComponent(baseUrl.pathname.replace(/^\/+/, '').split('/')[0] || 'postgres');
  const host = baseUrl.hostname;
  const port = Number(baseUrl.port || 5432);
  const roleName = projectRoleName(projectId);
  const schemaName = projectSchemaName(projectId);
  const sourceUsername = decodeURIComponent(baseUrl.username || 'postgres');
  const poolerSuffix = host.includes('pooler.supabase.com') && sourceUsername.includes('.') ? sourceUsername.split('.').slice(1).join('.') : '';
  const loginUsername = poolerSuffix ? `${roleName}.${poolerSuffix}` : roleName;
  const password = crypto.randomBytes(32).toString('base64url');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existingRole = await client.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [roleName]);
    if (existingRole.rowCount) {
      await client.query(`ALTER ROLE ${quotePgIdentifier(roleName)} WITH LOGIN PASSWORD ${quotePgLiteral(password)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5`);
    } else {
      await client.query(`CREATE ROLE ${quotePgIdentifier(roleName)} WITH LOGIN PASSWORD ${quotePgLiteral(password)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5`);
    }
    await client.query(`GRANT CONNECT ON DATABASE ${quotePgIdentifier(databaseName)} TO ${quotePgIdentifier(roleName)}`);
    await client.query(`CREATE SCHEMA IF NOT EXISTS ${quotePgIdentifier(schemaName)}`);
    // Project credentials can use their isolated schema but cannot create arbitrary
    // objects or fall back to the shared public schema. The platform backend owns DDL.
    await client.query(`GRANT USAGE ON SCHEMA ${quotePgIdentifier(schemaName)} TO ${quotePgIdentifier(roleName)}`);
    await client.query(`REVOKE CREATE ON SCHEMA ${quotePgIdentifier(schemaName)} FROM ${quotePgIdentifier(roleName)}`);
    await client.query(`REVOKE ALL ON SCHEMA public FROM ${quotePgIdentifier(roleName)}`);
    await client.query(`ALTER ROLE ${quotePgIdentifier(roleName)} IN DATABASE ${quotePgIdentifier(databaseName)} SET search_path TO ${quotePgLiteral(schemaName)}`);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${quotePgIdentifier(schemaName)} TO ${quotePgIdentifier(roleName)}`);
    await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${quotePgIdentifier(schemaName)} TO ${quotePgIdentifier(roleName)}`);
    const { rows } = await client.query(
      'UPDATE project_databases SET schema_name=$1,db_username=$2,db_password_cipher=$3,provisioned_at=NOW(),updated_at=NOW() WHERE project_id=$4 RETURNING *',
      [schemaName, loginUsername, encryptSecret(password), projectId]
    );
    await client.query('COMMIT');
    return projectDatabaseConnectionDetails(projectId, rows[0], password, { host, port, databaseName, schemaName });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    if (error.code === '42501' || /permission denied|must be.*createrole/i.test(error.message || '')) {
      throw new Error('O utilizador PostgreSQL configurado em DATABASE_URL não tem permissões para criar utilizadores de projeto. Verifica as permissões do utilizador postgres no Supabase.');
    }
    throw error;
  } finally { client.release?.(); }
}
const NEON_REGIONS = new Set(['aws-us-east-1','aws-us-east-2','aws-us-west-2','aws-eu-central-1','aws-eu-west-2','aws-ap-southeast-1','aws-ap-southeast-2','aws-sa-east-1']);
function parsePostgresUri(uri) {
  const parsed = new URL(String(uri || ''));
  if (!/^postgres(?:ql)?:$/.test(parsed.protocol)) throw new Error('O fornecedor não devolveu uma URL PostgreSQL válida.');
  return {
    hostname: parsed.hostname,
    port: Number(parsed.port || 5432),
    database: decodeURIComponent(parsed.pathname.replace(/^\//, '').split('/')[0] || 'neondb'),
    username: decodeURIComponent(parsed.username || ''),
    password: decodeURIComponent(parsed.password || '')
  };
}
function maskPostgresUri(uri) {
  try { const parsed = new URL(String(uri)); parsed.password = '••••••'; return parsed.toString(); }
  catch { return 'Ligação guardada'; }
}
function connectionUriFromPayload(payload) {
  if (typeof payload === 'string' && /^postgres(?:ql)?:\/\//i.test(payload)) return payload;
  const candidates = [payload?.uri, payload?.connection_uri, payload?.connectionUri, payload?.connection_string, payload?.connectionString];
  for (const value of candidates) if (typeof value === 'string' && /^postgres(?:ql)?:\/\//i.test(value)) return value;
  for (const value of [...(payload?.connection_uris || []), ...(payload?.connectionUris || [])]) {
    const candidate = value?.connection_uri || value?.uri || value?.connection_string;
    if (typeof candidate === 'string' && /^postgres(?:ql)?:\/\//i.test(candidate)) return candidate;
  }
  return '';
}
async function neonApiRequest(pathname, { method = 'GET', body } = {}) {
  if (!process.env.NEON_API_KEY) throw new Error('A criação de bases PostgreSQL reais precisa da variável NEON_API_KEY configurada nos segredos do servidor.');
  const url = new URL(`https://console.neon.tech/api/v2${pathname}`);
  if (process.env.NEON_ORG_ID && ['/api/v2/projects', '/api/v2/projects/count'].includes(url.pathname)) url.searchParams.set('org_id', process.env.NEON_ORG_ID);
  const response = await fetch(url, {
    method,
    headers: { 'Authorization': `Bearer ${process.env.NEON_API_KEY}`, 'Accept': 'application/json', 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(25000)
  });
  const textBody = await response.text();
  let payload = {};
  try { payload = textBody ? JSON.parse(textBody) : {}; } catch { payload = {}; }
  if (!response.ok) {
    const detail = payload?.message || payload?.error || payload?.errors?.[0]?.message || `HTTP ${response.status}`;
    const error = new Error(`O Neon não conseguiu concluir a operação (${String(detail).slice(0, 220)}). Verifica a chave API, organização, região e limites da conta.`);
    error.httpStatus = response.status;
    error.providerCode = String(payload?.code || payload?.error_code || 'NEON_API_ERROR').slice(0, 80);
    throw error;
  }
  return payload;
}
async function deleteNeonProjectResource(projectId, { checkFirst = true } = {}) {
  if (!/^[a-z0-9-]{1,60}$/i.test(String(projectId || ''))) throw new Error('Identificador do projeto Neon inválido; a eliminação foi bloqueada.');
  const path = `/projects/${encodeURIComponent(projectId)}`;
  // For an already-managed project, inspect it first so retries are safe after
  // uncertain network failures. During cleanup of a project created moments ago,
  // skip GET because provider read-after-write visibility can lag behind POST.
  if (checkFirst) {
    try {
      await neonApiRequest(path);
    } catch (error) {
      if (Number(error?.httpStatus) === 404 || Number(error?.httpStatus) === 410) return { alreadyAbsent: true };
      throw error;
    }
  }
  try {
    return await neonApiRequest(path, { method: 'DELETE' });
  } catch (error) {
    // Treat provider-confirmed absence as a reconciled success, not a reason to
    // orphan local metadata. Other failures preserve the durable operation row.
    if (Number(error?.httpStatus) === 404 || Number(error?.httpStatus) === 410) return { alreadyAbsent: true };
    throw error;
  }
}
async function waitForNeonConnectionUri(projectId, databaseName, roleName, branchId, pooled = false) {
  const query = new URLSearchParams({ database_name: databaseName, role_name: roleName });
  if (branchId) query.set('branch_id', branchId);
  if (pooled) query.set('pooled', 'true');
  let lastError;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const payload = await neonApiRequest(`/projects/${encodeURIComponent(projectId)}/connection_uri?${query.toString()}`);
      const uri = connectionUriFromPayload(payload);
      if (uri) return uri;
      lastError = new Error('O Neon ainda não disponibilizou a URL de ligação.');
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 1200 * (attempt + 1)));
  }
  throw lastError || new Error('Não foi possível obter a URL PostgreSQL do Neon.');
}
async function createNeonProjectDatabase(project, input) {
  if (!databaseConfigured) throw new Error('DATABASE_URL é necessária para guardar as informações da conta no LuzaWeb antes de criar bases para projectos.');
  if (!process.env.NEON_API_KEY) throw new Error('Para criar uma base PostgreSQL independente, configura NEON_API_KEY no Netlify. DATABASE_URL é a base interna do LuzaWeb; NEON_API_KEY permite criar a base do projecto no Neon.');
  const name = String(input.name || '').trim();
  if (!/^[A-Za-z0-9_-]{2,60}$/.test(name)) throw new Error('O nome deve ter 2–60 caracteres e conter apenas letras, números, _ ou -.');
  const regionId = String(input.region_id || 'aws-eu-central-1');
  if (!NEON_REGIONS.has(regionId)) throw new Error('A região escolhida não é uma região Neon suportada.');
  const pgVersion = Number(input.pg_version || 16);
  if (![14,15,16,17,18].includes(pgVersion)) throw new Error('Escolhe uma versão PostgreSQL suportada (14 a 18).');
  const previous = (await pool.query('SELECT provider_project_id,connection_uri_cipher FROM project_database_connections WHERE project_id=$1', [project.id])).rows[0];
  if (previous?.provider_project_id || previous?.connection_uri_cipher) throw new Error('Este projecto já tem uma base PostgreSQL configurada. Abre os dados de ligação existentes em vez de criares outra base.');

  let createdProjectId = '';
  try {
    // Check the real provider account before creating anything. The API count
    // can exclude in-flight projects, so local pending reservations are added
    // to reserve headroom across concurrent LuzaWeb instances.
    const countPayload = await neonApiRequest('/projects/count');
    const providerProjectCount = parseNeonProjectCount(countPayload);
    if (providerProjectCount === null) {
      const error = new Error('Não foi possível confirmar o número de projetos da conta Neon; a criação foi bloqueada para evitar ultrapassar os limites.');
      error.code = 'NEON_PROJECT_COUNT_UNAVAILABLE'; error.statusCode = 503;
      throw error;
    }
    const pending = await pool.query("SELECT COUNT(*)::int AS count FROM neon_provision_reservations WHERE state IN ('pending','cleanup_required')");
    const pendingReservations = Number(pending.rows?.[0]?.count || 0);
    if (providerProjectCount + pendingReservations > RESOURCE_QUOTAS.neonAccountProjectLimit) {
      const error = new Error('A conta Neon atingiu o limite de projetos reservado para o LuzaWeb. Revê os recursos existentes antes de criar outra base.');
      error.code = 'NEON_ACCOUNT_PROJECT_LIMIT'; error.statusCode = 429;
      throw error;
    }
    // Keep the LuzaWeb project ID at the end even for a user-supplied name at
    // the maximum length. This makes provider resources identifiable during
    // manual orphan reconciliation if the process dies before the ID is stored.
    const providerNameSuffix = `-luzaweb-${project.id}`;
    const providerNameBase = name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
    const providerProjectName = `${providerNameBase.slice(0, Math.max(2, 60 - providerNameSuffix.length))}${providerNameSuffix}`;
    const created = await neonApiRequest('/projects', { method: 'POST', body: { project: { name: providerProjectName, region_id: regionId, pg_version: pgVersion } } });
    const neonProject = created.project || created.projects?.[0] || {};
    createdProjectId = String(neonProject.id || created.project_id || created.id || '');
    if (!createdProjectId) {
      const error = new Error('O Neon confirmou uma criação sem devolver o identificador do projeto; é necessária reconciliação manual antes de tentar novamente.');
      error.code = 'NEON_PROJECT_ID_MISSING'; error.neonCleanupRequired = true; error.neonProjectId = '';
      logEvent('error', 'neon_project_created_without_id', { luza_project_id: Number(project.id) });
      void sendOperationalAlert('neon_project_created_without_id', { luza_project_id: Number(project.id) });
      throw error;
    }
    // Persist the external identifier immediately after creation, before any
    // further API call can fail or the function instance can be interrupted.
    const savedReservation = await pool.query("UPDATE neon_provision_reservations SET provider_project_id=$2,updated_at=NOW() WHERE project_id=$1 AND state='pending' RETURNING project_id", [project.id, createdProjectId]);
    if (!savedReservation.rows?.length) {
      const error = new Error('O projeto Neon foi criado, mas não foi possível registar a operação pendente no LuzaWeb.');
      error.neonCleanupRequired = true; error.neonProjectId = createdProjectId; error.code = 'NEON_RESERVATION_PERSIST_FAILED';
      throw error;
    }

    let branches = created.branches || (created.branch ? [created.branch] : []);
    let branchId = String(created.branch?.id || neonProject.default_branch_id || created.default_branch_id || branches[0]?.id || branches[0]?.branch_id || '');
    if (!branchId) {
      const branchPayload = await neonApiRequest(`/projects/${encodeURIComponent(createdProjectId)}/branches`);
      branches = branchPayload.branches || [];
      const branch = branches.find(item => item.name === 'main') || branches[0];
      branchId = String(branch?.id || branch?.branch_id || '');
    }

    let directUri = connectionUriFromPayload(created);
    let roleName = '';
    let defaultDatabase = '';
    if (directUri) {
      const parsed = parsePostgresUri(directUri);
      roleName = parsed.username;
      defaultDatabase = parsed.database;
    }
    if (!roleName && branchId) {
      const rolePayload = await neonApiRequest(`/projects/${encodeURIComponent(createdProjectId)}/branches/${encodeURIComponent(branchId)}/roles`);
      const roles = rolePayload.roles || [];
      const role = roles.find(item => item.role?.name || item.name) || roles[0];
      roleName = String(role?.role?.name || role?.name || '');
    }
    if (!defaultDatabase && branchId) {
      const databasePayload = await neonApiRequest(`/projects/${encodeURIComponent(createdProjectId)}/branches/${encodeURIComponent(branchId)}/databases`);
      const databases = databasePayload.databases || [];
      defaultDatabase = String((databases[0]?.database?.name || databases[0]?.name || ''));
    }
    if (!roleName || !defaultDatabase) throw new Error('O Neon criou o projecto, mas não devolveu o utilizador ou a base padrão. Verifica o estado do projecto no painel Neon.');

    let databaseName = name.toLowerCase();
    if (!/^[a-z_][a-z0-9_]{1,62}$/.test(databaseName)) databaseName = `db_${databaseName.replace(/[^a-z0-9_]+/g, '_')}`.slice(0, 63);
    if (databaseName !== defaultDatabase) {
      if (!branchId) throw new Error('O Neon criou a base padrão, mas não devolveu o identificador da branch para criar o nome de base solicitado.');
      await neonApiRequest(`/projects/${encodeURIComponent(createdProjectId)}/branches/${encodeURIComponent(branchId)}/databases`, {
        method: 'POST', body: { database: { name: databaseName, owner_name: roleName } }
      });
    } else databaseName = defaultDatabase;

    directUri = await waitForNeonConnectionUri(createdProjectId, databaseName, roleName, branchId, false);
    let pooledUri = directUri;
    try { pooledUri = await waitForNeonConnectionUri(createdProjectId, databaseName, roleName, branchId, true); } catch { /* The direct connection remains valid if pooler retrieval is unavailable. */ }
    const details = parsePostgresUri(directUri);
    const encryptedPassword = encryptSecret(details.password);
    const encryptedUri = encryptSecret(directUri);
    const encryptedPooledUri = encryptSecret(pooledUri);
    await ensureProjectDatabase(project.id);
    const { rows } = await pool.query(`INSERT INTO project_database_connections(project_id,name,provider,hostname,port,database_name,username,password_cipher,provider_project_id,provider_branch_id,connection_uri_cipher,pooled_uri_cipher,region_id,pg_version)
      VALUES($1,$2,'neon',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT(project_id) DO UPDATE SET name=EXCLUDED.name,provider='neon',hostname=EXCLUDED.hostname,port=EXCLUDED.port,database_name=EXCLUDED.database_name,username=EXCLUDED.username,password_cipher=EXCLUDED.password_cipher,provider_project_id=EXCLUDED.provider_project_id,provider_branch_id=EXCLUDED.provider_branch_id,connection_uri_cipher=EXCLUDED.connection_uri_cipher,pooled_uri_cipher=EXCLUDED.pooled_uri_cipher,region_id=EXCLUDED.region_id,pg_version=EXCLUDED.pg_version,updated_at=NOW()
      RETURNING id,project_id,name,provider,hostname,port,database_name,username,provider_project_id,provider_branch_id,region_id,pg_version`,
      [project.id, name, details.hostname, details.port, details.database, details.username, encryptedPassword, createdProjectId, branchId, encryptedUri, encryptedPooledUri, regionId, pgVersion]);
    // Use the provider-supplied connection URL and validate it with a real PostgreSQL query.
    const verificationClient = new Client({ connectionString: directUri, connectionTimeoutMillis: 10000 });
    try { await verificationClient.connect(); await verificationClient.query('SELECT 1'); }
    catch (error) {
      await pool.query('DELETE FROM project_database_connections WHERE project_id=$1 AND provider_project_id=$2', [project.id, createdProjectId]);
      throw new Error(`A ligação à base recém-criada no Neon não passou no teste (${String(error.message || '').slice(0,160)}). O LuzaWeb tentou remover os recursos desta tentativa; verifica o painel Neon antes de voltar a tentar.`);
    } finally { await verificationClient.end().catch(() => {}); }
    const externalUrl = directUri;
    return {
      database: rows[0],
      connection: {
        id: rows[0].id, name: rows[0].name, provider: 'neon', hostname: details.hostname, port: details.port,
        database: details.database, username: details.username, password: details.password,
        internal_url: null, external_url: externalUrl, pooled_url: pooledUri,
        psql_command: `psql "${externalUrl}"`, region_id: regionId, pg_version: pgVersion,
        connection_note: 'O Neon não fornece uma URL privada interna equivalente à do Render. A URL externa foi devolvida pela API do Neon; a URL pooled é utilizada internamente pelo LuzaWeb quando disponível.'
      }
    };
  } catch (error) {
    // If creation failed halfway, delete the provider project when possible. If
    // cleanup fails, preserve a reservation so retries cannot silently create
    // duplicate billable resources; an operator must reconcile it manually.
    if (createdProjectId) {
      try {
        await deleteNeonProjectResource(createdProjectId, { checkFirst: false });
        // The provider has confirmed the resource was removed (or absent), so
        // release the reservation rather than count a cleaned resource forever.
        error.neonCleanupRequired = false;
        error.neonProjectId = '';
      } catch (cleanupError) {
        error.neonCleanupRequired = true;
        error.neonProjectId = createdProjectId;
        logEvent('error', 'neon_project_cleanup_failed', { luza_project_id: Number(project.id), provider_project_id: createdProjectId, error_code: String(cleanupError?.providerCode || cleanupError?.code || 'provider_error').slice(0, 40) });
        void sendOperationalAlert('neon_project_cleanup_failed', { luza_project_id: Number(project.id), provider_project_id: createdProjectId });
      }
    }
    throw error;
  }
}
async function getProjectDataStore(projectId) {
  const { rows } = await pool.query('SELECT provider,connection_uri_cipher,pooled_uri_cipher FROM project_database_connections WHERE project_id=$1', [projectId]);
  const row = rows[0];
  if (row?.provider === 'neon' && row.connection_uri_cipher) {
    const uri = decryptSecret(row.pooled_uri_cipher || row.connection_uri_cipher);
    const fingerprint = crypto.createHash('sha256').update(uri).digest('hex');
    let cached = projectDataPools.get(Number(projectId));
    if (cached && cached.fingerprint === fingerprint) {
      projectDataPools.delete(Number(projectId));
      projectDataPools.set(Number(projectId), cached); // LRU: recently used pools move to the end.
    } else {
      if (cached?.pool) await cached.pool.end().catch(() => {});
      const projectPool = new Pool({ connectionString: uri, max: 1, idleTimeoutMillis: 10000, connectionTimeoutMillis: PG_CONNECTION_TIMEOUT_MS, statement_timeout: PG_STATEMENT_TIMEOUT_MS, query_timeout: PG_STATEMENT_TIMEOUT_MS, maxUses: 5000, keepAlive: true });
      projectPool.on('error', error => {
        const errorCode = String(error?.code || 'unknown').slice(0, 40);
        logEvent('error', 'project_postgres_pool_error', { project_id: Number(projectId), error_code: errorCode });
        void sendOperationalAlert('project_database_pool_error', { project_id: Number(projectId), error_code: errorCode });
      });
      cached = { fingerprint, pool: projectPool };
      projectDataPools.set(Number(projectId), cached);
      await evictProjectPoolIfNeeded();
    }
    return { executor: cached.pool, external: true, provider: 'neon' };
  }
  return { executor: pool, external: false, provider: row?.provider || 'managed' };
}
function projectDatabaseConnectionDetails(projectId, databaseRow, clearPassword = null, parsed = null) {
  const baseUrl = new URL(process.env.DATABASE_URL);
  const databaseName = parsed?.databaseName || decodeURIComponent(baseUrl.pathname.replace(/^\/+/, '').split('/')[0] || 'postgres');
  const host = parsed?.host || baseUrl.hostname;
  const port = parsed?.port || Number(baseUrl.port || 5432);
  const schemaName = parsed?.schemaName || databaseRow.schema_name || projectSchemaName(projectId);
  const password = clearPassword ?? decryptSecret(databaseRow.db_password_cipher);
  const url = new URL(process.env.DATABASE_URL);
  url.username = databaseRow.db_username;
  url.password = password;
  url.pathname = `/${databaseName}`;
  url.searchParams.set('sslmode', 'require');
  url.searchParams.delete('options');
  const externalUrl = url.toString();
  const psql = `psql \"host=${host} port=${port} dbname=${databaseName} user=${databaseRow.db_username} sslmode=require\"`;
  const supabaseHosted = host.endsWith('.supabase.co') || host.endsWith('.supabase.com');
  return {
    database: databaseName, hostname: host, port, username: databaseRow.db_username,
    password, schema: schemaName, internal_url: supabaseHosted ? null : externalUrl,
    external_url: externalUrl, psql_command: psql,
    connection_note: supabaseHosted ? 'O Supabase não disponibiliza uma URL privada separada neste modelo; utiliza a URL de ligação indicada.' : 'A URL é uma ligação à base de dados configurada pelo administrador.'
  };
}
async function hardenExistingProjectRoles(executor = pool) {
  if (!databaseConfigured) return;
  let databaseName = 'postgres';
  try { databaseName = decodeURIComponent(new URL(process.env.DATABASE_URL).pathname.replace(/^\/+/, '').split('/')[0] || 'postgres'); } catch {}
  return hardenProjectDatabaseRoles(executor, {
    databaseName,
    onFailure: fields => {
      logEvent('error', fields.event || 'project_role_hardening_failed', fields);
      void sendOperationalAlert(fields.event || 'project_role_hardening_failed', fields);
    }
  });
}

async function migrateLogicalTablesToPostgres(executor = null, { manageTransaction = true } = {}) {
  // A transaction-scoped table lock serializes cold-start migrations across
  // Netlify Function instances without relying on session advisory locks.
  const ownsClient = !executor;
  const client = executor || await pool.connect();
  try {
    if (manageTransaction) await client.query('BEGIN');
    await client.query('LOCK TABLE database_tables IN SHARE ROW EXCLUSIVE MODE');
    const { rows: tables } = await client.query(`
      SELECT t.*, d.project_id FROM database_tables t
      JOIN project_databases d ON d.id=t.database_id
      WHERE t.physical_ready=FALSE ORDER BY d.project_id,t.id
    `);
    for (const table of tables) {
      const columns = parseColumnDefinitions(table.columns);
      const projectId = Number(table.project_id);
      const ref = await createPhysicalTable(client, projectId, table.name, columns);
      const oldRecords = await client.query('SELECT id,data,created_at,updated_at FROM database_records WHERE table_id=$1 ORDER BY id', [table.id]);
      for (const old of oldRecords.rows) {
        let recordData = old.data;
        if (typeof recordData === 'string') { try { recordData = JSON.parse(recordData); } catch { recordData = {}; } }
        const normalized = normalizeRecord(recordData || {}, columns);
        const fields = columns.map(column => quotePgIdentifier(column.name));
        const values = columns.map(column => normalized[column.name] ?? null);
        const placeholders = values.map((_, index) => `$${index + 1}`);
        const createdIndex = values.length + 1;
        const updatedIndex = values.length + 2;
        await client.query(
          `INSERT INTO ${ref} (${fields.concat([quotePgIdentifier('__lzw_created_at'), quotePgIdentifier('__lzw_updated_at')]).join(', ')}) VALUES (${placeholders.concat([`$${createdIndex}`, `$${updatedIndex}`]).join(', ')})`,
          values.concat([old.created_at || new Date().toISOString(), old.updated_at || old.created_at || new Date().toISOString()])
        );
      }
      await client.query('UPDATE database_tables SET physical_ready=TRUE WHERE id=$1', [table.id]);
    }
    if (manageTransaction) await client.query('COMMIT');
  } catch (error) {
    if (manageTransaction) { try { await client.query('ROLLBACK'); } catch {} }
    throw new Error(`Não foi possível migrar as tabelas existentes para PostgreSQL: ${error.message}`);
  } finally {
    if (ownsClient) client.release?.();
  }
}

function signToken(user) { return jwt.sign({ id: user.id, ver: Number(user.token_version || 0), name: user.name, email: user.email, username: user.username || '', bio: user.bio || '', location: user.location || '', website: user.website || '', phone: user.phone || '', created_at: user.created_at || null }, JWT_SECRET, { expiresIn: '7d' }); }
function setAuthCookie(res, user) {
  res.cookie(COOKIE_NAME, signToken(user), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' || Boolean(process.env.NETLIFY),
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}
function clearAuthCookie(res) { res.clearCookie(COOKIE_NAME, { path: '/' }); res.clearCookie('webforge_token', { path: '/' }); }
function getUser(req) {
  try {
    const token = req.cookies[COOKIE_NAME] || req.cookies.webforge_token;
    return token ? jwt.verify(token, JWT_SECRET) : null;
  } catch { return null; }
}
async function requireAuth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sessão expirada.' });
  try {
    // Check persistent session version so password changes can revoke old JWTs.
    const { rows } = await pool.query('SELECT token_version FROM users WHERE id=$1', [user.id]);
    if (!rows[0] || Number(rows[0].token_version || 0) !== Number(user.ver || 0)) {
      clearAuthCookie(res);
      return res.status(401).json({ error: 'Sessão revogada. Inicia sessão novamente.' });
    }
    req.user = user;
    next();
  } catch (error) {
    logEvent('warn', 'session_validation_failed', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    return res.status(503).json({ error: 'Não foi possível validar a sessão. Tenta novamente.' });
  }
}

function connectionUrl(config, password) {
  const user = encodeURIComponent(config.username);
  const pass = encodeURIComponent(password);
  return `postgresql://${user}:${pass}@${config.hostname}:${config.port}/${encodeURIComponent(config.database_name)}?sslmode=require`;
}
function isSensitiveEnvName(name) {
  // Credentials must never be exposed to a static site, even if a user accidentally
  // unchecks the Secret option in the interface or an older record was misconfigured.
  return /(?:^|_)(?:DATABASE_URL|DATABASE_URI|DATABASE_CONNECTION_STRING|POSTGRES_URL|REDIS_URL|MONGODB_URI|DB_URL|PGPASSWORD|PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE_KEY|API_KEY|ACCESS_KEY|SIGNING_KEY|SESSION_KEY|CLIENT_SECRET|CREDENTIALS?)(?:_|$)/i.test(String(name || ''));
}
function safeEnvVariable(row) {
  const secret = Boolean(row.is_secret) || isSensitiveEnvName(row.name);
  return { id: row.id, project_id: row.project_id, group_id: row.group_id, name: row.name, value: secret ? '' : decryptSecret(row.value_cipher), is_secret: secret, has_value: Boolean(row.value_cipher), created_at: row.created_at, updated_at: row.updated_at };
}

let dbInitializationPromise;
async function readSchemaFile(schemaFile) {
  const candidates = [
    path.join(__dirname, schemaFile),
    path.resolve(__dirname, '../..', schemaFile),
    path.resolve(process.cwd(), schemaFile),
    path.resolve(process.cwd(), '..', schemaFile)
  ];
  let lastError;
  for (const candidate of candidates) {
    try { return await fs.readFile(candidate, 'utf8'); }
    catch (error) { lastError = error; }
  }
  throw new Error(`Não foi possível localizar ${schemaFile} no pacote do LUZAWEB: ${lastError?.message || 'ficheiro em falta'}`);
}
function initDb() {
  if (!dbInitializationPromise) {
    const attempt = (async () => {
      if (process.env.NETLIFY && !databaseConfigured) {
        throw new Error('DATABASE_URL é obrigatória no Netlify. Configura a ligação PostgreSQL interna do LuzaWeb nas variáveis do site.');
      }
      // Fail on invalid/missing production keys before opening the database or
      // accepting requests; one validator is shared with the encryption module.
      validateSecretConfiguration({ ...process.env, JWT_SECRET });
      if (!pool) {
        // This variable-based dynamic import is intentionally not statically
        // bundled into Netlify's PostgreSQL-only production function.
        const localDbModulePath = './local-db.js';
        const { SQLitePool } = await import(localDbModulePath);
        pool = new SQLitePool(localDatabasePath);
      }

      let migrationClient = null;
      let migrationTransactionStarted = false;
      const migrationExecutor = databaseConfigured ? (migrationClient = await pool.connect()) : pool;
      try {
        if (databaseConfigured) {
          // Transaction-scoped advisory lock works with direct PostgreSQL and
          // transaction-mode poolers, serializing all startup DDL/data migrations.
          await migrationExecutor.query('BEGIN');
          migrationTransactionStarted = true;
          // A cold start must fail with a controlled error rather than wait forever
          // behind a stalled migration. The transaction lock serializes all DDL.
          await migrationExecutor.query(`SET LOCAL lock_timeout = '${PG_MIGRATION_LOCK_TIMEOUT_MS}ms'`);
          await migrationExecutor.query(`SET LOCAL statement_timeout = '${PG_MIGRATION_STATEMENT_TIMEOUT_MS}ms'`);
          await migrationExecutor.query('SET LOCAL search_path TO public');
          await migrationExecutor.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 1]);
        }

        const schemaFile = databaseConfigured ? 'schema.sql' : 'schema.sqlite.sql';
        const schema = await readSchemaFile(schemaFile);
        if (typeof migrationExecutor.exec === 'function') migrationExecutor.exec(schema);
        else await migrationExecutor.query(schema);

        // Existing PostgreSQL installations receive the project/commit integrity
        // constraint when safe. SAVEPOINT keeps a detected legacy inconsistency
        // from aborting the wider startup migration transaction.
        if (databaseConfigured) {
          await migrationExecutor.query('SAVEPOINT project_isolation_constraint_migration');
          try {
            const unique = await migrationExecutor.query("SELECT 1 FROM pg_constraint WHERE conname='commits_id_project_id_unique' AND conrelid='commits'::regclass LIMIT 1");
            if (!unique.rowCount) await migrationExecutor.query('ALTER TABLE commits ADD CONSTRAINT commits_id_project_id_unique UNIQUE (id, project_id)');
            const invalid = await migrationExecutor.query('SELECT 1 FROM deployments d JOIN commits c ON c.id=d.commit_id WHERE d.project_id<>c.project_id LIMIT 1');
            if (!invalid.rowCount) {
              const fk = await migrationExecutor.query("SELECT 1 FROM pg_constraint WHERE conname='deployments_commit_project_fk' AND conrelid='deployments'::regclass LIMIT 1");
              if (!fk.rowCount) await migrationExecutor.query('ALTER TABLE deployments ADD CONSTRAINT deployments_commit_project_fk FOREIGN KEY (commit_id, project_id) REFERENCES commits(id, project_id) ON DELETE RESTRICT');
            } else {
              logEvent('error', 'project_isolation_legacy_data_mismatch', { table: 'deployments', action: 'composite constraint not applied' });
              void sendOperationalAlert('project_isolation_legacy_data_mismatch', { table: 'deployments' });
            }
            await migrationExecutor.query('RELEASE SAVEPOINT project_isolation_constraint_migration');
          } catch (error) {
            try { await migrationExecutor.query('ROLLBACK TO SAVEPOINT project_isolation_constraint_migration'); await migrationExecutor.query('RELEASE SAVEPOINT project_isolation_constraint_migration'); } catch {}
            // Only known legacy-data constraint conflicts may be deferred. Permission,
            // syntax, connection and unexpected failures must abort startup instead of
            // silently committing a migration without its intended integrity constraint.
            if (!['23503', '23505'].includes(String(error?.code || ''))) throw error;
            logEvent('error', 'project_isolation_constraint_migration_failed', { error_code: String(error?.code || 'unknown').slice(0, 40) });
            void sendOperationalAlert('project_isolation_migration_failed', { error_code: String(error?.code || 'unknown').slice(0, 40) });
          }
        }

        // Additive migrations run while holding the same PostgreSQL migration
        // lock. The IF NOT EXISTS guards make retries idempotent after a failure.
        const profileColumns = [
          ['token_version', 'INTEGER NOT NULL DEFAULT 0'],
          ['username', "TEXT NOT NULL DEFAULT ''"],
          ['bio', "TEXT NOT NULL DEFAULT ''"],
          ['location', "TEXT NOT NULL DEFAULT ''"],
          ['website', "TEXT NOT NULL DEFAULT ''"],
          ['phone', "TEXT NOT NULL DEFAULT ''"]
        ];
        if (databaseConfigured) {
          for (const [column, definition] of profileColumns) {
            await migrationExecutor.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
          }
          for (const [tableName, columns] of [
            ['project_databases', [['schema_name', "TEXT NOT NULL DEFAULT ''"], ['db_username', "TEXT NOT NULL DEFAULT ''"], ['db_password_cipher', "TEXT NOT NULL DEFAULT ''"], ['provisioned_at', 'TIMESTAMPTZ']]],
            ['project_database_connections', [['provider_project_id', "TEXT NOT NULL DEFAULT ''"], ['provider_branch_id', "TEXT NOT NULL DEFAULT ''"], ['connection_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['pooled_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['region_id', "TEXT NOT NULL DEFAULT ''"], ['pg_version', 'INTEGER NOT NULL DEFAULT 16']]],
            ['database_tables', [['physical_ready', 'BOOLEAN NOT NULL DEFAULT FALSE'], ['public_read', 'BOOLEAN NOT NULL DEFAULT FALSE'], ['public_insert', 'BOOLEAN NOT NULL DEFAULT FALSE']]],
            ['api_keys', [['key_type', "TEXT NOT NULL DEFAULT 'secret' CHECK (key_type IN ('secret','publishable'))"]]]
          ]) {
            for (const [column, definition] of columns) {
              await migrationExecutor.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
            }
          }
        } else {
          const info = await migrationExecutor.query('PRAGMA table_info(users)');
          const existing = new Set(info.rows.map(row => row.name));
          for (const [column, definition] of profileColumns) {
            if (!existing.has(column)) await migrationExecutor.query(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
          }
          const additiveColumns = [
            ['project_databases', [['schema_name', "TEXT NOT NULL DEFAULT ''"], ['db_username', "TEXT NOT NULL DEFAULT ''"], ['db_password_cipher', "TEXT NOT NULL DEFAULT ''"], ['provisioned_at', 'TEXT']]],
            ['project_database_connections', [['provider_project_id', "TEXT NOT NULL DEFAULT ''"], ['provider_branch_id', "TEXT NOT NULL DEFAULT ''"], ['connection_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['pooled_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['region_id', "TEXT NOT NULL DEFAULT ''"], ['pg_version', 'INTEGER NOT NULL DEFAULT 16']]],
            ['database_tables', [['physical_ready', 'INTEGER NOT NULL DEFAULT 0'], ['public_read', 'INTEGER NOT NULL DEFAULT 0'], ['public_insert', 'INTEGER NOT NULL DEFAULT 0']]],
            ['api_keys', [['key_type', "TEXT NOT NULL DEFAULT 'secret'"]]]
          ];
          for (const [tableName, columns] of additiveColumns) {
            const tableInfo = await migrationExecutor.query(`PRAGMA table_info(${tableName})`);
            const existingColumns = new Set(tableInfo.rows.map(row => row.name));
            for (const [column, definition] of columns) {
              if (!existingColumns.has(column)) await migrationExecutor.query(`ALTER TABLE ${tableName} ADD COLUMN ${column} ${definition}`);
            }
          }
        }
        await migrationExecutor.query("UPDATE project_databases SET schema_name='luza_project_' || project_id WHERE COALESCE(schema_name,'')=''");
        if (databaseConfigured) {
          await hardenExistingProjectRoles(migrationExecutor);
          await migrateLogicalTablesToPostgres(migrationExecutor, { manageTransaction: false });
          await migrationExecutor.query('COMMIT');
          migrationTransactionStarted = false;
        }
        return true;
      } catch (error) {
        if (databaseConfigured && migrationTransactionStarted) {
          try { await migrationExecutor.query('ROLLBACK'); } catch {}
        }
        throw error;
      } finally {
        if (databaseConfigured) migrationExecutor.release?.();
      }
    })();
    // Do not cache a rejected initialization promise forever. Serverless instances
    // can recover from transient database/network failures and retry on next request.
    dbInitializationPromise = attempt.catch(error => {
      dbInitializationPromise = undefined;
      throw error;
    });
  }
  return dbInitializationPromise;
}
async function getProject(projectId, userId, { includeTrash = false } = {}) {
  // Never resolve a project by ID alone: ownership is part of every lookup.
  // Reject malformed identifiers before they reach child-resource queries.
  const projectKey = Number(projectId);
  const ownerKey = Number(userId);
  if (!Number.isSafeInteger(projectKey) || projectKey < 1 || !Number.isSafeInteger(ownerKey) || ownerKey < 1) return null;
  const sql = includeTrash
    ? 'SELECT * FROM projects WHERE id=$1 AND user_id=$2'
    : 'SELECT * FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NULL';
  const { rows } = await pool.query(sql, [projectKey, ownerKey]);
  return rows[0] || null;
}
async function projectSize(projectId, extraPath = null, extraBytes = 0, executor = pool) {
  const { rows } = await executor.query('SELECT COALESCE(SUM(size_bytes),0)::int AS total FROM files WHERE project_id=$1 AND ($2::text IS NULL OR path<>$2)', [projectId, extraPath]);
  return Number(rows[0].total) + Number(extraBytes);
}
async function repositoryPathConflict(projectId, targetPath, kind, excludeFileId = null, executor = pool) {
  const [fileResult, folderResult] = await Promise.all([
    executor.query('SELECT id,path FROM files WHERE project_id=$1 AND ($2::bigint IS NULL OR id<>$2)', [projectId, excludeFileId]),
    executor.query('SELECT path FROM project_folders WHERE project_id=$1', [projectId])
  ]);
  const target = cleanPath(targetPath);
  if (!target) return true;
  const ancestors = [];
  const parts = target.split('/');
  for (let i = 1; i < parts.length; i++) ancestors.push(parts.slice(0, i).join('/'));
  const files = fileResult.rows.map(row => row.path);
  const folders = folderResult.rows.map(row => row.path);
  if (kind === 'file') {
    return files.some(file => file === target || file.startsWith(`${target}/`) || ancestors.includes(file)) ||
      folders.some(folder => folder === target || folder.startsWith(`${target}/`));
  }
  return files.some(file => file === target || file.startsWith(`${target}/`) || ancestors.includes(file)) ||
    folders.some(folder => folder === target);
}
async function seedProject(projectId, executor = pool) {
  const files = [
    ['index.html', `<!doctype html>\n<html lang="pt">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Meu site</title>\n  <link rel="stylesheet" href="style.css">\n</head>\n<body>\n  <main class="hero">\n    <span class="eyebrow">Publicado com LUZAWEB</span>\n    <h1>O teu próximo site começa aqui.</h1>\n    <p>Edita HTML, CSS e JavaScript e publica quando estiveres pronto.</p>\n    <button id="hello">Testar JavaScript</button>\n  </main>\n  <script src="script.js"></script>\n</body>\n</html>`],
    ['style.css', `:root { font-family: Inter, system-ui, sans-serif; color: #f7faf9; background: #0a0d0d; }\n* { box-sizing: border-box; }\nbody { margin: 0; min-height: 100vh; background: radial-gradient(circle at 15% 10%, #17332b, #0a0d0d 48%); }\n.hero { max-width: 900px; margin: 0 auto; padding: 15vh 24px; }\n.eyebrow { display: inline-block; padding: 7px 11px; border: 1px solid #295b4d; border-radius: 999px; color: #8ff3ca; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }\nh1 { max-width: 800px; margin: 18px 0; font-size: clamp(46px, 8vw, 86px); line-height: .98; letter-spacing: -.06em; }\np { max-width: 640px; color: #9aa9a4; font-size: 18px; line-height: 1.7; }\nbutton { margin-top: 12px; border: 0; border-radius: 12px; padding: 13px 18px; background: #79efbf; color: #07110d; font-weight: 800; cursor: pointer; }`],
    ['script.js', `document.getElementById('hello')?.addEventListener('click', () => {\n  alert('JavaScript está a funcionar.');\n});`]
  ];
  for (const [filePath, content] of files) {
    await executor.query('INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4) ON CONFLICT (project_id,path) DO NOTHING', [projectId, filePath, content, Buffer.byteLength(content)]);
  }
}
async function ensureProjectDatabase(projectId, executor = pool) {
  const schemaName = projectSchemaName(projectId);
  const { rows } = await executor.query("INSERT INTO project_databases(project_id,name,schema_name) VALUES($1,$2,$3) ON CONFLICT(project_id) DO UPDATE SET updated_at=NOW(),schema_name=CASE WHEN COALESCE(project_databases.schema_name,'')='' THEN EXCLUDED.schema_name ELSE project_databases.schema_name END RETURNING *", [projectId, 'main', schemaName]);
  return rows[0];
}
function normalizeColumns(input) {
  if (!Array.isArray(input) || !input.length) throw new Error('Adiciona pelo menos uma coluna.');
  const seen = new Set();
  const columns = input.slice(0, 20).map((column, index) => {
    const name = safeName(column?.name, `coluna_${index + 1}`);
    const type = DB_COLUMN_TYPES.has(column?.type) ? column.type : 'text';
    const required = Boolean(column?.required);
    if (name.startsWith('__lzw_')) throw new Error('O nome da coluna usa um prefixo reservado pelo LuzaWeb.');
    if (seen.has(name)) throw new Error(`A coluna ${name} está repetida.`);
    seen.add(name);
    return { name, type, required };
  });
  return columns;
}
function normalizeRecord(data, columns) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Os dados devem ser um objeto JSON.');
  const out = {};
  for (const column of columns) {
    let value = Object.prototype.hasOwnProperty.call(data, column.name) ? data[column.name] : null;
    if (value === '' && column.type !== 'text') value = null;
    if (value !== null && column.type === 'text' && typeof value !== 'string') value = String(value);
    if (value !== null && column.type === 'number') {
      value = Number(value);
      if (!Number.isFinite(value)) throw new Error(`A coluna ${column.name} precisa de um número.`);
    }
    if (value !== null && column.type === 'boolean') {
      if (value === true || value === false) { /* keep */ }
      else if (value === 'true' || value === '1') value = true;
      else if (value === 'false' || value === '0') value = false;
      else throw new Error(`A coluna ${column.name} precisa ser booleana.`);
    }
    if (value !== null && column.type === 'date') {
      const dateValue = String(value).slice(0, 10);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateValue) || Number.isNaN(new Date(`${dateValue}T00:00:00Z`).getTime()) || new Date(`${dateValue}T00:00:00Z`).toISOString().slice(0, 10) !== dateValue) {
        throw new Error(`A coluna ${column.name} precisa de uma data válida no formato AAAA-MM-DD.`);
      }
      value = dateValue;
    }
    if (column.required && (value === null || value === '')) throw new Error(`A coluna ${column.name} é obrigatória.`);
    out[column.name] = value;
  }
  return out;
}
async function getDbTable(tableId, projectId) {
  const { rows } = await pool.query(`SELECT t.*, d.project_id FROM database_tables t JOIN project_databases d ON d.id=t.database_id WHERE t.id=$1 AND d.project_id=$2`, [tableId, projectId]);
  return rows[0] || null;
}
function generateApiToken() { return `lzw_${crypto.randomBytes(24).toString('hex')}`; }
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }

app.get('/api/health/live', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ ok: true, app: 'LUZAWEB', status: 'alive' });
});
async function checkReadiness(req, res) {
  try {
    await pool.query('SELECT 1');
    const waitingCount = Number(pool?.waitingCount || 0);
    if (databaseConfigured && waitingCount > PG_POOL_WAITING_LIMIT) {
      logEvent('warn', 'database_pool_saturated', { request_id: req.requestId, waiting_count: waitingCount });
      void sendOperationalAlert('database_pool_saturated', { request_id: req.requestId, waiting_count: waitingCount });
      return res.status(503).json({ ok: false, app: 'LUZAWEB', status: 'not_ready', database: 'connected_but_saturated', error: 'O serviço está temporariamente sob carga elevada.' });
    }
    return res.json({ ok: true, app: 'LUZAWEB', status: 'ready', database: databaseConfigured ? 'connected' : 'local' });
  } catch (error) {
    logEvent('error', 'database_health_check_failed', { request_id: req.requestId, error_code: String(error?.code || 'unknown').slice(0, 40) });
    void sendOperationalAlert('database_unavailable', { request_id: req.requestId, database_configured: databaseConfigured });
    return res.status(503).json({ ok: false, app: 'LUZAWEB', status: 'not_ready', database: 'unavailable', error: 'A base de dados está temporariamente indisponível.' });
  }
}
app.get('/api/health/ready', checkReadiness);
app.get('/api/health', checkReadiness);

app.post('/api/auth/register', registrationRateLimit, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Preenche nome, email válido e palavra-passe com 12 a 72 bytes.' });
    }
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,username,bio,location,website,phone,created_at', [name, email, hash]);
    setAuthCookie(res, rows[0]);
    res.json({ user: rows[0] });
  } catch (error) {
    logEvent('error', 'registration_failed', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    if (error.code === '23505') return res.status(409).json({ error: 'Este email já está registado.' });
    if (!databaseConfigured) return res.status(503).json({ error: 'O PostgreSQL ainda não está configurado. Define DATABASE_URL no servidor e reinicia o LUZAWEB.' });
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND' || error.code === 'ETIMEDOUT') return res.status(503).json({ error: 'O LUZAWEB não conseguiu ligar ao PostgreSQL. Verifica a DATABASE_URL e a disponibilidade da base de dados.' });
    res.status(500).json({ error: 'Não foi possível criar a conta. Consulta os logs do servidor para mais detalhes.' });
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) {
      try { await recordAuthFailure(req); } catch (rateError) {
        logEvent('error', 'failed_login_counter_write_failed', { error_code: String(rateError?.code || rateError?.name || 'unknown').slice(0, 40) });
        return res.status(503).json({ error: 'O serviço de autenticação está temporariamente indisponível. Tenta novamente.' });
      }
      return res.status(401).json({ error: 'Email ou palavra-passe inválidos.' });
    }
    try { await clearAuthEmailFailures(req); } catch (rateError) {
      // A successful credential check must not fail solely because counter cleanup failed.
      logEvent('warn', 'successful_login_counter_cleanup_failed', { error_code: String(rateError?.code || rateError?.name || 'unknown').slice(0, 40) });
    }
    setAuthCookie(res, rows[0]);
    res.json({ user: { id: rows[0].id, name: rows[0].name, email: rows[0].email, username: rows[0].username || '', bio: rows[0].bio || '', location: rows[0].location || '', website: rows[0].website || '', phone: rows[0].phone || '', created_at: rows[0].created_at } });
  } catch (error) {
    logEvent('error', 'login_failed', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    if (!databaseConfigured) return res.status(503).json({ error: 'O PostgreSQL ainda não está configurado. Define DATABASE_URL no servidor.' });
    if (['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET'].includes(error?.code)) {
      return res.status(503).json({ error: 'O LUZAWEB não conseguiu consultar a base de dados. Tenta novamente dentro de alguns instantes.' });
    }
    res.status(500).json({ error: 'Não foi possível iniciar sessão. Consulta os logs do servidor para mais detalhes.' });
  }
});
app.post('/api/auth/logout', (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

app.put('/api/account', requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const username = String(req.body.username || '').trim().replace(/^@+/, '').toLowerCase();
    const bio = String(req.body.bio || '').trim().slice(0, 280);
    const location = String(req.body.location || '').trim().slice(0, 80);
    const phone = String(req.body.phone || '').trim().slice(0, 40);
    let website = String(req.body.website || '').trim();
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Indica um nome e email válidos.' });
    if (username && !/^[a-z0-9_.-]{3,24}$/.test(username)) return res.status(400).json({ error: 'O nome de utilizador deve ter 3 a 24 caracteres: letras, números, ponto, hífen ou sublinhado.' });
    if (website) {
      try { const parsed = new URL(website); if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(); website = parsed.href; }
      catch { return res.status(400).json({ error: 'Indica um endereço de site válido, começando por https:// ou http://.' }); }
    }
    const { rows } = await pool.query('UPDATE users SET name=$1,email=$2,username=$3,bio=$4,location=$5,website=$6,phone=$7 WHERE id=$8 RETURNING id,name,email,username,bio,location,website,phone,created_at,token_version', [name, email, username, bio, location, website, phone, req.user.id]);
    setAuthCookie(res, rows[0]);
    res.json({ user: rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Este email já está a ser usado.' });
    res.status(500).json({ error: 'Não foi possível atualizar a conta.' });
  }
});
app.post('/api/account/password', requireAuth, async (req, res) => {
  try {
    const current = String(req.body.currentPassword || '');
    const next = String(req.body.newPassword || '');
    if (next.length < 12 || Buffer.byteLength(next, 'utf8') > 72) return res.status(400).json({ error: 'A nova palavra-passe precisa de 12 a 72 bytes.' });
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0] || !(await bcrypt.compare(current, rows[0].password_hash))) return res.status(401).json({ error: 'A palavra-passe atual está incorreta.' });
    const hash = await bcrypt.hash(next, 10);
    const updated = await pool.query('UPDATE users SET password_hash=$1,token_version=token_version+1 WHERE id=$2 RETURNING id,name,email,username,bio,location,website,phone,created_at,token_version', [hash, req.user.id]);
    setAuthCookie(res, updated.rows[0]);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Não foi possível alterar a palavra-passe.' }); }
});

app.get('/api/projects', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id,p.name,p.slug,p.description,p.created_at,p.updated_at,p.published_at,
        (SELECT COUNT(*) FROM files f WHERE f.project_id=p.id) AS file_count,
        (SELECT COUNT(*) FROM commits c WHERE c.project_id=p.id) AS commit_count,
        (SELECT COUNT(*) FROM deployments d WHERE d.project_id=p.id AND d.status='LIVE') AS live_deploy_count,
        (SELECT status FROM deployments d WHERE d.project_id=p.id ORDER BY d.created_at DESC LIMIT 1) AS deploy_status
      FROM projects p WHERE p.user_id=$1 AND p.trashed_at IS NULL ORDER BY p.updated_at DESC
    `, [req.user.id]);
    res.json({ projects: rows });
  } catch { res.status(500).json({ error: 'Não foi possível carregar os projetos.' }); }
});

app.post('/api/projects', requireAuth, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  if (!name) return res.status(400).json({ error: 'Indica um nome para o projeto.', code: 'PROJECT_NAME_REQUIRED', request_id: req.requestId || null });
  if (name.length > 100 || description.length > 2000) return res.status(400).json({ error: 'O nome ou a descrição ultrapassa o tamanho permitido.', code: 'PROJECT_INPUT_TOO_LONG', request_id: req.requestId || null });

  try {
    let rateDecision;
    try {
      rateDecision = await consumeResourceCreationLimit(pool, {
        action: 'project-create', userId: req.user.id, ip: getRequestClientIp(req),
        perUserLimit: RESOURCE_QUOTAS.projectCreatePerUserPerHour,
        perIpLimit: RESOURCE_QUOTAS.projectCreatePerIpPerHour,
        windowMs: RESOURCE_QUOTAS.creationWindowMs
      });
    } catch (error) {
      logEvent('error', 'project_creation_limiter_unavailable', { request_id: req.requestId || null, error_code: String(error?.code || 'unknown').slice(0, 40) });
      void sendOperationalAlert('project_creation_limiter_unavailable', { request_id: req.requestId || null });
      return respondApiError(req, res, error, 'O serviço de criação de projetos está temporariamente indisponível.', 503);
    }
    if (!rateDecision.allowed) {
      const retry = Math.max(1, Math.ceil(rateDecision.retryAfterMs / 1000));
      res.setHeader('Retry-After', String(retry));
      return res.status(429).json({ error: 'Atingiste o limite de criação de projetos. Tenta novamente mais tarde.', code: 'PROJECT_CREATION_RATE_LIMITED', retry_after_seconds: retry, request_id: req.requestId || null });
    }

    const client = await pool.connect();
    let transactionStarted = false;
    try {
      await client.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
      transactionStarted = true;
      if (databaseConfigured) {
        // Serializes the global cap and slug generation across serverless instances.
        await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 3]);
        await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
      }
      const userCount = await client.query('SELECT COUNT(*)::int AS count FROM projects WHERE user_id=$1', [req.user.id]);
      const activeUserCount = await client.query('SELECT COUNT(*)::int AS count FROM projects WHERE user_id=$1 AND trashed_at IS NULL', [req.user.id]);
      const totalCount = await client.query('SELECT COUNT(*)::int AS count FROM projects');
      const perUser = Number(userCount.rows?.[0]?.count || 0);
      const activePerUser = Number(activeUserCount.rows?.[0]?.count || 0);
      const globalCount = Number(totalCount.rows?.[0]?.count || 0);
      if (perUser >= RESOURCE_QUOTAS.projectsPerUser) {
        await client.query('ROLLBACK'); transactionStarted = false;
        return res.status(429).json({ error: `A tua conta atingiu o limite de ${RESOURCE_QUOTAS.projectsPerUser} projetos. Elimina definitivamente projetos que já não precisas ou contacta o administrador.`, code: 'PROJECT_USER_QUOTA_REACHED', limit: RESOURCE_QUOTAS.projectsPerUser, request_id: req.requestId || null });
      }
      if (globalCount >= RESOURCE_QUOTAS.projectsGlobal) {
        await client.query('ROLLBACK'); transactionStarted = false;
        logEvent('warn', 'global_project_quota_reached', { request_id: req.requestId || null, configured_limit: RESOURCE_QUOTAS.projectsGlobal });
        void sendOperationalAlert('global_project_quota_reached', { configured_limit: RESOURCE_QUOTAS.projectsGlobal });
        return res.status(503).json({ error: 'O serviço atingiu temporariamente a capacidade de criação de projetos.', code: 'PROJECT_GLOBAL_QUOTA_REACHED', request_id: req.requestId || null });
      }

      const base = slugify(name);
      let slug = base;
      for (let n = 2; ; n++) {
        const found = await client.query('SELECT 1 FROM projects WHERE slug=$1', [slug]);
        if (!found.rowCount) break;
        slug = `${base}-${n}`;
      }
      const { rows } = await client.query('INSERT INTO projects(user_id,name,slug,description) VALUES($1,$2,$3,$4) RETURNING *', [req.user.id, name, slug, description]);
      if (activePerUser === 0) await seedProject(rows[0].id, client);
      await ensureProjectDatabase(rows[0].id, client);
      await client.query('COMMIT'); transactionStarted = false;
      res.status(201).json({ project: rows[0], quota: { projects_per_user: RESOURCE_QUOTAS.projectsPerUser, projects_remaining: Math.max(0, RESOURCE_QUOTAS.projectsPerUser - (perUser + 1)) } });
    } catch (error) {
      if (transactionStarted) { try { await client.query('ROLLBACK'); } catch {} }
      if (String(error?.code || '') === '23505') return res.status(409).json({ error: 'Já existe um projeto com um identificador semelhante. Tenta novamente com outro nome.', code: 'PROJECT_SLUG_CONFLICT', request_id: req.requestId || null });
      throw error;
    } finally { client.release?.(); }
  } catch (error) {
    respondApiError(req, res, error, 'Não foi possível criar o projeto.');
  }
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const [files, commits, deployments, folders] = await Promise.all([
      pool.query('SELECT id,path,content,size_bytes,updated_at FROM files WHERE project_id=$1 ORDER BY path', [project.id]),
      pool.query('SELECT id,message,created_at FROM commits WHERE project_id=$1 ORDER BY id DESC LIMIT 30', [project.id]),
      pool.query('SELECT id,commit_id,status,message,created_at,finished_at FROM deployments WHERE project_id=$1 ORDER BY id DESC LIMIT 30', [project.id]),
      pool.query('SELECT id,path,created_at FROM project_folders WHERE project_id=$1 ORDER BY path', [project.id])
    ]);
    res.json({ project, files: files.rows, commits: commits.rows, deployments: deployments.rows, folders: folders.rows });
  } catch { res.status(500).json({ error: 'Não foi possível carregar o projeto.' }); }
});

app.put('/api/projects/:id', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  if (!name) return res.status(400).json({ error: 'O nome não pode ficar vazio.' });
  const { rows } = await pool.query('UPDATE projects SET name=$1,description=$2,updated_at=NOW() WHERE id=$3 RETURNING *', [name, description, project.id]);
  res.json({ project: rows[0] });
});

async function changeProjectLifecycle(projectId, userId, action) {
  const client = await pool.connect();
  let transactionStarted = false;
  let neonProjectId = '';
  try {
    await client.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
    transactionStarted = true;
    if (databaseConfigured) {
      // Share the same account/project lifecycle lock as provisioning. The lock
      // protects the decision and durable operation row, never a network call.
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
    }
    const expectedTrashState = action === 'delete' ? 'trashed_at IS NOT NULL' : 'trashed_at IS NULL';
    const owned = await client.query(`SELECT id FROM projects WHERE id=$1 AND user_id=$2 AND ${expectedTrashState}${databaseConfigured ? ' FOR UPDATE' : ''}`, [projectId, userId]);
    if (!owned.rows?.[0]) {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 404, code: 'PROJECT_NOT_FOUND', error: action === 'delete' ? 'Item não encontrado na lixeira.' : 'Projeto não encontrado.' };
    }

    const reservation = (await client.query('SELECT state FROM neon_provision_reservations WHERE project_id=$1', [projectId])).rows[0];
    if (reservation && ['pending', 'cleanup_required'].includes(String(reservation.state))) {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 409, code: reservation.state === 'cleanup_required' ? 'NEON_CLEANUP_REQUIRED' : 'NEON_PROVISION_IN_PROGRESS', error: 'Este projeto tem uma criação de base Neon em curso ou pendente de reconciliação. Resolve-a antes de mover ou eliminar o projeto.' };
    }

    const lifecycleOperation = (await client.query('SELECT operation,state,provider_project_id,updated_at FROM project_lifecycle_operations WHERE project_id=$1', [projectId])).rows[0];
    if (action === 'trash') {
      if (lifecycleOperationBlocksRestore(lifecycleOperation)) {
        await client.query('ROLLBACK'); transactionStarted = false;
        return { ok: false, status: 409, code: 'NEON_DELETION_IN_PROGRESS', error: 'Este projeto tem uma operação de eliminação Neon pendente. Resolve-a antes de mover o projeto.' };
      }
      await client.query('UPDATE projects SET trashed_at=NOW(),updated_at=NOW() WHERE id=$1 AND user_id=$2 AND trashed_at IS NULL', [projectId, userId]);
      await client.query('COMMIT'); transactionStarted = false;
      return { ok: true };
    }

    if (action !== 'delete') {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 400, code: 'INVALID_LIFECYCLE_ACTION', error: 'Operação de projeto inválida.' };
    }

    if (lifecycleOperation) {
      const decision = classifyLifecycleDeleteOperation(lifecycleOperation);
      if (decision.action === 'in_progress') {
        await client.query('ROLLBACK'); transactionStarted = false;
        return { ok: false, status: 409, code: decision.code, error: 'A eliminação da base Neon deste projeto já está em curso. Aguarda alguns minutos antes de verificar novamente.' };
      }
      if (decision.action !== 'retry') {
        await client.query('ROLLBACK'); transactionStarted = false;
        logEvent('error', 'neon_delete_reconciliation_blocked', { project_id: Number(projectId), reason: decision.code || 'unknown' });
        void sendOperationalAlert('neon_delete_reconciliation_blocked', { project_id: Number(projectId) });
        return { ok: false, status: 409, code: decision.code || 'NEON_LIFECYCLE_RECONCILIATION_REQUIRED', error: 'A referência à base Neon está incompleta. O projeto foi mantido na lixeira para reconciliação administrativa.' };
      }
      neonProjectId = decision.providerProjectId;
      await client.query("UPDATE project_lifecycle_operations SET state='pending',last_error_code='',updated_at=NOW() WHERE project_id=$1", [projectId]);
    } else {
      const connection = (await client.query("SELECT provider,provider_project_id,connection_uri_cipher,pooled_uri_cipher FROM project_database_connections WHERE project_id=$1", [projectId])).rows[0];
      if (connection?.provider === 'neon') {
        const knownProviderId = String(connection.provider_project_id || '').trim();
        const hasExternalReference = Boolean(knownProviderId || connection.connection_uri_cipher || connection.pooled_uri_cipher);
        if (hasExternalReference && !knownProviderId) {
          await client.query('ROLLBACK'); transactionStarted = false;
          logEvent('error', 'neon_resource_id_missing_on_delete', { project_id: Number(projectId) });
          void sendOperationalAlert('neon_resource_id_missing_on_delete', { project_id: Number(projectId) });
          return { ok: false, status: 409, code: 'NEON_RESOURCE_ID_MISSING', error: 'A configuração indica uma base Neon, mas falta o identificador do projeto no fornecedor. O projeto foi mantido na lixeira para reconciliação; não foi apagado nenhum dado.' };
        }
        if (knownProviderId) {
          neonProjectId = knownProviderId;
          await client.query(`INSERT INTO project_lifecycle_operations(project_id,user_id,operation,state,provider_project_id,last_error_code,created_at,updated_at)
            VALUES($1,$2,'delete_neon_project','pending',$3,'',NOW(),NOW())`, [projectId, userId, neonProjectId]);
        }
      }
      if (!neonProjectId) {
        // Deployments reference commits with ON DELETE RESTRICT, so remove the
        // deployment rows first before the project's cascading data cleanup.
        await client.query('DELETE FROM deployments WHERE project_id=$1', [projectId]);
        await client.query('DELETE FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL', [projectId, userId]);
        await client.query('COMMIT'); transactionStarted = false;
        return { ok: true };
      }
    }

    await client.query('COMMIT'); transactionStarted = false;
  } catch (error) {
    if (transactionStarted) { try { await client.query('ROLLBACK'); } catch {} }
    throw error;
  } finally {
    client.release?.();
  }

  // A durable operation row now blocks restores and duplicate deletion requests.
  // Close cached connections before asking Neon to remove the remote resource.
  const cachedProjectPool = projectDataPools.get(Number(projectId));
  if (cachedProjectPool?.pool) await cachedProjectPool.pool.end().catch(() => {});
  projectDataPools.delete(Number(projectId));
  try {
    await deleteNeonProjectResource(neonProjectId);
  } catch (error) {
    const failureCode = String(error?.providerCode || error?.code || (error?.httpStatus ? `HTTP_${error.httpStatus}` : 'NEON_DELETE_FAILED')).slice(0, 80);
    try {
      await pool.query("UPDATE project_lifecycle_operations SET state='cleanup_required',last_error_code=$2,updated_at=NOW() WHERE project_id=$1 AND provider_project_id=$3", [projectId, failureCode, neonProjectId]);
    } catch (stateError) {
      logEvent('error', 'neon_delete_state_update_failed', { project_id: Number(projectId), error_code: String(stateError?.code || 'unknown').slice(0, 40) });
    }
    logEvent('error', 'neon_project_delete_failed', { project_id: Number(projectId), provider_project_id: neonProjectId, error_code: failureCode });
    void sendOperationalAlert('neon_project_delete_failed', { project_id: Number(projectId), provider_project_id: neonProjectId, error_code: failureCode });
    const status = [423, 429, 503].includes(Number(error?.httpStatus)) ? (Number(error.httpStatus) === 423 ? 409 : Number(error.httpStatus)) : 502;
    return { ok: false, status, code: 'NEON_DELETE_FAILED', error: 'Não foi possível confirmar a remoção da base Neon. O projeto e a referência externa foram mantidos na lixeira para nova tentativa ou reconciliação. Não tentes apagar os registos manualmente.' };
  }

  // Provider deletion completed (or Neon confirmed the resource is already absent).
  // Only now remove the internal project and all attached metadata.
  const finalClient = await pool.connect();
  let finalTransactionStarted = false;
  try {
    await finalClient.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
    finalTransactionStarted = true;
    if (databaseConfigured) await finalClient.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
    const finalProject = (await finalClient.query(`SELECT id FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL${databaseConfigured ? ' FOR UPDATE' : ''}`, [projectId, userId])).rows[0];
    if (!finalProject) {
      await finalClient.query('COMMIT'); finalTransactionStarted = false;
      return { ok: true };
    }
    const operation = (await finalClient.query('SELECT provider_project_id FROM project_lifecycle_operations WHERE project_id=$1', [projectId])).rows[0];
    const currentConnection = (await finalClient.query('SELECT provider,provider_project_id,connection_uri_cipher,pooled_uri_cipher FROM project_database_connections WHERE project_id=$1', [projectId])).rows[0];
    const connectionId = String(currentConnection?.provider_project_id || '');
    const connectionLooksManaged = currentConnection?.provider === 'neon' && Boolean(connectionId || currentConnection.connection_uri_cipher || currentConnection.pooled_uri_cipher);
    if (String(operation?.provider_project_id || '') !== neonProjectId || (currentConnection && currentConnection.provider !== 'neon') || (connectionLooksManaged && connectionId !== neonProjectId)) {
      await finalClient.query('ROLLBACK'); finalTransactionStarted = false;
      logEvent('error', 'neon_delete_finalization_mismatch', { project_id: Number(projectId) });
      void sendOperationalAlert('neon_delete_finalization_mismatch', { project_id: Number(projectId) });
      return { ok: false, status: 409, code: 'NEON_DELETE_RECONCILIATION_REQUIRED', error: 'O recurso Neon foi removido, mas o registo interno mudou inesperadamente. O projeto foi preservado para reconciliação.' };
    }
    await finalClient.query('DELETE FROM deployments WHERE project_id=$1', [projectId]);
    await finalClient.query('DELETE FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL', [projectId, userId]);
    await finalClient.query('COMMIT'); finalTransactionStarted = false;
    return { ok: true };
  } catch (error) {
    if (finalTransactionStarted) { try { await finalClient.query('ROLLBACK'); } catch {} finalTransactionStarted = false; }
    // Reuse the checked-out client so a low-pool deployment (Netlify max=1)
    // cannot deadlock while borrowing a second connection before release.
    try {
      await finalClient.query("UPDATE project_lifecycle_operations SET state='cleanup_required',last_error_code=$2,updated_at=NOW() WHERE project_id=$1 AND provider_project_id=$3", [projectId, String(error?.code || 'LOCAL_FINALIZATION_FAILED').slice(0, 80), neonProjectId]);
    } catch {}
    logEvent('error', 'neon_deleted_local_finalization_failed', { project_id: Number(projectId), error_code: String(error?.code || 'unknown').slice(0, 40) });
    void sendOperationalAlert('neon_deleted_local_finalization_failed', { project_id: Number(projectId) });
    return { ok: false, status: 503, code: 'NEON_DELETE_RECONCILIATION_REQUIRED', error: 'O Neon confirmou a remoção, mas o LuzaWeb ainda não conseguiu concluir a limpeza local. O registo foi preservado para reconciliação segura.' };
  } finally {
    finalClient.release?.();
  }
}

async function restoreTrashedProject(projectId, userId) {
  const client = await pool.connect();
  let transactionStarted = false;
  try {
    await client.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
    transactionStarted = true;
    if (databaseConfigured) await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
    const project = (await client.query(`SELECT id FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL${databaseConfigured ? ' FOR UPDATE' : ''}`, [projectId, userId])).rows[0];
    if (!project) {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 404, code: 'TRASH_ITEM_NOT_FOUND', error: 'Item não encontrado na lixeira.' };
    }
    const operation = (await client.query('SELECT state FROM project_lifecycle_operations WHERE project_id=$1', [projectId])).rows[0];
    if (lifecycleOperationBlocksRestore(operation)) {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 409, code: 'NEON_DELETION_RECONCILIATION_REQUIRED', error: 'Este projeto tem uma operação de remoção Neon pendente ou por reconciliar. Resolve-a antes de restaurar o projeto.' };
    }
    const reservation = (await client.query('SELECT state FROM neon_provision_reservations WHERE project_id=$1', [projectId])).rows[0];
    if (reservation && ['pending', 'cleanup_required'].includes(String(reservation.state))) {
      await client.query('ROLLBACK'); transactionStarted = false;
      return { ok: false, status: 409, code: 'NEON_PROVISION_RECONCILIATION_REQUIRED', error: 'Este projeto tem uma criação Neon pendente ou por reconciliar. Resolve-a antes de restaurar o projeto.' };
    }
    await client.query('UPDATE projects SET trashed_at=NULL,updated_at=NOW() WHERE id=$1 AND user_id=$2 AND trashed_at IS NOT NULL', [projectId, userId]);
    await client.query('COMMIT'); transactionStarted = false;
    return { ok: true };
  } catch (error) {
    if (transactionStarted) { try { await client.query('ROLLBACK'); } catch {} }
    throw error;
  } finally { client.release?.(); }
}

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const result = await changeProjectLifecycle(req.params.id, req.user.id, 'trash');
    if (!result.ok) return res.status(result.status).json({ error: result.error, code: result.code, request_id: req.requestId || null });
    res.json({ ok: true });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível mover o projeto para a lixeira.'); }
});

app.get('/api/trash', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id,name,slug,description,created_at,updated_at,published_at,trashed_at FROM projects WHERE user_id=$1 AND trashed_at IS NOT NULL ORDER BY trashed_at DESC`, [req.user.id]);
    res.json({ projects: rows });
  } catch { res.status(500).json({ error: 'Não foi possível carregar a lixeira.' }); }
});
app.post('/api/trash/:id/restore', requireAuth, async (req, res) => {
  try {
    const result = await restoreTrashedProject(req.params.id, req.user.id);
    if (!result.ok) return res.status(result.status).json({ error: result.error, code: result.code, request_id: req.requestId || null });
    res.json({ ok: true });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível restaurar o projeto.'); }
});
app.delete('/api/trash/:id', requireAuth, async (req, res) => {
  try {
    const result = await changeProjectLifecycle(req.params.id, req.user.id, 'delete');
    if (!result.ok) return res.status(result.status).json({ error: result.error, code: result.code, request_id: req.requestId || null });
    res.json({ ok: true });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível eliminar definitivamente o projeto.'); }
});

app.post('/api/projects/:id/folders', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const folderPath = cleanPath(req.body.path);
  if (!folderPath || folderPath.length > 180) return res.status(400).json({ error: 'Indica um nome de pasta válido.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (databaseConfigured) await client.query('SELECT id FROM projects WHERE id=$1 FOR UPDATE', [project.id]);
    if (await repositoryPathConflict(project.id, folderPath, 'folder', null, client)) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'O caminho da pasta entra em conflito com um ficheiro ou pasta existente.' });
    }
    const parts = folderPath.split('/');
    let partial = '';
    const folderPaths = [];
    for (const part of parts) { partial = partial ? `${partial}/${part}` : part; folderPaths.push(partial); }
    const existingFolders = await client.query('SELECT COUNT(*)::int AS count FROM project_folders WHERE project_id=$1', [project.id]);
    const uniqueMissing = [];
    for (const itemPath of folderPaths) {
      const exists = await client.query('SELECT 1 FROM project_folders WHERE project_id=$1 AND path=$2 LIMIT 1', [project.id, itemPath]);
      if (!exists.rowCount) uniqueMissing.push(itemPath);
    }
    if (Number(existingFolders.rows[0]?.count || 0) + uniqueMissing.length > MAX_FOLDERS_PER_PROJECT) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Limite de ${MAX_FOLDERS_PER_PROJECT} pastas por projeto.` });
    }
    for (const itemPath of uniqueMissing) await client.query('INSERT INTO project_folders(project_id,path) VALUES($1,$2) ON CONFLICT(project_id,path) DO NOTHING', [project.id, itemPath]);
    await client.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    const { rows } = await client.query('SELECT id,path,created_at FROM project_folders WHERE project_id=$1 AND path=$2', [project.id, folderPath]);
    await client.query('COMMIT');
    res.json({ folder: rows[0] });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'Não foi possível criar a pasta.' });
  } finally { client.release?.(); }
});

app.patch('/api/projects/:id/files/:fileId/path', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const fileId = Number(req.params.fileId);
  const newPath = cleanPath(req.body.path);
  if (!Number.isSafeInteger(fileId) || fileId < 1 || !newPath) return res.status(400).json({ error: 'Indica um destino válido.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (databaseConfigured) await client.query('SELECT id FROM projects WHERE id=$1 FOR UPDATE', [project.id]);
    const existingFile = await client.query('SELECT id,path,content,size_bytes,updated_at FROM files WHERE project_id=$1 AND id=$2', [project.id, fileId]);
    if (!existingFile.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Ficheiro não encontrado.' }); }
    if (existingFile.rows[0].path === newPath) { await client.query('COMMIT'); return res.json({ file: existingFile.rows[0] }); }
    if (await repositoryPathConflict(project.id, newPath, 'file', fileId, client)) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Já existe um ficheiro ou pasta com esse nome no destino.' });
    }
    const { rows } = await client.query('UPDATE files SET path=$1,updated_at=NOW() WHERE project_id=$2 AND id=$3 RETURNING id,path,content,size_bytes,updated_at', [newPath, project.id, fileId]);
    await client.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    await client.query('COMMIT');
    res.json({ file: rows[0] });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'Não foi possível mover o ficheiro.' });
  } finally { client.release?.(); }
});

app.post('/api/projects/:id/files', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const filePath = cleanPath(req.body.path);
  const content = String(req.body.content ?? '');
  const contentBytes = storedContentBytes(content);
  if (!filePath || !allowedFile(filePath)) return res.status(400).json({ error: 'Indica um caminho de ficheiro válido.' });
  if (contentBytes > MAX_FILE_BYTES) return res.status(413).json({ error: 'Ficheiro demasiado grande (máximo 300 KB).' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (databaseConfigured) await client.query('SELECT id FROM projects WHERE id=$1 FOR UPDATE', [project.id]);
    const exists = await client.query('SELECT id FROM files WHERE project_id=$1 AND path=$2', [project.id, filePath]);
    if (await repositoryPathConflict(project.id, filePath, 'file', exists.rows[0]?.id ?? null, client)) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'O caminho entra em conflito com um ficheiro ou pasta existente.' });
    }
    const count = await client.query('SELECT COUNT(*)::int AS count FROM files WHERE project_id=$1 AND path<>$2', [project.id, filePath]);
    if (!exists.rowCount && Number(count.rows[0].count) >= MAX_FILES_PER_PROJECT) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Limite de ${MAX_FILES_PER_PROJECT} ficheiros por projeto.` });
    }
    const total = await projectSize(project.id, filePath, contentBytes, client);
    if (total > MAX_PROJECT_BYTES) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O projeto ultrapassaria o limite de 5 MB.' });
    }
    const { rows } = await client.query(`
      INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4)
      ON CONFLICT(project_id,path) DO UPDATE SET content=EXCLUDED.content,size_bytes=EXCLUDED.size_bytes,updated_at=NOW()
      RETURNING id,path,content,size_bytes,updated_at
    `, [project.id, filePath, content, contentBytes]);
    await client.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    await client.query('COMMIT');
    res.json({ file: rows[0] });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'Não foi possível guardar o ficheiro.' });
  } finally { client.release?.(); }
});

app.delete('/api/projects/:id/files/:fileId', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { rows } = await pool.query('DELETE FROM files WHERE id=$1 AND project_id=$2 RETURNING path', [req.params.fileId, project.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Ficheiro não encontrado.' });
  await pool.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
  res.json({ ok: true, path: rows[0].path });
});

app.post('/api/projects/:id/commit', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const message = String(req.body.message || 'Atualização do projeto').trim().slice(0, 120) || 'Atualização do projeto';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT id FROM projects WHERE id=$1${databaseConfigured ? ' FOR UPDATE' : ''}`, [project.id]);
    const fileRows = await client.query('SELECT path,content FROM files WHERE project_id=$1 ORDER BY path', [project.id]);
    if (!fileRows.rows.some(file => file.path === 'index.html')) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O projeto precisa de um ficheiro index.html na raiz antes do commit.' });
    }
    const totalBytes = fileRows.rows.reduce((sum, file) => sum + storedContentBytes(String(file.content ?? '')), 0);
    if (fileRows.rows.length > MAX_FILES_PER_PROJECT || totalBytes > MAX_PROJECT_BYTES || fileRows.rows.some(file => !allowedFile(file.path) || storedContentBytes(String(file.content ?? '')) > MAX_FILE_BYTES)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O projeto excede os limites de ficheiros, caminhos ou tamanho. Revê os ficheiros antes de criar um snapshot.' });
    }
    const snapshot = Object.fromEntries(fileRows.rows.map(file => [file.path, file.content]));
    const committedAt = new Date().toISOString();
    const { rows } = await client.query('INSERT INTO commits(project_id,message,snapshot,created_at) VALUES($1,$2,$3::jsonb,$4) RETURNING id,message,created_at', [project.id, message, JSON.stringify(snapshot), committedAt]);
    await client.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    await pruneProjectHistory(client, project.id, HISTORY_RETENTION);
    await client.query('COMMIT');
    res.json({ commit: rows[0] });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    respondApiError(req, res, error, 'Não foi possível criar o commit.');
  } finally { client.release?.(); }
});
app.post('/api/projects/:id/commits/:commitId/restore', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { rows } = await pool.query('SELECT * FROM commits WHERE id=$1 AND project_id=$2', [req.params.commitId, project.id]);
  const commit = rows[0];
  if (!commit) return res.status(404).json({ error: 'Commit não encontrado.' });
  const entries = Object.entries(commit.snapshot || {});
  const totalBytes = entries.reduce((sum, [, content]) => sum + storedContentBytes(String(content ?? '')), 0);
  const normalizedPaths = entries.map(([filePath]) => cleanPath(filePath));
  if (!entries.some(([filePath]) => filePath === 'index.html')) return res.status(400).json({ error: 'Este snapshot não contém index.html e não pode ser restaurado como projeto publicável.' });
  if (entries.length > MAX_FILES_PER_PROJECT || totalBytes > MAX_PROJECT_BYTES ||
      entries.some(([, content]) => storedContentBytes(String(content ?? '')) > MAX_FILE_BYTES) ||
      normalizedPaths.some((filePath, index) => !filePath || filePath !== entries[index][0]) ||
      new Set(normalizedPaths).size !== normalizedPaths.length) {
    return res.status(400).json({ error: 'O commit contém caminhos inválidos ou excede os limites atuais do projeto.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM files WHERE project_id=$1', [project.id]);
    await client.query('DELETE FROM project_folders WHERE project_id=$1', [project.id]);
    const restoredFolders = new Set();
    for (const [filePath, content] of entries) {
      const clean = cleanPath(filePath);
      await client.query('INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4)', [project.id, clean, String(content ?? ''), storedContentBytes(String(content ?? ''))]);
      const parts = clean.split('/');
      for (let i = 1; i < parts.length; i++) restoredFolders.add(parts.slice(0, i).join('/'));
    }
    if (restoredFolders.size > MAX_FOLDERS_PER_PROJECT) throw new Error('O snapshot excede o limite de pastas do projecto.');
    for (const folderPath of restoredFolders) await client.query('INSERT INTO project_folders(project_id,path) VALUES($1,$2) ON CONFLICT(project_id,path) DO NOTHING', [project.id, folderPath]);
    await client.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Não foi possível restaurar o commit.' });
  } finally { client.release(); }
});

app.post('/api/projects/:id/deploy', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT id FROM projects WHERE id=$1${databaseConfigured ? ' FOR UPDATE' : ''}`, [project.id]);
    const fileRows = await client.query('SELECT path,content FROM files WHERE project_id=$1 ORDER BY path', [project.id]);
    const index = fileRows.rows.find(file => file.path === 'index.html');
    if (!index) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Adiciona um ficheiro index.html (com esse nome exacto) na raiz do projecto antes de publicar.' });
    }
    const totalBytes = fileRows.rows.reduce((sum, file) => sum + storedContentBytes(String(file.content ?? '')), 0);
    if (fileRows.rows.length > MAX_FILES_PER_PROJECT || totalBytes > MAX_PROJECT_BYTES ||
        fileRows.rows.some(file => !allowedFile(file.path) || storedContentBytes(String(file.content ?? '')) > MAX_FILE_BYTES)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O projeto excede os limites de ficheiros, caminhos ou tamanho e não pode ser publicado.' });
    }
    if (storedContentBytes(String(index.content ?? '')) > MAX_FILE_BYTES) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'O index.html é demasiado grande.' });
    }
    const snapshot = Object.fromEntries(fileRows.rows.map(file => [file.path, file.content]));
    const publishedAt = new Date().toISOString();
    const commit = await client.query('INSERT INTO commits(project_id,message,snapshot,created_at) VALUES($1,$2,$3::jsonb,$4) RETURNING id,created_at', [project.id, 'Publicação automática', JSON.stringify(snapshot), publishedAt]);
    const deployment = await client.query('INSERT INTO deployments(project_id,commit_id,status,message,created_at,finished_at) VALUES($1,$2,$3,$4,$5,$5) RETURNING *', [project.id, commit.rows[0].id, 'LIVE', 'Publicação concluída e disponível online.', publishedAt]);
    await client.query('UPDATE projects SET updated_at=NOW(),published_at=$1 WHERE id=$2', [commit.rows[0].created_at, project.id]);
    await pruneProjectHistory(client, project.id, HISTORY_RETENTION);
    await client.query('COMMIT');
    res.json({ deployment: deployment.rows[0], url: `/sites/${encodeURIComponent(project.slug)}/` });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    respondApiError(req, res, error, 'Falha ao publicar o site.');
  } finally { client.release?.(); }
});

// Database connection settings. Neon provisioning is server-side; API credentials are never sent to the browser.
app.get('/api/projects/:id/database/connection', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const { rows } = await pool.query('SELECT id,project_id,name,provider,hostname,port,database_name,username,password_cipher,provider_project_id,provider_branch_id,connection_uri_cipher,pooled_uri_cipher,region_id,pg_version,created_at,updated_at FROM project_database_connections WHERE project_id=$1', [project.id]);
    if (!rows[0]) return res.json({ connection: null });
    const row = rows[0];
    let externalUrl = `postgresql://${encodeURIComponent(row.username)}:••••••@${row.hostname}:${row.port}/${encodeURIComponent(row.database_name)}`;
    let internalUrl = null;
    if (row.provider === 'neon' && row.connection_uri_cipher) {
      externalUrl = maskPostgresUri(decryptSecret(row.connection_uri_cipher));
      internalUrl = null;
    }
    res.json({ connection: {
      id: row.id, name: row.name, provider: row.provider, hostname: row.hostname, port: row.port,
      database: row.database_name, username: row.username, has_password: Boolean(row.password_cipher),
      internal_url: internalUrl, external_url: externalUrl,
      psql_command: row.provider === 'neon' && row.connection_uri_cipher
        ? `psql "${maskPostgresUri(decryptSecret(row.connection_uri_cipher))}"`
        : `psql "host=${row.hostname} port=${row.port} dbname=${row.database_name} user=${row.username} sslmode=require"`,
      region_id: row.region_id || '', pg_version: Number(row.pg_version || 0) || null,
      is_provisioned: Boolean(row.provider_project_id && row.connection_uri_cipher),
      connection_note: row.provider === 'neon' ? 'O Neon não disponibiliza URL privada interna neste modelo. A URL externa apresentada está mascarada por segurança; guarda a URL completa apresentada no momento da criação.' : 'Ligação externa guardada. A palavra-passe permanece protegida no servidor.'
    }});
  } catch { res.status(500).json({ error: 'Não foi possível carregar a configuração da ligação.' }); }
});
app.post('/api/projects/:id/database/connection', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const name = String(req.body.name || '').trim().slice(0,80);
    const provider = String(req.body.provider || 'external').trim().slice(0,40);
    const hostnameInput = String(req.body.hostname || '').trim().slice(0,255);
    const portInput = Number(req.body.port ?? 5432);
    const databaseName = String(req.body.database || '').trim().slice(0,120);
    const username = String(req.body.username || '').trim().slice(0,120);
    const password = String(req.body.password || '');
    if (!name || !hostnameInput || !databaseName || !username || !password) return res.status(400).json({ error: 'Preenche o nome, hostname, database, username e password válidos.' });
    if (!['external', 'render', 'neon', 'supabase', 'railway', 'other'].includes(provider)) return res.status(400).json({ error: 'Escolhe um fornecedor PostgreSQL válido.' });
    let hostname;
    let port;
    try {
      hostname = normalizePostgresHostname(hostnameInput);
      port = validatePostgresPort(portInput, { ports: POSTGRES_ALLOWED_PORTS });
    } catch {
      return res.status(400).json({ error: 'Hostname ou porta não permitidos. Usa um servidor PostgreSQL público e uma porta autorizada pelo administrador.' });
    }
    const encrypted = encryptSecret(password);
    const client = await pool.connect();
    let transactionStarted = false;
    try {
      await client.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
      transactionStarted = true;
      if (databaseConfigured) await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
      const owner = await client.query(`SELECT id FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NULL${databaseConfigured ? ' FOR UPDATE' : ''}`, [project.id, req.user.id]);
      if (!owner.rows?.[0]) {
        await client.query('ROLLBACK'); transactionStarted = false;
        return res.status(404).json({ error: 'Projeto não encontrado ou já não está disponível.', code: 'PROJECT_NOT_FOUND', request_id: req.requestId || null });
      }
      const reservation = (await client.query('SELECT state FROM neon_provision_reservations WHERE project_id=$1', [project.id])).rows[0];
      if (reservation && ['pending', 'cleanup_required'].includes(String(reservation.state))) {
        await client.query('ROLLBACK'); transactionStarted = false;
        return res.status(409).json({ error: 'A criação de uma base Neon está em curso ou precisa de reconciliação; não alteres a ligação enquanto isso não estiver resolvido.', code: 'NEON_PROVISION_IN_PROGRESS', request_id: req.requestId || null });
      }
      const current = (await client.query('SELECT provider_project_id FROM project_database_connections WHERE project_id=$1', [project.id])).rows[0];
      if (current?.provider_project_id) {
        await client.query('ROLLBACK'); transactionStarted = false;
        return res.status(409).json({ error: 'Este projecto já tem uma base Neon criada. Não vou substituir as credenciais da base existente por uma ligação manual.', code: 'PROJECT_DATABASE_EXISTS', request_id: req.requestId || null });
      }
      const { rows } = await client.query(`INSERT INTO project_database_connections(project_id,name,provider,hostname,port,database_name,username,password_cipher,provider_project_id,provider_branch_id,connection_uri_cipher,pooled_uri_cipher,region_id,pg_version)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'','','','','',16)
        ON CONFLICT(project_id) DO UPDATE SET name=EXCLUDED.name,provider=EXCLUDED.provider,hostname=EXCLUDED.hostname,port=EXCLUDED.port,database_name=EXCLUDED.database_name,username=EXCLUDED.username,password_cipher=EXCLUDED.password_cipher,provider_project_id='',provider_branch_id='',connection_uri_cipher='',pooled_uri_cipher='',region_id='',pg_version=16,updated_at=NOW()
        RETURNING id,name,provider,hostname,port,database_name,username`, [project.id,name,provider,hostname,port,databaseName,username,encrypted]);
      await client.query('COMMIT'); transactionStarted = false;
      res.json({ ok: true, connection: { ...rows[0], database: rows[0].database_name, has_password: true } });
    } catch (error) {
      if (transactionStarted) { try { await client.query('ROLLBACK'); } catch {} }
      throw error;
    } finally { client.release?.(); }
  } catch (error) { respondApiError(req, res, error, 'Não foi possível guardar a configuração da ligação.'); }
});
app.post('/api/projects/:id/database/connection/test', requireAuth, async (req, res) => {
  let client;
  let project;
  try {
    project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });

    // This operation can make the server open an outbound TCP connection. Apply a
    // shared, database-backed limit before doing DNS resolution or connecting.
    let rateLimit;
    try {
      rateLimit = await consumePostgresConnectionTestLimit(pool, {
        projectId: project.id,
        ip: String(getRequestClientIp(req)),
        now: Date.now(),
        perIpLimit: POSTGRES_CONNECTION_TEST_LIMITS.perIp,
        perProjectLimit: POSTGRES_CONNECTION_TEST_LIMITS.perProject,
        windowMs: POSTGRES_CONNECTION_TEST_LIMITS.windowMs
      });
    } catch (error) {
      logEvent('error', 'postgres_connection_test_limiter_unavailable', {
        request_id: req.requestId || null,
        project_id: Number(project.id),
        error_code: String(error?.code || 'unknown').slice(0, 40)
      });
      void sendOperationalAlert('postgres_connection_test_limiter_unavailable', { request_id: req.requestId || null });
      return respondApiError(req, res, error, 'O serviço de teste de ligações está temporariamente indisponível.', 503);
    }
    if (!rateLimit.allowed) {
      const retryAfter = Math.max(1, Math.ceil(rateLimit.retryAfterMs / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'Atingiste o limite de testes de ligação PostgreSQL. Tenta novamente mais tarde.', retry_after_seconds: retryAfter });
    }

    const { rows } = await pool.query('SELECT hostname,port,database_name,username,password_cipher,provider,connection_uri_cipher FROM project_database_connections WHERE project_id=$1', [project.id]);
    if (!rows[0]) return res.status(400).json({ error: 'Configura primeiro uma ligação PostgreSQL.' });
    const c = rows[0];
    let target;
    let credentials;
    if (c.provider === 'neon' && c.connection_uri_cipher) {
      // Do not pass a user-controllable URI to pg.Client. Parse it, resolve the
      // hostname, reject special/private destinations and pin the socket to one
      // validated public IP while preserving TLS hostname verification.
      const uri = decryptSecret(c.connection_uri_cipher);
      const details = parsePostgresUri(uri);
      target = await resolvePublicPostgresTarget(details.hostname, details.port, { ports: POSTGRES_ALLOWED_PORTS });
      const parsedUri = new URL(uri);
      credentials = {
        database: details.database,
        user: details.username,
        password: details.password,
        enableChannelBinding: parsedUri.searchParams.get('channel_binding') === 'require'
      };
    } else {
      target = await resolvePublicPostgresTarget(c.hostname, Number(c.port), { ports: POSTGRES_ALLOWED_PORTS });
      credentials = {
        database: c.database_name,
        user: c.username,
        password: decryptSecret(c.password_cipher)
      };
    }
    client = new Client(buildPinnedPostgresClientConfig(target, credentials, { ports: POSTGRES_ALLOWED_PORTS }));
    await client.connect();
    await client.query('SELECT 1');
    res.json({ ok:true, message:'Ligação PostgreSQL testada com sucesso.' });
  } catch (error) {
    if (isPostgresTargetSecurityError(error)) {
      logEvent('warn', 'postgres_connection_target_rejected', {
        request_id: req.requestId || null,
        project_id: project ? Number(project.id) : null,
        reason: String(error.reason || 'target_rejected').slice(0, 48)
      });
      return res.status(400).json({ error: 'Destino PostgreSQL bloqueado por segurança. Usa um hostname público válido, sem endereços privados ou locais, e uma porta autorizada.' });
    }
    respondApiError(req, res, error, 'Não foi possível ligar à base de dados. Confirma os dados da ligação e tenta novamente.', 502);
  } finally {
    if (client) await client.end().catch(() => {});
  }
});

app.get('/api/projects/:id/environment', requireAuth, async (req, res) => {
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'});
    const groups=await pool.query('SELECT id,name,created_at,updated_at FROM project_env_groups WHERE project_id=$1 ORDER BY name',[project.id]);
    const vars=await pool.query('SELECT * FROM project_env_vars WHERE project_id=$1 ORDER BY name',[project.id]);
    res.json({ groups:groups.rows, variables:vars.rows.map(safeEnvVariable) });
  } catch { res.status(500).json({error:'Não foi possível carregar as variáveis do ambiente.'}); }
});
app.post('/api/projects/:id/environment/groups', requireAuth, async (req,res)=>{
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'}); const name=String(req.body.name||'').trim().slice(0,80); if(!name)return res.status(400).json({error:'Indica o nome do grupo.'}); const {rows}=await pool.query('INSERT INTO project_env_groups(project_id,name) VALUES($1,$2) RETURNING *',[project.id,name]); res.json({group:rows[0]}); }
  catch(error){if(error.code==='23505')return res.status(409).json({error:'Já existe um grupo com esse nome.'});res.status(400).json({error:'Não foi possível criar o grupo.'});}
});
app.patch('/api/projects/:id/environment/groups/:groupId', requireAuth, async (req,res)=>{
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'}); const name=String(req.body.name||'').trim().slice(0,80); if(!name)return res.status(400).json({error:'Indica o nome do grupo.'}); const {rows}=await pool.query('UPDATE project_env_groups SET name=$1,updated_at=NOW() WHERE id=$2 AND project_id=$3 RETURNING *',[name,req.params.groupId,project.id]); if(!rows[0])return res.status(404).json({error:'Grupo não encontrado.'});res.json({group:rows[0]});}
  catch(error){if(error.code==='23505')return res.status(409).json({error:'Já existe um grupo com esse nome.'});res.status(400).json({error:'Não foi possível editar o grupo.'});}
});
app.delete('/api/projects/:id/environment/groups/:groupId', requireAuth, async (req,res)=>{
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'}); const {rows}=await pool.query('DELETE FROM project_env_groups WHERE id=$1 AND project_id=$2 RETURNING id',[req.params.groupId,project.id]); if(!rows[0])return res.status(404).json({error:'Grupo não encontrado.'});res.json({ok:true});}
  catch {res.status(500).json({error:'Não foi possível eliminar o grupo.'});}
});
app.post('/api/projects/:id/environment/variables', requireAuth, async (req,res)=>{
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'}); const name=String(req.body.name||'').trim(); const value=String(req.body.value??''); const groupId=req.body.group_id?Number(req.body.group_id):null; const isSecret=Boolean(req.body.is_secret) || isSensitiveEnvName(name); if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))return res.status(400).json({error:'O nome deve começar por letra ou _ e conter apenas letras, números e _.'}); if(!value)return res.status(400).json({error:'Indica o valor da variável.'}); if(groupId){const g=await pool.query('SELECT id FROM project_env_groups WHERE id=$1 AND project_id=$2',[groupId,project.id]);if(!g.rows[0])return res.status(400).json({error:'Grupo inválido.'});} const isSecretValue = databaseConfigured ? isSecret : (isSecret ? 1 : 0); const {rows}=await pool.query('INSERT INTO project_env_vars(project_id,group_id,name,value_cipher,is_secret) VALUES($1,$2,$3,$4,$5) RETURNING *',[project.id,groupId,name,encryptSecret(value),isSecretValue]);res.json({variable:safeEnvVariable(rows[0])});}
  catch(error){if(error.code==='23505')return res.status(409).json({error:'Já existe uma variável com esse nome.'});res.status(400).json({error:'Não foi possível criar a variável.'});}
});
app.put('/api/projects/:id/environment/variables/:variableId', requireAuth, async (req,res)=>{
  try { const project=await getProject(req.params.id,req.user.id); if(!project)return res.status(404).json({error:'Projeto não encontrado.'}); const name=String(req.body.name||'').trim(); const isSecret=Boolean(req.body.is_secret) || isSensitiveEnvName(name); const groupId=req.body.group_id?Number(req.body.group_id):null; if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))return res.status(400).json({error:'Nome de variável inválido.'}); const current=await pool.query('SELECT * FROM project_env_vars WHERE id=$1 AND project_id=$2',[req.params.variableId,project.id]); if(!current.rows[0])return res.status(404).json({error:'Variável não encontrada.'}); let cipher=current.rows[0].value_cipher; if(req.body.value) cipher=encryptSecret(String(req.body.value)); if(groupId){const g=await pool.query('SELECT id FROM project_env_groups WHERE id=$1 AND project_id=$2',[groupId,project.id]);if(!g.rows[0])return res.status(400).json({error:'Grupo inválido.'});} const isSecretValue = databaseConfigured ? isSecret : (isSecret ? 1 : 0); const {rows}=await pool.query('UPDATE project_env_vars SET name=$1,value_cipher=$2,is_secret=$3,group_id=$4,updated_at=NOW() WHERE id=$5 AND project_id=$6 RETURNING *',[name,cipher,isSecretValue,groupId,req.params.variableId,project.id]);res.json({variable:safeEnvVariable(rows[0])});}
  catch(error){if(error.code==='23505')return res.status(409).json({error:'Já existe uma variável com esse nome.'});res.status(400).json({error:'Não foi possível editar a variável.'});}
});
app.delete('/api/projects/:id/environment/variables/:variableId', requireAuth, async (req,res)=>{
  try {const project=await getProject(req.params.id,req.user.id);if(!project)return res.status(404).json({error:'Projeto não encontrado.'});const {rows}=await pool.query('DELETE FROM project_env_vars WHERE id=$1 AND project_id=$2 RETURNING id',[req.params.variableId,project.id]);if(!rows[0])return res.status(404).json({error:'Variável não encontrada.'});res.json({ok:true});}
  catch {res.status(500).json({error:'Não foi possível eliminar a variável.'});}
});

app.get('/api/projects/:id/database', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const db = await ensureProjectDatabase(project.id);
    const store = await getProjectDataStore(project.id);
    const connection = (await pool.query('SELECT provider,name,database_name,username,region_id,pg_version,provider_project_id,connection_uri_cipher FROM project_database_connections WHERE project_id=$1', [project.id])).rows[0] || null;
    const query = await pool.query('SELECT t.* FROM database_tables t WHERE t.database_id=$1 ORDER BY t.name', [db.id]);
    const tables = await Promise.all(query.rows.map(async table => {
      let count = 0;
      if (table.physical_ready && (store.external || databaseConfigured)) {
        const result = await store.executor.query(`SELECT COUNT(*)::int AS count FROM ${projectPhysicalTableRefFor(project.id, table.name, store.external)}`);
        count = Number(result.rows[0]?.count || 0);
      } else {
        const result = await pool.query('SELECT COUNT(*)::int AS count FROM database_records WHERE table_id=$1', [table.id]);
        count = Number(result.rows[0]?.count || 0);
      }
      return { ...table, record_count: count };
    }));
    const neon = connection?.provider === 'neon' && Boolean(connection.provider_project_id && connection.connection_uri_cipher);
    res.json({
      database: {
        id: db.id, project_id: db.project_id, name: neon ? connection.database_name : db.name,
        engine: neon ? 'Neon PostgreSQL' : (databaseConfigured ? 'PostgreSQL' : 'SQLite local'),
        schema_name: neon ? 'public' : (db.schema_name || projectSchemaName(project.id)),
        db_username: neon ? connection.username : (db.db_username || ''),
        has_connection: Boolean(neon || (db.db_username && db.db_password_cipher)),
        provider: neon ? 'neon' : (connection?.provider || 'managed'),
        region_id: neon ? connection.region_id : '', pg_version: neon ? Number(connection.pg_version) : null,
        provisioned_at: db.provisioned_at || null, created_at: db.created_at, updated_at: db.updated_at
      }, tables
    });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível carregar a base de dados.'); }
});


app.post('/api/projects/:id/database/provision', requireAuth, async (req, res) => {
  let reservationCreated = false;
  let reservedProjectId = null;
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.', code: 'PROJECT_NOT_FOUND', request_id: req.requestId || null });

    let rateDecision;
    try {
      rateDecision = await consumeResourceCreationLimit(pool, {
        action: 'neon-provision', userId: req.user.id, ip: getRequestClientIp(req),
        perUserLimit: RESOURCE_QUOTAS.neonCreatePerUserPerHour,
        perIpLimit: RESOURCE_QUOTAS.neonCreatePerIpPerHour,
        windowMs: RESOURCE_QUOTAS.creationWindowMs
      });
    } catch (error) {
      logEvent('error', 'neon_creation_limiter_unavailable', { request_id: req.requestId || null, error_code: String(error?.code || 'unknown').slice(0, 40) });
      void sendOperationalAlert('neon_creation_limiter_unavailable', { request_id: req.requestId || null });
      return respondApiError(req, res, error, 'O serviço de criação de bases está temporariamente indisponível.', 503);
    }
    if (!rateDecision.allowed) {
      const retry = Math.max(1, Math.ceil(rateDecision.retryAfterMs / 1000));
      res.setHeader('Retry-After', String(retry));
      return res.status(429).json({ error: 'Atingiste o limite de criação de bases de dados. Tenta novamente mais tarde.', code: 'NEON_CREATION_RATE_LIMITED', retry_after_seconds: retry, request_id: req.requestId || null });
    }

    await reserveNeonProvisionSlot(pool, project, req.user.id, RESOURCE_QUOTAS, { databaseConfigured });
    reservationCreated = true;
    reservedProjectId = project.id;
    let result;
    try {
      result = await createNeonProjectDatabase(project, req.body || {});
    } catch (error) {
      if (error?.neonCleanupRequired) {
        // Mark the local reservation as retained before trying the DB update. If
        // storage is unavailable, leave the pending row in place (fail-closed).
        reservationCreated = false;
        try {
          await pool.query("UPDATE neon_provision_reservations SET state='cleanup_required',provider_project_id=$2,updated_at=NOW() WHERE project_id=$1", [project.id, String(error.neonProjectId || '')]);
        } catch (reservationError) {
          logEvent('error', 'neon_cleanup_reservation_update_failed', { request_id: req.requestId || null, project_id: Number(project.id), error_code: String(reservationError?.code || 'unknown').slice(0, 40) });
          void sendOperationalAlert('neon_cleanup_reservation_update_failed', { project_id: Number(project.id) });
        }
      } else {
        try { await pool.query("UPDATE neon_provision_reservations SET state='failed',updated_at=NOW() WHERE project_id=$1", [project.id]); }
        catch (reservationError) { logEvent('warn', 'neon_failed_reservation_update_failed', { project_id: Number(project.id), error_code: String(reservationError?.code || 'unknown').slice(0, 40) }); }
        // Failed rows are an audit trail and do not count against quota.
        reservationCreated = false;
      }
      throw error;
    }
    // The provider resource and credentials are now persisted. If releasing the
    // reservation fails, still report success and downgrade it to non-counting
    // failed state where possible; an active database already exists.
    try {
      await pool.query("DELETE FROM neon_provision_reservations WHERE project_id=$1 AND state='pending'", [project.id]);
    } catch (releaseError) {
      logEvent('error', 'neon_success_reservation_release_failed', { request_id: req.requestId || null, project_id: Number(project.id), error_code: String(releaseError?.code || 'unknown').slice(0, 40) });
      void sendOperationalAlert('neon_success_reservation_release_failed', { project_id: Number(project.id) });
      try { await pool.query("UPDATE neon_provision_reservations SET state='failed',updated_at=NOW() WHERE project_id=$1 AND state='pending'", [project.id]); } catch {}
    }
    reservationCreated = false;
    res.status(201).json({ ok: true, database: result.database, connection: result.connection, quota: {
      neon_databases_per_user: RESOURCE_QUOTAS.neonDatabasesPerUser,
      neon_account_project_limit: RESOURCE_QUOTAS.neonAccountProjectLimit
    } });
  } catch (error) {
    if (reservationCreated && reservedProjectId !== null) {
      try { await pool.query("DELETE FROM neon_provision_reservations WHERE project_id=$1 AND state='pending'", [reservedProjectId]); }
      catch (cleanupError) { logEvent('error', 'neon_reservation_release_failed', { request_id: req.requestId || null, project_id: Number(reservedProjectId), error_code: String(cleanupError?.code || 'unknown').slice(0, 40) }); }
    }
    const missingConfiguration = /NEON_API_KEY|DATABASE_URL/i.test(String(error?.message || ''));
    const status = Number(error?.statusCode) || (missingConfiguration ? 503 : 502);
    const publicMessage = missingConfiguration
      ? 'O serviço de bases de dados não está devidamente configurado.'
      : status === 429 || status === 409
        ? String(error.message || 'O limite foi atingido.')
        : status === 503
          ? 'O serviço de criação de bases está temporariamente indisponível ou atingiu um limite.'
          : 'Não foi possível criar a base de dados do projeto.';
    respondApiError(req, res, error, publicMessage, status);
  }
});

app.post('/api/projects/:id/database/tables', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const name = safeName(req.body.name, 'tabela');
  if (name.startsWith('__lzw_')) return res.status(400).json({ error: 'O nome da tabela utiliza um prefixo reservado.' });
  let columns;
  try { columns = normalizeColumns(req.body.columns); }
  catch (error) { return res.status(400).json({ error: 'As colunas fornecidas são inválidas. Revê os nomes e tipos e tenta novamente.', code: 'INVALID_COLUMNS', request_id: req.requestId || null }); }
  const store = await getProjectDataStore(project.id);
  const client = await pool.connect();
  let table;
  try {
    await client.query('BEGIN');
    const db = await ensureProjectDatabase(project.id, client);
    const insert = await client.query('INSERT INTO database_tables(database_id,name,columns,physical_ready,public_read,public_insert) VALUES($1,$2,$3::jsonb,FALSE,FALSE,FALSE) RETURNING *', [db.id, name, JSON.stringify(columns)]);
    table = insert.rows[0];
    if (!store.external && databaseConfigured) {
      await createPhysicalTable(client, project.id, name, columns);
      const updated = await client.query('UPDATE database_tables SET physical_ready=TRUE,updated_at=NOW() WHERE id=$1 RETURNING *', [table.id]);
      table = updated.rows[0];
    }
    await client.query('UPDATE project_databases SET updated_at=NOW() WHERE id=$1', [db.id]);
    await client.query('COMMIT');
    if (store.external) {
      try {
        await createPhysicalTable(store.executor, project.id, name, columns, { external: true });
        const updated = await pool.query('UPDATE database_tables SET physical_ready=TRUE,updated_at=NOW() WHERE id=$1 RETURNING *', [table.id]);
        table = updated.rows[0];
      } catch (error) {
        await pool.query('DELETE FROM database_tables WHERE id=$1', [table.id]).catch(() => {});
        throw error;
      }
    }
    res.json({ table });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    if (error.code === '23505') return res.status(409).json({ error: 'Já existe uma tabela com esse nome.' });
    respondApiError(req, res, error, 'Não foi possível criar a tabela.', 500);
  } finally { client.release?.(); }
});

app.patch('/api/projects/:id/database/tables/:tableId/public-access', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const table = await getDbTable(req.params.tableId, project.id);
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const publicRead = Boolean(req.body.public_read);
    const publicInsert = Boolean(req.body.public_insert);
    const { rows } = await pool.query('UPDATE database_tables SET public_read=$1,public_insert=$2,updated_at=NOW() WHERE id=$3 RETURNING *', [publicRead, publicInsert, table.id]);
    res.json({ table: rows[0] });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível guardar as permissões públicas.'); }
});

app.delete('/api/projects/:id/database/tables/:tableId', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const table = await getDbTable(req.params.tableId, project.id);
  if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
  const store = await getProjectDataStore(project.id);
  const client = await pool.connect();
  try {
    if (table.physical_ready && store.external) {
      await store.executor.query(`DROP TABLE IF EXISTS ${projectPhysicalTableRefFor(project.id, table.name, true)}`);
      await pool.query('DELETE FROM database_tables WHERE id=$1', [table.id]);
    } else {
      await client.query('BEGIN');
      if (databaseConfigured && table.physical_ready) await client.query(`DROP TABLE IF EXISTS ${projectPhysicalTableRefFor(project.id, table.name, false)}`);
      await client.query('DELETE FROM database_tables WHERE id=$1', [table.id]);
      await client.query('COMMIT');
    }
    res.json({ ok: true });
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    respondApiError(req, res, error, 'Não foi possível eliminar a tabela.');
  } finally { client.release?.(); }
});

app.get('/api/projects/:id/database/tables/:tableId/records', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const table = await getDbTable(req.params.tableId, project.id);
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 200);
    const store = await getProjectDataStore(project.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const { rows } = await store.executor.query(`SELECT * FROM ${projectPhysicalTableRefFor(project.id, table.name, store.external)} ORDER BY "__lzw_id" DESC LIMIT $1`, [limit]);
      return res.json({ table, records: rows.map(row => physicalRowToRecord(row, parseColumnDefinitions(table.columns))) });
    }
    const { rows } = await pool.query('SELECT id,data,created_at,updated_at FROM database_records WHERE table_id=$1 ORDER BY created_at DESC LIMIT $2', [table.id, limit]);
    res.json({ table, records: rows });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível carregar os registos.'); }
});

app.post('/api/projects/:id/database/tables/:tableId/records', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const table = await getDbTable(req.params.tableId, project.id);
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const data = normalizeRecord(req.body.data, parseColumnDefinitions(table.columns));
    const store = await getProjectDataStore(project.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const record = await insertPhysicalRecord(store.executor, project.id, table, data, { external: store.external });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.json({ record });
    }
    const { rows } = await pool.query('INSERT INTO database_records(table_id,data) VALUES($1,$2::jsonb) RETURNING *', [table.id, JSON.stringify(data)]);
    await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
    res.json({ record: rows[0] });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível adicionar o registo.', 500); }
});

app.put('/api/projects/:id/database/tables/:tableId/records/:recordId', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const table = await getDbTable(req.params.tableId, project.id);
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const columns = parseColumnDefinitions(table.columns);
    const data = normalizeRecord(req.body.data, columns);
    const store = await getProjectDataStore(project.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const ref = projectPhysicalTableRefFor(project.id, table.name, store.external);
      const fields = columns.map(column => quotePgIdentifier(column.name));
      const values = columns.map(column => data[column.name] ?? null);
      const assignments = fields.map((field, index) => `${field}=$${index + 1}`);
      assignments.push('"__lzw_updated_at"=NOW()');
      values.push(Number(req.params.recordId));
      const { rows } = await store.executor.query(`UPDATE ${ref} SET ${assignments.join(',')} WHERE "__lzw_id"=$${values.length} RETURNING *`, values);
      if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.json({ record: physicalRowToRecord(rows[0], columns) });
    }
    const { rows } = await pool.query('UPDATE database_records SET data=$1::jsonb,updated_at=NOW() WHERE id=$2 AND table_id=$3 RETURNING *', [JSON.stringify(data), req.params.recordId, table.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
    res.json({ record: rows[0] });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível atualizar o registo.', 500); }
});

app.delete('/api/projects/:id/database/tables/:tableId/records/:recordId', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const table = await getDbTable(req.params.tableId, project.id);
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const store = await getProjectDataStore(project.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const { rows } = await store.executor.query(`DELETE FROM ${projectPhysicalTableRefFor(project.id, table.name, store.external)} WHERE "__lzw_id"=$1 RETURNING "__lzw_id"`, [Number(req.params.recordId)]);
      if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.json({ ok: true });
    }
    const { rows } = await pool.query('DELETE FROM database_records WHERE id=$1 AND table_id=$2 RETURNING id', [req.params.recordId, table.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
    res.json({ ok: true });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível eliminar o registo.'); }
});

app.get('/api/projects/:id/api-keys', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { rows } = await pool.query('SELECT id,label,token_hint,key_type,created_at,last_used_at FROM api_keys WHERE project_id=$1 ORDER BY created_at DESC', [project.id]);
  res.json({ keys: rows });
});
app.post('/api/projects/:id/api-keys', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const token = generateApiToken();
  const label = String(req.body.label || 'Chave principal').trim().slice(0, 60) || 'Chave principal';
  const keyType = req.body.key_type === 'publishable' ? 'publishable' : 'secret';
  const { rows } = await pool.query('INSERT INTO api_keys(project_id,label,token_hash,token_hint,key_type) VALUES($1,$2,$3,$4,$5) RETURNING id,label,token_hint,key_type,created_at', [project.id, label, hashToken(token), token.slice(-4), keyType]);
  res.json({ key: rows[0], token });
});
app.delete('/api/projects/:id/api-keys/:keyId', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { rows } = await pool.query('DELETE FROM api_keys WHERE id=$1 AND project_id=$2 RETURNING id', [req.params.keyId, project.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Chave não encontrada.' });
  res.json({ ok: true });
});

let publicApiRateLimitCleanupCounter = 0;
const PUBLIC_API_RATE_LIMITS = Object.freeze({
  perIp: boundedIntegerEnv('PUBLIC_API_RATE_LIMIT_PER_IP', 120, 1, 10000),
  perKey: boundedIntegerEnv('PUBLIC_API_RATE_LIMIT_PER_KEY', 600, 1, 100000),
  perProject: boundedIntegerEnv('PUBLIC_API_RATE_LIMIT_PER_PROJECT', 1200, 1, 200000),
  windowMs: boundedIntegerEnv('PUBLIC_API_RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000)
});
const PRIVATE_API_RATE_LIMITS = Object.freeze({
  perIp: boundedIntegerEnv('PRIVATE_API_RATE_LIMIT_PER_IP', 300, 1, 20000),
  perKey: boundedIntegerEnv('PRIVATE_API_RATE_LIMIT_PER_KEY', 3000, 1, 200000),
  perProject: boundedIntegerEnv('PRIVATE_API_RATE_LIMIT_PER_PROJECT', 6000, 1, 500000),
  windowMs: boundedIntegerEnv('PRIVATE_API_RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000)
});
async function allowProjectApiRequest(req, res) {
  const keyId = Number(req.apiKey?.id || 0);
  const projectId = Number(req.apiProject?.id || req.apiKey?.project_id || 0);
  const limits = req.apiKey?.key_type === 'publishable' ? PUBLIC_API_RATE_LIMITS : PRIVATE_API_RATE_LIMITS;
  const ip = getRequestClientIp(req).slice(0, 100);
  try {
    const decision = await consumePublicApiRateLimit(pool, {
      keyId,
      projectId,
      keyType: req.apiKey?.key_type,
      ip,
      now: Date.now(),
      perIpLimit: limits.perIp,
      perKeyLimit: limits.perKey,
      perProjectLimit: limits.perProject,
      windowMs: limits.windowMs
    });
    publicApiRateLimitCleanupCounter += 1;
    if (publicApiRateLimitCleanupCounter % 100 === 0) {
      void pruneExpiredApiRateLimits(pool, Date.now()).catch(error => {
        logEvent('warn', 'public_api_rate_limit_cleanup_failed', { error_code: String(error?.code || 'unknown').slice(0, 40) });
      });
    }
    if (!decision.allowed) {
      const retryAfter = Math.max(1, Math.ceil(decision.retryAfterMs / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({ error: 'Limite de pedidos da API atingido. Tenta novamente mais tarde.', code: 'RATE_LIMITED', rate_limit_scope: decision.scope, retry_after_seconds: retryAfter });
      return false;
    }
    return true;
  } catch (error) {
    logEvent('error', 'project_api_rate_limiter_unavailable', { request_id: req.requestId || null, error_code: String(error?.code || 'unknown').slice(0, 40) });
    void sendOperationalAlert('project_api_rate_limiter_unavailable', { request_id: req.requestId || null });
    respondApiError(req, res, error, 'O limitador da API está temporariamente indisponível.', 503);
    return false;
  }
}

async function requireProjectApiKey(req, res, next) {
  try {
    const project = await pool.query('SELECT * FROM projects WHERE slug=$1 AND trashed_at IS NULL', [req.params.slug]);
    if (!project.rows[0]) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const token = String(req.get('x-luza-key') || req.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!token) return res.status(401).json({ error: 'API key necessária.' });
    const key = await pool.query('SELECT id,project_id,key_type FROM api_keys WHERE project_id=$1 AND token_hash=$2', [project.rows[0].id, hashToken(token)]);
    if (!key.rows[0]) return res.status(401).json({ error: 'API key inválida.' });
    req.apiKey = key.rows[0];
    req.apiProject = project.rows[0];
    if (!(await allowProjectApiRequest(req, res))) return;
    // last_used_at is useful for operators, but writing it for every API call
    // creates avoidable write contention under load. Update at most once per 5m.
    const lastUsedThreshold = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    await pool.query('UPDATE api_keys SET last_used_at=NOW() WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < $2)', [req.apiKey.id, lastUsedThreshold]);
    next();
  } catch { res.status(500).json({ error: 'Erro ao validar a API key.' }); }
}

app.use('/v1', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-LUZA-KEY');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.get('/v1/:slug/:table', requireProjectApiKey, async (req, res) => {
  try {
    const db = await ensureProjectDatabase(req.apiProject.id);
    const table = (await pool.query('SELECT * FROM database_tables WHERE database_id=$1 AND name=$2', [db.id, safeName(req.params.table, '')])).rows[0];
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    if (req.apiKey.key_type === 'publishable' && !table.public_read) return res.status(403).json({ error: 'A leitura pública não está autorizada para esta tabela.' });
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 200);
    const store = await getProjectDataStore(req.apiProject.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const { rows } = await store.executor.query(`SELECT * FROM ${projectPhysicalTableRefFor(req.apiProject.id, table.name, store.external)} ORDER BY "__lzw_id" DESC LIMIT $1`, [limit]);
      return res.json({ project: req.apiProject.slug, table: table.name, columns: parseColumnDefinitions(table.columns), records: rows.map(row => physicalRowToRecord(row, parseColumnDefinitions(table.columns))) });
    }
    const { rows } = await pool.query('SELECT id,data,created_at,updated_at FROM database_records WHERE table_id=$1 ORDER BY created_at DESC LIMIT $2', [table.id, limit]);
    res.json({ project: req.apiProject.slug, table: table.name, columns: parseColumnDefinitions(table.columns), records: rows });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível consultar a API.'); }
});
app.post('/v1/:slug/:table', requireProjectApiKey, async (req, res) => {
  try {
    const db = await ensureProjectDatabase(req.apiProject.id);
    const table = (await pool.query('SELECT * FROM database_tables WHERE database_id=$1 AND name=$2', [db.id, safeName(req.params.table, '')])).rows[0];
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    if (req.apiKey.key_type === 'publishable' && !table.public_insert) return res.status(403).json({ error: 'A inserção pública não está autorizada para esta tabela.' });
    const data = normalizeRecord(req.body, parseColumnDefinitions(table.columns));
    const store = await getProjectDataStore(req.apiProject.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const record = await insertPhysicalRecord(store.executor, req.apiProject.id, table, data, { external: store.external });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.status(201).json({ record });
    }
    const { rows } = await pool.query('INSERT INTO database_records(table_id,data) VALUES($1,$2::jsonb) RETURNING *', [table.id, JSON.stringify(data)]);
    res.status(201).json({ record: rows[0] });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível criar o registo.', 500); }
});
app.put('/v1/:slug/:table/:recordId', requireProjectApiKey, async (req, res) => {
  try {
    if (req.apiKey.key_type === 'publishable') return res.status(403).json({ error: 'Uma chave pública não pode actualizar registos. Utiliza uma chave secreta apenas no servidor.' });
    const db = await ensureProjectDatabase(req.apiProject.id);
    const table = (await pool.query('SELECT * FROM database_tables WHERE database_id=$1 AND name=$2', [db.id, safeName(req.params.table, '')])).rows[0];
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const columns = parseColumnDefinitions(table.columns);
    const data = normalizeRecord(req.body, columns);
    const store = await getProjectDataStore(req.apiProject.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const fields = columns.map(column => quotePgIdentifier(column.name));
      const values = columns.map(column => data[column.name] ?? null);
      const assignments = fields.map((field, index) => `${field}=$${index + 1}`);
      assignments.push('"__lzw_updated_at"=NOW()');
      values.push(Number(req.params.recordId));
      const { rows } = await store.executor.query(`UPDATE ${projectPhysicalTableRefFor(req.apiProject.id, table.name, store.external)} SET ${assignments.join(',')} WHERE "__lzw_id"=$${values.length} RETURNING *`, values);
      if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.json({ record: physicalRowToRecord(rows[0], columns) });
    }
    const { rows } = await pool.query('UPDATE database_records SET data=$1::jsonb,updated_at=NOW() WHERE id=$2 AND table_id=$3 RETURNING *', [JSON.stringify(data), req.params.recordId, table.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
    res.json({ record: rows[0] });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível atualizar o registo.', 500); }
});
app.delete('/v1/:slug/:table/:recordId', requireProjectApiKey, async (req, res) => {
  try {
    if (req.apiKey.key_type === 'publishable') return res.status(403).json({ error: 'Uma chave pública não pode eliminar registos. Utiliza uma chave secreta apenas no servidor.' });
    const db = await ensureProjectDatabase(req.apiProject.id);
    const table = (await pool.query('SELECT * FROM database_tables WHERE database_id=$1 AND name=$2', [db.id, safeName(req.params.table, '')])).rows[0];
    if (!table) return res.status(404).json({ error: 'Tabela não encontrada.' });
    const store = await getProjectDataStore(req.apiProject.id);
    if (table.physical_ready && (store.external || databaseConfigured)) {
      const { rows } = await store.executor.query(`DELETE FROM ${projectPhysicalTableRefFor(req.apiProject.id, table.name, store.external)} WHERE "__lzw_id"=$1 RETURNING "__lzw_id"`, [Number(req.params.recordId)]);
      if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
      await pool.query('UPDATE database_tables SET updated_at=NOW() WHERE id=$1', [table.id]);
      return res.json({ ok: true });
    }
    const { rows } = await pool.query('DELETE FROM database_records WHERE id=$1 AND table_id=$2 RETURNING id', [req.params.recordId, table.id]);
    if (!rows[0]) return res.status(404).json({ error: 'Registo não encontrado.' });
    res.json({ ok: true });
  } catch (error) { respondApiError(req, res, error, 'Não foi possível eliminar o registo.'); }
});

function contentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return ({
    '.html':'text/html; charset=utf-8','.htm':'text/html; charset=utf-8','.css':'text/css; charset=utf-8',
    '.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.cjs':'text/javascript; charset=utf-8',
    '.json':'application/json; charset=utf-8','.map':'application/json; charset=utf-8','.xml':'application/xml; charset=utf-8',
    '.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif',
    '.webp':'image/webp','.avif':'image/avif','.ico':'image/x-icon','.bmp':'image/bmp','.pdf':'application/pdf',
    '.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.otf':'font/otf','.wasm':'application/wasm',
    '.mp3':'audio/mpeg','.wav':'audio/wav','.ogg':'audio/ogg','.mp4':'video/mp4','.webm':'video/webm',
    '.txt':'text/plain; charset=utf-8','.md':'text/markdown; charset=utf-8','.csv':'text/csv; charset=utf-8',
    '.yaml':'application/yaml; charset=utf-8','.yml':'application/yaml; charset=utf-8','.webmanifest':'application/manifest+json; charset=utf-8'
  })[ext] || 'text/plain; charset=utf-8';
}
async function servePublished(req, res) {
  try {
    const slug = String(req.params.slug || '');
    const requested = Array.isArray(req.params.splat) ? req.params.splat.join('/') : String(req.params.splat || '');
    const requestedPath = cleanPath(requested || 'index.html') || 'index.html';
    if (isPrivatePublishedPath(requestedPath)) return res.status(404).send('Ficheiro não encontrado.');
    const { rows } = await pool.query(`SELECT d.*,p.id AS project_id FROM deployments d JOIN projects p ON p.id=d.project_id WHERE p.slug=$1 AND p.trashed_at IS NULL AND d.status='LIVE' ORDER BY d.id DESC LIMIT 1`, [slug]);
    const deployment = rows[0];
    if (!deployment) return res.status(404).send('Site ainda não foi publicado.');
    const commitResult = await pool.query('SELECT snapshot FROM commits WHERE id=$1 AND project_id=$2', [deployment.commit_id, deployment.project_id]);
    const snapshot = commitResult.rows[0]?.snapshot || {};
    let file = snapshot[requestedPath];
    if (file === undefined && !path.extname(requestedPath)) file = snapshot['index.html'];
    if (file === undefined) return res.status(404).send('Ficheiro não encontrado.');
    res.setHeader('X-LuzawWeb-Site', slug);
    res.setHeader('Content-Security-Policy', "sandbox allow-scripts allow-forms allow-popups; default-src * data: blob: 'unsafe-inline' 'unsafe-eval'");
    res.setHeader('Cache-Control', 'no-store');
    const binary = parseBinaryContent(file);
    if (binary) {
      const safeMime = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(binary.mime) ? binary.mime : contentType(requestedPath).split(';')[0];
      res.setHeader('Content-Type', safeMime);
      return res.send(Buffer.from(binary.base64, 'base64'));
    }
    let publishedContent = String(file);
    if (/\.html?$/i.test(requestedPath)) {
      const envScript = `<script src="/sites/${encodeURIComponent(slug)}/__luza_env.js"></script>`;
      if (/<head\b[^>]*>/i.test(publishedContent)) publishedContent = publishedContent.replace(/<head\b[^>]*>/i, match => `${match}\n${envScript}`);
      else publishedContent = `${envScript}\n${publishedContent}`;
    }
    return res.type(contentType(requestedPath)).send(publishedContent);
  } catch { res.status(500).send('Erro ao abrir o site publicado.'); }
}
app.get('/sites/:slug/__luza_env.js', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT p.id AS project_id FROM projects p JOIN deployments d ON d.project_id=p.id WHERE p.slug=$1 AND p.trashed_at IS NULL AND d.status='LIVE' ORDER BY d.id DESC LIMIT 1", [req.params.slug]);
    if (!rows[0]) return res.status(404).type('text/plain').send('Site ainda não foi publicado.');
    const result = await pool.query('SELECT name,value_cipher FROM project_env_vars WHERE project_id=$1 AND is_secret=FALSE ORDER BY name', [rows[0].project_id]);
    // Filter defensively by name as well, covering any older record that was saved as public.
    const values = Object.fromEntries(result.rows.filter(row => !isSensitiveEnvName(row.name)).map(row => [row.name, decryptSecret(row.value_cipher)]));
    const payload = JSON.stringify(values).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
    res.setHeader('Cache-Control', 'no-store');
    res.type('application/javascript; charset=utf-8').send(`window.LUZA_ENV = Object.freeze(${payload});`);
  } catch { res.status(500).type('text/plain').send('Não foi possível carregar as variáveis públicas.'); }
});
app.get('/sites/:slug', (req, res) => res.redirect(302, `/sites/${encodeURIComponent(req.params.slug)}/`));
app.get('/sites/:slug/', servePublished);
app.get('/sites/:slug/*splat', servePublished);

// Keep API failures consistently JSON-shaped and never return raw database/provider errors.
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Rota API não encontrada.', code: 'NOT_FOUND', request_id: req.requestId || null });
});
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const candidate = Number(error?.status || error?.statusCode);
  const status = Number.isInteger(candidate) && candidate >= 400 && candidate <= 499 ? candidate : 500;
  const message = status === 400
    ? 'Pedido inválido. Verifica o formato dos dados enviados.'
    : status === 413
      ? 'O pedido excede o tamanho permitido.'
      : status === 415
        ? 'Formato do pedido não suportado.'
        : status >= 500
          ? 'Ocorreu um erro interno. Tenta novamente mais tarde.'
          : 'Não foi possível processar o pedido.';
  return respondApiError(req, res, error, message, status);
});

// Netlify serves the public/ directory as static assets. The Function only handles
// /api, /v1 and /sites rewrites, while local Node deployments keep serving the SPA here.
if (!process.env.NETLIFY) {
  app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));
  app.get('*splat', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
}

export { app, initDb };

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMainModule) {
  const startHttpServer = (message) => {
    const httpServer = app.listen(PORT, '0.0.0.0', () => logEvent('info', 'server_listening', { port: PORT, database_configured: databaseConfigured, message }));
    let shutdownStarted = false;
    const shutdown = signal => {
      if (shutdownStarted) return;
      shutdownStarted = true;
      logEvent('info', 'graceful_shutdown_started', { signal });
      const forceTimer = setTimeout(() => {
        logEvent('error', 'graceful_shutdown_timeout', { signal });
        process.exit(1);
      }, 10000);
      forceTimer.unref();
      httpServer.close(async () => {
        const projectPools = [...projectDataPools.values()].map(entry => entry?.pool).filter(Boolean);
        await Promise.allSettled(projectPools.map(projectPool => projectPool.end()));
        try { await pool?.end?.(); } catch {}
        clearTimeout(forceTimer);
        logEvent('info', 'graceful_shutdown_complete', { signal });
        process.exitCode = 0;
      });
    };
    process.once('SIGTERM', () => shutdown('SIGTERM'));
    process.once('SIGINT', () => shutdown('SIGINT'));
    return httpServer;
  };

  initDb().then(() => {
    startHttpServer('ready');
  }).catch(error => {
    logEvent('error', 'database_init_failed', { error_code: String(error?.code || error?.name || 'unknown').slice(0, 40) });
    if (databaseConfigured || process.env.NODE_ENV === 'production' || process.env.NETLIFY) {
      logEvent('error', 'server_start_aborted', { reason: 'database_or_configuration_unavailable' });
      process.exit(1);
    }
    startHttpServer('database_not_configured_local_development');
  });
}
