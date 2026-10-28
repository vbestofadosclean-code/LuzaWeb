import path from 'node:path';

export function parsePostgresConnectionUrl(raw, { label = 'PostgreSQL', defaultSslMode = 'require' } = {}) {
  let url;
  try { url = new URL(String(raw || '')); }
  catch { throw new Error(`${label}: URL de ligação inválida.`); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) throw new Error(`${label}: só são aceites URLs PostgreSQL.`);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const portText = url.port || '5432';
  const port = Number(portText);
  const database = decodeURIComponent(url.pathname.replace(/^\/+/, '').split('/')[0] || '');
  const user = decodeURIComponent(url.username || '');
  const password = decodeURIComponent(url.password || '');
  if (!host || !database || !user || !password) throw new Error(`${label}: a URL tem de incluir host, base de dados, utilizador e palavra-passe.`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${label}: porta PostgreSQL inválida.`);
  const sslMode = String(url.searchParams.get('sslmode') || defaultSslMode).toLowerCase();
  const allowedSslModes = new Set(['require', 'verify-ca', 'verify-full', 'prefer', 'allow', 'disable']);
  if (!allowedSslModes.has(sslMode)) throw new Error(`${label}: sslmode inválido.`);
  if (sslMode === 'disable' && process.env.NODE_ENV === 'production') throw new Error(`${label}: ligações sem TLS não são permitidas em produção.`);
  return { url, host, port, database, user, password, sslMode };
}

export function cleanChildEnv(source = process.env) {
  const env = { ...source };
  const exactSecrets = new Set([
    'DATABASE_URL', 'PRODUCTION_DATABASE_URL', 'RESTORE_DATABASE_URL', 'SOURCE_DATABASE_URL',
    'PROJECT_PRODUCTION_DATABASE_URL', 'PROJECT_RESTORE_DATABASE_URL', 'SECRET_ENCRYPTION_KEY',
    'LEGACY_SECRET_ENCRYPTION_KEY', 'JWT_SECRET', 'NEON_API_KEY', 'BACKUP_ENCRYPTION_PASSPHRASE',
    'BACKUP_FILE', 'RESTORE_CONFIRM', 'RESTORE_WORK_DIR', 'DATABASE_URL_INTERNAL'
  ]);
  for (const key of Object.keys(env)) {
    if (exactSecrets.has(key) || /^LUZAWEB_/i.test(key) || /(?:^|_)DATABASE_URL$|(?:^|_)(?:SECRET|ENCRYPTION_KEY|PASSPHRASE|API_KEY)$/i.test(key) || /^PG(?:HOST|PORT|DATABASE|USER|PASSWORD|PASSFILE|SERVICE|SERVICEFILE|SSLMODE|SSLROOTCERT|SSLCERT|SSLKEY|CONNECT_TIMEOUT|APPNAME|OPTIONS)$/i.test(key)) delete env[key];
  }
  return env;
}

export function pgClientEnv(raw, { label = 'PostgreSQL', defaultSslMode = 'require' } = {}) {
  const parsed = parsePostgresConnectionUrl(raw, { label, defaultSslMode });
  const env = cleanChildEnv();
  env.PGHOST = parsed.host;
  env.PGPORT = String(parsed.port);
  env.PGDATABASE = parsed.database;
  env.PGUSER = parsed.user;
  env.PGPASSWORD = parsed.password;
  env.PGPASSFILE = process.platform === 'win32' ? 'NUL' : '/dev/null';
  env.PGSERVICEFILE = process.platform === 'win32' ? 'NUL' : '/dev/null';
  env.PGSSLMODE = parsed.sslMode;
  env.PGCONNECT_TIMEOUT = String(Math.max(1, Math.min(60, Number(parsed.url.searchParams.get('connect_timeout') || 15))));
  env.PGAPPNAME = 'luzaweb-backup-recovery';
  const mapping = [['sslrootcert', 'PGSSLROOTCERT'], ['sslcert', 'PGSSLCERT'], ['sslkey', 'PGSSLKEY'], ['application_name', 'PGAPPNAME'], ['options', 'PGOPTIONS']];
  for (const [param, variable] of mapping) if (parsed.url.searchParams.has(param)) env[variable] = parsed.url.searchParams.get(param);
  return { parsed, env };
}

export function safeBundleRelativePath(input) {
  if (typeof input !== 'string' || !input || input.includes('\0') || input.includes('\\')) return false;
  if (path.posix.isAbsolute(input) || path.win32.isAbsolute(input)) return false;
  const normalized = path.posix.normalize(input);
  return normalized !== '.' && normalized !== '..' && !normalized.startsWith('../') && normalized === input;
}

export function safeSlug(input) {
  return String(input || 'project').normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'project';
}
