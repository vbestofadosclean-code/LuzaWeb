import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import { SQLitePool } from './local-db.js';

const { Pool, Client } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const COOKIE_NAME = 'luzaweb_token';

const databaseConfigured = Boolean(process.env.DATABASE_URL);
const localDatabasePath = path.join(__dirname, '.data', 'luzaweb.sqlite');

const pool = databaseConfigured
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DB_SSL_REJECT_UNAUTHORIZED === 'false' ? { rejectUnauthorized: false } : undefined,
      max: Number(process.env.PG_POOL_MAX || (process.env.NETLIFY ? 1 : 10)),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    })
  : new SQLitePool(localDatabasePath);

// Separate Neon pools keep each project's data in its own real PostgreSQL database.
const projectDataPools = new Map();

if (!databaseConfigured) {
  console.warn(`PostgreSQL não configurado. O LUZAWEB está a usar a base local persistente: ${localDatabasePath}`);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const BINARY_FILE_PREFIX = 'LUZAWEB_BINARY_V1|';
const MAX_FILE_BYTES = 300_000;
const MAX_FILES_PER_PROJECT = 120;
const MAX_PROJECT_BYTES = 5_000_000;
const DB_COLUMN_TYPES = new Set(['text', 'number', 'boolean', 'date']);

const authAttempts = new Map();
function authRateLimit(req, res, next) {
  const ip = String(req.ip || 'unknown');
  const now = Date.now();
  const item = authAttempts.get(ip) || { count: 0, reset: now + 10 * 60 * 1000 };
  if (now > item.reset) {
    item.count = 0;
    item.reset = now + 10 * 60 * 1000;
  }
  if (item.count >= 20) return res.status(429).json({ error: 'Demasiadas tentativas. Tenta novamente dentro de alguns minutos.' });
  item.count += 1;
  authAttempts.set(ip, item);
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [key, item] of authAttempts.entries()) if (now > item.reset) authAttempts.delete(key);
}, 15 * 60 * 1000).unref();

function slugify(value) {
  const slug = String(value || '')
    .trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return slug || `site-${Date.now()}`;
}
function cleanPath(input) {
  let value = String(input || '').trim().replace(/\\/g, '/');
  value = value.split('/').filter(part => part && part !== '.' && part !== '..').join('/');
  return value.slice(0, 180);
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
  return /^(?:\.env(?:\..*)?|\.npmrc|\.yarnrc(?:\.yml)?|id_rsa|id_ed25519|authorized_keys|known_hosts)$/i.test(name) ||
    /\.(?:pem|key|p12|pfx|sqlite|sqlite3|db|dump|bak|backup|secret|secrets)$/i.test(name);
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
    await client.query(`GRANT USAGE, CREATE ON SCHEMA ${quotePgIdentifier(schemaName)} TO ${quotePgIdentifier(roleName)}`);
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
  if (process.env.NEON_ORG_ID && url.pathname === '/api/v2/projects') url.searchParams.set('org_id', process.env.NEON_ORG_ID);
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
    throw new Error(`O Neon não conseguiu concluir a operação (${String(detail).slice(0, 220)}). Verifica a chave API, organização, região e limites da conta.`);
  }
  return payload;
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
    const created = await neonApiRequest('/projects', { method: 'POST', body: { project: { name: `${name}-luzaweb-${project.id}`.slice(0, 60), region_id: regionId, pg_version: pgVersion } } });
    const neonProject = created.project || created.projects?.[0] || {};
    createdProjectId = String(neonProject.id || created.project_id || created.id || '');
    if (!createdProjectId) throw new Error('O Neon criou uma resposta sem identificador de projecto; não é possível concluir a ligação automaticamente.');

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
    // If creation failed halfway, do not leave a provider project behind when cleanup is possible.
    if (createdProjectId) {
      try { await neonApiRequest(`/projects/${encodeURIComponent(createdProjectId)}`, { method: 'DELETE' }); } catch {}
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
    if (!cached || cached.fingerprint !== fingerprint) {
      if (cached?.pool) await cached.pool.end().catch(() => {});
      const projectPool = new Pool({ connectionString: uri, max: 1, idleTimeoutMillis: 10000, connectionTimeoutMillis: 10000 });
      cached = { fingerprint, pool: projectPool };
      projectDataPools.set(Number(projectId), cached);
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
async function migrateLogicalTablesToPostgres() {
  // A transaction-scoped table lock serializes cold-start migrations across
  // Netlify Function instances without relying on session advisory locks.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
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
    await client.query('COMMIT');
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch {}
    throw new Error(`Não foi possível migrar as tabelas existentes para PostgreSQL: ${error.message}`);
  } finally {
    client.release?.();
  }
}

function signToken(user) { return jwt.sign({ id: user.id, name: user.name, email: user.email, username: user.username || '', bio: user.bio || '', location: user.location || '', website: user.website || '', phone: user.phone || '', created_at: user.created_at || null }, JWT_SECRET, { expiresIn: '7d' }); }
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
function requireAuth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sessão expirada.' });
  req.user = user;
  next();
}

function encryptSecret(value) {
  const key = crypto.createHash('sha256').update(JWT_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(value ?? ''), 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${encrypted.toString('base64')}`;
}
function decryptSecret(value) {
  if (!value) return '';
  try {
    const [iv, tag, data] = String(value).split('.');
    const key = crypto.createHash('sha256').update(JWT_SECRET).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
  } catch { throw new Error('Não foi possível descodificar um segredo. Confirma se JWT_SECRET não foi alterado.'); }
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
  if (!dbInitializationPromise) dbInitializationPromise = (async () => {
    if (process.env.NETLIFY && !databaseConfigured) {
      throw new Error('DATABASE_URL é obrigatória no Netlify. Configura a ligação PostgreSQL interna do LuzaWeb nas variáveis do site.');
    }
    if (process.env.NETLIFY && (JWT_SECRET === 'dev-only-change-me' || Buffer.byteLength(JWT_SECRET, 'utf8') < 32 || /replace-with|change-me|your-secret|dev-only/i.test(JWT_SECRET))) {
      throw new Error('JWT_SECRET é obrigatória no Netlify, deve ter pelo menos 32 bytes e não pode ser um valor de exemplo. Mantém o mesmo segredo entre publicações.');
    }
    const schemaFile = databaseConfigured ? 'schema.sql' : 'schema.sqlite.sql';
    const schema = await readSchemaFile(schemaFile);
    if (typeof pool.exec === 'function') pool.exec(schema);
    else await pool.query(schema);

    // Apply additive migrations to existing databases without changing user data.
    const profileColumns = [
      ['username', "TEXT NOT NULL DEFAULT ''"],
      ['bio', "TEXT NOT NULL DEFAULT ''"],
      ['location', "TEXT NOT NULL DEFAULT ''"],
      ['website', "TEXT NOT NULL DEFAULT ''"],
      ['phone', "TEXT NOT NULL DEFAULT ''"]
    ];
    if (databaseConfigured) {
      for (const [column, definition] of profileColumns) {
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
      }
      for (const [tableName, columns] of [
        ['project_databases', [['schema_name', "TEXT NOT NULL DEFAULT ''"], ['db_username', "TEXT NOT NULL DEFAULT ''"], ['db_password_cipher', "TEXT NOT NULL DEFAULT ''"], ['provisioned_at', 'TIMESTAMPTZ']]],
        ['project_database_connections', [['provider_project_id', "TEXT NOT NULL DEFAULT ''"], ['provider_branch_id', "TEXT NOT NULL DEFAULT ''"], ['connection_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['pooled_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['region_id', "TEXT NOT NULL DEFAULT ''"], ['pg_version', 'INTEGER NOT NULL DEFAULT 16']]],
        ['database_tables', [['physical_ready', 'BOOLEAN NOT NULL DEFAULT FALSE'], ['public_read', 'BOOLEAN NOT NULL DEFAULT FALSE'], ['public_insert', 'BOOLEAN NOT NULL DEFAULT FALSE']]],
        ['api_keys', [['key_type', "TEXT NOT NULL DEFAULT 'secret' CHECK (key_type IN ('secret','publishable'))"]]]
      ]) {
        for (const [column, definition] of columns) {
          await pool.query(`ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS ${column} ${definition}`);
        }
      }
    } else {
      const info = await pool.query('PRAGMA table_info(users)');
      const existing = new Set(info.rows.map(row => row.name));
      for (const [column, definition] of profileColumns) {
        if (!existing.has(column)) await pool.query(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
      }
      const additiveColumns = [
        ['project_databases', [['schema_name', "TEXT NOT NULL DEFAULT ''"], ['db_username', "TEXT NOT NULL DEFAULT ''"], ['db_password_cipher', "TEXT NOT NULL DEFAULT ''"], ['provisioned_at', 'TEXT']], 'project_databases'],
        ['project_database_connections', [['provider_project_id', "TEXT NOT NULL DEFAULT ''"], ['provider_branch_id', "TEXT NOT NULL DEFAULT ''"], ['connection_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['pooled_uri_cipher', "TEXT NOT NULL DEFAULT ''"], ['region_id', "TEXT NOT NULL DEFAULT ''"], ['pg_version', 'INTEGER NOT NULL DEFAULT 16']], 'project_database_connections'],
        ['database_tables', [['physical_ready', 'INTEGER NOT NULL DEFAULT 0'], ['public_read', 'INTEGER NOT NULL DEFAULT 0'], ['public_insert', 'INTEGER NOT NULL DEFAULT 0']], 'database_tables'],
        ['api_keys', [['key_type', "TEXT NOT NULL DEFAULT 'secret'"]], 'api_keys']
      ];
      for (const [tableName, columns] of additiveColumns) {
        const tableInfo = await pool.query(`PRAGMA table_info(${tableName})`);
        const existingColumns = new Set(tableInfo.rows.map(row => row.name));
        for (const [column, definition] of columns) {
          if (!existingColumns.has(column)) await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${column} ${definition}`);
        }
      }
    }
    await pool.query("UPDATE project_databases SET schema_name='luza_project_' || project_id WHERE COALESCE(schema_name,'')=''");
    if (databaseConfigured) await migrateLogicalTablesToPostgres();
    return true;
  })();
  return dbInitializationPromise;
}
async function getProject(projectId, userId, { includeTrash = false } = {}) {
  const sql = includeTrash
    ? 'SELECT * FROM projects WHERE id=$1 AND user_id=$2'
    : 'SELECT * FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NULL';
  const { rows } = await pool.query(sql, [projectId, userId]);
  return rows[0] || null;
}
async function projectSize(projectId, extraPath = null, extraBytes = 0) {
  const { rows } = await pool.query('SELECT COALESCE(SUM(size_bytes),0)::int AS total FROM files WHERE project_id=$1 AND ($2::text IS NULL OR path<>$2)', [projectId, extraPath]);
  return Number(rows[0].total) + Number(extraBytes);
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

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, app: 'LUZAWEB', database: databaseConfigured ? 'connected' : 'local' });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(503).json({ ok: false, app: 'LUZAWEB', database: 'unavailable', error: databaseConfigured ? 'Não foi possível ligar ao PostgreSQL.' : 'Não foi possível abrir a base local do LUZAWEB.' });
  }
});

app.post('/api/auth/register', authRateLimit, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6) {
      return res.status(400).json({ error: 'Preenche nome, email válido e palavra-passe com pelo menos 6 caracteres.' });
    }
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,username,bio,location,website,phone,created_at', [name, email, hash]);
    setAuthCookie(res, rows[0]);
    res.json({ user: rows[0] });
  } catch (error) {
    console.error('Registration failed:', error.message);
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
    if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Email ou palavra-passe inválidos.' });
    setAuthCookie(res, rows[0]);
    res.json({ user: { id: rows[0].id, name: rows[0].name, email: rows[0].email, username: rows[0].username || '', bio: rows[0].bio || '', location: rows[0].location || '', website: rows[0].website || '', phone: rows[0].phone || '', created_at: rows[0].created_at } });
  } catch { res.status(500).json({ error: 'Não foi possível iniciar sessão.' }); }
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
    const { rows } = await pool.query('UPDATE users SET name=$1,email=$2,username=$3,bio=$4,location=$5,website=$6,phone=$7 WHERE id=$8 RETURNING id,name,email,username,bio,location,website,phone,created_at', [name, email, username, bio, location, website, phone, req.user.id]);
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
    if (next.length < 6) return res.status(400).json({ error: 'A nova palavra-passe precisa de pelo menos 6 caracteres.' });
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
    if (!rows[0] || !(await bcrypt.compare(current, rows[0].password_hash))) return res.status(401).json({ error: 'A palavra-passe atual está incorreta.' });
    const hash = await bcrypt.hash(next, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, req.user.id]);
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
  if (!name) return res.status(400).json({ error: 'Indica um nome para o projeto.' });
  const base = slugify(name);
  let slug = base;
  for (let n = 2; ; n++) {
    const found = await pool.query('SELECT 1 FROM projects WHERE slug=$1', [slug]);
    if (!found.rowCount) break;
    slug = `${base}-${n}`;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const prior = await client.query('SELECT COUNT(*)::int AS count FROM projects WHERE user_id=$1', [req.user.id]);
    const isFirstProject = Number(prior.rows[0]?.count || 0) === 0;
    const { rows } = await client.query('INSERT INTO projects(user_id,name,slug,description) VALUES($1,$2,$3,$4) RETURNING *', [req.user.id, name, slug, description]);
    if (isFirstProject) await seedProject(rows[0].id, client);
    await ensureProjectDatabase(rows[0].id, client);
    await client.query('COMMIT');
    res.json({ project: rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Não foi possível criar o projeto.' });
  } finally { client.release(); }
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const [files, commits, deployments, folders] = await Promise.all([
      pool.query('SELECT id,path,content,size_bytes,updated_at FROM files WHERE project_id=$1 ORDER BY path', [project.id]),
      pool.query('SELECT id,message,created_at FROM commits WHERE project_id=$1 ORDER BY created_at DESC LIMIT 30', [project.id]),
      pool.query('SELECT id,commit_id,status,message,created_at,finished_at FROM deployments WHERE project_id=$1 ORDER BY created_at DESC LIMIT 30', [project.id]),
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

app.delete('/api/projects/:id', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  await pool.query('UPDATE projects SET trashed_at=NOW(),updated_at=NOW() WHERE id=$1', [project.id]);
  res.json({ ok: true });
});

app.get('/api/trash', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id,name,slug,description,created_at,updated_at,published_at,trashed_at FROM projects WHERE user_id=$1 AND trashed_at IS NOT NULL ORDER BY trashed_at DESC`, [req.user.id]);
    res.json({ projects: rows });
  } catch { res.status(500).json({ error: 'Não foi possível carregar a lixeira.' }); }
});
app.post('/api/trash/:id/restore', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id, { includeTrash: true });
  if (!project || !project.trashed_at) return res.status(404).json({ error: 'Item não encontrado na lixeira.' });
  await pool.query('UPDATE projects SET trashed_at=NULL,updated_at=NOW() WHERE id=$1', [project.id]);
  res.json({ ok: true });
});
app.delete('/api/trash/:id', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id, { includeTrash: true });
  if (!project || !project.trashed_at) return res.status(404).json({ error: 'Item não encontrado na lixeira.' });
  await pool.query('DELETE FROM projects WHERE id=$1', [project.id]);
  res.json({ ok: true });
});

app.post('/api/projects/:id/folders', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const folderPath = cleanPath(req.body.path);
  if (!folderPath || folderPath.length > 180) return res.status(400).json({ error: 'Indica um nome de pasta válido.' });
  try {
    const parts = folderPath.split('/');
    let partial = '';
    const folderPaths = [];
    for (const part of parts) { partial = partial ? `${partial}/${part}` : part; folderPaths.push(partial); }
    for (const itemPath of folderPaths) {
      const fileConflict = await pool.query('SELECT 1 FROM files WHERE project_id=$1 AND path=$2 LIMIT 1', [project.id, itemPath]);
      if (fileConflict.rowCount) return res.status(409).json({ error: 'Já existe um ficheiro no caminho dessa pasta.' });
    }
    for (const itemPath of folderPaths) {
      await pool.query('INSERT INTO project_folders(project_id,path) VALUES($1,$2) ON CONFLICT(project_id,path) DO NOTHING', [project.id, itemPath]);
    }
    const { rows } = await pool.query('SELECT id,path,created_at FROM project_folders WHERE project_id=$1 AND path=$2', [project.id, folderPath]);
    await pool.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    res.json({ folder: rows[0] });
  } catch { res.status(500).json({ error: 'Não foi possível criar a pasta.' }); }
});

app.patch('/api/projects/:id/files/:fileId/path', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const fileId = Number(req.params.fileId);
  const newPath = cleanPath(req.body.path);
  if (!newPath || newPath.length > 180) return res.status(400).json({ error: 'Indica um destino válido.' });
  try {
    const existingFile = await pool.query('SELECT id,path,content,size_bytes,updated_at FROM files WHERE project_id=$1 AND id=$2', [project.id, fileId]);
    if (!existingFile.rows[0]) return res.status(404).json({ error: 'Ficheiro não encontrado.' });
    if (existingFile.rows[0].path === newPath) return res.json({ file: existingFile.rows[0] });
    const [conflict, folderConflict, childPathConflict] = await Promise.all([
      pool.query('SELECT 1 FROM files WHERE project_id=$1 AND path=$2 AND id<>$3 LIMIT 1', [project.id, newPath, fileId]),
      pool.query('SELECT 1 FROM project_folders WHERE project_id=$1 AND path=$2 LIMIT 1', [project.id, newPath]),
      pool.query("SELECT 1 FROM files WHERE project_id=$1 AND id<>$3 AND SUBSTR(path,1,LENGTH($2)+1)=($2 || '/') LIMIT 1", [project.id, newPath, fileId])
    ]);
    if (conflict.rowCount || folderConflict.rowCount || childPathConflict.rowCount) return res.status(409).json({ error: 'Já existe um ficheiro ou pasta com esse nome no destino.' });
    const { rows } = await pool.query('UPDATE files SET path=$1,updated_at=NOW() WHERE project_id=$2 AND id=$3 RETURNING id,path,content,size_bytes,updated_at', [newPath, project.id, fileId]);
    await pool.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    res.json({ file: rows[0] });
  } catch { res.status(500).json({ error: 'Não foi possível mover o ficheiro.' }); }
});

app.post('/api/projects/:id/files', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const filePath = cleanPath(req.body.path);
    const content = String(req.body.content ?? '');
    if (!filePath || !allowedFile(filePath)) return res.status(400).json({ error: 'Indica um caminho de ficheiro válido.' });
    if (storedContentBytes(content) > MAX_FILE_BYTES) return res.status(413).json({ error: 'Ficheiro demasiado grande (máximo 300 KB).' });
    const count = await pool.query('SELECT COUNT(*)::int AS count FROM files WHERE project_id=$1 AND path<>$2', [project.id, filePath]);
    const exists = await pool.query('SELECT 1 FROM files WHERE project_id=$1 AND path=$2', [project.id, filePath]);
    if (!exists.rowCount && Number(count.rows[0].count) >= MAX_FILES_PER_PROJECT) return res.status(400).json({ error: `Limite de ${MAX_FILES_PER_PROJECT} ficheiros por projeto.` });
    const total = await projectSize(project.id, filePath, storedContentBytes(content));
    if (total > MAX_PROJECT_BYTES) return res.status(400).json({ error: 'O projeto ultrapassaria o limite de 5 MB.' });
    const { rows } = await pool.query(`
      INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4)
      ON CONFLICT(project_id,path) DO UPDATE SET content=EXCLUDED.content,size_bytes=EXCLUDED.size_bytes,updated_at=NOW()
      RETURNING id,path,content,size_bytes,updated_at
    `, [project.id, filePath, content, storedContentBytes(content)]);
    await pool.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    res.json({ file: rows[0] });
  } catch { res.status(500).json({ error: 'Não foi possível guardar o ficheiro.' }); }
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
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const message = String(req.body.message || 'Atualização do projeto').trim().slice(0, 120) || 'Atualização do projeto';
    const fileRows = await pool.query('SELECT path,content FROM files WHERE project_id=$1 ORDER BY path', [project.id]);
    if (!fileRows.rows.some(file => file.path === 'index.html')) return res.status(400).json({ error: 'O projeto precisa de um ficheiro index.html na raiz antes do commit.' });
    const snapshot = Object.fromEntries(fileRows.rows.map(file => [file.path, file.content]));
    const { rows } = await pool.query('INSERT INTO commits(project_id,message,snapshot) VALUES($1,$2,$3::jsonb) RETURNING id,message,created_at', [project.id, message, JSON.stringify(snapshot)]);
    await pool.query('UPDATE projects SET updated_at=NOW() WHERE id=$1', [project.id]);
    res.json({ commit: rows[0] });
  } catch { res.status(500).json({ error: 'Não foi possível criar o commit.' }); }
});
app.post('/api/projects/:id/commits/:commitId/restore', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const { rows } = await pool.query('SELECT * FROM commits WHERE id=$1 AND project_id=$2', [req.params.commitId, project.id]);
  const commit = rows[0];
  if (!commit) return res.status(404).json({ error: 'Commit não encontrado.' });
  const entries = Object.entries(commit.snapshot || {});
  const totalBytes = entries.reduce((sum, [, content]) => sum + storedContentBytes(String(content ?? '')), 0);
  if (entries.length > MAX_FILES_PER_PROJECT || totalBytes > MAX_PROJECT_BYTES) return res.status(400).json({ error: 'O commit excede os limites atuais do projeto.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM files WHERE project_id=$1', [project.id]);
    for (const [filePath, content] of entries) {
      if (!allowedFile(filePath)) continue;
      const clean = cleanPath(filePath);
      await client.query('INSERT INTO files(project_id,path,content,size_bytes) VALUES($1,$2,$3,$4)', [project.id, clean, String(content ?? ''), storedContentBytes(String(content ?? ''))]);
    }
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
  const fileRows = await pool.query('SELECT path,content FROM files WHERE project_id=$1 ORDER BY path', [project.id]);
  const index = fileRows.rows.find(file => file.path === 'index.html');
  if (!index) return res.status(400).json({ error: 'Adiciona um ficheiro index.html (com esse nome exacto) na raiz do projecto antes de publicar.' });
  const snapshot = Object.fromEntries(fileRows.rows.map(file => [file.path, file.content]));
  if (Buffer.byteLength(index.content) > MAX_FILE_BYTES) return res.status(400).json({ error: 'O index.html é demasiado grande.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const commit = await client.query('INSERT INTO commits(project_id,message,snapshot) VALUES($1,$2,$3::jsonb) RETURNING id,created_at', [project.id, 'Publicação automática', JSON.stringify(snapshot)]);
    const deployment = await client.query('INSERT INTO deployments(project_id,commit_id,status,message,finished_at) VALUES($1,$2,$3,$4,NOW()) RETURNING *', [project.id, commit.rows[0].id, 'LIVE', 'Publicação concluída e disponível online.']);
    await client.query('UPDATE projects SET updated_at=NOW(),published_at=$1 WHERE id=$2', [commit.rows[0].created_at, project.id]);
    await client.query('COMMIT');
    res.json({ deployment: deployment.rows[0], url: `/sites/${encodeURIComponent(project.slug)}/` });
  } catch {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Falha ao publicar o site.' });
  } finally { client.release(); }
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
    const current = (await pool.query('SELECT provider_project_id FROM project_database_connections WHERE project_id=$1', [project.id])).rows[0];
    if (current?.provider_project_id) return res.status(409).json({ error: 'Este projecto já tem uma base Neon criada. Não vou substituir as credenciais da base existente por uma ligação manual.' });
    const name = String(req.body.name || '').trim().slice(0,80);
    const provider = String(req.body.provider || 'external').trim().slice(0,40);
    const hostname = String(req.body.hostname || '').trim().slice(0,255);
    const port = Number(req.body.port || 5432);
    const databaseName = String(req.body.database || '').trim().slice(0,120);
    const username = String(req.body.username || '').trim().slice(0,120);
    const password = String(req.body.password || '');
    if (!name || !hostname || !databaseName || !username || !password || !Number.isInteger(port) || port < 1 || port > 65535) return res.status(400).json({ error: 'Preenche o nome, hostname, porta, database, username e password válidos.' });
    const encrypted = encryptSecret(password);
    const { rows } = await pool.query(`INSERT INTO project_database_connections(project_id,name,provider,hostname,port,database_name,username,password_cipher,provider_project_id,provider_branch_id,connection_uri_cipher,pooled_uri_cipher,region_id,pg_version)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,'','','','','',16)
      ON CONFLICT(project_id) DO UPDATE SET name=EXCLUDED.name,provider=EXCLUDED.provider,hostname=EXCLUDED.hostname,port=EXCLUDED.port,database_name=EXCLUDED.database_name,username=EXCLUDED.username,password_cipher=EXCLUDED.password_cipher,provider_project_id='',provider_branch_id='',connection_uri_cipher='',pooled_uri_cipher='',region_id='',pg_version=16,updated_at=NOW()
      RETURNING id,name,provider,hostname,port,database_name,username`, [project.id,name,provider,hostname,port,databaseName,username,encrypted]);
    res.json({ ok: true, connection: { ...rows[0], database: rows[0].database_name, has_password: true } });
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível guardar a configuração.' }); }
});
app.post('/api/projects/:id/database/connection/test', requireAuth, async (req, res) => {
  let client;
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const { rows } = await pool.query('SELECT hostname,port,database_name,username,password_cipher,provider,connection_uri_cipher FROM project_database_connections WHERE project_id=$1', [project.id]);
    if (!rows[0]) return res.status(400).json({ error: 'Configura primeiro uma ligação PostgreSQL.' });
    const c = rows[0];
    if (c.provider === 'neon' && c.connection_uri_cipher) {
      client = new Client({ connectionString: decryptSecret(c.connection_uri_cipher), connectionTimeoutMillis: 10000 });
    } else {
      client = new Client({ host:c.hostname, port:Number(c.port), database:c.database_name, user:c.username, password:decryptSecret(c.password_cipher), ssl:{rejectUnauthorized:true}, connectionTimeoutMillis:7000 });
    }
    await client.connect(); await client.query('SELECT 1');
    res.json({ ok:true, message:'Ligação PostgreSQL testada com sucesso.' });
  } catch (error) { res.status(400).json({ ok:false, error: `Não foi possível ligar à base de dados: ${String(error.message || 'erro de ligação').slice(0,220)}` }); }
  finally { if (client) await client.end().catch(()=>{}); }
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
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível carregar a base de dados.' }); }
});

app.post('/api/projects/:id/database/provision', requireAuth, async (req, res) => {
  try {
    const project = await getProject(req.params.id, req.user.id);
    if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
    const result = await createNeonProjectDatabase(project, req.body || {});
    res.status(201).json({ ok: true, database: result.database, connection: result.connection });
  } catch (error) {
    const message = error.message || 'Não foi possível criar a base de dados do projecto.';
    const status = /NEON_API_KEY|DATABASE_URL|região|versão PostgreSQL|nome deve|já tem uma base/i.test(message) ? 400 : 502;
    res.status(status).json({ error: message });
  }
});

app.post('/api/projects/:id/database/tables', requireAuth, async (req, res) => {
  const project = await getProject(req.params.id, req.user.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado.' });
  const name = safeName(req.body.name, 'tabela');
  if (name.startsWith('__lzw_')) return res.status(400).json({ error: 'O nome da tabela utiliza um prefixo reservado.' });
  let columns;
  try { columns = normalizeColumns(req.body.columns); }
  catch (error) { return res.status(400).json({ error: error.message }); }
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
    res.status(400).json({ error: error.message || 'Não foi possível criar a tabela.' });
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
  } catch (error) { res.status(400).json({ error: error.message || 'Não foi possível guardar as permissões públicas.' }); }
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
    res.status(500).json({ error: error.message || 'Não foi possível eliminar a tabela.' });
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
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível carregar os registos.' }); }
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
  } catch (error) { res.status(400).json({ error: error.message || 'Não foi possível adicionar o registo.' }); }
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
  } catch (error) { res.status(400).json({ error: error.message || 'Não foi possível atualizar o registo.' }); }
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
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível eliminar o registo.' }); }
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

const publicApiAttempts = new Map();
function allowPublicApiRequest(req, res) {
  const keyId = Number(req.apiKey?.id || 0);
  const ip = String(req.ip || 'unknown');
  const now = Date.now();
  const bucketKey = `${keyId}:${ip}`;
  const item = publicApiAttempts.get(bucketKey) || { count: 0, reset: now + 60_000 };
  if (now > item.reset) { item.count = 0; item.reset = now + 60_000; }
  item.count += 1;
  publicApiAttempts.set(bucketKey, item);
  if (publicApiAttempts.size > 5000) {
    for (const [key, value] of publicApiAttempts) if (now > value.reset) publicApiAttempts.delete(key);
  }
  if (item.count > 120) { res.status(429).json({ error: 'Limite de pedidos da chave pública atingido. Tenta novamente dentro de um minuto.' }); return false; }
  return true;
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
    if (req.apiKey.key_type === 'publishable' && !allowPublicApiRequest(req, res)) return;
    await pool.query('UPDATE api_keys SET last_used_at=NOW() WHERE id=$1', [req.apiKey.id]);
    req.apiProject = project.rows[0];
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
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível consultar a API.' }); }
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
  } catch (error) { res.status(400).json({ error: error.message || 'Não foi possível criar o registo.' }); }
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
  } catch (error) { res.status(400).json({ error: error.message || 'Não foi possível actualizar o registo.' }); }
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
  } catch (error) { res.status(500).json({ error: error.message || 'Não foi possível eliminar o registo.' }); }
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
    const { rows } = await pool.query(`SELECT d.*,p.id AS project_id FROM deployments d JOIN projects p ON p.id=d.project_id WHERE p.slug=$1 AND p.trashed_at IS NULL AND d.status='LIVE' ORDER BY d.created_at DESC LIMIT 1`, [slug]);
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
    const { rows } = await pool.query("SELECT p.id AS project_id FROM projects p JOIN deployments d ON d.project_id=p.id WHERE p.slug=$1 AND p.trashed_at IS NULL AND d.status='LIVE' ORDER BY d.created_at DESC LIMIT 1", [req.params.slug]);
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

// Netlify serves the public/ directory as static assets. The Function only handles
// /api, /v1 and /sites rewrites, while local Node deployments keep serving the SPA here.
if (!process.env.NETLIFY) {
  app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));
  app.get('*splat', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
}

export { app, initDb };

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMainModule) {
  initDb().then(() => {
    app.listen(PORT, '0.0.0.0', () => console.log(`LUZAWEB listening on ${PORT}`));
  }).catch(error => {
    console.error('Database init failed:', error.message);
    if (databaseConfigured) {
      console.error('O servidor não iniciou porque o PostgreSQL não respondeu. Verifica DATABASE_URL, SSL e disponibilidade da base.');
      process.exit(1);
    }
    app.listen(PORT, '0.0.0.0', () => console.log(`LUZAWEB listening on ${PORT} (database not configured)`));
  });
}
