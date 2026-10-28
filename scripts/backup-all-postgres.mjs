import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { Pool } from 'pg';
import { decryptSecret } from '../secret-crypto.js';
import { encryptBackupFile, decryptBackupFile, validateBackupPassphrase, createPrivateTempDir } from './backup-crypto.mjs';
import { cleanChildEnv, pgClientEnv, parsePostgresConnectionUrl, safeSlug, safeBundleRelativePath } from './backup-utils.mjs';

const MAX_COMMAND_MS = Math.max(60_000, Math.min(3_600_000, Number(process.env.BACKUP_COMMAND_TIMEOUT_MS || 1_800_000)));
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
const backupRoot = path.resolve(process.env.BACKUP_DIR || './backups');
const keepDays = Number(process.env.BACKUP_KEEP_DAYS || 30);
const passphrase = validateBackupPassphrase(process.env.BACKUP_ENCRYPTION_PASSPHRASE);
const databaseUrl = String(process.env.DATABASE_URL || '');
const internalDbConfig = parsePostgresConnectionUrl(databaseUrl, { label: 'DATABASE_URL', defaultSslMode: 'require' });
if (!['require', 'verify-ca', 'verify-full'].includes(internalDbConfig.sslMode)) throw new Error('DATABASE_URL tem de exigir TLS (sslmode=require, verify-ca ou verify-full).');
if (!Number.isInteger(keepDays) || keepDays < 1 || keepDays > 3650) throw new Error('BACKUP_KEEP_DAYS deve ser um inteiro entre 1 e 3650.');

const workRoot = await createPrivateTempDir('luzaweb-full-backup-');
const bundleDir = path.join(workRoot, 'luzaweb-bundle');
const tarPath = path.join(workRoot, 'luzaweb-bundle.tar.gz');
const finalPath = path.join(backupRoot, `luzaweb-full-${stamp}-${process.pid}.lzwbackup`);
const encryptedTempPath = `${finalPath}.tmp`;
let failed = true;

function runCommand(command, args, { env = cleanChildEnv(), timeoutMs = MAX_COMMAND_MS, allowStdout = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', allowStdout ? 'pipe' : 'ignore', 'pipe'], windowsHide: true });
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stderr.on('data', chunk => { if (stderr.length < 4000) stderr += chunk.toString().slice(0, 4000 - stderr.length); });
    let stdout = '';
    if (allowStdout) child.stdout.on('data', chunk => { if (stdout.length < 200_000) stdout += chunk.toString().slice(0, 200_000 - stdout.length); });
    child.on('error', error => { clearTimeout(timer); reject(new Error(`${command} não está disponível ou não pode ser executado.`)); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) {
        const timedOut = child.signal === 'SIGKILL';
        const diagnostic = stderr.replace(/postgres(?:ql)?:\/\/[^\s'"<>]+/gi, '[URL PostgreSQL ocultada]');
        reject(new Error(`${command} terminou com código ${code}${timedOut ? ' (timeout)' : ''}. ${diagnostic.trim().slice(0, 350)}`));
      } else resolve({ stdout });
    });
  });
}

function sha256(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function sqlLiteral(value) { return `'${String(value).replace(/'/g, "''")}'`; }
async function hashFile(filePath) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}
async function resolveVersionedPgTool(tool, major, label) {
  const versioned = `/usr/lib/postgresql/${major}/bin/${tool}`;
  try { await fs.access(versioned); return versioned; } catch {}
  const result = await runCommand(tool, ['--version'], { timeoutMs: 10000, allowStdout: true });
  const match = /PostgreSQL\)\s+(\d+)/i.exec(result.stdout);
  const installedMajor = match ? Number(match[1]) : NaN;
  if (installedMajor !== major) throw new Error(`${label}: é necessário o cliente PostgreSQL ${major}; instala pg_dump/pg_restore dessa versão.`);
  return tool;
}

function poolTlsOptions(uri) {
  const url = new URL(uri);
  const hasExplicitTlsOptions = ['sslmode', 'sslrootcert', 'sslcert', 'sslkey'].some(key => url.searchParams.has(key));
  return hasExplicitTlsOptions ? {} : { ssl: { rejectUnauthorized: true } };
}

async function readDatabaseVersion(uri, label) {
  const pool = new Pool({ connectionString: uri, ...poolTlsOptions(uri), max: 1, connectionTimeoutMillis: 10000, idleTimeoutMillis: 5000, application_name: 'luzaweb-backup-version-check' });
  try {
    const { rows } = await pool.query("SELECT current_setting('server_version') AS server_version, current_setting('server_version_num')::int AS server_version_num");
    const versionNum = Number(rows[0]?.server_version_num);
    const major = Math.floor(versionNum / 10000);
    if (!Number.isInteger(major) || major < 10) throw new Error(`${label}: não foi possível determinar a versão PostgreSQL de origem.`);
    return { major, version: String(rows[0]?.server_version || major) };
  } finally { await pool.end(); }
}

async function dumpDatabase(uri, destination, label, { snapshot = null } = {}) {
  const { parsed, env } = pgClientEnv(uri, { label, defaultSslMode: 'require' });
  if (!['require', 'verify-ca', 'verify-full'].includes(parsed.sslMode)) throw new Error(`${label}: o backup exige sslmode=require, verify-ca ou verify-full.`);
  const serverVersion = await readDatabaseVersion(uri, label);
  const pgDumpTool = await resolveVersionedPgTool('pg_dump', serverVersion.major, label);
  const pgRestoreTool = await resolveVersionedPgTool('pg_restore', serverVersion.major, label);
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const dumpArgs = [
    '--no-password', '--no-owner', '--no-privileges', '--format=custom', '--quote-all-identifiers',
    '--lock-wait-timeout=30s', ...(snapshot ? [`--snapshot=${snapshot}`] : []), '--file', destination
  ];
  await runCommand(pgDumpTool, dumpArgs, { env });
  const stat = await fs.stat(destination);
  if (!stat.isFile() || stat.size < 100) throw new Error(`${label}: pg_dump produziu um ficheiro vazio ou inválido.`);
  await runCommand(pgRestoreTool, ['--list', destination]);
  await fs.chmod(destination, 0o600).catch(() => {});
  return { bytes: stat.size, sha256: await hashFile(destination), database_name: parsed.database, postgres_major_version: serverVersion.major, postgres_server_version: serverVersion.version };
}

async function openInventorySnapshot() {
  const pool = new Pool({ connectionString: databaseUrl, ...poolTlsOptions(databaseUrl), options: '-c search_path=public', max: 1, connectionTimeoutMillis: 10000, idleTimeoutMillis: 5000, application_name: 'luzaweb-backup-inventory' });
  const client = await pool.connect();
  let open = false;
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    open = true;
    const { rows: snapshotRows } = await client.query('SELECT pg_export_snapshot() AS snapshot');
    const snapshot = String(snapshotRows[0]?.snapshot || '');
    if (!/^\d+-\d+-\d+$/.test(snapshot)) throw new Error('PostgreSQL não devolveu um identificador de snapshot válido; backup cancelado.');
    const managed = await client.query(`
      SELECT p.id AS project_id, p.slug AS project_slug,
             c.provider, c.provider_project_id, c.provider_branch_id,
             c.connection_uri_cipher, c.hostname, c.database_name, c.pg_version
      FROM project_database_connections c
      JOIN projects p ON p.id=c.project_id
      WHERE c.provider='neon'
      ORDER BY p.id
    `);
    const unmanaged = await client.query(`
      SELECT p.id AS project_id, p.slug AS project_slug, c.provider
      FROM project_database_connections c
      JOIN projects p ON p.id=c.project_id
      WHERE COALESCE(c.provider,'') <> 'neon' AND COALESCE(c.hostname,'') <> ''
      ORDER BY p.id
    `);
    const roles = await client.query(`
      SELECT project_id, COALESCE(schema_name,'') AS schema_name,
             COALESCE(db_username,'') AS db_username,
             COALESCE(db_password_cipher,'') AS db_password_cipher,
             provisioned_at
      FROM project_databases
      WHERE COALESCE(db_username,'') <> '' OR COALESCE(db_password_cipher,'') <> '' OR provisioned_at IS NOT NULL
      ORDER BY project_id
    `);
    let closed = false;
    return {
      inventory: { managed: managed.rows, unmanaged: unmanaged.rows, roles: roles.rows, snapshot },
      close: async () => {
        if (closed) return;
        closed = true;
        try { await client.query('COMMIT'); }
        finally { client.release(); await pool.end(); }
      },
      abort: async () => {
        if (closed) return;
        closed = true;
        try { if (open) await client.query('ROLLBACK'); }
        finally { client.release(); await pool.end(); }
      }
    };
  } catch (error) {
    try { if (open) await client.query('ROLLBACK'); } catch {}
    client.release();
    await pool.end();
    throw error;
  }
}

async function verifyTarArchive(filePath) {
  const { stdout } = await runCommand('tar', ['-tzf', filePath], { allowStdout: true, timeoutMs: 120_000 });
  const names = stdout.split(/\r?\n/).filter(Boolean);
  if (!names.length || names.some(name => !safeBundleRelativePath(name.replace(/\/$/, '')) || !(name === 'luzaweb-bundle' || name.startsWith('luzaweb-bundle/')))) {
    throw new Error('O arquivo de backup contém caminhos inesperados; operação cancelada.');
  }
}

async function pruneOldEncryptedBackups() {
  const expireBefore = Date.now() - keepDays * 24 * 60 * 60 * 1000;
  for (const entry of await fs.readdir(backupRoot, { withFileTypes: true })) {
    if (!entry.isFile() || !/^luzaweb-full-\d{8}T\d{6}Z-\d+\.lzwbackup$/.test(entry.name)) continue;
    const target = path.join(backupRoot, entry.name);
    const stat = await fs.lstat(target);
    if (stat.isSymbolicLink() || stat.mtimeMs >= expireBefore) continue;
    await fs.rm(target, { force: true });
    await fs.rm(`${target}.sha256`, { force: true });
  }
}

try {
  for (const tool of ['pg_dump', 'pg_restore', 'tar']) {
    await runCommand(tool, ['--version'], { timeoutMs: 10_000, allowStdout: true });
  }
  await fs.mkdir(backupRoot, { recursive: true, mode: 0o700 });
  if (backupRoot === process.cwd() || backupRoot === path.parse(backupRoot).root) throw new Error('BACKUP_DIR deve ser uma pasta dedicada, não a raiz nem a pasta do projeto.');
  const rootStat = await fs.lstat(backupRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('BACKUP_DIR tem de ser uma pasta real, não um link simbólico.');
  await fs.chmod(backupRoot, 0o700).catch(() => {});
  await fs.mkdir(bundleDir, { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(bundleDir, 'database'), { mode: 0o700 });
  await fs.mkdir(path.join(bundleDir, 'project-databases'), { mode: 0o700 });

  const snapshotHandle = await openInventorySnapshot();
  const { inventory } = snapshotHandle;
  let snapshotClosed = false;
  const databaseEntries = [];
  const internalPath = path.join(bundleDir, 'database', 'internal.dump');
  let internal;
  try {
    internal = await dumpDatabase(databaseUrl, internalPath, 'Base interna LuzaWeb', { snapshot: inventory.snapshot });
    await snapshotHandle.close();
    snapshotClosed = true;
  } finally {
    if (!snapshotClosed) await snapshotHandle.abort().catch(() => {});
  }
  databaseEntries.push({ kind: 'internal', file: 'database/internal.dump', database_name: internal.database_name, postgres_major_version: internal.postgres_major_version, postgres_server_version: internal.postgres_server_version, bytes: internal.bytes, sha256: internal.sha256 });

  for (const row of inventory.managed) {
    const id = String(row.project_id);
    const slug = safeSlug(row.project_slug);
    const providerProjectId = String(row.provider_project_id || '').trim();
    const cipher = String(row.connection_uri_cipher || '').trim();
    if (!providerProjectId || !cipher) throw new Error(`Projeto LuzaWeb ${id} tem uma ligação Neon incompleta. O backup total foi cancelado para não omitir dados.`);
    const uri = decryptSecret(cipher);
    const parsed = parsePostgresConnectionUrl(uri, { label: `Base Neon do projeto ${id}`, defaultSslMode: 'require' });
    if (!parsed.host.toLowerCase().endsWith('.neon.tech')) throw new Error(`A ligação identificada como Neon do projeto ${id} não aponta para um hostname *.neon.tech; backup cancelado por segurança.`);
    if (parsed.sslMode === 'disable' || parsed.sslMode === 'allow' || parsed.sslMode === 'prefer') throw new Error(`A ligação Neon do projeto ${id} não exige TLS de forma segura; backup cancelado.`);
    const file = `project-databases/project-${id}-${slug}.dump`;
    const dumpPath = path.join(bundleDir, file);
    const result = await dumpDatabase(uri, dumpPath, `Base Neon do projeto ${id}`);
    databaseEntries.push({
      kind: 'neon-project', project_id: Number(row.project_id), project_slug: String(row.project_slug),
      neon_project_id: providerProjectId, neon_branch_id: String(row.provider_branch_id || ''),
      postgres_major_version: result.postgres_major_version, postgres_server_version: result.postgres_server_version,
      file, database_name: result.database_name, bytes: result.bytes, sha256: result.sha256
    });
  }

  // pg_dump deliberately omits cluster-wide roles. Recreate only the known
  // per-project login roles from the internal metadata so a full recovery can
  // restore application access. This plaintext script lives only in the private
  // temporary bundle and is encrypted before leaving this process.
  const roleStatements = ['-- Sensitive recovery material. Run only on the dedicated recovery PostgreSQL cluster.', ''];
  for (const row of inventory.roles) {
    const projectId = Number(row.project_id);
    if (!Number.isSafeInteger(projectId) || projectId < 1) throw new Error('Metadados de role de projeto inválidos; backup total cancelado.');
    const roleName = `lzw_project_${projectId}`;
    const schemaName = `luza_project_${projectId}`;
    if (row.schema_name && row.schema_name !== schemaName) throw new Error(`O projeto ${projectId} tem um schema inesperado; backup total cancelado para exigir reconciliação.`);
    if (!row.db_password_cipher) throw new Error(`O projeto ${projectId} está provisionado mas não tem password cifrada; backup total cancelado.`);
    if (row.db_username && !new RegExp(`^${roleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:\\.[A-Za-z0-9_-]+)?$`).test(String(row.db_username))) {
      throw new Error(`O nome de login registado para o projeto ${projectId} não corresponde à role esperada; backup total cancelado.`);
    }
    const clearPassword = decryptSecret(row.db_password_cipher);
    const roleLiteral = sqlLiteral(roleName);
    const passwordLiteral = sqlLiteral(clearPassword);
    roleStatements.push(`DO $luzaweb_role$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${roleLiteral}) THEN
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5', ${roleLiteral}, ${passwordLiteral});
  ELSE
    EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5', ${roleLiteral}, ${passwordLiteral});
  END IF;
END
$luzaweb_role$;
`);
  }
  const rolesFile = 'database/project-roles.sql';
  const rolesPath = path.join(bundleDir, rolesFile);
  await fs.writeFile(rolesPath, `${roleStatements.join('\n')}\n`, { mode: 0o600, flag: 'wx' });
  const rolesFileInfo = { file: rolesFile, role_count: inventory.roles.length, sha256: await hashFile(rolesPath), bytes: (await fs.stat(rolesPath)).size };

  const manifest = {
    format_version: 1,
    product: 'LuzaWeb V1',
    backup_type: 'full-postgres-encrypted-bundle',
    created_at: new Date().toISOString(),
    internal_postgres_server_version: internal.postgres_server_version,
    databases: databaseEntries,
    supporting_files: [rolesFileInfo],
    external_connections_not_included: inventory.unmanaged.map(row => ({ project_id: Number(row.project_id), project_slug: String(row.project_slug), provider: String(row.provider || 'external') })),
    notes: [
      'The internal dump contains LuzaWeb users, project files, snapshots, settings and encrypted connection/secret metadata.',
      'database/project-roles.sql contains sensitive cleartext project-role passwords. It is covered by the encrypted bundle and must only be applied on a dedicated recovery PostgreSQL cluster; never publish or share an extracted plaintext bundle.',
      'Managed Neon databases are dumped separately. Restore each Neon dump to a newly provisioned, empty recovery database.',
      'External databases not managed by LuzaWeb are listed but are not backed up by this bundle.',
      'Databases are captured sequentially, not as one distributed transaction; application writes can occur between dump timestamps.'
    ]
  };
  await fs.writeFile(path.join(bundleDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  const checksumEntries = [];
  for (const item of databaseEntries) checksumEntries.push(`${item.sha256}  ${item.file}`);
  checksumEntries.push(`${rolesFileInfo.sha256}  ${rolesFile}`);
  checksumEntries.push(`${sha256(await fs.readFile(path.join(bundleDir, 'manifest.json')))}  manifest.json`);
  await fs.writeFile(path.join(bundleDir, 'SHA256SUMS'), `${checksumEntries.join('\n')}\n`, { mode: 0o600, flag: 'wx' });

  await runCommand('tar', ['-czf', tarPath, '-C', workRoot, 'luzaweb-bundle'], { timeoutMs: MAX_COMMAND_MS });
  await verifyTarArchive(tarPath);
  await encryptBackupFile(tarPath, encryptedTempPath, passphrase);
  // Decrypt/authenticate the created artifact before making it visible as a completed backup.
  const verificationTar = path.join(workRoot, 'verification.tar.gz');
  await decryptBackupFile(encryptedTempPath, verificationTar, passphrase);
  await verifyTarArchive(verificationTar);
  const encryptedHash = await hashFile(encryptedTempPath);
  await fs.rename(encryptedTempPath, finalPath);
  await fs.writeFile(`${finalPath}.sha256`, `${encryptedHash}  ${path.basename(finalPath)}\n`, { mode: 0o600, flag: 'wx' });
  await fs.chmod(finalPath, 0o600).catch(() => {});
  await fs.chmod(`${finalPath}.sha256`, 0o600).catch(() => {});
  await pruneOldEncryptedBackups();
  failed = false;
  console.log(`Backup completo cifrado e validado: ${finalPath}`);
  console.log(`Bases incluídas: ${databaseEntries.length} (1 interna, ${databaseEntries.length - 1} Neon geridas).`);
  console.log(`Ligações externas não geridas e não incluídas: ${inventory.unmanaged.length}.`);
  console.log(`SHA-256 do arquivo cifrado: ${encryptedHash}`);
  console.log(`Retenção local: ${keepDays} dias. O backup contém dados privados; guarda também uma cópia cifrada fora deste servidor.`);
} finally {
  await fs.rm(workRoot, { recursive: true, force: true }).catch(() => {});
  if (failed) {
    await fs.rm(encryptedTempPath, { force: true }).catch(() => {});
    await fs.rm(finalPath, { force: true }).catch(() => {});
    await fs.rm(`${finalPath}.sha256`, { force: true }).catch(() => {});
  }
}
