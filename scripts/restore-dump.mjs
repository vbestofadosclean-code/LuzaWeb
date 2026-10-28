import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { Pool } from 'pg';
import { cleanChildEnv, pgClientEnv, parsePostgresConnectionUrl, safeBundleRelativePath } from './backup-utils.mjs';

const sourceUrl = String(process.env.SOURCE_DATABASE_URL || '');
const restoreUrl = String(process.env.RESTORE_DATABASE_URL || '');
const backupFile = path.resolve(String(process.env.BACKUP_FILE || ''));
const restoreKind = String(process.env.RESTORE_KIND || '');
if (!sourceUrl || !restoreUrl || !process.env.BACKUP_FILE) throw new Error('Define a URL de origem, a URL de recuperação e BACKUP_FILE através do script de restauro correspondente.');
if (!['internal', 'project'].includes(restoreKind)) throw new Error('RESTORE_KIND inválido. Usa os scripts restore-postgres.sh ou restore-project-postgres.sh.');
if (process.env.RESTORE_CONFIRM !== 'YES') throw new Error('Restauro cancelado: define RESTORE_CONFIRM=YES após confirmares a base de recuperação.');
if (restoreKind === 'internal' && process.env.RESTORE_TARGET_CLUSTER_DEDICATED !== 'YES') {
  throw new Error('Restauro interno cancelado: confirma que o cluster PostgreSQL de destino é dedicado à recuperação definindo RESTORE_TARGET_CLUSTER_DEDICATED=YES.');
}
const source = parsePostgresConnectionUrl(sourceUrl, { label: 'Base de origem', defaultSslMode: 'require' });
const target = parsePostgresConnectionUrl(restoreUrl, { label: 'Base de recuperação', defaultSslMode: 'require' });
for (const [label, connection] of [['origem', source], ['recuperação', target]]) {
  if (!['require', 'verify-ca', 'verify-full'].includes(connection.sslMode)) throw new Error(`Restauro cancelado: a ligação à base de ${label} tem de exigir TLS.`);
}
const identity = item => `${item.url.protocol}//${item.host.toLowerCase()}:${item.port}/${item.database}`;
if (identity(source) === identity(target)) throw new Error('Restauro cancelado: o destino corresponde à base de origem.');
if (restoreKind === 'internal' && source.host.toLowerCase() === target.host.toLowerCase() && source.port === target.port) {
  throw new Error('Restauro interno cancelado: as roles PostgreSQL são globais ao cluster. Usa um cluster de recuperação diferente do cluster de produção.');
}

async function hashFile(filePath) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}
function run(command, args, env = cleanChildEnv(), { captureStdout = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ['ignore', captureStdout ? 'pipe' : 'ignore', 'pipe'], windowsHide: true });
    let err = ''; let out = '';
    child.stderr.on('data', chunk => { if (err.length < 2500) err += chunk.toString().slice(0, 2500 - err.length); });
    child.stdout?.on('data', chunk => { if (out.length < 200_000) out += chunk.toString().slice(0, 200_000 - out.length); });
    child.on('error', () => reject(new Error(`${command} não está disponível.`)));
    child.on('close', code => code === 0 ? resolve({ stdout: out }) : reject(new Error(`${command} falhou (código ${code}). ${err.trim().replace(/postgres(?:ql)?:\/\/[^\s'"<>]+/gi, '[URL ocultada]').slice(0, 300)}`)));
  });
}

async function findBundleRoot() {
  let current = path.dirname(backupFile);
  for (let depth = 0; depth < 9; depth += 1) {
    const manifestPath = path.join(current, 'manifest.json');
    const sumsPath = path.join(current, 'SHA256SUMS');
    const [manifestStat, sumsStat] = await Promise.all([
      fs.lstat(manifestPath).catch(() => null),
      fs.lstat(sumsPath).catch(() => null)
    ]);
    if (manifestStat && sumsStat) {
      if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || !sumsStat.isFile() || sumsStat.isSymbolicLink()) {
        throw new Error('O manifesto ou SHA256SUMS não é um ficheiro regular seguro.');
      }
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error('Não encontrei o manifesto e SHA256SUMS do backup completo. Extrai primeiro o ficheiro .lzwbackup com npm run backup:extract.');
}

async function verifyIntegrity() {
  const dumpStat = await fs.lstat(backupFile).catch(() => null);
  if (!dumpStat?.isFile() || dumpStat.isSymbolicLink() || dumpStat.size < 100) throw new Error('O dump não existe ou não é um ficheiro regular válido.');
  const sidecar = `${backupFile}.sha256`;
  if (await fs.stat(sidecar).catch(() => null)) {
    const match = /^([a-f0-9]{64})  ([^\s]+)\s*$/.exec((await fs.readFile(sidecar, 'utf8')).trim());
    if (!match || match[2] !== path.basename(backupFile) || await hashFile(backupFile) !== match[1]) throw new Error('Checksum do dump inválido.');
  }

  const bundleRoot = await findBundleRoot();
  const relative = path.relative(bundleRoot, backupFile).split(path.sep).join('/');
  if (!safeBundleRelativePath(relative)) throw new Error('O caminho relativo do dump é inválido.');
  const sumsText = await fs.readFile(path.join(bundleRoot, 'SHA256SUMS'), 'utf8');
  const checksums = new Map();
  for (const row of sumsText.split(/\r?\n/).filter(Boolean)) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(row);
    if (!match || !safeBundleRelativePath(match[2]) || checksums.has(match[2])) throw new Error('SHA256SUMS tem um formato inválido.');
    checksums.set(match[2], match[1]);
  }
  const manifestPath = path.join(bundleRoot, 'manifest.json');
  if (!checksums.has('manifest.json') || await hashFile(manifestPath) !== checksums.get('manifest.json')) throw new Error('O manifesto não corresponde ao SHA256SUMS.');
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  if (manifest.format_version !== 1 || !Array.isArray(manifest.databases) || !Array.isArray(manifest.supporting_files)) throw new Error('Manifesto de backup incompatível.');
  const entry = manifest.databases.find(item => item.file === relative);
  if (!entry || !safeBundleRelativePath(entry.file)) throw new Error('O dump selecionado não pertence à lista de bases deste backup.');
  if (restoreKind === 'internal' && entry.kind !== 'internal') throw new Error('O script de restauro interno requer database/internal.dump.');
  if (restoreKind === 'project' && entry.kind !== 'neon-project') throw new Error('O script de restauro de projeto requer um dump Neon gerido pelo LuzaWeb.');
  const expectedHash = checksums.get(relative);
  if (!expectedHash || expectedHash !== entry.sha256 || await hashFile(backupFile) !== expectedHash) throw new Error('O dump não corresponde ao manifesto e ao SHA256SUMS do pacote.');

  let rolesFile = null;
  if (restoreKind === 'internal') {
    const rolesInfo = manifest.supporting_files.find(item => item.file === 'database/project-roles.sql');
    if (!rolesInfo || !safeBundleRelativePath(rolesInfo.file) || !/^[a-f0-9]{64}$/.test(String(rolesInfo.sha256 || ''))) {
      throw new Error('O backup não contém o ficheiro autenticado para recuperar as roles dos projetos. Cria um backup completo novo.');
    }
    rolesFile = path.join(bundleRoot, rolesInfo.file);
    const rolesStat = await fs.lstat(rolesFile).catch(() => null);
    const rolesExpectedHash = checksums.get(rolesInfo.file);
    if (!rolesStat?.isFile() || rolesStat.isSymbolicLink() || !rolesExpectedHash || rolesExpectedHash !== rolesInfo.sha256 || await hashFile(rolesFile) !== rolesExpectedHash) {
      throw new Error('O ficheiro de recuperação das roles está ausente ou não corresponde aos checksums.');
    }
  }
  return { bundleRoot, manifest, entry, rolesFile };
}

async function resolveVersionedPgTool(toolName, major) {
  if (!Number.isInteger(major) || major < 10) throw new Error('Não foi possível identificar uma versão PostgreSQL válida no manifesto.');
  const versioned = `/usr/lib/postgresql/${major}/bin/${toolName}`;
  try { await fs.access(versioned); return versioned; } catch {}
  const output = await run(toolName, ['--version'], cleanChildEnv(), { captureStdout: true });
  const match = /PostgreSQL\)\s+(\d+)/i.exec(output.stdout);
  if (Number(match?.[1]) !== major) throw new Error(`Instala ${toolName} da versão PostgreSQL ${major} para recuperar este dump com segurança.`);
  return toolName;
}

const { entry, rolesFile } = await verifyIntegrity();
const dumpMajor = Number(entry.postgres_major_version);
if (!Number.isInteger(dumpMajor) || dumpMajor < 10) throw new Error('O manifesto não contém uma versão PostgreSQL válida para este dump.');
const pgRestoreTool = await resolveVersionedPgTool('pg_restore', dumpMajor);
await run(pgRestoreTool, ['--list', backupFile]);

const targetHasTlsParameters = ['sslmode', 'sslrootcert', 'sslcert', 'sslkey'].some(key => target.url.searchParams.has(key));
const pool = new Pool({ connectionString: restoreUrl, ...(targetHasTlsParameters ? {} : { ssl: { rejectUnauthorized: true } }), max: 1, connectionTimeoutMillis: 10000, idleTimeoutMillis: 5000, application_name: 'luzaweb-safe-restore-check' });
try {
  const { rows: versionRows } = await pool.query("SELECT current_setting('server_version_num')::int AS server_version_num");
  const restoreMajor = Math.floor(Number(versionRows[0]?.server_version_num) / 10000);
  if (!Number.isInteger(restoreMajor) || restoreMajor < dumpMajor) throw new Error(`Restauro cancelado: o dump é PostgreSQL ${dumpMajor}, mas o destino é ${restoreMajor}. Cria uma base da mesma versão ou mais recente.`);
  const { rows } = await pool.query(`
    SELECT COUNT(*)::int AS object_count
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND c.relkind IN ('r','p','v','m','S','f')
  `);
  if (Number(rows[0]?.object_count || 0) !== 0) throw new Error('Restauro cancelado: a base de recuperação não está vazia. Cria uma base nova e vazia.');
} finally { await pool.end(); }

const { env: targetEnv } = pgClientEnv(restoreUrl, { label: 'Base de recuperação', defaultSslMode: 'require' });
if (restoreKind === 'internal') {
  // Database dumps intentionally exclude cluster-wide roles. Recreate only
  // project roles from the authenticated/encrypted bundle, on an explicitly
  // dedicated recovery cluster and before restoring database objects.
  await run('psql', [
    '--no-password', '--no-psqlrc', '--set=ON_ERROR_STOP=1', '--single-transaction',
    '--dbname', target.database, '--file', rolesFile
  ], targetEnv);
}
await run(pgRestoreTool, [
  '--no-password', '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges',
  '--dbname', target.database, backupFile
], targetEnv);
console.log(`Restauro ${restoreKind === 'internal' ? 'interno' : 'de projeto'} concluído numa base vazia e separada. Valida a aplicação e os dados antes de qualquer mudança de produção.`);
