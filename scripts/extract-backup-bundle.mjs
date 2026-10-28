import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { createReadStream } from 'node:fs';
import { decryptBackupFile, createPrivateTempDir, validateBackupPassphrase } from './backup-crypto.mjs';
import { cleanChildEnv, safeBundleRelativePath } from './backup-utils.mjs';

const backupFile = path.resolve(String(process.env.BACKUP_FILE || ''));
const destination = path.resolve(String(process.env.RESTORE_WORK_DIR || ''));
const passphrase = validateBackupPassphrase(process.env.BACKUP_ENCRYPTION_PASSPHRASE);
if (!process.env.BACKUP_FILE || !process.env.RESTORE_WORK_DIR) throw new Error('Define BACKUP_FILE e RESTORE_WORK_DIR. O destino não pode existir previamente.');
const backupStat = await fs.lstat(backupFile).catch(() => null);
if (!backupStat?.isFile() || backupStat.isSymbolicLink()) throw new Error('O ficheiro de backup cifrado não existe ou não é um ficheiro regular.');

function run(command, args, { stdout = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: cleanChildEnv(), stdio: ['ignore', stdout ? 'pipe' : 'ignore', 'pipe'], windowsHide: true });
    let out = ''; let err = '';
    child.stdout?.on('data', chunk => { if (out.length < 500_000) out += chunk.toString().slice(0, 500_000 - out.length); });
    child.stderr.on('data', chunk => { if (err.length < 2000) err += chunk.toString().slice(0, 2000 - err.length); });
    child.on('error', () => reject(new Error(`${command} não está disponível.`)));
    child.on('close', code => code === 0 ? resolve(out) : reject(new Error(`${command} falhou durante a verificação do backup. ${err.trim().slice(0, 250)}`)));
  });
}
async function hashFile(filePath) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}
async function resolveVersionedPgRestore(major) {
  if (!Number.isInteger(major) || major < 10) throw new Error('O manifesto não contém uma versão PostgreSQL válida.');
  const versioned = `/usr/lib/postgresql/${major}/bin/pg_restore`;
  try { await fs.access(versioned); return versioned; } catch {}
  const output = await run('pg_restore', ['--version'], { stdout: true });
  const match = /PostgreSQL\)\s+(\d+)/i.exec(output);
  if (Number(match?.[1]) !== major) throw new Error(`Instala pg_restore da versão PostgreSQL ${major} para validar este dump.`);
  return 'pg_restore';
}

async function verifyChecksums(bundle) {
  const sumsPath = path.join(bundle, 'SHA256SUMS');
  const content = await fs.readFile(sumsPath, 'utf8');
  const lines = content.split(/\r?\n/).filter(Boolean);
  if (!lines.length) throw new Error('SHA256SUMS está vazio.');
  const listed = new Set();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match || !safeBundleRelativePath(match[2]) || listed.has(match[2])) throw new Error('Formato de SHA256SUMS inválido.');
    const target = path.join(bundle, match[2]);
    const stat = await fs.lstat(target).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error(`Ficheiro do backup em falta ou inválido: ${match[2]}`);
    if (await hashFile(target) !== match[1]) throw new Error(`Checksum inválido para ${match[2]}.`);
    listed.add(match[2]);
  }
  const manifestPath = path.join(bundle, 'manifest.json');
  const manifestStat = await fs.lstat(manifestPath).catch(() => null);
  if (!manifestStat?.isFile() || manifestStat.isSymbolicLink() || !listed.has('manifest.json')) throw new Error('O manifesto está ausente, inválido ou não está protegido por checksum.');
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  if (manifest.format_version !== 1 || !Array.isArray(manifest.databases) || !manifest.databases.some(item => item.kind === 'internal')) throw new Error('Manifesto de backup incompatível ou sem base interna.');
  for (const database of manifest.databases) {
    if (!safeBundleRelativePath(database.file) || !listed.has(database.file)) throw new Error('Manifesto contém um caminho de backup inválido.');
    if (!database.sha256 || (await hashFile(path.join(bundle, database.file))) !== database.sha256) throw new Error(`O dump ${database.file} não corresponde ao manifesto.`);
  }
  if (!Array.isArray(manifest.supporting_files)) throw new Error('Manifesto sem lista de ficheiros auxiliares.');
  for (const supporting of manifest.supporting_files) {
    if (!safeBundleRelativePath(supporting.file) || !listed.has(supporting.file) || !/^[a-f0-9]{64}$/.test(String(supporting.sha256 || ''))) throw new Error('O manifesto contém um ficheiro auxiliar sem checksum válido.');
    const supportingPath = path.join(bundle, supporting.file);
    const supportingStat = await fs.lstat(supportingPath).catch(() => null);
    if (!supportingStat?.isFile() || supportingStat.isSymbolicLink() || await hashFile(supportingPath) !== supporting.sha256) throw new Error(`Ficheiro auxiliar inválido: ${supporting.file}`);
  }
  if (!manifest.supporting_files.some(item => item.file === 'database/project-roles.sql')) throw new Error('Backup sem o ficheiro de recuperação das roles PostgreSQL. Cria um novo backup completo.');
  for (const database of manifest.databases) {
    const tool = await resolveVersionedPgRestore(Number(database.postgres_major_version));
    await run(tool, ['--list', path.join(bundle, database.file)]);
  }
  return manifest;
}

const temp = await createPrivateTempDir('luzaweb-restore-check-');
const tarPath = path.join(temp, 'backup.tar.gz');
const extractRoot = path.join(temp, 'extracted');
try {
  if (await fs.lstat(destination).catch(() => null)) throw new Error('RESTORE_WORK_DIR já existe. Escolhe uma pasta nova para não sobrescrever ficheiros.');
  const sidecar = `${backupFile}.sha256`;
  if (await fs.stat(sidecar).catch(() => null)) {
    const text = await fs.readFile(sidecar, 'utf8');
    const match = /^([a-f0-9]{64})  ([^\s]+)\s*$/.exec(text.trim());
    if (!match || match[2] !== path.basename(backupFile) || await hashFile(backupFile) !== match[1]) throw new Error('Checksum do arquivo cifrado inválido.');
  }
  await decryptBackupFile(backupFile, tarPath, passphrase);
  const namesText = await run('tar', ['-tzf', tarPath], { stdout: true });
  const names = namesText.split(/\r?\n/).filter(Boolean);
  if (!names.length || names.some(name => {
    const trimmed = name.replace(/\/$/, '');
    return !safeBundleRelativePath(trimmed) || !(trimmed === 'luzaweb-bundle' || trimmed.startsWith('luzaweb-bundle/'));
  })) throw new Error('O arquivo contém caminhos inesperados. Extração cancelada.');
  await fs.mkdir(extractRoot, { recursive: true, mode: 0o700 });
  await run('tar', ['-xzf', tarPath, '--no-same-owner', '--no-same-permissions', '-C', extractRoot]);
  const bundle = path.join(extractRoot, 'luzaweb-bundle');
  const manifest = await verifyChecksums(bundle);
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  await fs.rename(bundle, destination);
  await fs.chmod(destination, 0o700).catch(() => {});
  console.log(`Backup decifrado, autenticado e verificado: ${destination}`);
  console.log(`Bases disponíveis: ${manifest.databases.length} (inclui a base interna).`);
  console.log('Nenhuma base de dados foi alterada. Usa os scripts de restauro para recuperar cada dump numa base vazia e separada da produção.');
} finally { await fs.rm(temp, { recursive: true, force: true }).catch(() => {}); }
