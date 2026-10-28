import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
export const BACKUP_MAGIC = Buffer.from('LZWBKP01', 'ascii');
const HEADER_LENGTH = 8 + 16 + 12;
const TAG_LENGTH = 16;

export function validateBackupPassphrase(value) {
  const passphrase = String(value || '');
  if (Buffer.byteLength(passphrase, 'utf8') < 32) throw new Error('BACKUP_ENCRYPTION_PASSPHRASE deve ter pelo menos 32 bytes aleatórios.');
  return passphrase;
}

async function deriveKey(passphrase, salt) {
  const validated = validateBackupPassphrase(passphrase);
  return scrypt(validated, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

export async function encryptBackupFile(inputPath, outputPath, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const header = Buffer.concat([BACKUP_MAGIC, salt, iv]);
  const temporaryPath = `${outputPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    await fs.writeFile(temporaryPath, header, { flag: 'wx', mode: 0o600 });
    await pipeline(createReadStream(inputPath), cipher, createWriteStream(temporaryPath, { flags: 'a', mode: 0o600 }));
    await fs.appendFile(temporaryPath, cipher.getAuthTag(), { mode: 0o600 });
    await fs.chmod(temporaryPath, 0o600).catch(() => {});
    await fs.rename(temporaryPath, outputPath);
    return { outputPath, bytes: (await fs.stat(outputPath)).size };
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  } finally { key.fill(0); }
}

export async function decryptBackupFile(inputPath, outputPath, passphrase) {
  const stat = await fs.stat(inputPath);
  if (!stat.isFile() || stat.size < HEADER_LENGTH + TAG_LENGTH + 1) throw new Error('O ficheiro de backup cifrado está truncado ou inválido.');
  const handle = await fs.open(inputPath, 'r');
  let header, tag;
  try {
    header = Buffer.alloc(HEADER_LENGTH);
    tag = Buffer.alloc(TAG_LENGTH);
    const h = await handle.read(header, 0, HEADER_LENGTH, 0);
    const t = await handle.read(tag, 0, TAG_LENGTH, stat.size - TAG_LENGTH);
    if (h.bytesRead !== HEADER_LENGTH || t.bytesRead !== TAG_LENGTH || !header.subarray(0, 8).equals(BACKUP_MAGIC)) throw new Error('Formato do backup cifrado não reconhecido.');
  } finally { await handle.close(); }
  const salt = header.subarray(8, 24);
  const iv = header.subarray(24, 36);
  const key = await deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const temporaryPath = `${outputPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    await pipeline(createReadStream(inputPath, { start: HEADER_LENGTH, end: stat.size - TAG_LENGTH - 1 }), decipher, createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 }));
    await fs.chmod(temporaryPath, 0o600).catch(() => {});
    await fs.rename(temporaryPath, outputPath);
    return { outputPath, bytes: (await fs.stat(outputPath)).size };
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    if (error?.code === 'ERR_OSSL_EVP_BAD_DECRYPT' || /authenticate|Unsupported state|unable to authenticate/i.test(String(error?.message || ''))) {
      throw new Error('Não foi possível autenticar o backup. Confirma a passphrase e a integridade do ficheiro.');
    }
    throw error;
  } finally { key.fill(0); }
}

export async function createPrivateTempDir(prefix = 'luzaweb-backup-') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  await fs.chmod(dir, 0o700).catch(() => {});
  return dir;
}
