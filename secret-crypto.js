import crypto from 'node:crypto';

const LOCAL_DEVELOPMENT_ENCRYPTION_KEY = 'luzaweb-local-development-encryption-key-not-for-production';

function keyFor(secret, version = 2) {
  const material = version === 1 ? secret : `luzaweb-secret-encryption-v2:${secret}`;
  return crypto.createHash('sha256').update(material).digest();
}

function isProductionRuntime(env = process.env) {
  return env.NODE_ENV === 'production' || Boolean(env.NETLIFY) || Boolean(String(env.DATABASE_URL || '').trim());
}

/** Validate startup encryption/JWT configuration before serving requests. */
export function validateSecretConfiguration(env = process.env) {
  const production = isProductionRuntime(env);
  const encryptionSecret = String(env.SECRET_ENCRYPTION_KEY || '').trim();
  const jwtSecret = String(env.JWT_SECRET || 'dev-only-change-me').trim();
  if (production && !encryptionSecret) {
    throw new Error('SECRET_ENCRYPTION_KEY é obrigatória em produção; configura uma chave independente de JWT_SECRET.');
  }
  if (encryptionSecret && Buffer.byteLength(encryptionSecret, 'utf8') < 32) {
    throw new Error('SECRET_ENCRYPTION_KEY deve ter pelo menos 32 bytes.');
  }
  if (production && /replace-with|change-me|your-secret|not-for-production|example/i.test(encryptionSecret)) {
    throw new Error('SECRET_ENCRYPTION_KEY não pode ser um valor de exemplo. Gera uma chave aleatória forte.');
  }
  if (encryptionSecret && encryptionSecret === jwtSecret) {
    throw new Error('SECRET_ENCRYPTION_KEY tem de ser diferente de JWT_SECRET.');
  }
  if (production && (jwtSecret === 'dev-only-change-me' || Buffer.byteLength(jwtSecret, 'utf8') < 32 || /replace-with|change-me|your-secret|dev-only/i.test(jwtSecret))) {
    throw new Error('JWT_SECRET é obrigatória em produção, deve ter pelo menos 32 bytes e não pode ser um valor de exemplo. Mantém o mesmo segredo entre publicações.');
  }
  return { production, encryptionSecret, jwtSecret };
}

function activeEncryptionSecret() {
  const { encryptionSecret, production } = validateSecretConfiguration();
  const secret = encryptionSecret || LOCAL_DEVELOPMENT_ENCRYPTION_KEY;
  if (production && secret === LOCAL_DEVELOPMENT_ENCRYPTION_KEY) {
    throw new Error('A chave de desenvolvimento nunca pode ser usada em produção.');
  }
  return secret;
}

function decryptionSecrets(isVersioned) {
  const current = String(process.env.SECRET_ENCRYPTION_KEY || '').trim();
  const legacy = String(process.env.LEGACY_SECRET_ENCRYPTION_KEY || '').trim();
  const production = isProductionRuntime(process.env);
  // Legacy ciphertexts (both v2 and the original unversioned format) may only
  // be read with an explicitly configured prior key. JWT_SECRET is never an
  // implicit decryption key. The fixed local key is development-only.
  const candidates = [current, legacy];
  if (!production && !current && !legacy) candidates.push(LOCAL_DEVELOPMENT_ENCRYPTION_KEY);
  return [...new Set(candidates.filter(Boolean))];
}

function encryptWithSecret(value, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyFor(secret, 2), iv);
  const encrypted = Buffer.concat([cipher.update(String(value ?? ''), 'utf8'), cipher.final()]);
  return `v2.${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${encrypted.toString('base64')}`;
}

export function encryptSecret(value) {
  return encryptWithSecret(value, activeEncryptionSecret());
}

export function decryptSecret(value) {
  if (!value) return '';
  const parts = String(value).split('.');
  const versioned = parts[0] === 'v2' && parts.length === 4;
  const [ivText, tagText, dataText] = versioned ? parts.slice(1) : parts;
  if (![ivText, tagText, dataText].every(part => typeof part === 'string' && part.length > 0)) {
    throw new Error('Formato de segredo cifrado inválido.');
  }
  for (const secret of decryptionSecrets(versioned)) {
    try {
      const key = keyFor(secret, versioned ? 2 : 1);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivText, 'base64'));
      decipher.setAuthTag(Buffer.from(tagText, 'base64'));
      return Buffer.concat([decipher.update(Buffer.from(dataText, 'base64')), decipher.final()]).toString('utf8');
    } catch { /* Try another explicitly configured compatibility key. */ }
  }
  throw new Error('Não foi possível descodificar um segredo. Confirma SECRET_ENCRYPTION_KEY e, durante uma migração, LEGACY_SECRET_ENCRYPTION_KEY.');
}
