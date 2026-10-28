import pg from 'pg';
import { decryptSecret, encryptSecret, validateSecretConfiguration } from '../secret-crypto.js';

const { Pool } = pg;
if (!process.env.DATABASE_URL) throw new Error('Define DATABASE_URL para apontar à base interna do LuzaWeb.');
if (!process.env.SECRET_ENCRYPTION_KEY || Buffer.byteLength(process.env.SECRET_ENCRYPTION_KEY, 'utf8') < 32) {
  throw new Error('Define SECRET_ENCRYPTION_KEY com pelo menos 32 bytes antes da rotação.');
}
if (String(process.env.SECRET_ENCRYPTION_KEY).trim() === String(process.env.JWT_SECRET || '').trim()) {
  throw new Error('SECRET_ENCRYPTION_KEY tem de ser diferente de JWT_SECRET.');
}
// Use the exact runtime validator: rotation must not proceed with placeholder,
// whitespace-only, or otherwise invalid production keys.
validateSecretConfiguration();
if (process.env.ROTATE_SECRETS_CONFIRM !== 'YES') {
  throw new Error('Rotação cancelada. Depois de criar um backup, define ROTATE_SECRETS_CONFIRM=YES.');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2, connectionTimeoutMillis: 5000, statement_timeout: 30000 });
const targets = [
  ['project_databases', 'db_password_cipher'],
  ['project_database_connections', 'password_cipher'],
  ['project_database_connections', 'connection_uri_cipher'],
  ['project_database_connections', 'pooled_uri_cipher'],
  ['project_env_vars', 'value_cipher']
];
let changed = 0;
try {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const [table, column] of targets) {
      const { rows } = await client.query(`SELECT id, ${column} AS cipher FROM ${table} WHERE ${column} IS NOT NULL AND ${column} <> '' FOR UPDATE`);
      for (const row of rows) {
        const plaintext = decryptSecret(row.cipher);
        const replacement = encryptSecret(plaintext);
        if (replacement !== row.cipher) {
          await client.query(`UPDATE ${table} SET ${column}=$1 WHERE id=$2`, [replacement, row.id]);
          changed++;
        }
      }
      console.log(`Verificado ${table}.${column}: ${rows.length} registo(s).`);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
  console.log(`Rotação concluída. ${changed} valor(es) cifrado(s) foram reescritos com SECRET_ENCRYPTION_KEY.`);
} finally { await pool.end(); }
