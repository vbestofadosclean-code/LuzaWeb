import crypto from 'node:crypto';

function bucketHash(scope, id, ip = '') {
  // Hash identifiers so storage does not contain raw client IPs or public IDs.
  const input = scope === 'ip' ? `ip:${id}:${ip}` : `${scope}:${id}`;
  return `api:${scope}:` + crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Consume one request from per-key, per-key/IP and per-project windows. A single
 * multi-row UPSERT reduces database round-trips while keeping every bucket update
 * atomic across serverless instances.
 */
export async function consumePublicApiRateLimit(executor, {
  keyId,
  projectId,
  keyType = 'publishable',
  ip,
  now = Date.now(),
  perIpLimit = 120,
  perKeyLimit = 600,
  perProjectLimit = 1200,
  windowMs = 60_000
} = {}) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('Rate-limit executor must support query().');
  const normalizedKeyId = Number(keyId);
  const normalizedProjectId = Number(projectId);
  if (!Number.isSafeInteger(normalizedKeyId) || normalizedKeyId < 1) throw new TypeError('A valid API key ID is required.');
  if (!Number.isSafeInteger(normalizedProjectId) || normalizedProjectId < 1) throw new TypeError('A valid API project ID is required.');
  const clientIp = String(ip || 'unknown').slice(0, 100);
  const limits = [
    { key: bucketHash('key', normalizedKeyId), max: perKeyLimit, scope: 'key' },
    { key: bucketHash('ip', normalizedKeyId, clientIp), max: perIpLimit, scope: 'ip' },
    { key: bucketHash(keyType === 'secret' ? 'project-secret' : 'project-public', normalizedProjectId), max: perProjectLimit, scope: 'project' }
  ];
  const result = await executor.query(`
    INSERT INTO api_rate_limits(bucket_key, attempts, reset_at)
    VALUES($1, 1, $4), ($2, 1, $4), ($3, 1, $4)
    ON CONFLICT(bucket_key) DO UPDATE SET
      attempts = CASE WHEN api_rate_limits.reset_at <= $5 THEN 1 ELSE api_rate_limits.attempts + 1 END,
      reset_at = CASE WHEN api_rate_limits.reset_at <= $5 THEN excluded.reset_at ELSE api_rate_limits.reset_at END
    RETURNING bucket_key, attempts, reset_at
  `, [limits[0].key, limits[1].key, limits[2].key, now + windowMs, now]);

  const byKey = new Map((result.rows || []).map(row => [row.bucket_key, row]));
  const decisions = limits.map(bucket => {
    const row = byKey.get(bucket.key);
    if (!row) throw new Error('Public API rate-limit update returned no row.');
    const attempts = Number(row.attempts);
    const resetAt = Number(row.reset_at);
    return {
      allowed: Number.isFinite(attempts) && attempts <= bucket.max,
      attempts,
      max: bucket.max,
      scope: bucket.scope,
      resetAt: Number.isFinite(resetAt) ? resetAt : now + windowMs
    };
  });
  const blocked = decisions.filter(item => !item.allowed).sort((a, b) => a.resetAt - b.resetAt)[0];
  if (!blocked) return { allowed: true, limits: decisions };
  return {
    allowed: false,
    scope: blocked.scope,
    attempts: blocked.attempts,
    max: blocked.max,
    retryAfterMs: Math.max(1, blocked.resetAt - now)
  };
}

export async function pruneExpiredApiRateLimits(executor, now = Date.now()) {
  const result = await executor.query('DELETE FROM api_rate_limits WHERE reset_at <= $1', [now]);
  return Number(result.rowCount || 0);
}
