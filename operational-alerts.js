import crypto from 'node:crypto';

function alertKey(event) {
  const safeEvent = String(event || '').trim().slice(0, 80);
  if (!safeEvent) throw new TypeError('Alert event is required.');
  return `alert:${crypto.createHash('sha256').update(safeEvent).digest('hex')}`;
}

/** Atomically claims one alert event cooldown across all backend instances. */
export async function claimOperationalAlertCooldown(executor, event, now = Date.now(), cooldownMs = 300_000) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('Alert cooldown executor must support query().');
  const time = Number(now);
  const cooldown = Number(cooldownMs);
  if (!Number.isFinite(time) || !Number.isFinite(cooldown) || cooldown < 0) throw new TypeError('Alert cooldown timing is invalid.');
  const result = await executor.query(`
    INSERT INTO operational_alert_cooldowns(event_key,last_sent_at) VALUES($1,$2)
    ON CONFLICT(event_key) DO UPDATE SET last_sent_at=excluded.last_sent_at
      WHERE operational_alert_cooldowns.last_sent_at <= $3
    RETURNING event_key
  `, [alertKey(event), time, time - cooldown]);
  return Boolean(result.rows?.length);
}

export async function pruneOperationalAlertCooldowns(executor, now = Date.now(), maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('Alert cooldown executor must support query().');
  const result = await executor.query('DELETE FROM operational_alert_cooldowns WHERE last_sent_at <= $1', [Number(now) - Number(maxAgeMs)]);
  return Number(result.rowCount || 0);
}
