import crypto from 'node:crypto';

function hashPart(value) {
  return crypto.createHash('sha256').update(String(value ?? 'unknown')).digest('hex');
}

function bucket(scope, action, identifier) {
  return `resource:${scope}:${action}:${hashPart(identifier)}`;
}

/**
 * Shared atomic creation limiter. Reuses api_rate_limits so every serverless
 * instance applies the same counters without persisting clear IP addresses.
 */
export async function consumeResourceCreationLimit(executor, {
  action,
  userId,
  ip,
  now = Date.now(),
  perUserLimit = 5,
  perIpLimit = 10,
  windowMs = 60 * 60 * 1000
} = {}) {
  if (!executor || typeof executor.query !== 'function') throw new TypeError('A resource-limit executor with query() is required.');
  const normalizedAction = String(action || '').trim().toLowerCase();
  if (!/^[a-z0-9-]{2,48}$/.test(normalizedAction)) throw new TypeError('A valid resource-limit action is required.');
  const normalizedUserId = String(userId ?? '').trim();
  if (!normalizedUserId) throw new TypeError('A user id is required.');
  const clientIp = String(ip || 'unknown').slice(0, 100);
  const buckets = [
    { key: bucket('user', normalizedAction, normalizedUserId), max: perUserLimit, scope: 'user' },
    { key: bucket('ip', normalizedAction, clientIp), max: perIpLimit, scope: 'ip' }
  ];
  const decisions = [];
  for (const item of buckets) {
    const result = await executor.query(`
      INSERT INTO api_rate_limits(bucket_key, attempts, reset_at)
      VALUES($1, 1, $2)
      ON CONFLICT(bucket_key) DO UPDATE SET
        attempts = CASE WHEN api_rate_limits.reset_at <= $3 THEN 1 ELSE api_rate_limits.attempts + 1 END,
        reset_at = CASE WHEN api_rate_limits.reset_at <= $3 THEN $2 ELSE api_rate_limits.reset_at END
      RETURNING attempts, reset_at
    `, [item.key, now + windowMs, now]);
    const row = result.rows?.[0];
    if (!row) throw new Error('Resource-limit update returned no row.');
    const attempts = Number(row.attempts);
    const resetAt = Number(row.reset_at);
    decisions.push({
      allowed: Number.isFinite(attempts) && attempts <= item.max,
      attempts,
      max: item.max,
      scope: item.scope,
      resetAt: Number.isFinite(resetAt) ? resetAt : now + windowMs
    });
  }
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

export function parseNeonProjectCount(payload) {
  const candidates = [
    payload?.projects_count,
    payload?.project_count,
    payload?.projectsCount,
    payload?.count,
    payload?.data?.projects_count,
    payload?.data?.project_count,
    payload?.data?.count
  ];
  for (const candidate of candidates) {
    const value = typeof candidate === 'number' ? candidate : (typeof candidate === 'string' && /^\d+$/.test(candidate) ? Number(candidate) : NaN);
    if (Number.isSafeInteger(value) && value >= 0) return value;
  }
  if (typeof payload === 'number' && Number.isSafeInteger(payload) && payload >= 0) return payload;
  return null;
}

export function resourceQuotaLimits(env = process.env) {
  const read = (name, fallback, min, max) => {
    const n = Number.parseInt(env[name] || '', 10);
    return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
  };
  return Object.freeze({
    projectsPerUser: read('PROJECTS_PER_USER_LIMIT', 10, 1, 100),
    projectsGlobal: read('PROJECTS_GLOBAL_LIMIT', 1000, 10, 1000000),
    projectCreatePerUserPerHour: read('PROJECT_CREATIONS_PER_USER_PER_HOUR', 5, 1, 100),
    projectCreatePerIpPerHour: read('PROJECT_CREATIONS_PER_IP_PER_HOUR', 10, 1, 200),
    neonDatabasesPerUser: read('NEON_DATABASES_PER_USER_LIMIT', 3, 1, 100),
    neonDatabasesGlobal: read('NEON_DATABASES_GLOBAL_LIMIT', 80, 1, 1000000),
    neonAccountProjectLimit: read('NEON_ACCOUNT_PROJECT_LIMIT', 90, 1, 1000000),
    neonCreatePerUserPerHour: read('NEON_DATABASE_CREATIONS_PER_USER_PER_HOUR', 3, 1, 100),
    neonCreatePerIpPerHour: read('NEON_DATABASE_CREATIONS_PER_IP_PER_HOUR', 5, 1, 200),
    creationWindowMs: read('RESOURCE_CREATION_WINDOW_MS', 3600000, 60000, 86400000)
  });
}


export async function reserveNeonProvisionSlot(pool, project, userId, quotas, { databaseConfigured = true } = {}) {
  const client = await pool.connect();
  let transactionStarted = false;
  try {
    await client.query(databaseConfigured ? 'BEGIN' : 'BEGIN IMMEDIATE');
    transactionStarted = true;
    if (databaseConfigured) {
      // One reservation lock per Neon account prevents concurrent requests on
      // different projects from bypassing the local resource quotas.
      await client.query('SELECT pg_advisory_xact_lock($1, $2)', [1280653889, 2]);
    }
    const ownedProject = await client.query(`SELECT id FROM projects WHERE id=$1 AND user_id=$2 AND trashed_at IS NULL${databaseConfigured ? ' FOR UPDATE' : ''}`, [project.id, userId]);
    if (!ownedProject.rows?.[0]) {
      const error = new Error('Projeto não encontrado ou já não está disponível.');
      error.code = 'PROJECT_NOT_FOUND'; error.statusCode = 404; throw error;
    }
    const existing = (await client.query('SELECT provider,provider_project_id,connection_uri_cipher FROM project_database_connections WHERE project_id=$1', [project.id])).rows[0];
    if (existing?.provider_project_id || existing?.connection_uri_cipher) {
      const error = new Error('Este projeto já tem uma base PostgreSQL configurada. Abre os dados existentes em vez de criares outra base.');
      error.code = 'PROJECT_DATABASE_EXISTS'; error.statusCode = 409; throw error;
    }
    const lifecycleOperation = (await client.query('SELECT state FROM project_lifecycle_operations WHERE project_id=$1', [project.id])).rows[0];
    if (lifecycleOperation) {
      const error = new Error('Este projeto tem uma operação de eliminação Neon pendente ou por reconciliar. Resolve-a antes de criar ou substituir recursos.');
      error.code = 'NEON_LIFECYCLE_OPERATION_PENDING'; error.statusCode = 409; throw error;
    }
    const priorReservation = (await client.query('SELECT state FROM neon_provision_reservations WHERE project_id=$1', [project.id])).rows[0];
    if (priorReservation && ['pending', 'cleanup_required'].includes(String(priorReservation.state))) {
      const error = new Error(priorReservation.state === 'cleanup_required'
        ? 'Existe uma criação anterior que precisa de reconciliação no painel Neon antes de tentar novamente.'
        : 'A criação da base deste projeto já está em curso. Aguarda e atualiza a página.');
      error.code = priorReservation.state === 'cleanup_required' ? 'NEON_CLEANUP_REQUIRED' : 'NEON_PROVISION_IN_PROGRESS';
      error.statusCode = 409; throw error;
    }
    if (priorReservation?.state === 'failed') await client.query('DELETE FROM neon_provision_reservations WHERE project_id=$1', [project.id]);

    const userConnections = await client.query(`SELECT COUNT(DISTINCT c.project_id)::int AS count
      FROM project_database_connections c JOIN projects p ON p.id=c.project_id
      WHERE p.user_id=$1 AND c.provider='neon' AND COALESCE(c.provider_project_id,'')<>''`, [userId]);
    const userPending = await client.query("SELECT COUNT(*)::int AS count FROM neon_provision_reservations WHERE user_id=$1 AND state IN ('pending','cleanup_required')", [userId]);
    if (Number(userConnections.rows?.[0]?.count || 0) + Number(userPending.rows?.[0]?.count || 0) >= quotas.neonDatabasesPerUser) {
      const error = new Error(`A tua conta atingiu o limite de ${quotas.neonDatabasesPerUser} bases Neon geridas pelo LuzaWeb.`);
      error.code = 'NEON_USER_QUOTA_REACHED'; error.statusCode = 429; throw error;
    }
    const globalConnections = await client.query("SELECT COUNT(DISTINCT project_id)::int AS count FROM project_database_connections WHERE provider='neon' AND COALESCE(provider_project_id,'')<>''");
    const globalPending = await client.query("SELECT COUNT(*)::int AS count FROM neon_provision_reservations WHERE state IN ('pending','cleanup_required')");
    if (Number(globalConnections.rows?.[0]?.count || 0) + Number(globalPending.rows?.[0]?.count || 0) >= quotas.neonDatabasesGlobal) {
      const error = new Error('O serviço atingiu o limite de bases Neon geridas pelo LuzaWeb. Contacta o administrador.');
      error.code = 'NEON_GLOBAL_QUOTA_REACHED'; error.statusCode = 503; throw error;
    }
    await client.query(`INSERT INTO neon_provision_reservations(project_id,user_id,state,provider_project_id,created_at,updated_at)
      VALUES($1,$2,'pending','',NOW(),NOW())`, [project.id, userId]);
    await client.query('COMMIT'); transactionStarted = false;
    return true;
  } catch (error) {
    if (transactionStarted) { try { await client.query('ROLLBACK'); } catch {} }
    throw error;
  } finally { client.release?.(); }
}

