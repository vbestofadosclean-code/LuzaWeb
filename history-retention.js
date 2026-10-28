function positiveLimit(value, fallback, min, max) {
  const number = Number.parseInt(value ?? '', 10);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

export function historyRetentionLimits(env = process.env) {
  return {
    commitLimit: positiveLimit(env.COMMIT_RETENTION_PER_PROJECT, 30, 5, 200),
    deploymentLimit: positiveLimit(env.DEPLOYMENT_RETENTION_PER_PROJECT, 10, 3, 100)
  };
}

/**
 * Prunes one project's history. Caller must hold a transaction and, when using
 * PostgreSQL, lock the project row before invoking this helper. It keeps the
 * most recent N commits plus every commit referenced by retained deployments.
 * The most recent LIVE deployment is retained even if older than the count cap.
 */
export async function pruneProjectHistory(executor, projectId, options = {}) {
  const limits = {
    commitLimit: positiveLimit(options.commitLimit, 30, 5, 200),
    deploymentLimit: positiveLimit(options.deploymentLimit, 10, 3, 100)
  };
  const result = await executor.query(
    'SELECT id,commit_id,status,created_at FROM deployments WHERE project_id=$1 ORDER BY id DESC',
    [projectId]
  );
  const deployments = result.rows || [];
  const keepDeployments = new Set(deployments.slice(0, limits.deploymentLimit).map(row => String(row.id)));
  // Never prune an in-progress deployment, even if it is older than the newest-N window.
  for (const row of deployments) if (row.status === 'BUILDING') keepDeployments.add(String(row.id));
  const latestLive = deployments.find(row => row.status === 'LIVE');
  if (latestLive) keepDeployments.add(String(latestLive.id));

  let removedDeployments = 0;
  for (const row of deployments) {
    if (keepDeployments.has(String(row.id))) continue;
    await executor.query('DELETE FROM deployments WHERE id=$1 AND project_id=$2', [row.id, projectId]);
    removedDeployments++;
  }

  // Keep newest snapshots and all snapshots still referenced by deployment rows.
  const keepCommits = await executor.query(
    'SELECT id FROM commits WHERE project_id=$1 ORDER BY id DESC LIMIT $2',
    [projectId, limits.commitLimit]
  );
  const retainedCommitIds = new Set((keepCommits.rows || []).map(row => String(row.id)));
  const retainedDeployments = await executor.query('SELECT commit_id FROM deployments WHERE project_id=$1', [projectId]);
  for (const row of retainedDeployments.rows || []) retainedCommitIds.add(String(row.commit_id));

  const allCommits = await executor.query('SELECT id FROM commits WHERE project_id=$1', [projectId]);
  let removedCommits = 0;
  for (const row of allCommits.rows || []) {
    if (retainedCommitIds.has(String(row.id))) continue;
    await executor.query('DELETE FROM commits WHERE id=$1 AND project_id=$2', [row.id, projectId]);
    removedCommits++;
  }
  return { removedDeployments, removedCommits, retainedDeployments: keepDeployments.size, retainedCommits: retainedCommitIds.size };
}
