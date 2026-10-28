export const NEON_DELETE_PENDING_STALE_MS = 5 * 60 * 1000;

export function classifyLifecycleDeleteOperation(operation, { now = Date.now(), staleAfterMs = NEON_DELETE_PENDING_STALE_MS } = {}) {
  if (!operation) return { action: 'start' };
  const state = String(operation.state || '');
  const providerProjectId = String(operation.provider_project_id || '');
  if (!providerProjectId) return { action: 'manual_reconciliation', code: 'NEON_RESOURCE_ID_MISSING' };
  if (state === 'cleanup_required') return { action: 'retry', providerProjectId };
  if (state === 'pending') {
    const updatedAt = Date.parse(operation.updated_at || '');
    if (!Number.isFinite(updatedAt) || now - updatedAt < staleAfterMs) return { action: 'in_progress', code: 'NEON_DELETION_IN_PROGRESS' };
    return { action: 'retry', providerProjectId };
  }
  return { action: 'manual_reconciliation', code: 'NEON_LIFECYCLE_STATE_INVALID' };
}

export function lifecycleOperationBlocksRestore(operation) {
  return Boolean(operation && ['pending', 'cleanup_required'].includes(String(operation.state || '')));
}
