#!/usr/bin/env bash
set -Eeuo pipefail
: "${PRODUCTION_DATABASE_URL:?Define PRODUCTION_DATABASE_URL para impedir restauro acidental sobre produção}"
: "${RESTORE_DATABASE_URL:?Define RESTORE_DATABASE_URL para uma base de recuperação VAZIA}"
: "${BACKUP_FILE:?Define BACKUP_FILE com o caminho de database/internal.dump extraído do pacote completo}"
: "${RESTORE_TARGET_CLUSTER_DEDICATED:?Define RESTORE_TARGET_CLUSTER_DEDICATED=YES apenas se o cluster de recuperação for dedicado}"
[[ "${RESTORE_TARGET_CLUSTER_DEDICATED}" == "YES" ]] || { echo "Restauro cancelado: o cluster tem de ser dedicado à recuperação." >&2; exit 1; }
[[ "${RESTORE_CONFIRM:-}" == "YES" ]] || { echo "Para confirmar, define RESTORE_CONFIRM=YES. Usa uma base vazia e separada da produção." >&2; exit 1; }
export SOURCE_DATABASE_URL="$PRODUCTION_DATABASE_URL"
export RESTORE_KIND=internal
exec node "$(dirname "$0")/restore-dump.mjs"
