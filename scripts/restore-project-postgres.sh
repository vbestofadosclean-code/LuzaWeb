#!/usr/bin/env bash
set -Eeuo pipefail
: "${PROJECT_PRODUCTION_DATABASE_URL:?Define PROJECT_PRODUCTION_DATABASE_URL com a URL da base Neon original}"
: "${PROJECT_RESTORE_DATABASE_URL:?Define PROJECT_RESTORE_DATABASE_URL com uma base Neon nova e vazia}"
: "${BACKUP_FILE:?Define BACKUP_FILE com o caminho do dump do projeto}"
[[ "${RESTORE_CONFIRM:-}" == "YES" ]] || { echo "Restauro cancelado. Define RESTORE_CONFIRM=YES depois de criar uma base de recuperação vazia." >&2; exit 1; }
export SOURCE_DATABASE_URL="$PROJECT_PRODUCTION_DATABASE_URL"
export RESTORE_KIND=project
export RESTORE_DATABASE_URL="$PROJECT_RESTORE_DATABASE_URL"
exec node "$(dirname "$0")/restore-dump.mjs"
