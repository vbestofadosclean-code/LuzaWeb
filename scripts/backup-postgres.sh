#!/usr/bin/env bash
set -Eeuo pipefail

# Secure, validated backup of the LuzaWeb internal PostgreSQL database.
# Run from a trusted machine with PostgreSQL client tools installed.
: "${DATABASE_URL:?Define DATABASE_URL no ambiente antes do backup}"
command -v pg_dump >/dev/null || { echo "Erro: pg_dump não está instalado." >&2; exit 1; }
command -v pg_restore >/dev/null || { echo "Erro: pg_restore não está instalado." >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "Erro: sha256sum não está disponível." >&2; exit 1; }
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
[[ "$KEEP_DAYS" =~ ^[0-9]+$ ]] || { echo "BACKUP_KEEP_DAYS deve ser um número inteiro não negativo." >&2; exit 1; }
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_DIR/luzaweb-$STAMP.dump"
TMP="$DEST.tmp"
SUM="$DEST.sha256"
cleanup() { rm -f "$TMP" "$SUM.tmp"; }
trap cleanup EXIT
pg_dump --no-owner --no-privileges --format=custom --file="$TMP" "$DATABASE_URL"
[[ -s "$TMP" ]] || { echo "Erro: o backup ficou vazio." >&2; exit 1; }
pg_restore --list "$TMP" >/dev/null
mv "$TMP" "$DEST"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$DEST")" > "$(basename "$SUM.tmp")")
mv "$SUM.tmp" "$SUM"
chmod 600 "$DEST" "$SUM"
# Delete only this script's backup files older than retention; never delete arbitrary files.
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'luzaweb-*.dump' -mtime "+$KEEP_DAYS" -print -delete | while IFS= read -r old; do rm -f "$old.sha256"; done
printf 'Backup criado e validado: %s\n' "$DEST"
printf 'Checksum criado: %s\n' "$SUM"
printf 'IMPORTANTE: copia ambos para armazenamento externo privado/cifrado e testa o restauro regularmente. Este script não agenda a execução.\n'
