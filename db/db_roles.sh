#!/bin/sh
set -eu

: "${APP_USER_PASSWORD:?APP_USER_PASSWORD is required}"
: "${APP_ADMIN_PASSWORD:?APP_ADMIN_PASSWORD is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"

APP_USER_PASSWORD_SQL=$(printf '%s' "$APP_USER_PASSWORD" | sed "s/'/''/g")
APP_ADMIN_PASSWORD_SQL=$(printf '%s' "$APP_ADMIN_PASSWORD" | sed "s/'/''/g")

SQL_FILE=$(mktemp)

cat > "$SQL_FILE" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    EXECUTE format('CREATE ROLE app_user LOGIN PASSWORD %L', '__APP_USER_PASSWORD__');
  ELSE
    EXECUTE format('ALTER ROLE app_user LOGIN PASSWORD %L', '__APP_USER_PASSWORD__');
  END IF;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_admin') THEN
    EXECUTE format('CREATE ROLE app_admin LOGIN PASSWORD %L', '__APP_ADMIN_PASSWORD__');
  ELSE
    EXECUTE format('ALTER ROLE app_admin LOGIN PASSWORD %L', '__APP_ADMIN_PASSWORD__');
  END IF;
END
$$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO app_user, app_admin;

GRANT SELECT, INSERT ON users TO app_user;
GRANT SELECT ON documents TO app_user;
GRANT SELECT ON document_shares TO app_user;

GRANT INSERT ON documents TO app_user;
GRANT INSERT ON document_shares TO app_user;

GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO app_user;
GRANT USAGE, SELECT ON SEQUENCE documents_id_seq TO app_user;
GRANT USAGE, SELECT ON SEQUENCE document_shares_id_seq TO app_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON document_shares TO app_admin;

GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE documents_id_seq TO app_admin;
GRANT USAGE, SELECT ON SEQUENCE document_shares_id_seq TO app_admin;
SQL

sed -i "s|__APP_USER_PASSWORD__|$APP_USER_PASSWORD_SQL|g; s|__APP_ADMIN_PASSWORD__|$APP_ADMIN_PASSWORD_SQL|g" "$SQL_FILE"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -f "$SQL_FILE"

rm -f "$SQL_FILE"