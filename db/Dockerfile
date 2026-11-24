FROM postgres:15

# Copy initialization scripts in order (Postgres runs them alphabetically)
# 01-init.sql: creates tables and seeds initial data
# 02-db_roles.sh: creates app_user and app_admin roles with least privilege
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql
COPY db_roles.sh /docker-entrypoint-initdb.d/02-db_roles.sh

# Convert Windows line endings (CRLF) to Unix (LF) for shell scripts
RUN sed -i 's/\r$//' /docker-entrypoint-initdb.d/02-db_roles.sh
RUN chmod +x /docker-entrypoint-initdb.d/02-db_roles.sh

# Ensure PostgreSQL listens on all interfaces (required for external connections)
RUN echo "listen_addresses = '*'" >> /usr/share/postgresql/postgresql.conf.sample