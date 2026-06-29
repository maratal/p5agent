#!/usr/bin/env bash
# Wire a PostgreSQL database to the app: create a role + database named $DB_NAME
# and write /etc/$DB_NAME.env. Run by install_app.sh for apps that depend on
# postgresql and have no installer of their own. db_password / write_db_env are
# provided (exported) by install_app.sh.
set -e

env_file="/etc/${DB_NAME}.env"
pass=$(db_password "$env_file")

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_NAME'" | grep -q 1; then
    echo "Creating role $DB_NAME"
    sudo -u postgres psql -c "CREATE USER \"$DB_NAME\" WITH PASSWORD '$pass';"
fi
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
    echo "Creating database $DB_NAME"
    sudo -u postgres psql -c "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_NAME\";"
fi

write_db_env postgres 5432 "$pass"
