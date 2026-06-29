#!/usr/bin/env bash
# Wire SQLite — no server or credentials, just a data dir and DB file path, with
# its location written to /etc/$DB_NAME.env. Run by install_app.sh for apps that
# depend on sqlite and have no installer of their own.
set -e

data_dir="/var/lib/${DB_NAME}"
db_file="${data_dir}/db.sqlite"
mkdir -p "$data_dir"
echo "SQLite database at $db_file"

( umask 077; cat > "/etc/${DB_NAME}.env" <<EOF
DATABASE_PATH=$db_file
DATABASE_URL=sqlite://$db_file
EOF
)
echo "Wrote DB connection settings to /etc/${DB_NAME}.env"
