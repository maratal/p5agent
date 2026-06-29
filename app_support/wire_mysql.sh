#!/usr/bin/env bash
# Wire a MySQL database to the app: create a database + user named $DB_NAME and
# write /etc/$DB_NAME.env. Run by install_app.sh for apps that depend on mysql
# and have no installer of their own. Root authenticates via the unix socket on a
# fresh install. db_password / write_db_env come (exported) from install_app.sh.
set -e

env_file="/etc/${DB_NAME}.env"
pass=$(db_password "$env_file")

mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\`;"
mysql -e "CREATE USER IF NOT EXISTS '$DB_NAME'@'localhost' IDENTIFIED BY '$pass';"
mysql -e "ALTER USER '$DB_NAME'@'localhost' IDENTIFIED BY '$pass';"
mysql -e "GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_NAME'@'localhost'; FLUSH PRIVILEGES;"

write_db_env mysql 3306 "$pass"
