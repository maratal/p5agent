#!/usr/bin/env bash
# Wire a MariaDB database — identical to MySQL (same `mysql` CLI and protocol).
set -e
exec bash "$(cd "$(dirname "$0")" && pwd)/wire_mysql.sh"
