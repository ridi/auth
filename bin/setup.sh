#!/usr/bin/env bash

set -e

mysql -uroot -e 'SET GLOBAL max_connections = 5000; CREATE DATABASE IF NOT EXISTS oauth2;'

vendor/bin/phinx migrate -e local
vendor/bin/phinx seed:run -e local
