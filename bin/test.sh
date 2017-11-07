#!/usr/bin/env bash

# Set up
service mysql start
mysql -uroot -proot -e 'CREATE DATABASE IF NOT EXISTS oauth2_db'
composer install
composer run-script phinx

# Run phpunit
composer run-script test

# Run Postman
php -S localhost:8000 -t tests/integration/web & TEST_WEB_PID=$!
newman run tests/integration/postman/Performance_Auth_Test.postman_collection.json -e tests/integration/postman/local.postman_environment.json --ignore-redirects
kill $TEST_WEB_PID
