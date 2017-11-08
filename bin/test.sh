#!/usr/bin/env bash

# Set up
vendor/bin/phinx migrate -e local
vendor/bin/phinx seed:run -e local

# Run PHPUnit
composer run-script test
PHPUNIT_RESULT=$?
if [ ${PHPUNIT_RESULT} -ne 0 ]; then
    printf '%s\n' 'Unit test failed!' >&2
    exit ${PHPUNIT_RESULT}
fi

# Run Newman
php -S localhost:8010 -t tests/integration/web & TEST_WEB_PID=$!
newman run tests/integration/postman/Performance_Auth_Test.postman_collection.json -e tests/integration/postman/local.postman_environment.json --ignore-redirects
NEWMAN_RESULT=$?
kill ${TEST_WEB_PID}
if [ ${NEWMAN_RESULT} -ne 0 ]; then
    printf '%s\n' 'Integration test failed!' >&2
    exit ${NEWMAN_RESULT}
fi

