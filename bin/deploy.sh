#!/usr/bin/env bash

# Migrate DB
export PHINX_DBHOST=${OAUTH_DBHOST}
export PHINX_DBPORT=${OAUTH_DBPORT:-3306}
export PHINX_DBNAME=${OAUTH_DBNAME}
export PHINX_DBUSER=${OAUTH_DBUSER}
export PHINX_DBPASS=${OAUTH_DBPASS}
if ! vendor/bin/phinx migrate -e prod; then
    printf '%s\n' 'DB migration failed!' >&2
    exit 1
fi

# Deploy to AWS ECS
export DOCKER_TAG=${TRAVIS_TAG:-latest}
if ! [ -x "$(command -v ecs-cli)" ]; then
    UNAME_RESULT=`uname`
    if [[ "${UNAME_RESULT}" == 'Darwin' ]]; then
       PLATFORM='darwin'
    else
       PLATFORM='linux'
    fi
    curl -o ecs-cli https://s3.amazonaws.com/amazon-ecs-cli/ecs-cli-${PLATFORM}-amd64-latest && chmod +x ecs-cli
    ./ecs-cli compose up -c ${AWS_ECS_CLUSTER}
else
    ecs-cli compose up -c ${AWS_ECS_CLUSTER}
fi
