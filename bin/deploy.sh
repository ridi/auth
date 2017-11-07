#!/usr/bin/env bash

# Migrate DB
export PHINX_DBHOST=${OAUTH_DBHOST}
export PHINX_DBPORT=${OAUTH_DBPORT:-3306}
export PHINX_DBNAME=${OAUTH_DBNAME}
export PHINX_DBUSER=${OAUTH_DBUSER}
export PHINX_DBPASS=${OAUTH_DBPASS}
vendor/bin/phinx migrate -e prod

# Deploy to AWS ECS
if ! [ -x "$(command -v ecs-cli)" ]; then
    UNAME_RESULT=`uname`
    if [[ "${UNAME_RESULT}" == 'Darwin' ]]; then
       PLATFORM='darwin'
    else
       PLATFORM='linux'
    fi
    sudo curl -o /usr/local/bin/ecs-cli https://s3.amazonaws.com/amazon-ecs-cli/ecs-cli-${PLATFORM}-amd64-latest
    sudo chmod +x /usr/local/bin/ecs-cli
fi

export DOCKER_TAG=${TRAVIS_TAG:-latest}
ecs-cli compose --file docker-compose.yml up -p ${TRAVIS_REPO_SLUG} -c ${AWS_ECS_CLUSTER}
