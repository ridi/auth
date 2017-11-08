#!/usr/bin/env bash

DOCKER_TAG=${TRAVIS_TAG:-latest}
COMMIT=${TRAVIS_COMMIT::8}

docker login -e ${DOCKER_EMAIL} -u ${DOCKER_USER} -p ${DOCKER_PASS}
docker build -t ${DOCKER_REPO}:${COMMIT} .

echo "Pushing ${DOCKER_REPO}"
docker tag ${DOCKER_REPO}:${COMMIT} ${DOCKER_REPO}:${DOCKER_TAG}
docker push ${DOCKER_REPO}
echo "Pushed ${DOCKER_REPO}"
