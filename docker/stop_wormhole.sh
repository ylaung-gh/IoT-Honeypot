#!/bin/bash

for container in "$@"
do
    docker-compose -f compose-wormholes.yml stop $container
done