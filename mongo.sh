#!/bin/bash
if [ "$1" == "" ] ; then
    echo No database >&2
    exit 1
fi
cont="$(docker ps -a | grep mongo | awk '{print $1;}')"
if [ "$cont" != "" ] ; then
    docker stop "$cont"
    docker rm "$cont"
fi
docker run -p 27017:27017 \
           --name mongo-${1} \
           -v "$(realpath ../${1}-data):/data/db" \
           -d mongo:8.0

