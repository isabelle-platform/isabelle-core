#!/bin/bash
if [ "$1" == "" ] ; then
    echo No database >&2
    exit 1
fi
# Only this stand's own container, by its exact name. Matching "mongo"
# anywhere in `docker ps` also caught other stands' databases on the same
# machine, and would have stopped and deleted them.
docker rm -f "mongo-${1}" > /dev/null 2>&1 || true
# 8.2, not 8.0: mongod 8.0 refuses to start on a Linux kernel of 6.19 or
# newer (SERVER-121912), and that is what Docker Desktop's VM runs now. 8.2
# opens data written by 8.0 and leaves its compatibility version at 8.0, so a
# stand can still go back. MONGO_IMAGE picks another one.
#
# mongod runs as root, straight from the entrypoint. The image's own start-up
# drops to its `mongodb` user, which owns the files only while Docker Desktop
# maps ownership for it; once it stops doing that (it did, after a restart)
# every data file is root's with mode 600 and mongod dies with "Operation
# not permitted" on WiredTiger.wt. This is a development database on the
# developer's own disk: root in its own container is not a concern there.
docker run -p 27017:27017 \
           --name mongo-${1} \
           -v "$(realpath ../${1}-data):/data/db" \
           --user 0:0 --entrypoint mongod \
           -d "${MONGO_IMAGE:-mongo:8.2}" --bind_ip_all --dbpath /data/db

