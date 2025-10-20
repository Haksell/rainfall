#!/bin/bash

PORT=4244
HOST=127.0.0.1

PWD=$(dirname $(readlink -f $0))
FILES_DIR=${PWD}/../files
LEVEL_NAME=$(basename $(dirname $(dirname ${PWD})))

export SSH_ASKPASS="${PWD}/askpass.sh"
export SSH_ASKPASS_REQUIRE="force"

scp -P ${PORT} "${LEVEL_NAME}@${HOST}:~/*" ${FILES_DIR}/
scp -P ${PORT} "${LEVEL_NAME}@${HOST}:~/.*" ${FILES_DIR}/

for file in $(find ${FILES_DIR} -type f); do
    chmod 440 ${file}
done
