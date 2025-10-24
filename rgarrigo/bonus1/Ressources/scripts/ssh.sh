#!/bin/bash

PORT=4244
HOST=127.0.0.1

PWD=$(dirname $(readlink -f $0))
LEVEL_NAME=$(basename $(dirname $(dirname ${PWD})))

export SSH_ASKPASS="${PWD}/askpass.sh"
export SSH_ASKPASS_REQUIRE="force"

ssh -p ${PORT} ${LEVEL_NAME}@${HOST}
