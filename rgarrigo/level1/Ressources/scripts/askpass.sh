#/bin/bash

PWD=$(dirname $(readlink -f $0))
LEVEL_NAME=$(basename $(dirname $(dirname ${PWD})))

if [ ${LEVEL_NAME##level} != ${LEVEL_NAME} ]; then
    LEVEL_ID=${LEVEL_NAME##level}
    PREVIOUS_LEVEL_ID=$(echo "${LEVEL_ID} - 1" | bc)
    PREVIOUS_LEVEL_NAME=level${PREVIOUS_LEVEL_ID}
else
    LEVEL_ID=${LEVEL_NAME##bonus}
    if [ ${LEVEL_ID} -eq 0 ]; then
        PREVIOUS_LEVEL_NAME=level9
    else
        PREVIOUS_LEVEL_ID=$(echo "${LEVEL_ID} - 1" | bc)
        PREVIOUS_LEVEL_NAME=bonus${LEVEL_ID}
    fi
fi
FLAG_FILE=${PWD}/../../../${PREVIOUS_LEVEL_NAME}/flag

cat ${FLAG_FILE}
