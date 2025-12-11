#!/bin/bash

PWD=$(dirname $(readlink -f $0))
FILES_DIR=${PWD}/../files
DUMP_DIR=${PWD}/../dumps

for file in $(find ${FILES_DIR} -type f -executable); do
    objdump -d ${file} > ${DUMP_DIR}/$(basename ${file}).text
    objdump -s ${file} > ${DUMP_DIR}/$(basename ${file}).dump
done

for file in $(find ${DUMP_DIR} -type f); do
    chmod 440 ${file}
done
