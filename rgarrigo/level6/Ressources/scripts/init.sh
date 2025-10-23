#!/bin/bash

PWD=$(dirname $(readlink -f $0))

${PWD}/scp.sh
${PWD}/dump.sh
