#!/bin/bash

PWD=$(dirname $(readlink -f $0))

HOST_PORT=4244
GUEST_IP=10.0.2.15
GUEST_PORT=4242

qemu-system-x86_64															\
	-cdrom ${PWD}/RainFall.iso												\
	-nic user,hostfwd=tcp::${HOST_PORT}-${GUEST_IP}:${GUEST_PORT}
