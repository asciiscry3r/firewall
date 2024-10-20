#!/usr/bin/env bash

[ -z "$CONNECTION_UUID" ] && exit 0

INTERFACE="$1"
ACTION="$2"

case $ACTION in
    up)
	systemctl restart simplestatefulfirewall.service
	;;
    down)
	systemctl restart simplestatefulfirewall.service
	;;
esac
