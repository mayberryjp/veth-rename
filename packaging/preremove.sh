#!/bin/sh
set -eu

case "${1:-}" in
    remove|deconfigure)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now veth-renamer.service
        fi
        ;;
esac
