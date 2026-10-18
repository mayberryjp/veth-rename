#!/bin/sh
set -eu

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
printf '%s\n' 'veth-renamer installed. The service has not been started or restarted.'
printf '%s\n' 'Enable/start: systemctl enable --now veth-renamer.service'
printf '%s\n' 'After an upgrade, restart explicitly: systemctl restart veth-renamer.service'
