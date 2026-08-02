#!/bin/sh
set -eu

PURGE=false
case "${1:-}" in
    "") ;;
    --purge) PURGE=true ;;
    --help|-h)
        echo "usage: relayward-agent-uninstall [--purge]"
        echo "--purge also removes configuration, identity, local state, and the service account"
        exit 0
        ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "relayward-agent-uninstall must run as root" >&2
    exit 1
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    init_system=systemd
elif [ -d /run/openrc ] && command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    init_system=openrc
else
    echo "unsupported init system: refusing to remove a potentially running service" >&2
    exit 1
fi

if [ "$init_system" = systemd ]; then
    systemctl disable --now relayward-agent.service 2>/dev/null || true
else
    rc-service relayward-agent stop 2>/dev/null || true
    rc-update del relayward-agent default 2>/dev/null || true
fi
rm -f /etc/systemd/system/relayward-agent.service /etc/init.d/relayward-agent
if [ "$init_system" = systemd ]; then
    systemctl daemon-reload
    systemctl reset-failed relayward-agent.service 2>/dev/null || true
fi
rm -f /etc/relayward-agent/runtime-assets.sha256
rm -f /usr/local/bin/relayward-agent /usr/local/sbin/relayward-agent-uninstall
rm -f /usr/local/libexec/relayward-agent-launcher

if [ "$PURGE" = true ]; then
    rm -rf /etc/relayward-agent /var/lib/relayward-agent
    if [ "$init_system" = systemd ]; then
        userdel relayward-agent 2>/dev/null || true
        groupdel relayward-agent 2>/dev/null || true
    else
        deluser relayward-agent 2>/dev/null || true
        delgroup relayward-agent 2>/dev/null || true
    fi
fi

echo "Relayward Agent removed; revoke its node credential in the center if needed"
