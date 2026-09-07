#!/bin/sh
# Startet acme-helper als unprivilegierter Benutzer.
# PUID/PGID (Unraid-Konvention) bestimmen den Besitzer von /data; Default 1000:1000.
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$(id -u)" = "0" ]; then
    if [ "$(id -g acme)" != "$PGID" ]; then
        groupmod -o -g "$PGID" acme
    fi
    if [ "$(id -u acme)" != "$PUID" ]; then
        usermod -o -u "$PUID" acme
    fi
    chown -R "$PUID:$PGID" /data 2>/dev/null || true
    chown "$PUID:$PGID" /config 2>/dev/null || true   # read-only Mounts werden ignoriert
    exec gosu "$PUID:$PGID" acme-helper "$@"
fi

exec acme-helper "$@"
