#!/bin/sh
# Container setup for e2e nodes, from environment variables:
#   ADDRS                  interface addresses, "IF=ADDR/LEN[,ADDR/LEN] ...": the
#                          networks have no IPAM (identical addresses in every
#                          copy of the network), so each node sets its own
#   GW_V4 / GW_V6          default routes (users and servers: their router)
#   SERVICE_V4 / SERVICE_V6 service addresses put on lo (ansage servers)
#   ANSAGE_USER            run ansage as this user (no capabilities), e.g. nobody
#   ANSAGE_SUPERVISED=1    start ansage again when it exits with 75 (`ansage
#                          upgrade`), like systemd RestartForceExitStatus=75
#   ANSAGE_STAY=1          (supervised) keep the container when ansage exits
#                          on its own, so a test can look at what it left
# Then runs the command (default: ansage if a config is mounted, else sleep).
set -eu

for spec in ${ADDRS:-}; do
    dev=${spec%%=*}
    for a in $(echo "${spec#*=}" | tr ',' ' '); do
        ip addr replace "$a" dev "$dev"
    done
done

if [ -n "${SERVICE_V4:-}" ]; then
    ip addr add "$SERVICE_V4/32" dev lo
fi
if [ -n "${SERVICE_V6:-}" ]; then
    ip -6 addr add "$SERVICE_V6/128" dev lo
fi
if [ -n "${GW_V4:-}" ]; then
    ip route replace default via "$GW_V4"
fi
if [ -n "${GW_V6:-}" ]; then
    ip -6 route replace default via "$GW_V6"
fi

if [ -n "${SERVICE_V4:-}${SERVICE_V6:-}" ]; then
    # Answers with the hostname, so tests see which server got the request.
    mkdir -p /www
    hostname > /www/index.html
    httpd -p 80 -h /www
fi

if [ "$#" -gt 0 ]; then
    exec "$@"
fi
if [ -f /etc/ansage.toml ]; then
    # Runtime directory for the control socket (like systemd RuntimeDirectory).
    mkdir -p /run/ansage
    if [ -n "${ANSAGE_USER:-}" ]; then
        chown "$ANSAGE_USER" /run/ansage
    fi
    if [ "${ANSAGE_SUPERVISED:-}" = 1 ]; then
        export ANSAGE_SUPERVISED
        # Forward stop signals; any exit but 75 ends the container.
        stopping=
        trap 'stopping=1; kill -TERM "$pid" 2>/dev/null' TERM INT
        while :; do
            if [ -n "${ANSAGE_USER:-}" ]; then
                su -s /bin/sh "$ANSAGE_USER" -c "exec ansage --config /etc/ansage.toml" &
            else
                ansage --config /etc/ansage.toml &
            fi
            pid=$!
            status=0
            wait "$pid" || status=$?
            # A trap interrupts wait; wait for ansage itself.
            while kill -0 "$pid" 2>/dev/null; do
                status=0
                wait "$pid" || status=$?
            done
            if [ -z "$stopping" ] && [ "$status" != 75 ] && [ "${ANSAGE_STAY:-}" = 1 ]; then
                exec sleep infinity
            fi
            if [ -n "$stopping" ] || [ "$status" != 75 ]; then
                exit "$status"
            fi
        done
    fi
    # Not PID 1 (compose `init: true`), so `kill -9` reaches ansage.
    if [ -n "${ANSAGE_USER:-}" ]; then
        exec su -s /bin/sh "$ANSAGE_USER" -c "exec ansage --config /etc/ansage.toml"
    fi
    exec ansage --config /etc/ansage.toml
fi
exec sleep infinity
