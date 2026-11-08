#!/usr/bin/env bash
# Tests dist/install.sh against systemd in containers: Debian 12 (systemd
# 252, Type=notify) and Ubuntu 24.04 (systemd 255, Type=notify-reload).
# Uses the musl build (just e2e-build) as a local release (ANSAGE_BASE_URL).
#
# NEVER run these containers with --privileged: a privileged container gets
# the host's /dev/tty*, its getty takes over tty1 and kills the desktop
# session running there. Instead: no devices, SYS_ADMIN only, a private
# cgroup namespace (remounted rw: only the container's own subtree), and
# every getty masked in the image.
set -euo pipefail
cd "$(dirname "$0")/../../.."
bin=target/x86_64-unknown-linux-musl/release/ansage
[ -x "$bin" ] || { echo "build first: just e2e-build" >&2; exit 2; }

work=$(mktemp -d)
trap 'docker rm -f ansage-install-debian ansage-install-ubuntu >/dev/null 2>&1; rm -rf "$work"' EXIT
mkdir -p "$work/rel"
install -m 0755 "$bin" "$work/rel/ansage-x86_64-linux-musl"
install -m 0644 dist/ansage.service dist/install.sh test/e2e/install/ansage.toml test/e2e/install/steps.sh "$work/rel/"
mv "$work/rel/ansage.toml" "$work/rel/steps.sh" "$work/"
(cd "$work/rel" && sha256sum ansage-x86_64-linux-musl ansage.service install.sh >SHA256SUMS)

status=0
for distro in debian:12 ubuntu:24.04; do
    name=ansage-install-${distro%%:*}
    docker build -q -t "$name" - >/dev/null <<EOF
FROM $distro
RUN apt-get update -q && apt-get install -yq --no-install-recommends systemd systemd-sysv curl ca-certificates >/dev/null && apt-get clean \
 && systemctl mask getty@.service serial-getty@.service console-getty.service autovt@.service getty.target systemd-logind.service \
 && useradd -m op
EOF
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker create -t --name "$name" --cap-add SYS_ADMIN --cgroupns=private \
        --tmpfs /run --tmpfs /run/lock \
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
        -v "$work:/t:ro" --entrypoint /bin/sh "$name" \
        -c 'mount -o remount,rw /sys/fs/cgroup && exec /sbin/init' >/dev/null
    if [ "$(docker inspect -f '{{.HostConfig.Privileged}} {{len .HostConfig.Devices}}' "$name")" != "false 0" ]; then
        echo "$name: refusing to boot systemd in a privileged container" >&2
        exit 2
    fi
    docker start "$name" >/dev/null
    for _ in $(seq 30); do
        s=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        case $s in running | degraded) break ;; esac
        sleep 0.5
    done
    echo "== $distro"
    docker exec "$name" sh /t/steps.sh || status=1
    docker rm -f "$name" >/dev/null
done
exit $status
