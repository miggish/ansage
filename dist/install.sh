#!/bin/sh
# ansage installer: installs or updates ansage as a systemd service.
#
#   curl -fsSL https://github.com/miggish/ansage/releases/latest/download/install.sh | sudo sh
#   curl -fsSL .../install.sh | sudo sh -s -- --operator "$USER" --config ./ansage.toml
#
# Options:
#   --config PATH    install PATH as /etc/ansage/ansage.toml (checked with the
#                    new binary first; the old one is kept as .bak.<time>)
#   --operator USER  add USER to group ansage, for `ansage show` etc.
#   --restart        if ansage is running and the binary or unit changed,
#                    restart it with `ansage upgrade` (refuses if a neighbor
#                    would withdraw our routes; then restart by hand)
#   --binary PATH    install this binary instead of downloading one
#
# Environment:
#   ANSAGE_VERSION   release tag to install, e.g. v0.1.0 (default: latest)
#   ANSAGE_BASE_URL  download from here instead of GitHub Releases; must hold
#                    ansage-<arch>-linux-musl, ansage.service and SHA256SUMS
#
# What it does: creates the system user/group ansage, installs
# /usr/local/bin/ansage, /etc/ansage (root:ansage 0750, files 0640: they may
# hold TCP-MD5 keys) and the hardened unit, enables it and starts it once a
# config exists. Safe to run again: only changed files are replaced (old ones
# kept as .bak.<time>), a changed config is applied with a reload, and a
# running ansage is not restarted unless --restart is given.

# Everything is in main, called on the last line: a download cut short runs
# nothing.
main() {
    set -eu
    REPO=miggish/ansage
    BIN=/usr/local/bin/ansage
    ETC=/etc/ansage
    CONF=$ETC/ansage.toml
    UNIT=/etc/systemd/system/ansage.service

    binary="" config="" operators="" restart=false
    while [ $# -gt 0 ]; do
        case "$1" in
            --binary) [ $# -ge 2 ] || die "--binary needs a path"; binary=$2; shift 2 ;;
            --config) [ $# -ge 2 ] || die "--config needs a path"; config=$2; shift 2 ;;
            --operator) [ $# -ge 2 ] || die "--operator needs a user"; operators="$operators $2"; shift 2 ;;
            --restart) restart=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown argument: $1 (see --help)" ;;
        esac
    done

    [ "$(id -u)" = 0 ] || die "must run as root (curl ... | sudo sh)"
    command -v systemctl >/dev/null || die "systemd is required"
    PATH=$PATH:/usr/sbin:/sbin
    [ -z "$config" ] || [ -f "$config" ] || die "$config not found"

    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) die "no ansage build for $(uname -m)" ;;
    esac
    if [ -n "${ANSAGE_BASE_URL:-}" ]; then
        base=${ANSAGE_BASE_URL%/}
    elif [ -n "${ANSAGE_VERSION:-}" ]; then
        base=https://github.com/$REPO/releases/download/$ANSAGE_VERSION
    else
        base=https://github.com/$REPO/releases/latest/download
    fi

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT INT TERM
    stamp=$(date +%Y%m%d-%H%M%S)

    # --- download ---------------------------------------------------------
    asset=ansage-$arch-linux-musl
    say "downloading from $base"
    fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
    fetch "$base/ansage.service" "$work/ansage.service"
    if [ -z "$binary" ]; then
        fetch "$base/$asset" "$work/$asset"
        verify "$asset"
        binary=$work/$asset
    fi
    verify ansage.service
    chmod 0755 "$binary"
    version=$("$binary" --version) || die "$binary --version failed"

    # --- user and group ---------------------------------------------------
    if ! getent group ansage >/dev/null; then
        say "creating group ansage"
        groupadd --system ansage
    fi
    if ! getent passwd ansage >/dev/null; then
        say "creating user ansage"
        useradd --system --gid ansage --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --comment "ansage BGP speaker" ansage
    fi
    for u in $operators; do
        getent passwd "$u" >/dev/null || die "operator $u does not exist"
        if ! id -nG "$u" | tr ' ' '\n' | grep -qx ansage; then
            say "adding $u to group ansage (takes effect at their next login)"
            usermod -aG ansage "$u"
        fi
    done

    # --- config -----------------------------------------------------------
    # Checked with the new binary before anything is replaced.
    check=${config:-$CONF}
    if [ -f "$check" ]; then
        "$binary" check -c "$check" || die "$check is not valid for $version"
    fi
    install -d -o root -g ansage -m 0750 "$ETC"
    conf_changed=false restart_needed=false
    if [ -n "$config" ] && ! { [ -f "$CONF" ] && cmp -s "$config" "$CONF"; }; then
        backup "$CONF"
        say "installing $CONF"
        install -o root -g ansage -m 0640 "$config" "$CONF"
        conf_changed=true
    fi
    for f in "$ETC"/*; do
        case "$f" in *.bak.*) continue ;; esac
        [ -f "$f" ] || continue
        chown root:ansage "$f"
        chmod 0640 "$f"
    done

    # --- binary -----------------------------------------------------------
    if [ -f "$BIN" ] && cmp -s "$binary" "$BIN"; then
        say "binary unchanged ($version)"
    else
        say "installing $BIN ($version)"
        # Atomic: a running ansage keeps its (old) file.
        install -o root -g root -m 0755 "$binary" "$BIN.new"
        mv -f "$BIN.new" "$BIN"
        restart_needed=true
    fi
    chown root:root "$BIN"
    chmod 0755 "$BIN"

    # --- unit -------------------------------------------------------------
    sysd=$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')
    if [ -n "$sysd" ] && [ "$sysd" -lt 253 ]; then
        # No Type=notify-reload before systemd 253.
        sed -i -e 's/^Type=notify-reload$/Type=notify/' \
            -e 's|^#ExecReload=|ExecReload=|' "$work/ansage.service"
    fi
    if [ -f "$CONF" ] && grep -q '^[[:space:]]*\[kernel\]' "$CONF"; then
        # ansage installs routes: it needs CAP_NET_ADMIN and netlink.
        sed -i -e 's/^#\(AmbientCapabilities=CAP_NET_ADMIN\)$/\1/' \
            -e 's/^#\(CapabilityBoundingSet=CAP_NET_ADMIN\)$/\1/' \
            -e 's/^#\(RestrictAddressFamilies=AF_NETLINK\)$/\1/' "$work/ansage.service"
    fi
    if [ -f "$UNIT" ] && cmp -s "$work/ansage.service" "$UNIT"; then
        say "unit unchanged"
    else
        backup "$UNIT"
        say "installing $UNIT"
        install -o root -g root -m 0644 "$work/ansage.service" "$UNIT"
        systemctl daemon-reload
        restart_needed=true
    fi
    systemctl enable --quiet ansage

    # --- start ------------------------------------------------------------
    if [ ! -f "$CONF" ]; then
        say "no $CONF yet: write one (README: 'A minimal config'), then"
        echo "      ansage check -c $CONF && systemctl start ansage"
        return 0
    fi
    # Also when an earlier run replaced the binary or the unit but did not
    # restart: either is newer than the running process. (Not readlink
    # /proc/PID/exe: needs ptrace rights on a process of another user.)
    # Whole seconds: installed in the same second ansage started = older.
    started=$(systemctl show -p ExecMainStartTimestamp --value ansage 2>/dev/null || true)
    if [ -n "$started" ] && started=$(date -d "$started" +%s 2>/dev/null); then
        for f in "$BIN" "$UNIT"; do
            [ "$(stat -c %Y "$f")" -le "$started" ] || restart_needed=true
        done
    fi
    if ! systemctl is-active --quiet ansage; then
        say "starting ansage"
        systemctl start ansage
    elif $restart_needed && $restart; then
        say "restarting ansage with ansage upgrade"
        "$BIN" -c "$CONF" upgrade --binary "$BIN" ||
            die "ansage upgrade refused or failed (restart by hand: systemctl restart ansage)"
    else
        # Also before a pending restart: the running process takes the new
        # config now. If it rejects it, it keeps running with the old one.
        if $conf_changed; then
            say "reloading ansage"
            "$BIN" -c "$CONF" reload ||
                die "ansage rejected $CONF and runs on with the old config (kept as $CONF.bak.$stamp)"
        fi
        if $restart_needed; then
            say "ansage still runs the old binary/unit. To switch:"
            echo "      ansage upgrade --dry-run    # which neighbors keep our routes"
            echo "      ansage upgrade              # or: systemctl restart ansage"
        elif ! $conf_changed; then
            say "ansage is running, nothing changed"
        fi
    fi
    systemctl --no-pager --lines=0 status ansage || true
}

say() { echo "==> $*"; }
die() { echo "ansage install: $*" >&2; exit 1; }
usage() {
    cat <<'EOF'
usage: curl -fsSL .../install.sh | sudo sh -s -- [options]
  --config PATH    install PATH as /etc/ansage/ansage.toml
  --operator USER  add USER to group ansage (may repeat)
  --restart        restart a running ansage (ansage upgrade) if it changed
  --binary PATH    install this binary instead of downloading one
env: ANSAGE_VERSION=vX.Y.Z, ANSAGE_BASE_URL=https://...
EOF
}
fetch() {
    if command -v curl >/dev/null; then
        curl -fsSL --proto '=https,file' --tlsv1.2 -o "$2" "$1" || die "download failed: $1"
    elif command -v wget >/dev/null; then
        wget -q --https-only -O "$2" "$1" || die "download failed: $1"
    else
        die "need curl or wget"
    fi
}
# Checks $work/$1 against SHA256SUMS.
verify() {
    want=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS")
    [ -n "$want" ] || die "$1 is not in SHA256SUMS"
    have=$(sha256sum "$work/$1" | awk '{ print $1 }')
    [ "$want" = "$have" ] || die "checksum mismatch for $1"
}
backup() {
    [ -f "$1" ] || return 0
    cp -p "$1" "$1.bak.$stamp"
    say "old $1 kept as $1.bak.$stamp"
}

main "$@"
