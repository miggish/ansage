#!/bin/sh
# herald installer: installs or updates herald as a systemd service.
#
#   curl -fsSL https://github.com/miggish/herald/releases/latest/download/install.sh | sudo sh
#   curl -fsSL .../install.sh | sudo sh -s -- --operator "$USER" --config ./herald.toml
#
# Options:
#   --config PATH    install PATH as /etc/herald/herald.toml (checked with the
#                    new binary first; the old one is kept as .bak.<time>)
#   --operator USER  add USER to group herald, for `herald show` etc.
#   --restart        if herald is running and the binary or unit changed,
#                    restart it with `herald upgrade` (refuses if a neighbor
#                    would withdraw our routes; then restart by hand)
#   --binary PATH    install this binary instead of downloading one
#
# Environment:
#   HERALD_VERSION   release tag to install, e.g. v0.1.0 (default: latest)
#   HERALD_BASE_URL  download from here instead of GitHub Releases; must hold
#                    herald-<arch>-linux-musl, herald.service and SHA256SUMS
#
# What it does: creates the system user/group herald, installs
# /usr/local/bin/herald, /etc/herald (root:herald 0750, files 0640: they may
# hold TCP-MD5 keys) and the hardened unit, enables it and starts it once a
# config exists. Safe to run again: only changed files are replaced (old ones
# kept as .bak.<time>), a changed config is applied with a reload, and a
# running herald is not restarted unless --restart is given.

# Everything is in main, called on the last line: a download cut short runs
# nothing.
main() {
    set -eu
    REPO=miggish/herald
    BIN=/usr/local/bin/herald
    ETC=/etc/herald
    CONF=$ETC/herald.toml
    UNIT=/etc/systemd/system/herald.service

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
        *) die "no herald build for $(uname -m)" ;;
    esac
    if [ -n "${HERALD_BASE_URL:-}" ]; then
        base=${HERALD_BASE_URL%/}
    elif [ -n "${HERALD_VERSION:-}" ]; then
        base=https://github.com/$REPO/releases/download/$HERALD_VERSION
    else
        base=https://github.com/$REPO/releases/latest/download
    fi

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT INT TERM
    stamp=$(date +%Y%m%d-%H%M%S)

    # --- download ---------------------------------------------------------
    asset=herald-$arch-linux-musl
    say "downloading from $base"
    fetch "$base/SHA256SUMS" "$work/SHA256SUMS"
    fetch "$base/herald.service" "$work/herald.service"
    if [ -z "$binary" ]; then
        fetch "$base/$asset" "$work/$asset"
        verify "$asset"
        binary=$work/$asset
    fi
    verify herald.service
    chmod 0755 "$binary"
    version=$("$binary" --version) || die "$binary --version failed"

    # --- user and group ---------------------------------------------------
    if ! getent group herald >/dev/null; then
        say "creating group herald"
        groupadd --system herald
    fi
    if ! getent passwd herald >/dev/null; then
        say "creating user herald"
        useradd --system --gid herald --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --comment "herald BGP speaker" herald
    fi
    for u in $operators; do
        getent passwd "$u" >/dev/null || die "operator $u does not exist"
        if ! id -nG "$u" | tr ' ' '\n' | grep -qx herald; then
            say "adding $u to group herald (takes effect at their next login)"
            usermod -aG herald "$u"
        fi
    done

    # --- config -----------------------------------------------------------
    # Checked with the new binary before anything is replaced.
    check=${config:-$CONF}
    if [ -f "$check" ]; then
        "$binary" check -c "$check" || die "$check is not valid for $version"
    fi
    install -d -o root -g herald -m 0750 "$ETC"
    conf_changed=false restart_needed=false
    if [ -n "$config" ] && ! { [ -f "$CONF" ] && cmp -s "$config" "$CONF"; }; then
        backup "$CONF"
        say "installing $CONF"
        install -o root -g herald -m 0640 "$config" "$CONF"
        conf_changed=true
    fi
    for f in "$ETC"/*; do
        case "$f" in *.bak.*) continue ;; esac
        [ -f "$f" ] || continue
        chown root:herald "$f"
        chmod 0640 "$f"
    done

    # --- binary -----------------------------------------------------------
    if [ -f "$BIN" ] && cmp -s "$binary" "$BIN"; then
        say "binary unchanged ($version)"
    else
        say "installing $BIN ($version)"
        # Atomic: a running herald keeps its (old) file.
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
            -e 's|^#ExecReload=|ExecReload=|' "$work/herald.service"
    fi
    if [ -f "$CONF" ] && grep -q '^[[:space:]]*\[kernel\]' "$CONF"; then
        # herald installs routes: it needs CAP_NET_ADMIN and netlink.
        sed -i -e 's/^#\(AmbientCapabilities=CAP_NET_ADMIN\)$/\1/' \
            -e 's/^#\(CapabilityBoundingSet=CAP_NET_ADMIN\)$/\1/' \
            -e 's/^#\(RestrictAddressFamilies=AF_NETLINK\)$/\1/' "$work/herald.service"
    fi
    if [ -f "$UNIT" ] && cmp -s "$work/herald.service" "$UNIT"; then
        say "unit unchanged"
    else
        backup "$UNIT"
        say "installing $UNIT"
        install -o root -g root -m 0644 "$work/herald.service" "$UNIT"
        systemctl daemon-reload
        restart_needed=true
    fi
    systemctl enable --quiet herald

    # --- start ------------------------------------------------------------
    if [ ! -f "$CONF" ]; then
        say "no $CONF yet: write one (README: 'A minimal config'), then"
        echo "      herald check -c $CONF && systemctl start herald"
        return 0
    fi
    # Also when an earlier run replaced the binary or the unit but did not
    # restart: either is newer than the running process. (Not readlink
    # /proc/PID/exe: needs ptrace rights on a process of another user.)
    # Whole seconds: installed in the same second herald started = older.
    started=$(systemctl show -p ExecMainStartTimestamp --value herald 2>/dev/null || true)
    if [ -n "$started" ] && started=$(date -d "$started" +%s 2>/dev/null); then
        for f in "$BIN" "$UNIT"; do
            [ "$(stat -c %Y "$f")" -le "$started" ] || restart_needed=true
        done
    fi
    if ! systemctl is-active --quiet herald; then
        say "starting herald"
        systemctl start herald
    elif $restart_needed && $restart; then
        say "restarting herald with herald upgrade"
        "$BIN" -c "$CONF" upgrade --binary "$BIN" ||
            die "herald upgrade refused or failed (restart by hand: systemctl restart herald)"
    else
        # Also before a pending restart: the running process takes the new
        # config now. If it rejects it, it keeps running with the old one.
        if $conf_changed; then
            say "reloading herald"
            "$BIN" -c "$CONF" reload ||
                die "herald rejected $CONF and runs on with the old config (kept as $CONF.bak.$stamp)"
        fi
        if $restart_needed; then
            say "herald still runs the old binary/unit. To switch:"
            echo "      herald upgrade --dry-run    # which neighbors keep our routes"
            echo "      herald upgrade              # or: systemctl restart herald"
        elif ! $conf_changed; then
            say "herald is running, nothing changed"
        fi
    fi
    systemctl --no-pager --lines=0 status herald || true
}

say() { echo "==> $*"; }
die() { echo "herald install: $*" >&2; exit 1; }
usage() {
    cat <<'EOF'
usage: curl -fsSL .../install.sh | sudo sh -s -- [options]
  --config PATH    install PATH as /etc/herald/herald.toml
  --operator USER  add USER to group herald (may repeat)
  --restart        restart a running herald (herald upgrade) if it changed
  --binary PATH    install this binary instead of downloading one
env: HERALD_VERSION=vX.Y.Z, HERALD_BASE_URL=https://...
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
