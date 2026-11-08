#!/bin/sh
# Installer test steps; run.sh runs this inside a systemd container.
# /t (read-only): rel/ (a local "release": binary, unit, installer,
# SHA256SUMS) and ansage.toml.
set -u
export ANSAGE_BASE_URL=file:///t/rel
INSTALL="sh /t/rel/install.sh"
CONF=/etc/ansage/ansage.toml
failed=0 out=/tmp/out

step() { echo "-- $*"; }
ok() { echo "   ok: $*"; }
bad() { echo "   FAIL: $*"; failed=$((failed + 1)); }
# expect WHAT CMD...: CMD exits 0.
expect() { w=$1; shift; if "$@" >/dev/null 2>&1; then ok "$w"; else bad "$w"; fi; }
# install EXPECTED_EXIT ARGS...: runs the installer, output in $out.
run_install() {
    want=$1; shift
    $INSTALL "$@" >"$out" 2>&1; rc=$?
    if [ "$rc" = "$want" ]; then ok "installer exit $rc"; else bad "installer exit $rc, want $want"; sed 's/^/      /' "$out"; fi
}
said() { grep -q -- "$1" "$out"; }
pid() { systemctl show -p MainPID --value ansage; }
reloads() { journalctl -u ansage --no-pager -o cat | grep -c "config reloaded"; }

sysd=$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')
echo "systemd $sysd"

step "1. fresh install, no config"
run_install 0 --operator op
expect "enabled" systemctl is-enabled ansage
expect "not started without a config" sh -c '! systemctl is-active ansage'
if [ "$sysd" -lt 253 ]; then
    expect "Type=notify + ExecReload" sh -c 'grep -qx Type=notify /etc/systemd/system/ansage.service && grep -q "^ExecReload=/usr/local/bin/ansage .* reload$" /etc/systemd/system/ansage.service'
else
    expect "Type=notify-reload" grep -qx Type=notify-reload /etc/systemd/system/ansage.service
fi

step "2. with config: starts, permissions, operator"
run_install 0 --config /t/ansage.toml --operator op
sleep 1
expect "active" systemctl is-active ansage
expect "/etc/ansage root:ansage 0750" sh -c '[ "$(stat -c %U:%G:%a /etc/ansage)" = root:ansage:750 ]'
expect "config root:ansage 0640" sh -c "[ \"\$(stat -c %U:%G:%a $CONF)\" = root:ansage:640 ]"
expect "op in group ansage" sh -c 'id -nG op | grep -qw ansage'
expect "op can use the control socket" su op -s /bin/sh -c "ansage -c $CONF show summary"

step "3. rerun, nothing changed"
run_install 0 --config /t/ansage.toml
expect "says nothing changed" said "nothing changed"

step "4. changed config: reloaded, old one kept"
r=$(reloads)
sed 's/hold_time = 90/hold_time = 60/' /t/ansage.toml >/tmp/h2.toml
run_install 0 --config /tmp/h2.toml
expect "reloaded" sh -c "[ \$(journalctl -u ansage --no-pager -o cat | grep -c 'config reloaded') -gt $r ]"
expect "backup kept" sh -c "ls $CONF.bak.* >/dev/null"

step "5. invalid config refused, old one stays"
echo 'asn = "x"' >/tmp/bad.toml
run_install 1 --config /tmp/bad.toml
expect "config unchanged" grep -q "hold_time = 60" $CONF

step "6. new binary without --restart: installed, not restarted"
cp /t/rel/ansage-x86_64-linux-musl /tmp/ansage-new && printf '\0' >>/tmp/ansage-new
p=$(pid)
run_install 0 --binary /tmp/ansage-new
expect "same process" sh -c "[ \$(systemctl show -p MainPID --value ansage) = $p ]"
expect "hint to upgrade" said "still runs the old binary"

step "6b. config change while a restart is pending: reloaded anyway"
r=$(reloads)
sed 's/hold_time = 90/hold_time = 45/' /t/ansage.toml >/tmp/h3.toml
run_install 0 --config /tmp/h3.toml
expect "reloaded" sh -c "[ \$(journalctl -u ansage --no-pager -o cat | grep -c 'config reloaded') -gt $r ]"
expect "hint still there" said "still runs the old binary"

step "7. rerun with --restart: ansage upgrade"
run_install 0 --binary /tmp/ansage-new --restart
expect "upgrade done" said "Upgrade done"
expect "new process" sh -c "[ \$(systemctl show -p MainPID --value ansage) != $p ]"
expect "active" systemctl is-active ansage

step "8. bad checksum refused"
mkdir -p /tmp/rel && cp /t/rel/* /tmp/rel/ && printf x >>/tmp/rel/ansage-x86_64-linux-musl
ANSAGE_BASE_URL=file:///tmp/rel; run_install 1; ANSAGE_BASE_URL=file:///t/rel
expect "says checksum mismatch" said "checksum mismatch"

step "9. systemctl reload, sandbox"
expect "systemctl reload" systemctl reload ansage
expect "active" systemctl is-active ansage
systemd-analyze security ansage 2>/dev/null | tail -1

echo "failed: $failed"
[ "$failed" = 0 ]
