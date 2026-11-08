# M: malformed input and hostile peers, played by the rogue peer
# (examples/rogue.rs, container `rogue`, 10.201.0.20, AS 64520).
#
# srv-c runs with its real neighbors plus the rogue (gen-m.toml), so every
# scenario also checks that the real sessions survive. Each scenario restores
# srv-c's default config and stops the rogue on exit; the rogue's log is kept
# in out/<run>/<ID>.rogue.

m_restore() {
    rogue_save
    rogue_stop
    srv_c_use ansage.toml
}

# m_begin [srv_c_conf key=value...]: starts the rogue with the script on stdin,
# then srv-c with the rogue as an extra neighbor. Sets M_SINCE once srv-c's
# real sessions are up. M_START: before srv-c started (for the rogue session).
m_begin() {
    allow_flap srv-c
    trap m_restore EXIT
    rogue_start
    M_START=$(now)
    srv_c_conf m "extra=$(rogue_neighbor)" "$@"
    srv_c_use gen-m.toml
    wait_until 30 ansage_established srv-c 10.201.0.2
    wait_until 30 ansage_established srv-c 10.201.0.3
    M_SINCE=$(now)
}

# srv-c's real sessions stayed up since m_begin.
m_real_ok() {
    if log_has srv-c "$M_SINCE" 'addr=10\.201\.0\.[23]:179.*session down'; then
        fail "srv-c lost a real session: $(ansage_logs srv-c "$M_SINCE" | grep 'session down')"
    fi
    ansage_established srv-c 10.201.0.2 || fail "srv-c: session to r1 is not Established"
    ansage_established srv-c 10.201.0.3 || fail "srv-c: session to r2 is not Established"
}

# ansage (srv-c) has a route for PREFIX from the rogue.
m_has_route() { ansage_routes srv-c "$1" | grep -E "^[^ ]+ $ROGUE_ASN" >/dev/null; }

# NOTIFICATIONs srv-c sent to the rogue, "code/subcode" per line, from its log.
m_sent() {
    ansage_logs srv-c "$M_START" | grep 'addr=10.201.0.20:179.*session down: sent NOTIFICATION' |
        sed -E 's/.*\(([0-9]+\/[0-9]+)\).*/\1/'
}

# CPU time of srv-c's ansage in clock ticks (user + system).
ansage_cpu() { on_sh srv-c 'awk "{ print \$14 + \$15 }" /proc/$(pidof ansage)/stat'; }

scenario M1 default - "RFC 7606: malformed attributes -> treat-as-withdraw / discard, session stays"
scn_M1() {
    allow_warn srv-c 'malformed UPDATE, its routes are treated as withdrawn'
    allow_warn srv-c 'malformed attributes discarded'
    m_begin <<'EOF'
accept 30
handshake
announce 10.99.1.0/24 10.99.2.0/24 2001:db8:99:1::/64
run 2
# MED (optional non-transitive) with length 3: treat-as-withdraw (RFC 7606 §7.4)
announce 10.99.1.0/24 2001:db8:99:1::/64 attr=80:4:000001
# AGGREGATOR with length 2: attribute discard (RFC 7606 §7.7), the route stays
announce 10.99.2.0/24 attr=c0:7:0001
run 120
EOF
    wait_log srv-c "$M_START" 'treated as withdrawn \(RFC 7606\) err=attribute length error \(type 4\) .*routes=\["10.99.1.0/24"\] update=[0-9a-f]{20,}' 20
    wait_log srv-c "$M_START" 'treated as withdrawn .*routes=\["2001:db8:99:1::/64"\] update=[0-9a-f]{20,}' 5
    wait_log srv-c "$M_START" 'malformed attributes discarded .*routes=\["10.99.2.0/24"\]' 5
    wait_until 5 eval '[ "$(ansage_received srv-c $ROGUE)" = "1 0" ]'
    m_has_route 10.99.2.0/24 || fail "10.99.2.0/24 is gone (attribute discard must keep it)"
    if m_has_route 10.99.1.0/24; then fail "10.99.1.0/24 still stored (treat-as-withdraw)"; fi
    ansage_established srv-c $ROGUE || fail "rogue session went down"
    [ -z "$(m_sent)" ] || fail "srv-c sent a NOTIFICATION: $(m_sent)"
    rogue_ok
    m_real_ok
}

scenario M2 default - "header errors: bad marker, bad length, bad type -> Message Header Error"
scn_M2() {
    m_begin <<'EOF'
accept 30
handshake
raw 00*16 0013 04         # marker not all ones
expect notification 1/1
expect close
accept 30
handshake
raw ff*16 0012 04         # length 18 < 19
expect notification 1/2
expect close
accept 30
handshake
raw ff*16 0014 04 00      # KEEPALIVE of length 20
expect notification 1/2
expect close
accept 30
handshake
raw ff*16 0013 09         # type 9
expect notification 1/3
expect close
accept 30
handshake
run 120
EOF
    wait_until 40 rogue_has '> run 120'
    rogue_ok
    rogue_has 'recv NOTIFICATION .* 1/2 data=0012$' || fail "no length 18 in the Bad Message Length data"
    rogue_has 'recv NOTIFICATION .* 1/2 data=0014$' || fail "no length 20 in the Bad Message Length data"
    rogue_has 'recv NOTIFICATION .* 1/3 data=09$' || fail "no type 9 in the Bad Message Type data"
    [ "$(m_sent | xargs)" = "1/1 1/2 1/2 1/3" ] || fail "srv-c sent '$(m_sent | xargs)'"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M3 default - "wrong order: UPDATE before OPEN, OPEN twice, OPEN when Established -> FSM Error"
scn_M3() {
    m_begin <<'EOF'
accept 30
expect open
msg update 0000 0000      # UPDATE in OpenSent
expect notification 5/1
expect close
accept 30
open
expect open
open                      # second OPEN in OpenConfirm
expect notification 5/2
expect close
accept 30
handshake
open                      # OPEN in Established
expect notification 5/3
expect close
accept 30
handshake
run 120
EOF
    # Backoff after the failures before Established: 2 s + 4 s.
    wait_until 40 rogue_has '> run 120'
    rogue_ok
    # RFC 6608: the data is the type of the unexpected message.
    rogue_has 'recv NOTIFICATION .* 5/1 data=02$' || fail "5/1 without type UPDATE as data"
    rogue_has 'recv NOTIFICATION .* 5/2 data=01$' || fail "5/2 without type OPEN as data"
    rogue_has 'recv NOTIFICATION .* 5/3 data=01$' || fail "5/3 without type OPEN as data"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M4 default - "bad OPEN: version 3, hold time 1, unknown parameter; unknown capability is fine"
scn_M4() {
    m_begin <<'EOF'
accept 30
expect open
open version=3
expect notification 2/1
expect close
accept 30
expect open
open hold=1
expect notification 2/6
expect close
accept 30
expect open
open param=99:0102        # optional parameter type 99
expect notification 2/4
expect close
accept 30
handshake cap=200:abcd    # unknown capability: ignored (RFC 5492 §5)
run 120
EOF
    # Backoff after three failures before Established: 2 + 4 + 8 s.
    wait_until 50 rogue_has '> run 120'
    rogue_ok
    # RFC 4271 §6.2: Unsupported Version Number carries the version we support.
    rogue_has 'recv NOTIFICATION .* 2/1 data=0004$' || fail "2/1 without version 4 as data"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M5 full - "silent peer: ansage gives up after the OpenSent hold time (240 s)"
scn_M5() {
    m_begin <<'EOF'
accept 30
expect open
expect notification 4/0 timeout=300
expect close
EOF
    rogue_wait 320
    local t_open t_notif
    t_open=$(rogue_time 'recv OPEN')
    t_notif=$(rogue_time 'recv NOTIFICATION')
    local waited
    waited=$(awk -v a="$t_open" -v b="$t_notif" 'BEGIN { printf "%.2f", b - a }')
    measure "silent peer: OPEN to Hold Timer Expired" "$waited"
    awk -v w="$waited" 'BEGIN { exit !(w >= 235 && w <= 245) }' || fail "gave up after $waited s, expected 240 s"
    m_real_ok
}

scenario M6 full - "trickling peer: messages one byte at a time; no busy loop; hold timer on a stalled message"
scn_M6() {
    m_begin <<'EOF'
accept 30
pace 200                  # ~10 s for the OPEN, ~4 s for the KEEPALIVE
handshake
pace 100
announce 10.99.6.0/24
pace 0
run 10
pace 1000                 # 8 bytes over 8 s, then nothing: no complete message
raw ff*8
pace 0
expect notification 4/0 timeout=20
expect close
accept 30
handshake
run 120
EOF
    local cpu0 cpu1 t0
    cpu0=$(ansage_cpu)
    t0=$(now)
    wait_until 40 m_has_route 10.99.6.0/24
    cpu1=$(ansage_cpu)
    measure "CPU while trickling ($(elapsed "$t0") s)" "$((cpu1 - cpu0))" ticks
    [ $((cpu1 - cpu0)) -le 100 ] || fail "ansage used $((cpu1 - cpu0)) ticks while the peer trickled"
    wait_until 40 rogue_has '> run 120'
    rogue_ok
    [ "$(m_sent | xargs)" = "4/0" ] || fail "srv-c sent '$(m_sent | xargs)', expected Hold Timer Expired"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M7 full - "truncated message, then FIN: session down, reconnect, no panic"
scn_M7() {
    m_begin <<'EOF'
accept 30
handshake
raw ff*16 0030 02 0000    # header of a 48-byte UPDATE, 2 bytes of body
close
accept 30
handshake
run 120
EOF
    wait_until 20 rogue_has '> run 120'
    rogue_ok
    assert_log srv-c "$M_START" 'addr=10.201.0.20:179.*session down: connection closed'
    [ -z "$(m_sent)" ] || fail "srv-c sent a NOTIFICATION: $(m_sent)"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M8 full - "odd NOTIFICATION: oversized and non-UTF-8 shutdown text logged safely"
scn_M8() {
    m_begin <<'EOF'
accept 30
handshake
notification 6/2 ff 41*300               # length byte 255, 300 bytes follow
expect close
accept 30
handshake
notification 6/2 06 ff fe c3 28 80 41    # not UTF-8
expect close
accept 30
handshake
run 120
EOF
    # Administrative Shutdown backs off: 2 s + 4 s.
    wait_until 30 rogue_has '> run 120'
    rogue_ok
    local lines
    lines=$(ansage_logs srv-c "$M_START" | grep 'addr=10.201.0.20:179.*peer sent NOTIFICATION')
    [ "$(wc -l <<<"$lines")" = 2 ] || fail "expected 2 NOTIFICATION lines, got:
$lines"
    if LC_ALL=C grep -n '[^[:print:]]' <<<"$lines"; then fail "unprintable bytes in the log"; fi
    info "$(cut -c1-200 <<<"$lines" | sed 's/^.*session down/session down/')"
    wait_until 10 ansage_established srv-c $ROGUE
    m_real_ok
}

scenario M9 full - "65535-byte UPDATE: accepted with and without extended messages (ansage always accepts them)"
scn_M9() {
    m_begin <<'EOF'
accept 30
handshake                 # no Extended Message capability
announce 10.99.9.0/24 size=65535
run 8
close
accept 30
handshake caps=mp4,mp6,rr,as4,ext
announce 10.99.10.0/24 size=65535
run 120
EOF
    wait_until 20 m_has_route 10.99.9.0/24
    wait_until 20 m_has_route 10.99.10.0/24
    rogue_ok
    [ -z "$(m_sent)" ] || fail "srv-c sent a NOTIFICATION: $(m_sent)"
    m_real_ok
}

scenario M10 default - "multicast/reserved prefixes from a peer are ignored"
scn_M10() {
    m_begin <<'EOF'
accept 30
handshake
announce 10.99.10.0/24 224.1.0.0/16 240.0.0.0/8 2001:db8:99::/48 ff02::/16
run 120
EOF
    wait_until 30 eval '[ "$(ansage_received srv-c $ROGUE)" = "1 1" ]'
    local p
    for p in 224.1.0.0/16 240.0.0.0/8 ff02::/16; do
        if m_has_route "$p"; then fail "srv-c stored $p"; fi
    done
    m_has_route 10.99.10.0/24 || fail "srv-c has no 10.99.10.0/24"
    m_has_route 2001:db8:99::/48 || fail "srv-c has no 2001:db8:99::/48"
    rogue_ok
    m_real_ok
}

scenario M11 full - "fuzz corpus live: every input on a session; ansage survives, real sessions stay"
scn_M11() {
    allow_warn srv-c 'malformed'
    local n max=${E2E_M11_MAX:-200}
    n=$(on rogue sh -c 'ls /fuzz/corpus/decode 2>/dev/null | wc -l')
    if [ "$n" = 0 ]; then
        info "SKIP: test/fuzz/corpus/decode is empty (just fuzz decode)"
        return 0
    fi
    info "corpus: $n inputs, replaying $((n < max ? n : max)) (E2E_M11_MAX)"
    m_begin <<EOF
replay /fuzz/corpus/decode max=$max
EOF
    rogue_wait $((max * 3 + 60))
    measure "replay" "'$(rogue_out | grep -o 'replay summary.*')'" ""
    on srv-c pidof ansage >/dev/null || fail "ansage is not running"
    m_real_ok
}
