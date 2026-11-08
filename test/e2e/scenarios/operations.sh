# O: process and operations.

# o_bad_config NAME EXPECTED_REGEX TOML: ansage must refuse TOML quickly
# (exit != 0 within 3 s), say why (EXPECTED_REGEX) and not start sessions.
o_bad_config() {
    local name=$1 want=$2 toml=$3 out rc
    out=$(on srv-c sh -c "cat >/tmp/o1.toml; timeout 3 ansage --config /tmp/o1.toml 2>&1; echo rc=\$?" <<<"$toml")
    rc=$(sed -n 's/^rc=//p' <<<"$out")
    [ "$rc" != 0 ] && [ "$rc" != 124 ] && [ "$rc" != 143 ] || fail "O1 $name: exit code $rc (124/143 = still running)
$out"
    grep -E "$want" <<<"$out" >/dev/null || fail "O1 $name: message does not match '$want':
$out"
    if grep -E 'connecting|ansage started' <<<"$out"; then fail "O1 $name: partial start"; fi
    log "$name: $(grep ERROR <<<"$out" | head -1 | sed 's/.*ERROR ansage: //')"
}

O1_BASE='asn = 64502
router_id = "203.0.113.23"'
O1_NEIGHBOR='[[neighbor]]
address = "10.201.0.2"
asn = 64510'

scenario O1 default - "invalid config: exits non-zero with a clear message, no partial start"
scn_O1() {
    local out
    out=$(on srv-c sh -c 'timeout 3 ansage --config /nonexistent 2>&1; echo rc=$?')
    [[ $out == *"rc=1"* && $out == *"No such file"* ]] || fail "missing file: $out"
    o_bad_config "broken TOML" 'parsing /tmp/o1.toml' 'asn = '
    o_bad_config "unknown field" 'unknown field `colour`' "$O1_BASE
colour = 1"
    o_bad_config "missing asn" 'missing field `asn`' 'router_id = "203.0.113.23"'
    o_bad_config "asn 0" 'asn must not be 0' 'asn = 0
router_id = "203.0.113.23"'
    o_bad_config "bad router_id" 'router_id|invalid' 'asn = 1
router_id = "1.2.3"'
    o_bad_config "host bits in prefix" '192.0.2.1/24' "$O1_BASE
announce = [\"192.0.2.1/24\"]"
    o_bad_config "prefix twice" 'announced twice' "$O1_BASE
announce = [\"192.0.2.0/24\", \"192.0.2.0/24\"]"
    o_bad_config "hold time 2" 'hold_time' "$O1_BASE
hold_time = 2"
    o_bad_config "connect_retry 0" 'connect_retry' "$O1_BASE
connect_retry = 0"
    o_bad_config "max below connect_retry" 'max_connect_retry' "$O1_BASE
connect_retry = 60
max_connect_retry = 10"
    o_bad_config "neighbor twice" 'configured twice' "$O1_BASE
$O1_NEIGHBOR
$O1_NEIGHBOR"
    o_bad_config "neighbor without asn" 'missing field `asn`' "$O1_BASE
[[neighbor]]
address = \"10.201.0.2\""
    o_bad_config "next hop is the neighbor" 'next hop is the neighbor itself' "$O1_BASE
$O1_NEIGHBOR
next_hop_ipv4 = \"10.201.0.2\""
    o_bad_config "link-local as global next hop" 'next_hop_ipv6 must be a global' "$O1_BASE
$O1_NEIGHBOR
next_hop_ipv6 = \"fe80::1\""
    o_bad_config "unknown import policy" 'import|unknown variant' "$O1_BASE
$O1_NEIGHBOR
import = \"some\""
}

# Exit code of a stopped service's container.
exit_code() { state_of "$1" ExitCode; }

scenario O2 default - "SIGINT and SIGTERM: Cease sent, exit 0"
scn_O2() {
    allow_flap srv-a
    trap 'server_start srv-a' EXIT
    local sig mark
    for sig in INT TERM; do
        mark=$(frr_log_mark r1)
        on_sh srv-a "kill -$sig \$(pidof ansage)"
        wait_until 5 eval '! running srv-a'
        wait_until 5 frr_log_has r1 "$mark" '10.201.11.10 6/2 \(Cease/Administrative Shutdown\) "ansage shutting down"'
        [ "$(exit_code srv-a)" = 0 ] || fail "SIG$sig: exit code $(exit_code srv-a)"
        server_start srv-a
        wait_until 15 frr_established r1 10.201.11.10
    done
}

scenario O3 default - "shutdown while connecting: exits within 3 s"
scn_O3() {
    allow_flap srv-a
    allow_flap srv-c
    trap 'compose start r1 >/dev/null 2>&1; server_start srv-a' EXIT
    compose stop -t 2 r1 >/dev/null 2>&1
    # srv-a is now in its connect/backoff loop.
    sleep 4
    local start t
    start=$(now)
    compose stop -t 10 srv-a >/dev/null 2>&1
    t=$(elapsed "$start")
    measure "stop while connecting" "$t"
    assert_le "stop while connecting" "$t" 3
    [ "$(exit_code srv-a)" = 0 ] || fail "exit code $(exit_code srv-a)"
}

# Announce list body: srv-c's service prefixes plus N IPv4 /32s in 100.64.0.0/10.
o4_prefixes() {
    awk -v n="$1" 'BEGIN {
        printf "\"198.51.100.0/24\", \"2001:db8:2::/48\""
        for (i = 0; i < n; i++) printf ", \"100.%d.%d.%d/32\"", 64 + int(i / 65536), int(i / 256) % 256, i % 256
    }'
}

# Bytes in the send queue of srv-c's connection to r1 (0 if none).
o4_send_q() { on srv-c ss -tnH state established dst 10.201.0.2 | awk '{ q += $2 } END { print q + 0 }'; }

scenario O4 full - "stop while the peer does not keep up: exits in time, FRR drops the session at once"
scn_O4() {
    # Routes queued in ansage's socket buffer ahead of the final Cease.
    # Old ansage exited, the container's network namespace went away with the
    # queue, and FRR kept srv-c's routes until its hold timer expired. Now
    # ansage resets the connection when the Cease cannot get through in time.
    allow_flap srv-c
    allow_warn srv-c 'timed out flushing'
    trap 'on r1 tc qdisc del dev core root >/dev/null 2>&1; frr_shutdown 10.201.0.10 off; n_restore' EXIT
    frr_shutdown 10.201.0.10 "O4"
    # ~500 kB of UPDATEs, only to r1 (r2 would pass them on).
    srv_c_conf o4 r2=0 announce="$(o4_prefixes 100000)"
    srv_c_use gen-o4.toml
    # r1 acknowledges slowly (its outgoing ACKs at 8 kbit/s), so ansage's
    # initial send waits in ansage's own socket buffer. (FRR reads at once
    # into its own buffers, so slowing bgpd down does not work; a rate limit
    # on srv-c's side would queue everything, the RST too, in srv-c's own
    # qdisc, which dies with the container.)
    on r1 tc qdisc replace dev core root netem rate 8kbit
    local mark start t q
    mark=$(frr_log_mark r1)
    frr_shutdown 10.201.0.10 off
    wait_until 15 frr_established r1 10.201.0.10
    sleep 2
    q=$(o4_send_q)
    info "srv-c send queue to r1: $q bytes"
    [ "$q" -gt 100000 ] || fail "test is void: only $q bytes queued at srv-c"
    start=$(now)
    compose stop -t 10 srv-c >/dev/null 2>&1
    t=$(elapsed "$start")
    measure "stop with $q bytes queued" "$t"
    # FLUSH_TIMEOUT (2 s) + 1 s.
    assert_le "stop with routes queued" "$t" 3.5
    # The reset reaches r1 at once (incoming traffic is not shaped); before the
    # fix the session stayed up until r1's hold timer (9 s) expired.
    wait_until 2 eval '! frr_established r1 10.201.0.10'
    measure "FRR session down after the stop" "$(elapsed "$start")"
    if frr_log_has r1 "$mark" 'Hold Timer Expired'; then
        fail "FRR dropped srv-c only by its hold timer"
    fi
}

scenario O5 default - "unprivileged: ansage as nobody without capabilities"
scn_O5() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    SRV_C_USER=nobody srv_c_use ansage.toml
    wait_until 30 frr_established r1 10.201.0.10
    wait_until 30 bird_established r2 srv_c
    local status
    status=$(on_sh srv-c 'cat /proc/$(pidof ansage)/status')
    grep -E '^Uid:\s+65534\s' <<<"$status" >/dev/null || fail "ansage does not run as nobody:
$(grep -E '^(Uid|Gid):' <<<"$status")"
    grep -E '^CapEff:\s+0+$' <<<"$status" >/dev/null || fail "ansage has capabilities: $(grep CapEff <<<"$status")"
    wait_until 5 http_is user1 198.51.100.10 srv-c
}

# --- runtime commands over the control socket --------------------------------

# Does ROUTER have PREFIX from srv-c?
r1_has_from_c() { frr_has_path_from r1 "$1" 10.201.0.10; }
frr_has_path_from() { frr_path "$1" "$2" "$3" | grep -v '^null$' >/dev/null; }
r2_has_from_c() { bird r2 show route "$1" protocol srv_c | grep -q "$1"; }

O7_PREFIXES='198.18.0.0/24 2001:db8:3::/48'

scenario O7 default - "runtime announce / withdraw: routers learn and lose the prefixes"
scn_O7() {
    # shellcheck disable=SC2086
    trap 'on srv-c ansage withdraw $O7_PREFIXES >/dev/null 2>&1' EXIT
    local out p
    local est
    est=$(ansage_peer srv-c 10.201.0.2 .counters.established)
    # shellcheck disable=SC2086
    out=$(on srv-c ansage announce $O7_PREFIXES 198.51.100.0/24) || fail "announce failed: $out"
    log "$out"
    grep -q '^Announced: 198.18.0.0/24, 2001:db8:3::/48$' <<<"$out" || fail "announce output: $out"
    grep -q '^Already announced: 198.51.100.0/24$' <<<"$out" || fail "announce output: $out"
    for p in $O7_PREFIXES; do
        wait_until 10 r1_has_from_c "$p" || fail "r1 did not learn $p"
        wait_until 10 r2_has_from_c "$p" || fail "r2 did not learn $p"
    done
    [ "$(ansage_show srv-c summary | jq -r '.announce | length')" = 4 ] || fail "summary does not list 4 prefixes"

    out=$(on srv-c ansage announce 10.0.0.1/8 2>&1) && fail "host bits accepted: $out"
    grep -q 'did you mean 10.0.0.0/8' <<<"$out" || fail "unclear error: $out"

    # shellcheck disable=SC2086
    out=$(on srv-c ansage withdraw $O7_PREFIXES) || fail "withdraw failed: $out"
    for p in $O7_PREFIXES; do
        wait_until 10 eval "! r1_has_from_c $p" || fail "r1 still has $p"
        wait_until 10 eval "! r2_has_from_c $p" || fail "r2 still has $p"
    done
    # The configured prefixes were not touched, sessions stayed up.
    r1_has_from_c 198.51.100.0/24 || fail "r1 lost srv-c's configured prefix"
    [ "$(ansage_peer srv-c 10.201.0.2 .counters.established)" = "$est" ] || fail "srv-c's session to r1 flapped"
}

scenario O8 default - "peer disable / enable / reset: Cease 6/2 with reason, stays down, 6/4 reconnects"
scn_O8() {
    allow_flap srv-c
    trap 'on srv-c ansage peer 10.201.0.2 enable >/dev/null 2>&1' EXIT
    local mark out est
    mark=$(frr_log_mark r1)
    out=$(on srv-c ansage peer 10.201.0.2 disable --reason "e2e maintenance") || fail "disable failed: $out"
    grep -q 'disable requested' <<<"$out" || fail "disable output: $out"
    wait_until 5 frr_log_has r1 "$mark" 'NOTIFICATION: received from neighbor 10.201.0.10 6/2' ||
        fail "FRR got no Administrative Shutdown"
    frr_log r1 "$mark" | grep -m1 'NOTIFICATION: received from neighbor 10.201.0.10 6/2' | sed 's/^/    frr: /'
    frr_log_has r1 "$mark" 'e2e maintenance' || fail "FRR did not log the shutdown text"
    [ "$(ansage_peer srv-c 10.201.0.2 .status.disabled)" = true ] || fail "srv-c: not shown as disabled"
    # Stays down (FRR is passive, srv-c must not reconnect).
    sleep 6
    frr_established r1 10.201.0.10 && fail "session came back while disabled"
    [ "$(ansage_peer srv-c 10.201.0.2 .status.last_down.reason)" = administrative ] ||
        fail "srv-c: last_down is not administrative"
    bird_established r2 srv_c || fail "srv-c's session to r2 went down"

    on srv-c ansage peer 10.201.0.2 enable >/dev/null || fail "enable failed"
    wait_until 10 frr_established r1 10.201.0.10 || fail "no session after enable"
    [ "$(ansage_peer srv-c 10.201.0.2 .status.disabled)" = false ] || fail "srv-c: still disabled"

    est=$(ansage_peer srv-c 10.201.0.2 .counters.established)
    mark=$(frr_log_mark r1)
    on srv-c ansage peer 10.201.0.2 reset >/dev/null || fail "reset failed"
    wait_until 5 frr_log_has r1 "$mark" 'NOTIFICATION: received from neighbor 10.201.0.10 6/4' ||
        fail "FRR got no Administrative Reset"
    wait_until 10 eval '[ "$(ansage_peer srv-c 10.201.0.2 .counters.established)" = $((est + 1)) ]' ||
        fail "srv-c did not re-establish after the reset"
    wait_until 10 frr_established r1 10.201.0.10 || fail "FRR not Established after the reset"
    out=$(on srv-c ansage peer 10.201.9.9 reset 2>&1) && fail "unknown neighbor accepted: $out"
    true
}

# --- config reload -----------------------------------------------------------

# Rewrites srv-c's running config in place (same file, same inode: the
# container sees it) and asks ansage to reload. Prints the reply.
o9_reload() {
    srv_c_conf o9 "$@"
    on srv-c ansage reload
}

scenario O9 default - "config reload: neighbors added / removed / restarted, prefixes follow the file, runtime state kept"
scn_O9() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    local out est
    srv_c_conf o9 r2=0
    srv_c_use gen-o9.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with r1"

    # 1. r2 added, r1's description changed, one more prefix: r1 untouched.
    out=$(o9_reload r1_desc='r1 renamed' announce='"198.51.100.0/24", "2001:db8:2::/48", "198.18.1.0/24"') ||
        fail "reload failed: $out"
    log "$out"
    grep -q '^Neighbors added: 10.201.0.3:179$' <<<"$out" || fail "reload output: $out"
    grep -q '^Descriptions updated: 10.201.0.2:179$' <<<"$out" || fail "reload output: $out"
    grep -q '^Prefixes announced: 198.18.1.0/24$' <<<"$out" || fail "reload output: $out"
    wait_until 15 bird_established r2 srv_c || fail "added neighbor r2 did not come up"
    wait_until 10 frr_has_path_from r1 198.18.1.0/24 10.201.0.10 || fail "r1 did not learn the new prefix"
    [ "$(ansage_peer srv-c 10.201.0.2 .neighbor.description)" = 'r1 renamed' ] || fail "description not updated"
    [ "$(ansage_peer srv-c 10.201.0.2 .counters.established)" = 1 ] || fail "r1's session was reset"

    # 2. A health check withdrew a prefix at runtime; a reload that changes
    # r1's hold time restarts r1 (6/6) but does not bring the prefix back.
    on srv-c ansage withdraw 198.51.100.0/24 >/dev/null || fail "runtime withdraw failed"
    wait_until 10 eval '! frr_has_path_from r1 198.51.100.0/24 10.201.0.10' || fail "r1 still has the withdrawn prefix"
    local mark
    mark=$(frr_log_mark r1)
    out=$(o9_reload r1_desc='r1 renamed' r1_extra='hold_time = 6' \
        announce='"198.51.100.0/24", "2001:db8:2::/48", "198.18.1.0/24"') || fail "reload failed: $out"
    grep -q '^Neighbors reconnecting with new settings: 10.201.0.2:179$' <<<"$out" || fail "reload output: $out"
    wait_until 5 frr_log_has r1 "$mark" 'NOTIFICATION: received from neighbor 10.201.0.10 6/6' ||
        fail "FRR got no Other Configuration Change"
    wait_until 15 frr_established r1 10.201.0.10 || fail "r1 did not come back"
    [ "$(ansage_peer srv-c 10.201.0.2 .status.session.hold_time)" = 6 ] || fail "new hold time not used"
    wait_until 10 frr_has_path_from r1 198.18.1.0/24 10.201.0.10 || fail "r1 lost 198.18.1.0/24"
    sleep 2
    frr_has_path_from r1 198.51.100.0/24 10.201.0.10 && fail "the reload re-announced a prefix withdrawn at runtime"

    # 3. A restart-only change is refused as a whole.
    out=$(o9_reload asn=64599 r1_extra='hold_time = 6' 2>&1) && fail "asn change accepted: $out"
    grep -q 'asn changed' <<<"$out" || fail "unclear refusal: $out"
    frr_established r1 10.201.0.10 || fail "refused reload touched r1"

    # 4. r2 removed with SIGHUP: BIRD gets Peer De-configured (6/3).
    local since
    since=$(now)
    srv_c_conf o9 r2=0 r1_extra='hold_time = 6'
    on_sh srv-c 'kill -HUP $(pidof ansage)'
    wait_until 10 eval '! bird_established r2 srv_c' || fail "r2 still up after its removal"
    wait_log srv-c "$since" 'config reloaded.*removed=\[10.201.0.3:179\]' 5 || fail "srv-c did not log the reload"
    [ "$(ansage_show srv-c summary | jq '.peers | length')" = 1 ] || fail "summary still lists r2"
    running srv-c || fail "srv-c died"
    frr_established r1 10.201.0.10 || fail "r1 went down"
}

# --- metrics -----------------------------------------------------------------

o10_scrape() { on srv-c wget -qO- "http://127.0.0.1:9179${1:-/metrics}"; }

scenario O10 default - "Prometheus metrics: sessions, counters, RIB and process"
scn_O10() {
    trap 'srv_c_use ansage.toml' EXIT
    srv_c_conf o10 top='metrics_listen = "127.0.0.1:9179"'
    srv_c_use gen-o10.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with r1"
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
    local m line
    m=$(o10_scrape) || fail "scrape failed"
    for line in \
        'ansage_info{version="[^"]*",asn="64502",router_id="203.0.113.23"} 1' \
        'ansage_peer_up{neighbor="10.201.0.2:179",asn="64510"} 1' \
        'ansage_peer_up{neighbor="10.201.0.3:179",asn="64511"} 1' \
        'ansage_peer_state{neighbor="10.201.0.2:179",state="Established"} 1' \
        'ansage_peer_info{neighbor="10.201.0.2:179",asn="64510",description="r1 \(FRR\)"} 1' \
        'ansage_peer_messages_received_total{neighbor="10.201.0.2:179",type="open"} 1' \
        'ansage_peer_prefixes_advertised{neighbor="10.201.0.2:179",family="ipv4"} 1' \
        'ansage_own_prefixes 2' \
        'ansage_rib_up 1' \
        'process_resident_memory_bytes [0-9]+' \
        'process_open_fds [0-9]+'; do
        grep -Eq "^$line\$" <<<"$m" || fail "missing: $line"
    done
    # Every sample line belongs to a family declared with TYPE.
    local undeclared
    undeclared=$(awk '/^# TYPE / { t[$3] = 1; next } /^#/ { next }
        { n = $1; sub(/\{.*/, "", n); if (!(n in t)) print n }' <<<"$m" | sort -u)
    [ -z "$undeclared" ] || fail "samples without TYPE: $undeclared"
    measure "metrics size" "$(wc -c <<<"$m")" bytes
    o10_scrape /nothing >/dev/null 2>&1 && fail "/nothing did not 404"
    # Read-only JSON API (for a dashboard): the control socket's answers.
    local api
    api=$(o10_scrape /api/summary) || fail "/api/summary failed"
    [ "$(jq -r '.asn' <<<"$api")" = 64502 ] || fail "/api/summary asn: $api"
    [ "$(jq '.peers | length' <<<"$api")" = "$(ansage_show srv-c summary | jq '.peers | length')" ] ||
        fail "/api/summary peers differ from ansage show"
    api=$(o10_scrape '/api/peers?peer=10.201.0.2') || fail "/api/peers failed"
    [ "$(jq -r '.[0].status.state' <<<"$api")" = Established ] || fail "/api/peers: $api"
    api=$(o10_scrape '/api/rib?family=ipv4&limit=3') || fail "/api/rib failed"
    jq -e '.routes | length > 0' <<<"$api" >/dev/null || fail "/api/rib: $api"
    o10_scrape /api/reload >/dev/null 2>&1 && fail "/api/reload is not 404"
    # Counters move: a reset adds an established session.
    on srv-c ansage peer 10.201.0.2 reset >/dev/null
    wait_until 15 eval 'o10_scrape | grep -q "^ansage_peer_established_total{neighbor=\"10.201.0.2:179\",asn=\"64510\"} 2$"' ||
        fail "established_total did not count the reset"
    # Live events (SSE): the summary first, then the reset as peer events.
    wait_until 15 frr_established r1 10.201.0.10 || fail "r1 not back after the reset"
    on_sh srv-c 'timeout 8 wget -qO- http://127.0.0.1:9179/api/events >/tmp/o10-events 2>/dev/null &
        sleep 1; ansage peer 10.201.0.2 reset >/dev/null; wait' || true
    local ev
    ev=$(on srv-c cat /tmp/o10-events)
    [ "$(head -1 <<<"$ev")" = "event: summary" ] || fail "stream does not start with the summary: $(head -3 <<<"$ev")"
    grep -A1 '^event: peer$' <<<"$ev" | grep '^data: ' | sed 's/^data: //' |
        jq -r 'select(.neighbor.address == "10.201.0.2:179") | .status.state' | grep -qv Established ||
        fail "no peer event for the reset: $(grep -c '^event: peer$' <<<"$ev") peer events"
    true
}

# --- drain (RFC 8326) --------------------------------------------------------

# Community of PREFIX's path on r1 from PEER ("none" if it has none).
r1_community() { frr_path r1 "$1" "$2" | jq -r '.community.string // "none"'; }
# BIRD attribute line of r2's route for PREFIX from srv-b, e.g. "bgp_path: 64500".
r2_from_b() { bird r2 show route "$1" protocol srv_b all | grep -E "^\s*$2:" | sed 's/^\s*//'; }

scenario O11 default - "drain: FRR acts on GRACEFUL_SHUTDOWN, BIRD moves by drain_prepend, no gap, undrain restores"
scn_O11() {
    trap 'on srv-a ansage undrain >/dev/null 2>&1; on srv-b ansage undrain >/dev/null 2>&1' EXIT
    wait_until 5 http_is user1 192.0.2.10 srv-a || fail "user1 does not start at srv-a"
    wait_until 5 http_is user2 192.0.2.10 srv-b || fail "user2 does not start at srv-b"
    local est_a est_b out gap
    est_a=$(ansage_peer srv-a 10.201.11.2 .counters.established)
    est_b=$(ansage_peer srv-b 10.201.12.2 .counters.established)

    # 1. srv-a behind r1 (FRR, which gives routes with GRACEFUL_SHUTDOWN
    # LOCAL_PREF 0 by itself): user1 moves to srv-b via r2.
    probe_start user1 192.0.2.10 o11-a
    out=$(on srv-a ansage drain) || fail "drain failed: $out"
    grep -q '^Drained: ' <<<"$out" || fail "drain output: $out"
    wait_until 10 eval '[ "$(r1_community 192.0.2.0/24 10.201.11.10)" = graceful-shutdown ]' ||
        fail "r1 sees no GRACEFUL_SHUTDOWN on 192.0.2.0/24"
    wait_until 10 eval '[ "$(r1_community 2001:db8:1::/48 10.201.11.10)" = graceful-shutdown ]' ||
        fail "r1 sees no GRACEFUL_SHUTDOWN on 2001:db8:1::/48"
    wait_until 10 http_is user1 192.0.2.10 srv-b || fail "user1 did not move to srv-b"
    [ "$(ansage_show srv-a summary | jq -r '.drained | type')" = number ] || fail "summary: not drained"
    on srv-a ansage show summary | grep -q '^Drained for ' || fail "show summary has no Drained line"
    out=$(on srv-a ansage drain) || fail "second drain failed"
    grep -q '^Already drained for ' <<<"$out" || fail "second drain output: $out"
    out=$(on srv-a ansage undrain) || fail "undrain failed: $out"
    wait_until 10 http_is user1 192.0.2.10 srv-a || fail "user1 did not come back to srv-a"
    [ "$(r1_community 192.0.2.0/24 10.201.11.10)" = none ] || fail "r1 still sees a community"
    gap=$(probe_stop user1 o11-a | probe_max_gap)
    measure "longest gap, drain + undrain srv-a" "$gap"
    assert_le "drain srv-a gap" "$gap" 1

    # 2. srv-b behind r2 (BIRD keeps such routes as they are): the two
    # extra prepends (drain_prepend = 2) move user2 to srv-a via r1.
    probe_start user2 192.0.2.10 o11-b
    on srv-b ansage drain >/dev/null || fail "drain srv-b failed"
    wait_until 10 eval '[ "$(r2_from_b 192.0.2.0/24 bgp_path)" = "bgp_path: 64500 64500 64500" ]' ||
        fail "r2: path from srv-b is $(r2_from_b 192.0.2.0/24 bgp_path)"
    [ "$(r2_from_b 192.0.2.0/24 bgp_community)" = "bgp_community: (65535,0)" ] ||
        fail "r2: community from srv-b is $(r2_from_b 192.0.2.0/24 bgp_community)"
    wait_until 10 http_is user2 192.0.2.10 srv-a || fail "user2 did not move to srv-a"
    on srv-b ansage undrain >/dev/null || fail "undrain srv-b failed"
    wait_until 10 http_is user2 192.0.2.10 srv-b || fail "user2 did not come back to srv-b"
    [ "$(r2_from_b 192.0.2.0/24 bgp_path)" = "bgp_path: 64500" ] || fail "r2: prepends left after undrain"
    gap=$(probe_stop user2 o11-b | probe_max_gap)
    measure "longest gap, drain + undrain srv-b" "$gap"
    assert_le "drain srv-b gap" "$gap" 1

    [ "$(ansage_peer srv-a 10.201.11.2 .counters.established)" = "$est_a" ] || fail "srv-a's session flapped"
    [ "$(ansage_peer srv-b 10.201.12.2 .counters.established)" = "$est_b" ] || fail "srv-b's session flapped"
}

o12_start() {
    srv_c_use gen-o12.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with r1"
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
}
o12_term() { on_sh srv-c 'kill -TERM $(pidof ansage)'; }
o12_cease() { wait_until "$2" frr_log_has r1 "$1" 'NOTIFICATION: received from neighbor 10.201.0.10 6/2'; }

scenario O12 default - "stop with drain_time: GRACEFUL_SHUTDOWN first, Cease after drain_time; a second SIGTERM or an earlier drain shortens it"
scn_O12() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    srv_c_conf o12 top='drain_time = 4'
    local mark start t since

    # 1. SIGTERM: drained at once, sessions closed after 4 s.
    o12_start
    mark=$(frr_log_mark r1)
    since=$(now)
    start=$(now)
    o12_term
    wait_until 3 eval '[ "$(r1_community 198.51.100.0/24 10.201.0.10)" = graceful-shutdown ]' ||
        fail "r1 sees no GRACEFUL_SHUTDOWN after SIGTERM"
    frr_established r1 10.201.0.10 || fail "session closed before drain_time"
    o12_cease "$mark" 10 || fail "FRR got no Cease"
    t=$(elapsed "$start")
    measure "SIGTERM to Cease with drain_time = 4" "$t"
    awk -v t="$t" 'BEGIN { exit !(t >= 3.5) }' || fail "Cease after $t s, before drain_time"
    assert_le "SIGTERM to Cease" "$t" 6
    log_has srv-c "$since" 'draining before the stop' || fail "srv-c did not log the drain"

    # 2. A second SIGTERM ends the wait.
    o12_start
    mark=$(frr_log_mark r1)
    since=$(now)
    start=$(now)
    o12_term
    wait_log srv-c "$since" 'draining before the stop' 3 || fail "srv-c did not start draining"
    o12_term
    o12_cease "$mark" 5 || fail "FRR got no Cease"
    t=$(elapsed "$start")
    measure "two SIGTERMs to Cease" "$t"
    assert_le "two SIGTERMs to Cease" "$t" 2

    # 3. An earlier `ansage drain` counts towards drain_time.
    o12_start
    on srv-c ansage drain >/dev/null || fail "drain failed"
    sleep 4
    mark=$(frr_log_mark r1)
    start=$(now)
    o12_term
    o12_cease "$mark" 5 || fail "FRR got no Cease"
    t=$(elapsed "$start")
    measure "SIGTERM to Cease after an earlier drain" "$t"
    assert_le "SIGTERM after an earlier drain" "$t" 1.5
}
