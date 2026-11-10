# G: graceful restart. srv-c with graceful_restart = true, under a
# supervisor that starts ansage again after exit 75 (ANSAGE_SUPERVISED, like
# systemd RestartForceExitStatus=75). srv-c is the only server for
# 198.51.100.0/24 / 2001:db8:2::/48: if a router dropped its routes, traffic
# from user1 (via r1, FRR) and user2 (via r2, BIRD) would stop.

# g_start NAME [srv_c_conf args...]: srv-c with graceful restart, both
# sessions up and its prefixes at both routers.
g_start() {
    local name=$1
    shift
    srv_c_conf "$name" top="graceful_restart = true
${G_TOP:-}" "$@"
    SRV_C_SUPERVISED=1 SRV_C_CRASH_TEST=1 srv_c_use "gen-$name.toml"
    wait_until 20 frr_established r1 10.201.0.10 || fail "r1: no session with srv-c"
    wait_until 20 bird_established r2 srv_c || fail "r2: no session with srv-c"
    wait_until 10 g_routes_at_both || fail "routers do not have srv-c's prefixes"
}

g_routes_at_both() {
    local p
    for p in 198.51.100.0/24 2001:db8:2::/48; do
        r1_has_from_c "$p" && r2_has_from_c "$p" || return 1
    done
}

g_routes_at_none() {
    local p
    for p in 198.51.100.0/24 2001:db8:2::/48; do
        ! r1_has_from_c "$p" && ! r2_has_from_c "$p" || return 1
    done
}

# r1_has_from_c, r2_has_from_c: operations.sh; frr_path: baseline.sh.

# Is r1's path for PREFIX from srv-c marked stale?
r1_stale() { frr_path r1 "$1" 10.201.0.10 | jq -e '.stale == true' >/dev/null; }

# Probes srv-c's service address from both users (v4 via r1, v6 via r2).
g_probes_start() {
    probe_start user1 198.51.100.10 "$1-u1"
    probe_start user2 2001:db8:2::10 "$1-u2"
}

g_probes_gap() {
    local u gap max=0
    for u in u1 u2; do
        probe_stop "user${u#u}" "$1-$u" >"$RUN_DIR/$SCN_ID.probe.$1-$u"
        gap=$(probe_max_gap <"$RUN_DIR/$SCN_ID.probe.$1-$u")
        measure "$1 gap $u" "$gap"
        max=$(awk -v a="$gap" -v b="$max" 'BEGIN { print (a > b) ? a : b }')
    done
    echo "$max"
}

scenario G1 default - "ansage upgrade: routers keep srv-c's routes, no traffic lost, exit 0"
scn_G1() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    g_start g1
    local n
    for n in 10.201.0.2 10.201.0.3; do
        [ "$(ansage_peer srv-c "$n" '.status.session.graceful_restart != null')" = true ] ||
            fail "srv-c: no graceful restart negotiated with $n"
    done
    log "N bit with r1: $(ansage_peer srv-c 10.201.0.2 .status.session.graceful_restart.notification), r2: $(ansage_peer srv-c 10.201.0.3 .status.session.graceful_restart.notification)"

    # Dry run: both keep our routes, nothing refused.
    local plan
    plan=$(on srv-c ansage upgrade --dry-run --json) || fail "dry run failed: $plan"
    jq -e '(.neighbors | map(.action) | all(startswith("keep"))) and (.refused == [])' <<<"$plan" >/dev/null ||
        fail "unexpected dry run: $plan"

    local pid mark start out gap
    pid=$(ansage_pid srv-c)
    mark=$(frr_log_mark r1)
    g_probes_start g1
    start=$(now)
    out=$(on srv-c ansage upgrade --binary /usr/local/bin/ansage 2>&1) || fail "ansage upgrade failed:
$out"
    measure "upgrade until all neighbors back" "$(elapsed "$start")"
    info "${out//$'\n'/$'\n'    }"
    [ "$(ansage_pid srv-c)" != "$pid" ] || fail "ansage was not restarted"
    gap=$(g_probes_gap g1)
    assert_le "traffic gap during the upgrade" "$gap" 0.5
    g_routes_at_both || fail "a router lost srv-c's prefixes after the upgrade"
    if frr_log_has r1 "$mark" 'Hard Reset|6/9'; then fail "r1 got a Hard Reset"; fi
}

scenario G2 default - "stop with graceful restart: Hard Reset (N bit) or Cease, routers withdraw at once"
scn_G2() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    g_start g2
    local mark start t
    mark=$(frr_log_mark r1)
    start=$(now)
    compose stop -t 5 srv-c >/dev/null 2>&1
    wait_until 3 g_routes_at_none || fail "routers kept srv-c's routes after a stop"
    t=$(elapsed "$start")
    measure "withdrawn after stop" "$t"
    assert_le "withdrawal after stop" "$t" 2
    # FRR has the N bit (G1): a Hard Reset around the Administrative Shutdown.
    frr_log_has r1 "$mark" 'NOTIFICATION\(Hard Reset\).* 6/2 ' ||
        fail "r1 did not log a Hard Reset wrapping 6/2: $(frr_log r1 "$mark" | grep NOTIFICATION)"
}

scenario G3 default - "kill -9: routers keep the routes as stale, until ansage is back or restart_time"
scn_G3() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    G_TOP='restart_time = 6' g_start g3
    local start t
    on srv-c pkill -9 -x ansage
    # The supervisor only restarts after exit 75: srv-c stops, nobody is
    # back within restart_time.
    start=$(now)
    sleep 1
    g_routes_at_both || fail "routers dropped the routes at once after kill -9"
    wait_until 3 r1_stale 198.51.100.0/24 || fail "r1 does not mark the route stale"
    wait_until 10 g_routes_at_none || fail "stale routes still there after restart_time"
    t=$(elapsed "$start")
    measure "stale routes removed after kill -9" "$t"
    assert_le "stale routes gone after restart_time (6 s)" "$t" 8
}

scenario G4 default - "panic: the hook sends a Cease (Hard Reset with N), routers withdraw at once"
scn_G4() {
    allow_flap srv-c
    allow_warn srv-c 'panicked|crash requested'
    trap 'srv_c_use ansage.toml' EXIT
    g_start g4
    local mark start t
    mark=$(frr_log_mark r1)
    start=$(now)
    on srv-c ansage debug-crash >/dev/null 2>&1 || true
    wait_until 3 g_routes_at_none || fail "routers kept srv-c's routes after a panic"
    t=$(elapsed "$start")
    measure "withdrawn after panic" "$t"
    assert_le "withdrawal after panic" "$t" 2
    frr_log_has r1 "$mark" 'NOTIFICATION\(Hard Reset\).* 6/2 ' ||
        fail "r1 did not log the crash Hard Reset: $(frr_log r1 "$mark" | grep NOTIFICATION)"
    log_has srv-c "$start" 'sent the final Cease on 2 sessions' || fail "the hook did not reach both sessions"
}

scenario G5 default - "upgrade refused: a neighbor without graceful restart would withdraw"
scn_G5() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    g_start g5 r2_extra='graceful_restart = false'
    local pid out
    pid=$(ansage_pid srv-c)
    if out=$(on srv-c ansage upgrade 2>&1); then fail "upgrade not refused: $out"; fi
    [[ $out == *"would withdraw our routes: 10.201.0.3:179"* ]] || fail "unexpected refusal: $out"
    [ "$(ansage_pid srv-c)" = "$pid" ] || fail "ansage restarted anyway"
    # A bad binary is refused before anything happens.
    if out=$(on srv-c ansage upgrade --force --binary /bin/false 2>&1); then fail "bad binary accepted: $out"; fi
    [ "$(ansage_pid srv-c)" = "$pid" ] || fail "ansage restarted with a bad binary"
}

scenario G6 default - "upgrade with no neighbor to wait for: waits for the new process, exit 0"
scn_G6() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    g_start g6
    local n pid out
    for n in 10.201.0.2 10.201.0.3; do
        on srv-c ansage peer "$n" disable >/dev/null || fail "cannot disable $n"
    done
    wait_until 5 g_routes_at_none || fail "routers kept srv-c's routes after disable"
    pid=$(ansage_pid srv-c)
    # Before the fix, upgrade returned at once ("did not come back").
    out=$(on srv-c ansage upgrade --timeout 15 2>&1) || fail "ansage upgrade failed:
$out"
    info "${out//$'\n'/$'\n'    }"
    [[ $out == *"ansage is back after"* && $out == *"Upgrade done"* ]] || fail "unexpected output: $out"
    [ "$(ansage_pid srv-c)" != "$pid" ] || fail "ansage was not restarted"
    # Runtime disable is not persistent: the new process connects again.
    wait_until 20 g_routes_at_both || fail "routers do not have srv-c's prefixes after the upgrade"
}

# --- helper side: a neighbor restarts, srv-c keeps its routes -------------

# g_metric NAME NEIGHBOR: value of srv-c's per-neighbor metric NAME.
g_metric() {
    on srv-c wget -qO- http://127.0.0.1:9179/metrics |
        awk -v m="$1{neighbor=\"$2:179\"" 'index($0, m) == 1 { print $2 }'
}
g_r1_stale() { [ "$(g_metric ansage_peer_prefixes_stale 10.201.0.2)" = "$1" ]; }
g_r1_received() { [ "$(ansage_received srv-c 10.201.0.2)" = "$1" ]; }

scenario G7 default - "helper: r1 (FRR, full GR) drops the session without Cease, srv-c keeps its routes stale until refreshed"
scn_G7() {
    allow_flap srv-c
    allow_warn srv-c 'session down'
    trap 'on srv-c ip route del blackhole 10.201.0.2/32 >/dev/null 2>&1 || true; frr_conf r1 "router bgp 64510" "no neighbor 10.201.0.10 graceful-restart" "no bgp graceful-restart preserve-fw-state" >/dev/null; srv_c_use ansage.toml' EXIT
    # r1 restarting-capable towards srv-c, with the F bit (FRR resets the session).
    frr_conf r1 'router bgp 64510' 'bgp graceful-restart preserve-fw-state' 'neighbor 10.201.0.10 graceful-restart' >/dev/null
    G_TOP='metrics_listen = "127.0.0.1:9179"' g_start g7
    wait_until 10 eval '[ "$(ansage_peer srv-c 10.201.0.2 .rib.initial_sync_done)" = true ]' || fail "no initial sync with r1"
    # r1's End-of-RIB for both families (srv-c was just recreated: whole log).
    wait_until 10 eval '[ "$(ansage_logs srv-c | grep -c "end of RIB from peer peer=1 ")" -ge 2 ]' ||
        fail "no End-of-RIB from r1 for both families"

    local gr
    gr=$(ansage_peer srv-c 10.201.0.2 .status.session.graceful_restart)
    log "graceful restart with r1: $(jq -c . <<<"$gr")"
    # The N bit makes r1's hold-timer NOTIFICATION keep the routes. The F bit
    # (FRR sets it only sometimes, also with preserve-fw-state) only decides
    # whether the stale routes wait for r1's End-of-RIB or go at reconnect;
    # both end with the same routes and no stale ones.
    jq -e '.notification' <<<"$gr" >/dev/null || fail "r1: no N bit: $gr"
    local m
    for m in ansage_peer_graceful_restart ansage_peer_graceful_restart_notification \
        ansage_peer_graceful_restart_offered ansage_peer_graceful_restart_enabled; do
        [ "$(g_metric $m 10.201.0.2)" = 1 ] || fail "metric $m for r1 is not 1"
    done
    g_r1_stale 0 || fail "stale routes before anything happened"

    local rcvd n start t
    rcvd=$(ansage_received srv-c 10.201.0.2)
    n=$(awk '{ print $1 + $2 }' <<<"$rcvd")
    [ "$n" -gt 0 ] || fail "srv-c has no routes from r1"
    # srv-c's packets to r1 vanish: r1's hold timer expires and it sends a
    # NOTIFICATION (not a Hard Reset), which srv-c still receives.
    on srv-c ip route add blackhole 10.201.0.2/32 || fail "cannot add the blackhole"
    start=$(now)
    wait_until 15 eval '! ansage_established srv-c 10.201.0.2' || fail "session with r1 did not go down"
    measure "session down after blackhole" "$(elapsed "$start")"
    log "last down: $(ansage_peer srv-c 10.201.0.2 .status.last_down | jq -c .)"
    wait_until 3 g_r1_stale "$n" || fail "srv-c did not keep r1's $n routes as stale (metric: $(g_metric ansage_peer_prefixes_stale 10.201.0.2))"
    log_has srv-c "$start" 'routes kept as stale' || fail "no 'kept as stale' log"
    local p
    p=$(ansage_show srv-c rib --json | jq -r '[.[] | select(.source != "local")][0].prefix // empty' 2>/dev/null || true)
    [ -z "$p" ] || log "a kept route: $p"

    on srv-c ip route del blackhole 10.201.0.2/32
    start=$(now)
    wait_until 20 ansage_established srv-c 10.201.0.2 || fail "r1 did not come back"
    wait_until 10 g_r1_stale 0 || fail "stale routes left after r1's End-of-RIB: $(g_metric ansage_peer_prefixes_stale 10.201.0.2)"
    measure "back and refreshed" "$(elapsed "$start")"
    g_r1_received "$rcvd" || fail "r1's routes after the refresh: $(ansage_received srv-c 10.201.0.2), before: $rcvd"
}

scenario G8 default - "BIRD with graceful restart on (as in the docs): keeps srv-c's routes through ansage upgrade"
scn_G8() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml; bird_restore r2' EXIT
    # G1 covers BIRD's default (aware); this is the explicit line from
    # docs/03-guides/02-router-config.mdx.
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/passive on;/passive on;\n    graceful restart on;/'
    g_start g8
    [ "$(ansage_peer srv-c 10.201.0.3 '.status.session.graceful_restart != null')" = true ] ||
        fail "srv-c: no graceful restart negotiated with r2"
    local pid out gap
    pid=$(ansage_pid srv-c)
    g_probes_start g8
    out=$(on srv-c ansage upgrade --binary /usr/local/bin/ansage 2>&1) || fail "ansage upgrade failed:
$out"
    [ "$(ansage_pid srv-c)" != "$pid" ] || fail "ansage was not restarted"
    gap=$(g_probes_gap g8)
    assert_le "traffic gap during the upgrade" "$gap" 0.5
    g_routes_at_both || fail "a router lost srv-c's prefixes after the upgrade"
}
