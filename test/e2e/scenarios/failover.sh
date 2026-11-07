# F: failover and convergence.
#
# Failover times come from probes (HTTP every 100 ms from a user): the longest
# time without any answer. Limits follow E-D6 (measured first, then fixed with
# ~50% margin); measured values go to RUN_DIR/timings.

SRV_A_ADDRS="10.201.11.10 2001:db8:201:11::10"

# Starts SERVER again (after a stop or a crash) and waits for its sessions.
server_start() {
    compose start "$1" >/dev/null 2>&1 || fail "cannot start $1"
}

# Restores srv-a's link a after it was down: IPv6 addresses and default routes
# are flushed by the kernel on link down.
srv_a_link_restore() {
    on_sh srv-a 'ip link set dev a up
        ip -6 addr replace 2001:db8:201:11::10/64 dev a nodad
        ip route replace default via 10.201.11.2
        ip -6 route replace default via 2001:db8:201:11::2' 2>/dev/null || true
}

# probes_start USER NAME: probes for the anycast address over IPv4 and IPv6.
probes_start() {
    probe_start "$1" 192.0.2.10 "$2-v4"
    probe_start "$1" 2001:db8:1::10 "$2-v6"
}

# probes_gap USER NAME: stops both probes, records and prints the longest gap.
probes_gap() {
    local fam gap max=0
    for fam in v4 v6; do
        probe_stop "$1" "$2-$fam" >"$RUN_DIR/$SCN_ID.probe.$2-$fam"
        gap=$(probe_max_gap <"$RUN_DIR/$SCN_ID.probe.$2-$fam")
        measure "$2 gap $fam" "$gap"
        max=$(awk -v a="$gap" -v b="$max" 'BEGIN { print (a > b) ? a : b }')
    done
    echo "$max"
}

# Waits until USER gets ANSWER for the anycast address on both families.
wait_anycast() {
    wait_until "$3" http_is "$1" 192.0.2.10 "$2"
    wait_until "$3" http_is "$1" 2001:db8:1::10 "$2"
}

scenario F1 default - "graceful stop: srv-a sends Cease, user1 fails over to srv-b"
scn_F1() {
    allow_flap srv-a
    trap 'server_start srv-a' EXIT
    local mark gap
    mark=$(frr_log_mark r1)
    probes_start user1 f1
    compose stop -t 5 srv-a >/dev/null 2>&1
    wait_anycast user1 srv-b 10
    sleep 0.5
    gap=$(probes_gap user1 f1)
    assert_le "failover after graceful stop" "$gap" 1.5
    assert_path user1 192.0.2.10 10.201.1.2 10.201.0.3 192.0.2.10
    frr_log_has r1 "$mark" '10.201.11.10 6/2 \(Cease/Administrative Shutdown\) "herald shutting down"' ||
        fail "r1 did not log the Cease with the shutdown text"
}

scenario F2 default - "restart: user1 back to srv-a within connect_retry + 5 s"
scn_F2() {
    allow_flap srv-a
    trap 'server_start srv-a' EXIT
    compose stop -t 5 srv-a >/dev/null 2>&1
    wait_anycast user1 srv-b 10
    local start t
    start=$(now)
    server_start srv-a
    wait_anycast user1 srv-a 15
    t=$(elapsed "$start")
    measure "back to srv-a after start" "$t"
    assert_le "recovery after restart" "$t" 3
}

scenario F3 default - "crash: kill -9 herald, kernel closes TCP, fast failover"
scn_F3() {
    allow_flap srv-a
    trap 'server_start srv-a' EXIT
    local mark gap
    mark=$(frr_log_mark r1)
    probes_start user1 f3
    # herald dying stops the container (init exits with it).
    on_sh srv-a 'kill -9 $(pidof herald)' >/dev/null 2>&1 || true
    wait_anycast user1 srv-b 15
    sleep 0.5
    gap=$(probes_gap user1 f3)
    assert_le "failover after crash" "$gap" 1.5
    if frr_log_has r1 "$mark" 'NOTIFICATION: received from neighbor 10.201.11.10'; then
        fail "r1 got a NOTIFICATION from a killed herald"
    fi
}

scenario F4 default - "frozen process: router hold timer expires, herald recovers after unpause"
scn_F4() {
    allow_flap srv-a
    allow_warn srv-a 'hold timer expired|Hold Timer'
    trap 'compose unpause srv-a >/dev/null 2>&1 || true' EXIT
    local start t gap
    probes_start user1 f4
    start=$(now)
    compose pause srv-a >/dev/null 2>&1
    wait_anycast user1 srv-b 15
    t=$(elapsed "$start")
    measure "r1 hold timer failover" "$t"
    assert_le "failover after freeze" "$t" 12
    sleep $((15 - ${t%.*}))
    local since
    since=$(now)
    compose unpause srv-a >/dev/null 2>&1
    wait_anycast user1 srv-a 15
    t=$(elapsed "$since")
    measure "back to srv-a after unpause" "$t"
    gap=$(probes_gap user1 f4)
    wait_until 5 frr_established r1 10.201.11.10
    local n
    n=$(herald_logs srv-a "$since" | grep -c 'session established' || true)
    [ "$n" = 1 ] || fail "srv-a: $n sessions established after unpause, expected 1"
}

# Drops all packets on srv-a's link a (both ways) with nftables.
srv_a_blackhole() {
    on_sh srv-a 'nft add table inet e2e
        nft "add chain inet e2e in { type filter hook input priority -10; }"
        nft "add chain inet e2e out { type filter hook output priority -10; }"
        nft add rule inet e2e in iifname a drop
        nft add rule inet e2e out oifname a drop'
}
srv_a_blackhole_off() { on srv-a nft delete table inet e2e 2>/dev/null || true; }

scenario F5 default - "silent blackhole: both hold timers expire, no TCP close"
scn_F5() {
    allow_flap srv-a
    allow_warn srv-a 'hold timer expired|Hold Timer'
    trap srv_a_blackhole_off EXIT
    local start t since
    probes_start user1 f5
    start=$(now)
    srv_a_blackhole
    wait_anycast user1 srv-b 15
    t=$(elapsed "$start")
    measure "failover on blackhole" "$t"
    assert_le "failover on blackhole" "$t" 12
    wait_log srv-a "$start" 'session down' 15
    sleep $((15 - ${t%.*}))
    since=$(now)
    srv_a_blackhole_off
    wait_anycast user1 srv-a 20
    t=$(elapsed "$since")
    measure "back to srv-a after blackhole" "$t"
    probes_gap user1 f5 >/dev/null
    # herald notices on its own (hold timer), the reconnect then waits for backoff.
    assert_le "recovery after blackhole" "$t" 12
}

scenario F6 default - "link down on srv-a, later up"
scn_F6() {
    allow_flap srv-a
    allow_warn srv-a 'hold timer expired|Hold Timer'
    trap srv_a_link_restore EXIT
    local start t since
    probes_start user1 f6
    start=$(now)
    on srv-a ip link set dev a down
    wait_anycast user1 srv-b 15
    t=$(elapsed "$start")
    measure "failover on link down" "$t"
    assert_le "failover on link down" "$t" 12
    sleep $((15 - ${t%.*}))
    since=$(now)
    srv_a_link_restore
    wait_anycast user1 srv-a 20
    t=$(elapsed "$since")
    measure "back to srv-a after link up" "$t"
    probes_gap user1 f6 >/dev/null
    assert_le "recovery after link up" "$t" 12
}

# No route for the anycast prefixes on ROUTER (BGP RIB and kernel).
no_anycast_route() {
    local rib
    case $1 in
    r1) rib=$(frr_rib r1) ;;
    *) rib=$(bird_rib "$1") ;;
    esac
    if grep -E '^(192.0.2.0/24|2001:db8:1::/48) ' <<<"$rib"; then return 1; fi
    if on "$1" ip route get 192.0.2.10 2>/dev/null; then return 1; fi
    if on "$1" ip -6 route get 2001:db8:1::10 2>/dev/null | grep -v unreachable; then return 1; fi
}

scenario F7 default - "full stop: anycast unreachable, no stale route anywhere"
scn_F7() {
    allow_flap srv-a
    allow_flap srv-b
    trap 'server_start srv-a; server_start srv-b' EXIT
    compose stop -t 5 srv-a srv-b >/dev/null 2>&1
    wait_until 10 no_anycast_route r1
    wait_until 10 no_anycast_route r2
    assert_no_http user1 192.0.2.10
    assert_no_http user2 2001:db8:1::10
    # Still unreachable a little later (no route coming back from somewhere).
    sleep 3
    no_anycast_route r1 >/dev/null || fail "r1 has an anycast route again"
    no_anycast_route r2 >/dev/null || fail "r2 has an anycast route again"
}

scenario F8 default - "router restart: herald reconnects to FRR and BIRD on its own"
scn_F8() {
    local s
    for s in "${SERVERS[@]}"; do allow_flap "$s"; done
    local start t
    start=$(now)
    compose restart r1 >/dev/null 2>&1
    wait_until 60 frr_established r1 10.201.11.10
    wait_until 10 frr_established r1 10.201.0.10
    t=$(elapsed "$start")
    measure "r1 restart to srv-a and srv-c Established" "$t"
    wait_anycast user1 srv-a 15
    start=$(now)
    compose restart r2 >/dev/null 2>&1
    wait_until 60 bird_established r2 srv_b
    wait_until 10 bird_established r2 srv_c
    t=$(elapsed "$start")
    measure "r2 restart to srv-b and srv-c Established" "$t"
    wait_anycast user2 srv-b 15
}

# FRR admin shutdown of NEIGHBOR on r1 (with a message), or "off".
frr_shutdown() {
    if [ "$2" = off ]; then
        frr_conf r1 'router bgp 64510' "no neighbor $1 shutdown" >/dev/null
    else
        frr_conf r1 'router bgp 64510' "neighbor $1 shutdown message $2" >/dev/null
    fi
}

scenario F9 default - "admin shutdown by FRR: herald logs the text, backs off, reconnects"
scn_F9() {
    allow_flap srv-a
    trap 'frr_shutdown 10.201.11.10 off' EXIT
    local since t
    since=$(now)
    frr_shutdown 10.201.11.10 "maintenance F9"
    # herald's view first: the RFC 9003 text, and the reconnect delay doubled
    # (RFC 4486 §4). Polled, as it is only there until the reconnect ~1 s later
    # (r1 then closes the connection: last_down becomes "connection closed"),
    # so it is read before the slower log checks.
    f9_down() {
        local down
        down=$(herald_peer srv-a 10.201.11.2 .status)
        jq -e '.last_down.reason == "notification received" and .last_down.notification.subcode == 2
            and .last_down.notification.shutdown_text == "maintenance F9" and .backoff_ms >= 2000' \
            <<<"$down" >/dev/null || { echo "srv-a status: $(jq -c . <<<"$down")"; return 1; }
    }
    wait_until 5 f9_down
    wait_log srv-a "$since" 'peer sent NOTIFICATION notification=cease \(6/2\)' 5
    log_has srv-a "$since" 'maintenance F9' || fail "srv-a did not log the shutdown text:
$(herald_logs srv-a "$since" | grep NOTIFICATION)"
    wait_anycast user1 srv-b 5
    sleep 10
    since=$(now)
    frr_shutdown 10.201.11.10 off
    wait_until 15 frr_established r1 10.201.11.10
    t=$(elapsed "$since")
    measure "Established after no shutdown" "$t"
    assert_le "reconnect after no shutdown" "$t" 9
}

# Delays between herald's "connecting" lines for PEER (addr:port) since a time.
connect_delays() {
    herald_logs "$1" "$2" | grep "addr=$3.*connecting" | cut -c1-26 |
        while read -r ts; do date -d "$ts" +%s.%N; done |
        awk 'NR > 1 { printf "%s%.1f", sep, $1 - prev; sep = " " } { prev = $1 } END { print "" }'
}

scenario F10 full - "repeated shutdown: backoff doubles up to max_connect_retry, resets"
scn_F10() {
    allow_flap srv-a
    trap 'frr_shutdown 10.201.11.10 off' EXIT
    local since delays
    since=$(now)
    frr_shutdown 10.201.11.10 "F10"
    sleep 30
    delays=$(connect_delays srv-a "$since" 10.201.11.2:179)
    measure "reconnect delays while shut down" "'$delays'"
    local backoff
    backoff=$(herald_peer srv-a 10.201.11.2 .status.backoff_ms)
    measure "backoff after 30 s shut down" "$backoff" ms
    [ "$backoff" = 8000 ] || fail "backoff_ms $backoff after 30 s, want max_connect_retry 8000"
    # connect_retry 1 s doubling to max 8 s, jitter 0.75..1 (+ connect time). The delays
    # are between attempts, so the first one (Cease to first attempt, 1 s) is not listed.
    awk -v d="$delays" 'BEGIN {
        n = split(d, a, " "); want[1] = 2; want[2] = 4
        for (i = 1; i <= n; i++) {
            w = (i in want) ? want[i] : 8
            if (a[i] < w * 0.7 || a[i] > w + 0.6) exit 1
        }
        exit !(n >= 4)
    }' || fail "unexpected backoff delays: $delays (want 2 4 8 8 ...)"
    frr_shutdown 10.201.11.10 off
    wait_until 15 frr_established r1 10.201.11.10
    wait_until 5 herald_established srv-a 10.201.11.2
    backoff=$(herald_peer srv-a 10.201.11.2 .status.backoff_ms)
    [ "$backoff" = 1000 ] || fail "backoff_ms $backoff after Established, want connect_retry 1000"
    # The next failure starts at connect_retry again: 1 s to the first attempt
    # (not listed), 2 s to the second.
    since=$(now)
    frr_shutdown 10.201.11.10 "F10 again"
    sleep 5
    delays=$(connect_delays srv-a "$since" 10.201.11.2:179)
    measure "reconnect delays after Established" "'$delays'"
    awk -v d="$delays" 'BEGIN { split(d, a, " "); exit !(a[1] >= 1.4 && a[1] <= 2.6) }' ||
        fail "backoff did not reset after Established: $delays"
}

scenario F11 full - "BIRD disable/enable: like F9 on the BIRD side"
scn_F11() {
    allow_flap srv-b
    trap 'bird r2 enable srv_b >/dev/null' EXIT
    local since t
    since=$(now)
    bird r2 disable srv_b >/dev/null
    wait_log srv-b "$since" 'peer sent NOTIFICATION notification=cease \(6/2\)' 5
    wait_anycast user2 srv-a 5
    sleep 10
    since=$(now)
    bird r2 enable srv_b >/dev/null
    wait_until 15 bird_established r2 srv_b
    t=$(elapsed "$since")
    measure "Established after enable" "$t"
    assert_le "reconnect after enable" "$t" 9
    wait_anycast user2 srv-b 10
}

scenario F12 default - "flap storm: restart srv-a 10 times, final state equals baseline"
scn_F12() {
    allow_flap srv-a
    local i
    for i in $(seq 10); do
        compose restart -t 1 srv-a >/dev/null 2>&1
        sleep 0.5
    done
    wait_anycast user1 srv-a 20
    local n
    n=$(frr_rib r1 | grep -c '^192.0.2.0/24 10.201.11.10 ' || true)
    [ "$n" = 1 ] || fail "r1 has $n paths from srv-a for 192.0.2.0/24"
}

scenario F13 full - "alternating flaps for 60 s: never both servers missing"
scn_F13() {
    allow_flap srv-a
    allow_flap srv-b
    trap 'server_start srv-a; server_start srv-b' EXIT
    probe_start user1 192.0.2.10 f13-u1
    probe_start user2 192.0.2.10 f13-u2
    local end=$((SECONDS + 60))
    while [ $SECONDS -lt $end ]; do
        compose stop -t 5 srv-a >/dev/null 2>&1
        compose start srv-a >/dev/null 2>&1
        wait_anycast user1 srv-a 15
        compose stop -t 5 srv-b >/dev/null 2>&1
        compose start srv-b >/dev/null 2>&1
        wait_anycast user2 srv-b 15
    done
    local u gap
    for u in user1 user2; do
        gap=$(probe_stop "$u" "f13-$(sed 's/user/u/' <<<"$u")" | tee "$RUN_DIR/F13.probe.$u" | probe_max_gap)
        measure "$u longest gap" "$gap"
        assert_le "$u longest gap" "$gap" 1.5
    done
}

scenario F14 default - "start order: servers first, routers later"
scn_F14() {
    local s
    for s in "${SERVERS[@]}"; do allow_flap "$s"; done
    trap 'compose start r1 r2 >/dev/null 2>&1' EXIT
    compose stop -t 2 r1 r2 >/dev/null 2>&1
    compose restart -t 2 "${SERVERS[@]}" >/dev/null 2>&1
    local since
    since=$(now)
    sleep 10
    # Backoff 1, 2, 4 s (+ 1 s connect timeout each): a few attempts, no flood.
    local n
    for s in "${SERVERS[@]}"; do
        n=$(herald_logs "$s" "$since" | grep -c 'connect failed' || true)
        info "$s: $n connect failures in 10 s"
        [ "$n" -le 12 ] || fail "$s: $n connect failures in 10 s (log flood)"
        [ "$n" -ge 1 ] || fail "$s: no connect attempt while routers are down"
    done
    local start t
    start=$(now)
    compose start r1 r2 >/dev/null 2>&1
    wait_until 60 all_established
    t=$(elapsed "$start")
    measure "routers start to all Established" "$t"
    # Router start-up (~5 s) plus at most one backoff step (max_connect_retry 8 s).
    assert_le "routers start to all Established" "$t" 15
}

scenario F15 full - "neighbor removed on FRR: herald backs off without log flood"
scn_F15() {
    allow_flap srv-a
    allow_warn srv-a 'peer sent NOTIFICATION'
    trap frr_srv_a_neighbor EXIT
    local since n t
    since=$(now)
    frr_conf r1 'router bgp 64510' 'no neighbor 10.201.11.10' >/dev/null
    sleep 20
    n=$(herald_logs srv-a "$since" | grep -cE ' (WARN|ERROR) ' || true)
    info "srv-a: $n WARN lines in 20 s"
    # Backoff 1, 2, 4, 8, 8 s: about 5 attempts with 1-2 WARN lines each.
    [ "$n" -le 10 ] || fail "srv-a: $n WARN lines in 20 s (log flood)"
    since=$(now)
    frr_srv_a_neighbor
    wait_until 15 frr_established r1 10.201.11.10
    t=$(elapsed "$since")
    measure "Established after re-adding the neighbor" "$t"
}

frr_srv_a_neighbor() {
    frr_conf r1 'router bgp 64510' \
        'neighbor 10.201.11.10 remote-as 64500' 'neighbor 10.201.11.10 description srv-a' \
        'neighbor 10.201.11.10 passive' 'neighbor 10.201.11.10 advertisement-interval 0' \
        'address-family ipv4 unicast' 'neighbor 10.201.11.10 activate' 'exit-address-family' \
        'address-family ipv6 unicast' 'neighbor 10.201.11.10 activate' 'exit-address-family' >/dev/null
}

scenario F16 full - "long TCP flow over failover breaks, short requests continue (informative)"
scn_F16() {
    allow_flap srv-a
    trap 'frr_shutdown 10.201.11.10 off; on srv-a rm -f /www/big' EXIT
    on srv-a dd if=/dev/zero of=/www/big bs=1M count=8 2>/dev/null
    # 8 MiB at 1 MiB/s: still running when the route moves to srv-b.
    on_bg user1 sh -c 'curl -s --limit-rate 1M -o /dev/null -w "%{http_code} %{size_download}\n" http://192.0.2.10/big >/tmp/f16 2>&1; echo "exit $?" >>/tmp/f16'
    sleep 2
    frr_shutdown 10.201.11.10 "F16"
    wait_anycast user1 srv-b 5
    wait_until 15 on user1 grep -q exit /tmp/f16
    info "long flow: $(on user1 cat /tmp/f16 | xargs)"
    on user1 rm -f /tmp/f16
}
