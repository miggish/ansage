# K: kernel routes ([kernel]). srv-c learns the routers' routes and
# installs its best ones into its own routing table (protocol bgp). r1 (FRR)
# and r2 (BIRD) both send 192.0.2.0/24 (srv-a/srv-b's anycast) with
# themselves as next hop: equal paths, r1 (10.201.0.2) wins the tie-break,
# r2 (10.201.0.3) is the alternative. Each router passes the other's own
# networks on with the other's next hop (third-party next hop on the shared
# core subnet), so user1's network stays via r1 while r1's session is down,
# and leaves the kernel only when r1 itself is unreachable.

R1=10.201.0.2
R2=10.201.0.3

# k_start NAME [srv_c_conf args...]: srv-c with [kernel], both sessions up
# and 192.0.2.0/24 in its kernel.
k_start() {
    local name=$1
    shift
    srv_c_conf "$name" extra="[kernel]
${K_KERNEL:-}" "$@"
    SRV_C_SUPERVISED=1 SRV_C_STAY=${K_STAY:-} srv_c_use "gen-$name.toml"
    wait_until 20 frr_established r1 10.201.0.10 || fail "r1: no session with srv-c"
    wait_until 20 bird_established r2 srv_c || fail "r2: no session with srv-c"
    wait_until 10 k_via_is 192.0.2.0/24 "$R1" || fail "192.0.2.0/24 not in srv-c's kernel via r1"
}

# k_via PREFIX: the gateway of ansage's kernel route for PREFIX (empty: none).
k_via() {
    local fam=-4
    [[ $1 == *:* ]] && fam=-6
    on srv-c ip "$fam" -j route show proto bgp "$1" | jq -r '.[0].gateway // empty'
}

k_via_is() { [ "$(k_via "$1")" = "$2" ]; }
k_absent() { [ -z "$(k_via "$1")" ]; }

# Number of ansage's kernel routes (both families).
k_count() {
    on_sh srv-c 'ip -4 route show proto bgp; ip -6 route show proto bgp' | wc -l
}

fib_json() { on srv-c ansage show fib --json; }

k_ansage_gone() { ! on srv-c pidof ansage >/dev/null 2>&1; }

scenario K1 default - "[kernel]: srv-c installs the routers' best routes; own and connected prefixes stay out"
scn_K1() {
    trap 'srv_c_use ansage.toml' EXIT
    k_start k1
    wait_until 10 k_via_is 10.201.2.0/24 "$R2" || fail "user2's network not via r2"
    wait_until 10 k_via_is 2001:db8:1::/48 2001:db8:201::2 || fail "2001:db8:1::/48 not via r1"
    k_absent 198.51.100.0/24 || fail "srv-c installed its own prefix"
    k_absent 2001:db8:2::/48 || fail "srv-c installed its own IPv6 prefix"
    # r2 sends the core subnet; the connected route (metric 256 for IPv6)
    # must stay in charge.
    k_absent 2001:db8:201::/64 || fail "srv-c took over its connected IPv6 subnet"
    on srv-c ip -6 route show 2001:db8:201::/64 | grep -q 'proto kernel' ||
        fail "connected IPv6 route gone"
    local fib
    fib=$(fib_json)
    jq -e '.shadowed >= 1 and .failed == 0 and .unresolved == 0' <<<"$fib" >/dev/null ||
        fail "unexpected FIB state: $fib"
    jq -e '[.next_hops[] | select(.via == null)] | length == 0' <<<"$fib" >/dev/null ||
        fail "unreachable next hops: $fib"
    log "kernel routes: $(k_count), $(jq -c '{installed_ipv4, installed_ipv6, shadowed}' <<<"$fib")"
    # The kernel uses them: user2 is reached via r2 directly, not via the
    # default route through r1.
    on srv-c ip route get 10.201.2.10 | grep -q "via $R2" || fail "user2 not routed via r2"
    on srv-c ping -c 1 -W 2 10.201.2.10 >/dev/null || fail "srv-c cannot reach user2"
}

scenario K2 default - "r1's session goes down: srv-c's kernel route moves to r2, and back"
scn_K2() {
    allow_flap srv-c
    trap 'frr_conf r1 "router bgp 64510" "no neighbor 10.201.0.10 shutdown" >/dev/null; srv_c_use ansage.toml' EXIT
    k_start k2
    local start t
    start=$(now)
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 shutdown' >/dev/null
    wait_until 5 k_via_is 192.0.2.0/24 "$R2" || fail "192.0.2.0/24 did not move to r2"
    t=$(elapsed "$start")
    measure "kernel route moved after r1 shutdown" "$t"
    assert_le "kernel route moved to r2" "$t" 2
    # r2's copy of user1's network still points at r1.
    k_via_is 10.201.1.0/24 "$R1" || fail "user1's network not via r1 any more: $(k_via 10.201.1.0/24)"
    frr_conf r1 'router bgp 64510' 'no neighbor 10.201.0.10 shutdown' >/dev/null
    wait_until 20 k_via_is 192.0.2.0/24 "$R1" || fail "192.0.2.0/24 did not move back to r1"
}

scenario K3 default - "r1's address becomes unreachable in srv-c's kernel: routes move before the session notices"
scn_K3() {
    allow_flap srv-c
    trap 'on srv-c ip route del unreachable '"$R1"'/32 2>/dev/null || true; srv_c_use ansage.toml' EXIT
    k_start k3
    local start t
    start=$(now)
    on srv-c ip route add unreachable "$R1/32"
    wait_until 5 k_via_is 192.0.2.0/24 "$R2" || fail "192.0.2.0/24 did not move to r2"
    t=$(elapsed "$start")
    measure "kernel route moved after next hop became unreachable" "$t"
    assert_le "next hop change noticed (event + 100 ms debounce)" "$t" 1.5
    ansage_established srv-c "$R1" || fail "the session to r1 was already down: nothing to show"
    # Every path to user1's network leads to r1: none usable.
    wait_until 2 k_absent 10.201.1.0/24 || fail "user1's network still in the kernel"
    jq -e --arg r1 "$R1" '.next_hops[] | select(.address == $r1) | .via == null' <<<"$(fib_json)" >/dev/null ||
        fail "show fib does not list r1 as unreachable"
    on srv-c ip route del unreachable "$R1/32"
    wait_until 5 k_via_is 192.0.2.0/24 "$R1" || fail "192.0.2.0/24 did not move back to r1"
}

scenario K4 default - "ansage upgrade keeps the kernel routes: no gap, then taken over"
scn_K4() {
    allow_flap srv-c
    trap 'srv_c_use ansage.toml' EXIT
    k_start k4 top="graceful_restart = true"
    local before pid out min=100000 n
    before=$(k_count)
    pid=$(ansage_pid srv-c)
    on srv-c ansage upgrade --binary /usr/local/bin/ansage >"$RUN_DIR/$SCN_ID.upgrade" 2>&1 &
    local up=$!
    # Count ansage's kernel routes while the upgrade runs.
    while kill -0 "$up" 2>/dev/null; do
        n=$(k_count)
        [ "$n" -lt "$min" ] && min=$n
        sleep 0.1
    done
    wait "$up" || fail "ansage upgrade failed: $(cat "$RUN_DIR/$SCN_ID.upgrade")"
    [ "$(ansage_pid srv-c)" != "$pid" ] || fail "ansage was not restarted"
    log "kernel routes before: $before, fewest during the upgrade: $min"
    [ "$min" -ge "$before" ] || fail "kernel routes went missing during the upgrade ($min of $before)"
    wait_log srv-c "" 'neighbors in sync' 10
    wait_until 5 k_via_is 192.0.2.0/24 "$R1" || fail "192.0.2.0/24 not via r1 after the upgrade"
    jq -e '.adopted == 0' <<<"$(fib_json)" >/dev/null || fail "adopted routes left: $(fib_json)"
}

scenario K5 default - "stop: ansage removes its kernel routes"
scn_K5() {
    allow_flap srv-c
    # Back to both sessions up before the next scenario: after the Cease,
    # r2 (BIRD) can still close a fresh connection while it settles.
    trap 'srv_c_use ansage.toml
        wait_until 20 frr_established r1 10.201.0.10
        wait_until 20 bird_established r2 srv_c' EXIT
    K_STAY=1 k_start k5
    [ "$(k_count)" -gt 0 ] || fail "no kernel routes to begin with"
    on srv-c pkill -TERM -x ansage
    wait_until 10 k_ansage_gone
    [ "$(k_count)" = 0 ] || fail "kernel routes left after the stop: $(on srv-c ip route show proto bgp)"
    [ -z "$(on srv-c ip nexthop show)" ] || fail "nexthop objects left: $(on srv-c ip nexthop show)"
}
