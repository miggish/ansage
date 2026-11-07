# I: network impairment with tc netem on link a (both ends: srv-a and r1).

netem_a() {
    on srv-a tc qdisc replace dev a root netem "$@" || fail "netem on srv-a failed"
    on r1 tc qdisc replace dev a root netem "$@" || fail "netem on r1 failed"
}
netem_a_off() {
    on srv-a tc qdisc del dev a root 2>/dev/null || true
    on r1 tc qdisc del dev a root 2>/dev/null || true
}

# The srv-a session stays up for SECONDS (no drop on r1, no "session down").
assert_stable_a() {
    local dropped since
    dropped=$(frr_neighbor r1 10.201.11.10 .connectionsDropped)
    since=$(now)
    sleep "$1"
    frr_established r1 10.201.11.10 || fail "session down"
    [ "$(frr_neighbor r1 10.201.11.10 .connectionsDropped)" = "$dropped" ] || fail "session flapped"
    if log_has srv-a "$since" 'session down'; then fail "srv-a: session down"; fi
}

# Route refreshes push UPDATEs through the impaired link.
refresh_a() {
    local i
    for i in 1 2 3; do
        frr r1 "clear bgp 10.201.11.10 soft in" >/dev/null
        sleep 1
    done
}

scenario I1 full - "latency 200 ms +- 50 ms: stable, routes correct"
scn_I1() {
    trap netem_a_off EXIT
    netem_a delay 200ms 50ms
    refresh_a
    assert_stable_a 30
    assert_http user1 192.0.2.10 srv-a
}

scenario I2 full - "loss 10 % stable; 30 % recorded"
scn_I2() {
    allow_flap srv-a
    allow_warn srv-a 'hold timer expired|Hold Timer'
    trap netem_a_off EXIT
    netem_a loss 10%
    refresh_a
    assert_stable_a 30
    local dropped since
    netem_a loss 30%
    dropped=$(frr_neighbor r1 10.201.11.10 .connectionsDropped)
    since=$(now)
    sleep 30
    measure "flaps in 30 s at 30 % loss" "$(($(frr_neighbor r1 10.201.11.10 .connectionsDropped) - dropped))" flaps
    measure "srv-a session down lines at 30 % loss" "$(herald_logs srv-a "$since" | grep -c 'session down' || true)" lines
}

scenario I3 full - "reorder 25 % + duplicate 5 %: stable, no decode errors"
scn_I3() {
    trap netem_a_off EXIT
    netem_a delay 10ms reorder 25% 50% duplicate 5%
    refresh_a
    assert_stable_a 30
}

scenario I4 full - "MTU 1280 on srv-c's link + 5000/2000 own prefixes: all arrive"
scn_I4() {
    allow_flap srv-c
    trap 'n_restore' EXIT
    srv_c_conf i4 announce="$(many_prefixes 5000 2000)"
    srv_c_use gen-i4.toml
    on srv-c ip link set dev core mtu 1280
    # New TCP sessions after the MTU change (MSS 1240).
    frr r1 "clear bgp 10.201.0.10" >/dev/null
    bird r2 restart srv_c >/dev/null
    wait_until 60 eval '[ "$(pfx_rcvd ipv4Unicast) $(pfx_rcvd ipv6Unicast)" = "5001 2001" ]'
    wait_until 60 eval '[ "$(bird_srv_c_imported)" = "5001 2001" ]'
    sleep 15
    frr_established r1 10.201.0.10 || fail "r1 session down"
    bird_established r2 srv_c || fail "r2 session down"
}
