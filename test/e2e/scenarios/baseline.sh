# B: baseline and steady state.

scenario B1 default - "baseline routing: user1 <-> user2 without herald"
scn_B1() {
    ping_ok user1 10.201.2.10 || fail "user1 cannot ping user2 (IPv4)"
    ping_ok user1 2001:db8:201:2::10 || fail "user1 cannot ping user2 (IPv6)"
    ping_ok user2 10.201.1.10 || fail "user2 cannot ping user1 (IPv4)"
    ping_ok user2 2001:db8:201:1::10 || fail "user2 cannot ping user1 (IPv6)"
    assert_path user1 10.201.2.10 10.201.1.2 10.201.0.3 10.201.2.10
    assert_path user1 2001:db8:201:2::10 2001:db8:201:1::2 2001:db8:201::3 2001:db8:201:2::10
}

scenario B2 default - "steady anycast: each user reaches its nearest server"
scn_B2() {
    local addr
    for addr in 192.0.2.10 2001:db8:1::10; do
        assert_http user1 "$addr" srv-a
        assert_http user2 "$addr" srv-b
    done
    for addr in 198.51.100.10 2001:db8:2::10; do
        assert_http user1 "$addr" srv-c
        assert_http user2 "$addr" srv-c
    done
    assert_path user1 192.0.2.10 10.201.1.2 192.0.2.10
    assert_path user2 192.0.2.10 10.201.2.2 192.0.2.10
    assert_path user1 2001:db8:1::10 2001:db8:201:1::2 2001:db8:1::10
    assert_path user2 2001:db8:1::10 2001:db8:201:2::2 2001:db8:1::10
    assert_path user1 198.51.100.10 10.201.1.2 198.51.100.10
    assert_path user2 198.51.100.10 10.201.2.2 198.51.100.10
}

# Kernel route of ROUTER towards ADDR must go via NEXT_HOP on DEV.
assert_kernel_route() {
    local got
    got=$(on "$1" ip route get "$2" 2>&1)
    [[ $got == *"via $3 dev $4 "* ]] || fail "$1: route to $2 should be via $3 dev $4, got: $got"
}

scenario B3 default - "next hop: session address (IPv4), next_hop_ipv6 (IPv6)"
scn_B3() {
    local rib
    rib=$(frr_rib r1)
    grep -qx '192.0.2.0/24 10.201.11.10 64500 10.201.11.10 best' <<<"$rib" ||
        fail "r1: 192.0.2.0/24 from srv-a not best via 10.201.11.10:
$(grep '^192.0.2.0/24' <<<"$rib")"
    grep -qx '2001:db8:1::/48 10.201.11.10 64500 2001:db8:201:11::10 best' <<<"$rib" ||
        fail "r1: 2001:db8:1::/48 from srv-a not best via 2001:db8:201:11::10:
$(grep '^2001:db8:1::/48' <<<"$rib")"
    grep -qx '198.51.100.0/24 10.201.0.10 64502 10.201.0.10 best' <<<"$rib" ||
        fail "r1: 198.51.100.0/24 from srv-c not best via 10.201.0.10"
    grep -qx '2001:db8:2::/48 10.201.0.10 64502 2001:db8:201::10 best' <<<"$rib" ||
        fail "r1: 2001:db8:2::/48 from srv-c not best via 2001:db8:201::10"
    rib=$(bird_rib r2)
    grep -qx '192.0.2.0/24 srv_b AS64500i 10.201.12.10 best' <<<"$rib" ||
        fail "r2: 192.0.2.0/24 from srv-b not best via 10.201.12.10:
$(grep '^192.0.2.0/24' <<<"$rib")"
    grep -qx '2001:db8:1::/48 srv_b AS64500i 2001:db8:201:12::10 best' <<<"$rib" ||
        fail "r2: 2001:db8:1::/48 from srv-b not best via 2001:db8:201:12::10"
    grep -qx '198.51.100.0/24 srv_c AS64502i 10.201.0.10 best' <<<"$rib" ||
        fail "r2: 198.51.100.0/24 from srv-c not best via 10.201.0.10"
    grep -qx '2001:db8:2::/48 srv_c AS64502i 2001:db8:201::10 best' <<<"$rib" ||
        fail "r2: 2001:db8:2::/48 from srv-c not best via 2001:db8:201::10"
    # The routers installed them in the kernel.
    assert_kernel_route r1 192.0.2.10 10.201.11.10 a
    assert_kernel_route r1 2001:db8:1::10 2001:db8:201:11::10 a
    assert_kernel_route r2 192.0.2.10 10.201.12.10 b
    assert_kernel_route r2 2001:db8:1::10 2001:db8:201:12::10 b
    assert_kernel_route r1 198.51.100.10 10.201.0.10 core
    assert_kernel_route r2 2001:db8:2::10 2001:db8:201::10 core
}

# Attributes FRR shows for the path of PREFIX learned from PEER, as JSON.
frr_path() {
    local afi=ipv4
    case $2 in *:*) afi=ipv6 ;; esac
    frr "$1" "show bgp $afi unicast $2 json" | jq -c --arg p "$3" '[.paths[] | select(.peer.peerId == $p)][0]'
}

# FRR: ORIGIN IGP, AS_PATH exactly ASN, nothing else (no MED, LOCAL_PREF,
# communities, aggregator, ...).
assert_frr_attrs() {
    local path keys
    path=$(frr_path "$1" "$2" "$3")
    [ "$path" != null ] || fail "$1: no path for $2 from $3"
    keys=$(jq -r 'keys | join(" ")' <<<"$path")
    [ "$keys" = "aspath bestpath lastUpdate lastUpdateStr nexthops origin peer valid version" ] ||
        fail "$1: $2 from $3 has unexpected attributes: $keys"
    [ "$(jq -r .origin <<<"$path")" = IGP ] || fail "$1: $2 origin $(jq -r .origin <<<"$path")"
    [ "$(jq -r .aspath.string <<<"$path")" = "$4" ] || fail "$1: $2 AS path '$(jq -r .aspath.string <<<"$path")', expected '$4'"
}

# BIRD: the bgp_* attributes of PREFIX from PROTOCOL. BIRD adds
# bgp_local_pref 100 itself on eBGP import.
assert_bird_attrs() {
    local attrs
    attrs=$(bird "$1" show route all "$2" protocol "$3" | awk '$1 ~ /^bgp_/ { sub(/:$/, "", $1); $1 = $1 "="; print }' | tr -d ' ' | sort | paste -sd' ')
    local want="bgp_local_pref=100 bgp_next_hop=$5 bgp_origin=IGP bgp_path=$4"
    [ "$attrs" = "$want" ] || fail "$1: $2 from $3 has attributes '$attrs', expected '$want'"
}

scenario B4 default - "attributes on the wire: ORIGIN IGP, AS path only, nothing else"
scn_B4() {
    assert_frr_attrs r1 192.0.2.0/24 10.201.11.10 64500
    assert_frr_attrs r1 2001:db8:1::/48 10.201.11.10 64500
    assert_frr_attrs r1 198.51.100.0/24 10.201.0.10 64502
    assert_frr_attrs r1 2001:db8:2::/48 10.201.0.10 64502
    assert_bird_attrs r2 192.0.2.0/24 srv_b 64500 10.201.12.10
    # IPv6 over an IPv4 session: one global next hop, no link-local (RFC 2545).
    assert_bird_attrs r2 2001:db8:1::/48 srv_b 64500 2001:db8:201:12::10
    assert_bird_attrs r2 198.51.100.0/24 srv_c 64502 10.201.0.10
    assert_bird_attrs r2 2001:db8:2::/48 srv_c 64502 2001:db8:201::10
}

scenario B5 default - "capabilities and timers as negotiated"
scn_B5() {
    local n caps
    for n in 10.201.11.10 10.201.0.10; do
        caps=$(frr_neighbor r1 "$n" .neighborCapabilities)
        jq -e '."4byteAs" == "advertisedAndReceived" and .extendedMessage == "advertisedAndReceived"
            and .routeRefresh == "advertisedAndReceived"
            and .multiprotocolExtensions.ipv4Unicast.advertisedAndReceived
            and .multiprotocolExtensions.ipv6Unicast.advertisedAndReceived
            and (.gracefulRestart == "advertised") and (.addPath.ipv4Unicast.rxReceived | not)' \
            <<<"$caps" >/dev/null || fail "r1 $n: unexpected capabilities: $caps"
        [ "$(frr_neighbor r1 "$n" .bgpTimerHoldTimeMsecs)" = 9000 ] || fail "r1 $n: hold time not 9 s"
    done
    for n in srv_b srv_c; do
        caps=$(bird r2 show protocols all "$n" | sed -n '/Neighbor capabilities/,/Session:/p')
        local c
        for c in 'AF announced: ipv4 ipv6' 'Route refresh' 'Extended message' '4-octet AS numbers'; do
            grep -q "$c" <<<"$caps" || fail "r2 $n: neighbor capability '$c' missing:
$caps"
        done
        for c in 'Graceful restart' 'Long-lived' 'Enhanced refresh' 'ADD-PATH'; do
            if grep -q "$c" <<<"$caps"; then fail "r2 $n: herald should not announce '$c'"; fi
        done
        bird r2 show protocols all "$n" | grep -E 'Hold timer: +[0-9.]+/9$' >/dev/null || fail "r2 $n: hold time not 9 s"
    done
}

scenario B6 default - "End-of-RIB sent for both families"
scn_B6() {
    allow_flap srv-a
    allow_flap srv-b
    local mark since
    # FRR logs every received End-of-RIB; reset the session and look.
    mark=$(frr_log_mark r1)
    frr r1 "clear bgp 10.201.11.10" >/dev/null
    wait_until 15 frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv4 Unicast from 10.201.11.10'
    wait_until 5 frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv6 Unicast from 10.201.11.10'
    # BIRD logs packets only with debugging on.
    since=$(now)
    bird r2 debug srv_b "{ packets }" >/dev/null
    bird r2 restart srv_b >/dev/null
    poll_until 15 bird_established r2 srv_b || { bird r2 debug srv_b off >/dev/null; fail "srv_b not back"; }
    sleep 1
    bird r2 debug srv_b off >/dev/null
    local n
    n=$(bird_log r2 "$since" | grep -c 'srv_b: Got END-OF-RIB' || true)
    [ "$n" = 2 ] || fail "r2: $n End-of-RIB from srv-b, expected 2"
}

# Sets FRR's timers for NEIGHBOR (keepalive hold) and resets the session.
frr_timers() {
    if [ "$2" = default ]; then
        frr_conf r1 'router bgp 64510' "no neighbor $1 timers"
    else
        frr_conf r1 'router bgp 64510' "neighbor $1 timers $2 $3"
    fi
    frr r1 "clear bgp $1" >/dev/null
}

scenario B7 default - "hold time negotiation: router proposes 30, then 6"
scn_B7() {
    allow_flap srv-a
    trap 'frr_timers 10.201.11.10 default' EXIT
    local since dropped
    since=$(now)
    frr_timers 10.201.11.10 10 30
    wait_log srv-a "$since" 'session established .*hold_time=9' 20
    wait_until 10 frr_established r1 10.201.11.10
    [ "$(frr_neighbor r1 10.201.11.10 .bgpTimerHoldTimeMsecs)" = 9000 ] || fail "r1: hold time not 9 s with 30 proposed"

    since=$(now)
    frr_timers 10.201.11.10 2 6
    wait_log srv-a "$since" 'session established .*hold_time=6' 20
    wait_until 10 frr_established r1 10.201.11.10
    [ "$(frr_neighbor r1 10.201.11.10 .bgpTimerHoldTimeMsecs)" = 6000 ] || fail "r1: hold time not 6 s with 6 proposed"
    # herald must send keepalives every 2 s now: the session survives 3 hold times.
    dropped=$(frr_neighbor r1 10.201.11.10 .connectionsDropped)
    since=$(now)
    sleep 18
    frr_established r1 10.201.11.10 || fail "session dropped with hold time 6"
    [ "$(frr_neighbor r1 10.201.11.10 .connectionsDropped)" = "$dropped" ] || fail "session flapped with hold time 6"
    if log_has srv-a "$since" 'session down'; then fail "srv-a: session went down with hold time 6"; fi
}

scenario B8 default - "quiet logs: no WARN/ERROR while idle"
scn_B8() {
    sleep "${E2E_IDLE:-30}"
    # The invariant check fails on any WARN/ERROR since the scenario started.
}

# Routes FRR router R1 sends to NEIGHBOR for AFI (ipv4/ipv6) whose path has
# none of ASN (herald drops those as AS loops): the count herald must store.
frr_sent_without_loop() {
    frr "$1" "show bgp $3 unicast neighbors $2 advertised-routes json" |
        jq --arg asn "$4" '[.advertisedRoutes[] | select(.path | split(" ") | index($asn) | not)] | length'
}

# BIRD protocol routes: "imported_v4 imported_v6 exported_v4 exported_v6".
bird_route_counts() {
    bird "$1" show protocols all "$2" | awk '/Routes:/ { i[++n] = $2; e[n] = $4 } END { print i[1], i[2], e[1], e[2] }'
}

scenario B9 default - "herald's own view (control socket): sessions and counts agree with the routers"
scn_B9() {
    local s mode
    for s in "${SERVERS[@]}"; do
        mode=$(on "$s" stat -c %A /run/herald/herald.sock) || fail "$s: no control socket"
        [ "$mode" = srwxrwx--- ] || [ "$mode" = srw-rw---- ] || fail "$s: socket mode $mode"
        # The text output works too.
        on "$s" herald show summary | grep -E '^1 +.* Established ' >/dev/null ||
            fail "$s: summary shows no Established neighbor:
$(on "$s" herald show summary)"
    done

    # What herald says it sent = what the routers got; what it stored = what
    # they sent (minus AS loops; srv-b imports nothing).
    local server peer local_addr asn adv recv sent4 sent6 counts
    for s in "srv-a 10.201.11.2 10.201.11.10 64500" "srv-c 10.201.0.2 10.201.0.10 64502"; do
        read -r server peer local_addr asn <<<"$s"
        adv=$(herald_peer "$server" "$peer" '.rib | "\(.advertised_ipv4) \(.advertised_ipv6)"')
        counts=$(frr r1 "show bgp summary json" |
            jq -r --arg n "$local_addr" '"\(.ipv4Unicast.peers[$n].pfxRcd) \(.ipv6Unicast.peers[$n].pfxRcd)"')
        [ "$adv" = "$counts" ] || fail "$server -> r1: herald advertised $adv, r1 received $counts"
        sent4=$(frr_sent_without_loop r1 "$local_addr" ipv4 "$asn")
        sent6=$(frr_sent_without_loop r1 "$local_addr" ipv6 "$asn")
        recv=$(herald_received "$server" "$peer")
        [ "$recv" = "$sent4 $sent6" ] || fail "r1 -> $server: herald stored $recv, r1 sent $sent4 $sent6 (without AS loops)"
    done
    local i4 i6 e4 e6
    for s in "srv-b 10.201.12.2 srv_b" "srv-c 10.201.0.3 srv_c"; do
        read -r server peer local_addr <<<"$s"
        read -r i4 i6 e4 e6 <<<"$(bird_route_counts r2 "$local_addr")"
        adv=$(herald_peer "$server" "$peer" '.rib | "\(.advertised_ipv4) \(.advertised_ipv6)"')
        [ "$adv" = "$i4 $i6" ] || fail "$server -> r2: herald advertised $adv, r2 imported $i4 $i6"
        recv=$(herald_received "$server" "$peer")
        if [ "$server" = srv-b ]; then
            [ "$recv" = "0 0" ] || fail "srv-b imports nothing, but stored $recv"
        else
            [ "$recv" = "$e4 $e6" ] || fail "r2 -> $server: herald stored $recv, r2 exported $e4 $e6"
        fi
    done

    # Counters of a healthy session.
    local c
    for s in "${HERALD_SESSIONS[@]}"; do
        read -r server peer <<<"$s"
        c=$(herald_peer "$server" "$peer" .counters)
        jq -e '.messages_in.keepalive > 0 and .messages_out.keepalive > 0 and .messages_out.update > 0
            and .prefixes_announced > 0 and .decode_errors == 0 and .malformed_updates == 0
            and .control_drops == 0 and .data_drops == 0' <<<"$c" >/dev/null ||
            fail "$server $peer: unexpected counters: $(jq -c . <<<"$c")"
    done
}
