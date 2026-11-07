# N: session and negotiation.
#
# herald-side cases recreate srv-c with a generated config (srv_c_conf +
# srv_c_use); router-side cases change FRR at runtime (vtysh) or run BIRD
# with a variant config (bird_use). Every scenario restores both on exit.

# Restores srv-c's default config and FRR's srv-c neighbor.
n_restore() {
    srv_c_use herald.toml
    local c
    for c in 'neighbor 10.201.0.10 remote-as 64502' 'no neighbor 10.201.0.10 password' \
        'no neighbor 10.201.0.10 timers' 'no neighbor 10.201.0.10 ttl-security hops 1' \
        'no neighbor 10.201.0.10 timers connect' 'neighbor 10.201.0.10 passive'; do
        frr_conf r1 'router bgp 64510' "$c" >/dev/null 2>&1 || true
    done
    frr r1 "clear bgp 10.201.0.10" >/dev/null 2>&1 || true
    bird_restore r2
}

# Is the FRR path for PREFIX from PEER present (prints it)?
frr_has_path() { frr_path r1 "$1" "$2" | grep -v '^null$'; }

scenario N1 default - "wrong AS (herald side): herald sends Bad Peer AS, retries with backoff"
scn_N1() {
    allow_flap srv-c
    allow_warn srv-c 'sent NOTIFICATION'
    trap n_restore EXIT
    local mark since
    mark=$(frr_log_mark r1)
    since=$(now)
    srv_c_conf n1 r1_asn=64999
    srv_c_use gen-n1.toml
    wait_log srv-c "$since" 'addr=10.201.0.2:179.*sent NOTIFICATION notification=.*\(2/2\)' 10
    wait_until 5 frr_log_has r1 "$mark" 'NOTIFICATION: received from neighbor 10.201.0.10 2/2'
    # The other session is not affected.
    wait_until 10 bird_established r2 srv_c
    sleep 12
    bird_established r2 srv_c || fail "srv-c's session to r2 went down"
    # herald's view: what it sent, and whether it backs off.
    local down delays backoff
    down=$(herald_peer srv-c 10.201.0.2 .status.last_down)
    jq -e '.reason == "notification sent" and .notification.code == 2 and .notification.subcode == 2' \
        <<<"$down" >/dev/null || fail "srv-c: last down is not Bad Peer AS: $(jq -c . <<<"$down")"
    delays=$(connect_delays srv-c "$since" 10.201.0.2:179)
    measure "retry delays after Bad Peer AS" "'$delays'"
    backoff=$(herald_peer srv-c 10.201.0.2 .status.backoff_ms)
    measure "backoff after 12 s of Bad Peer AS" "$backoff" ms
    [ "$backoff" -ge 4000 ] || fail "no backoff: backoff_ms $backoff after 12 s (connect_retry 1 s)"
    # Backoff 1, 2, 4, 8 s: within 12 s at least one delay of 3 s or more.
    awk -v d="$delays" 'BEGIN { n = split(d, a, " "); for (i = 1; i <= n; i++) if (a[i] >= 3) exit 0; exit 1 }' ||
        fail "no backoff: retry delays $delays"
}

scenario N2 default - "wrong AS (router side): FRR sends Bad Peer AS, herald logs it"
scn_N2() {
    allow_flap srv-c
    trap n_restore EXIT
    local since
    since=$(now)
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 remote-as 64999' >/dev/null
    frr r1 "clear bgp 10.201.0.10" >/dev/null
    wait_log srv-c "$since" 'addr=10.201.0.2:179.*peer sent NOTIFICATION notification=.*\(2/2\)' 15
    bird_established r2 srv_c || fail "srv-c's session to r2 went down"
}

scenario N3 default - "IPv4-only peer: BIRD without IPv6 channel for srv-b"
scn_N3() {
    allow_flap srv-b
    trap 'bird_restore r2' EXIT
    local since
    since=$(now)
    bird_use r2 '/^protocol bgp srv_b/,/^}/{/^    ipv6 /d}'
    wait_log srv-b "$since" 'session established .*families=\[\(Afi\(1\), Safi\(1\)\)\]' 15
    wait_until 10 http_is user2 192.0.2.10 srv-b
    # No IPv6 route from srv-b: user2's IPv6 traffic goes to srv-a.
    wait_until 10 http_is user2 2001:db8:1::10 srv-a
    wait_log srv-b "$since" 'end of RIB from peer peer=1 afi=Afi\(1\)' 5
}

# BIRD variant: srv_c over IPv6 transport.
N4_BIRD='/^protocol bgp srv_c/,/^}/{
s/local 10.201.0.3;/local 2001:db8:201::3;/
s/neighbor 10.201.0.10 as/neighbor 2001:db8:201::10 as/
s/ipv4 { import all; export all; };/ipv4 { import all; export all; next hop address 10.201.0.3; };/
s/ipv6 { import all; export all; next hop address 2001:db8:201::3; };/ipv6 { import all; export all; };/
}'

scenario N4 default - "session over IPv6 transport: next hops per family"
scn_N4() {
    allow_flap srv-c
    allow_warn srv-c 'no next hop for this family'
    trap n_restore EXIT
    local since rib n
    bird_use r2 "$N4_BIRD"
    # Without next_hop_ipv4: IPv6 uses the session address, IPv4 is skipped with one warning.
    since=$(now)
    srv_c_conf n4a r2_addr=2001:db8:201::3 r2_nh6=
    srv_c_use gen-n4a.toml
    wait_until 15 bird_established r2 srv_c
    wait_until 5 eval 'bird_rib r2 | grep -x "2001:db8:2::/48 srv_c AS64502i 2001:db8:201::10 best"'
    rib=$(bird_rib r2)
    if grep '^198.51.100.0/24 srv_c ' <<<"$rib"; then fail "r2 got IPv4 routes from srv-c without an IPv4 next hop"; fi
    n=$(herald_logs srv-c "$since" | grep -c 'no next hop for this family' || true)
    [ "$n" = 1 ] || fail "srv-c: $n 'no next hop' warnings, expected 1"
    # With next_hop_ipv4, IPv4 works too.
    srv_c_conf n4b r2_addr=2001:db8:201::3 r2_nh6= r2_extra='next_hop_ipv4 = "10.201.0.10"'
    srv_c_use gen-n4b.toml
    wait_until 15 bird_established r2 srv_c
    wait_until 5 eval 'bird_rib r2 | grep -x "198.51.100.0/24 srv_c AS64502i 10.201.0.10 best"'
    wait_until 5 eval 'bird_rib r2 | grep -x "2001:db8:2::/48 srv_c AS64502i 2001:db8:201::10 best"'
    assert_http user2 198.51.100.10 srv-c
    assert_http user2 2001:db8:2::10 srv-c
}

scenario N5 default - "link-local next hop: global + link-local (RFC 2545)"
scn_N5() {
    allow_flap srv-c
    trap n_restore EXIT
    srv_c_conf n5 r1_extra='next_hop_ipv6_link_local = "fe80::ff:feff:10"' \
        r2_extra='next_hop_ipv6_link_local = "fe80::ff:feff:10"'
    srv_c_use gen-n5.toml
    wait_until 15 frr_established r1 10.201.0.10
    wait_until 15 bird_established r2 srv_c
    local nh
    wait_until 5 eval 'frr_path r1 2001:db8:2::/48 10.201.0.10 | jq -e "[.nexthops[].ip] == [\"2001:db8:201::10\", \"fe80::ff:feff:10\"]"'
    nh=$(bird r2 show route all 2001:db8:2::/48 protocol srv_c | awk '/bgp_next_hop/ { $1 = ""; print }' | xargs)
    [ "$nh" = "2001:db8:201::10 fe80::ff:feff:10" ] || fail "r2: next hop '$nh'"
    wait_until 5 http_is user1 2001:db8:2::10 srv-c
    wait_until 5 http_is user2 2001:db8:2::10 srv-c
}

scenario N6 full - "hold time 0: no keepalives, session stays up"
scn_N6() {
    allow_flap srv-c
    trap n_restore EXIT
    srv_c_conf n6 hold_time=0
    srv_c_use gen-n6.toml
    wait_until 15 frr_established r1 10.201.0.10
    wait_until 15 bird_established r2 srv_c
    [ "$(frr_neighbor r1 10.201.0.10 .bgpTimerHoldTimeMsecs)" = 0 ] || fail "r1: hold time not 0"
    local ka dropped
    ka=$(frr_neighbor r1 10.201.0.10 .messageStats.keepalivesRecv)
    dropped=$(frr_neighbor r1 10.201.0.10 .connectionsDropped)
    sleep 30
    frr_established r1 10.201.0.10 || fail "r1 session down"
    bird_established r2 srv_c || fail "r2 session down"
    [ "$(frr_neighbor r1 10.201.0.10 .connectionsDropped)" = "$dropped" ] || fail "r1 session flapped"
    [ "$(frr_neighbor r1 10.201.0.10 .messageStats.keepalivesRecv)" = "$ka" ] || fail "srv-c sent keepalives with hold time 0"
}

scenario N7 default - "iBGP: empty AS path and LOCAL_PREF 100"
scn_N7() {
    allow_flap srv-c
    trap n_restore EXIT
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 remote-as 64510' >/dev/null
    srv_c_conf n7 asn=64510 r2=0
    srv_c_use gen-n7.toml
    wait_until 15 frr_established r1 10.201.0.10
    local p
    wait_until 5 frr_has_path 198.51.100.0/24 10.201.0.10
    p=$(frr_path r1 198.51.100.0/24 10.201.0.10)
    # FRR shows an empty AS path as "Local".
    jq -e '.aspath.length == 0 and .locPrf == 100 and .origin == "IGP"' <<<"$p" >/dev/null ||
        fail "r1: iBGP path from srv-c: $p"
    jq -e '.peer.type == "internal"' <<<"$p" >/dev/null || info "peer type: $(jq -c .peer <<<"$p")"
    wait_until 5 http_is user1 198.51.100.10 srv-c
    # r2 learns it from r1 with r1's AS only.
    wait_until 10 eval 'bird_rib r2 | grep -x "198.51.100.0/24 r1 AS64510i 10.201.0.10 best"'
}

scenario N8 default - "4-octet AS 65536: routers see path 65536"
scn_N8() {
    allow_flap srv-c
    trap n_restore EXIT
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 remote-as 65536' >/dev/null
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/neighbor 10.201.0.10 as 64502;/neighbor 10.201.0.10 as 65536;/'
    srv_c_conf n8 asn=65536
    srv_c_use gen-n8.toml
    wait_until 15 frr_established r1 10.201.0.10
    wait_until 15 bird_established r2 srv_c
    wait_until 5 eval 'frr_path r1 198.51.100.0/24 10.201.0.10 | jq -e ".aspath.string == \"65536\""'
    wait_until 5 eval 'bird_rib r2 | grep -x "198.51.100.0/24 srv_c AS65536i 10.201.0.10 best"'
}

scenario N9 default - "2-octet-only peer (rogue): AS_TRANS + AS4_PATH both ways"
scn_N9() {
    allow_flap srv-c
    trap 'rogue_save; rogue_stop; srv_c_use herald.toml' EXIT
    rogue_start <<'SCRIPT'
accept 30
handshake caps=mp4,mp6,rr   # no 4-octet AS capability
# AS_PATH 64520 23456 + AS4_PATH 64520 65537: herald must rebuild 64520 65537
announce 10.99.9.0/24 path=64520,23456 attr=c0:17:02020000fc0800010001
run 120
SCRIPT
    # Only the rogue: r1/r2 expect AS 64502.
    srv_c_conf n9 asn=65536 r1=0 r2=0 "extra=$(rogue_neighbor)"
    srv_c_use gen-n9.toml
    wait_until 30 herald_established srv-c $ROGUE
    # herald's OPEN: My AS = AS_TRANS; its UPDATEs: AS_PATH 23456 + AS4_PATH 65536.
    wait_until 5 rogue_has 'recv OPEN .* as=23456 '
    wait_until 10 rogue_has 'recv UPDATE .*AS_PATH=\[seq 23456\] attr3=0ac9000a AS4_PATH=\[seq 65536\] nlri='
    wait_until 5 rogue_has 'recv UPDATE .*attr14=.*AS_PATH=\[seq 23456\] AS4_PATH=\[seq 65536\]'
    wait_until 10 eval 'herald_routes srv-c 10.99.9.0/24 | grep "^[^ ]* 64520,65537 "'
    rogue_ok
}

scenario N11 default - "route refresh from FRR and BIRD: resend, no session reset"
scn_N11() {
    local dropped_a since
    dropped_a=$(frr_neighbor r1 10.201.11.10 .connectionsDropped)
    since=$(now)
    frr r1 "clear bgp 10.201.11.10 soft in" >/dev/null
    wait_log srv-a "$since" 'route refresh requested peer=1 afi=Afi\(1\)' 5
    wait_log srv-a "$since" 'route refresh requested peer=1 afi=Afi\(2\)' 5
    bird r2 reload bgp in srv_b >/dev/null
    wait_log srv-b "$since" 'route refresh requested peer=1 afi=Afi\(1\)' 5
    wait_log srv-b "$since" 'route refresh requested peer=1 afi=Afi\(2\)' 5
    sleep 1
    [ "$(frr_neighbor r1 10.201.11.10 .connectionsDropped)" = "$dropped_a" ] || fail "r1 session reset"
    if log_has srv-a "$since" 'session down'; then fail "srv-a session went down"; fi
    if log_has srv-b "$since" 'session down'; then fail "srv-b session went down"; fi
}

scenario N12 default - "peer without route refresh capability"
scn_N12() {
    allow_flap srv-b
    trap 'bird_restore r2' EXIT
    local since
    since=$(now)
    bird_use r2 '/^protocol bgp srv_b/,/^}/s/passive on;/passive on;\n    enable route refresh off;/'
    wait_until 15 bird_established r2 srv_b
    sleep 1
    if bird r2 show protocols all srv_b | sed -n '/Local capabilities/,/Neighbor capabilities/p' | grep 'Route refresh'; then
        fail "BIRD still announces route refresh"
    fi
    wait_until 10 http_is user2 192.0.2.10 srv-b
    wait_until 10 http_is user2 2001:db8:1::10 srv-b
}

scenario N13 default - "non-standard port 1179"
scn_N13() {
    allow_flap srv-c
    trap n_restore EXIT
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/local 10.201.0.3;/local 10.201.0.3 port 1179;/'
    srv_c_conf n13 r2_port=1179
    srv_c_use gen-n13.toml
    wait_until 15 bird_established r2 srv_c
    wait_log srv-c "" 'addr=10.201.0.3:1179.*session established' 5
}

scenario N14 default - "TCP MD5 on the router only: no session, backoff, no crash"
scn_N14() {
    allow_flap srv-c
    trap n_restore EXIT
    local since n
    since=$(now)
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 password e2e-secret' >/dev/null
    frr r1 "clear bgp 10.201.0.10" >/dev/null
    sleep 20
    running srv-c || fail "srv-c died"
    frr_established r1 10.201.0.10 && fail "session up despite MD5"
    n=$(herald_logs srv-c "$since" | grep -c 'addr=10.201.0.2:179.*connecting' || true)
    local delays
    delays=$(connect_delays srv-c "$since" 10.201.0.2:179)
    measure "connect delays against MD5" "'$delays'"
    [ "$n" -le 8 ] || fail "srv-c: $n connection attempts in 20 s (expected backoff)"
    bird_established r2 srv_c || fail "srv-c's session to r2 went down"
}

scenario N16 default - "TCP MD5 on both ends: Established; wrong key: no session"
scn_N16() {
    allow_flap srv-c
    trap n_restore EXIT
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 password e2e-secret' >/dev/null
    srv_c_conf n16 r1_extra='password = "e2e-secret"'
    srv_c_use gen-n16.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with matching MD5 keys"
    [ "$(herald_peer srv-c 10.201.0.2 .neighbor.tcp_md5)" = true ] || fail "srv-c: tcp_md5 not shown"
    # FRR learned srv-c's prefix over the signed session.
    wait_until 10 frr_has_path 198.51.100.0/24 10.201.0.10 >/dev/null ||
        fail "r1 has no route from srv-c"
    wait_until 10 bird_established r2 srv_c || fail "srv-c's unsigned session to r2 is down"

    # Same router, wrong key on herald's side: the kernel drops every segment.
    srv_c_conf n16b r1_extra='password = "wrong-secret"'
    srv_c_use gen-n16b.toml
    sleep 12
    running srv-c || fail "srv-c died"
    frr_established r1 10.201.0.10 && fail "session up with a wrong MD5 key"
    herald_established srv-c 10.201.0.2 && fail "srv-c reports a session with a wrong key"
    bird_established r2 srv_c || fail "srv-c's session to r2 went down"
}

scenario N22 default - "TCP MD5 with BIRD (password, as in the docs): Established; wrong key: no session"
scn_N22() {
    allow_flap srv-c
    trap n_restore EXIT
    # website/content/docs/guides/router-config.mdx shows this line.
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/passive on;/passive on;\n    password "e2e-secret";/'
    srv_c_conf n22 r2_extra='password = "e2e-secret"'
    srv_c_use gen-n22.toml
    wait_until 15 bird_established r2 srv_c || fail "no session with matching MD5 keys"
    [ "$(herald_peer srv-c 10.201.0.3 .neighbor.tcp_md5)" = true ] || fail "srv-c: tcp_md5 not shown"
    # BIRD learned srv-c's prefixes over the signed session.
    wait_until 10 r2_has_from_c 198.51.100.0/24 || fail "r2 has no route from srv-c"
    wait_until 10 frr_established r1 10.201.0.10 || fail "srv-c's unsigned session to r1 is down"

    # Same router, wrong key on herald's side: the kernel drops every segment.
    srv_c_conf n22b r2_extra='password = "wrong-secret"'
    srv_c_use gen-n22b.toml
    sleep 12
    running srv-c || fail "srv-c died"
    bird_established r2 srv_c && fail "BIRD session up with a wrong MD5 key"
    herald_established srv-c 10.201.0.3 && fail "srv-c reports a session with a wrong key"
    frr_established r1 10.201.0.10 || fail "srv-c's session to r1 went down"
}

scenario N17 default - "GTSM (TTL security): both ends Established; herald only: no session"
scn_N17() {
    allow_flap srv-c
    trap n_restore EXIT
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 ttl-security hops 1' >/dev/null
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/passive on;/passive on;\n    ttl security on;/'
    srv_c_conf n17 r1_extra='ttl_security = 1' r2_extra='ttl_security = 1'
    srv_c_use gen-n17.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no GTSM session with FRR"
    wait_until 15 bird_established r2 srv_c || fail "no GTSM session with BIRD"
    [ "$(herald_peer srv-c 10.201.0.2 .neighbor.ttl_security)" = 1 ] ||
        fail "srv-c: ttl_security not shown"
    wait_until 10 frr_has_path 198.51.100.0/24 10.201.0.10 >/dev/null ||
        fail "r1 has no route from srv-c"

    # Routers back to their normal TTL (FRR eBGP: 1, BIRD: 1 for direct
    # peers): herald drops their packets, nothing comes up.
    frr_conf r1 'router bgp 64510' 'no neighbor 10.201.0.10 ttl-security hops 1' >/dev/null
    bird_restore r2
    frr r1 "clear bgp 10.201.0.10" >/dev/null 2>&1 || true
    sleep 12
    running srv-c || fail "srv-c died"
    frr_established r1 10.201.0.10 && fail "FRR session up although its TTL is 1"
    bird_established r2 srv_c && fail "BIRD session up although its TTL is 1"
    true
}

# Routers connect to srv-c instead of waiting for it.
routers_active() {
    frr_conf r1 'router bgp 64510' 'no neighbor 10.201.0.10 passive' \
        'neighbor 10.201.0.10 timers connect 2' >/dev/null
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/passive on;/connect retry time 2;/'
}

# Is srv-c's session with PEER on a connection the peer opened?
srv_c_inbound() { [[ $(herald_peer srv-c "$1" .status.local) == *:179 ]]; }

scenario N18 default - "passive listen: FRR and BIRD connect to herald"
scn_N18() {
    allow_flap srv-c
    trap n_restore EXIT
    routers_active
    srv_c_conf n18 top='listen = ["0.0.0.0:179"]' r1_extra='passive = true' r2_extra='passive = true'
    srv_c_use gen-n18.toml
    wait_until 20 frr_established r1 10.201.0.10 || fail "FRR did not connect to srv-c"
    wait_until 20 bird_established r2 srv_c || fail "BIRD did not connect to srv-c"
    local peer
    for peer in 10.201.0.2 10.201.0.3; do
        srv_c_inbound $peer || fail "srv-c: session with $peer is not on the listener"
        [ "$(herald_peer srv-c $peer .counters.connect_attempts)" = 0 ] ||
            fail "srv-c connected to the passive neighbor $peer"
    done
    wait_until 10 frr_has_path 198.51.100.0/24 10.201.0.10 >/dev/null || fail "r1 has no route from srv-c"
    # After a reset herald waits in Active and the router comes back.
    frr r1 "clear bgp 10.201.0.10" >/dev/null
    sleep 1
    wait_until 20 frr_established r1 10.201.0.10 || fail "FRR did not reconnect"
    [ "$(herald_peer srv-c 10.201.0.2 .counters.connect_attempts)" = 0 ] ||
        fail "srv-c connected to the passive neighbor after the reset"
}

scenario N19 default - "connection collisions: both sides connect, one stable session each"
scn_N19() {
    allow_flap srv-c
    trap n_restore EXIT
    routers_active
    srv_c_conf n19 top='listen = ["0.0.0.0:179"]'
    local since
    since=$(now)
    srv_c_use gen-n19.toml
    local round est1 est2
    for round in 1 2 3 4 5; do
        wait_until 20 frr_established r1 10.201.0.10 || fail "round $round: no session with FRR"
        wait_until 20 bird_established r2 srv_c || fail "round $round: no session with BIRD"
        wait_until 10 herald_established srv-c 10.201.0.2 || fail "round $round: srv-c not Established with r1"
        wait_until 10 herald_established srv-c 10.201.0.3 || fail "round $round: srv-c not Established with r2"
        est1=$(herald_peer srv-c 10.201.0.2 .counters.established)
        est2=$(herald_peer srv-c 10.201.0.3 .counters.established)
        # A collision resolved differently on both ends shows up as flapping.
        sleep 5
        frr_established r1 10.201.0.10 && bird_established r2 srv_c || fail "round $round: a session flapped"
        [ "$(herald_peer srv-c 10.201.0.2 .counters.established)" = "$est1" ] &&
            [ "$(herald_peer srv-c 10.201.0.3 .counters.established)" = "$est2" ] ||
            fail "round $round: srv-c re-established a session"
        # Both sides reconnect at about the same time.
        frr r1 "clear bgp 10.201.0.10" >/dev/null
        bird r2 restart srv_c >/dev/null
    done
    local won lost
    won=$(herald_logs srv-c "$since" | grep -c 'rejecting the connection from the peer reason=Collision' || true)
    lost=$(herald_logs srv-c "$since" | grep -c 'collision: continuing on the peer' || true)
    measure "collisions srv-c won / lost in 5 rounds x 2 routers" "'$won / $lost'"
    # srv-c's router ID (203.0.113.23) is above r1's and r2's: it never gives in.
    [ "$lost" = 0 ] || fail "srv-c gave up its own connection $lost times despite the higher router ID"
}

scenario N20 default - "listener closes connections from addresses that are not neighbors"
scn_N20() {
    allow_flap srv-c
    trap n_restore EXIT
    srv_c_conf n20 top='listen = ["0.0.0.0:179"]'
    srv_c_use gen-n20.toml
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with FRR"
    local start took
    start=$(now)
    # The rogue (10.201.0.20) is not srv-c's neighbor.
    on_sh rogue 'timeout 5 nc 10.201.0.10 179 </dev/null >/dev/null' ||
        fail "rogue could not even connect, or the connection stayed open"
    took=$(awk -v a="$start" -v b="$(now)" 'BEGIN { printf "%.2f", b - a }')
    measure "time until srv-c closed the rogue's connection" "$took" s
    running srv-c || fail "srv-c died"
    frr_established r1 10.201.0.10 || fail "srv-c's session to r1 went down"
}

scenario N21 default - "collision rule (rogue): higher BGP ID keeps its connection, Established refuses"
scn_N21() {
    allow_flap srv-c
    trap 'rogue_save; rogue_stop; srv_c_use herald.toml' EXIT
    # srv-c is 203.0.113.23. Round 1: the rogue is lower (10.201.0.20), so
    # srv-c keeps its own connection and turns the rogue's away. While
    # Established, another connection is refused too.
    rogue_start <<'SCRIPT'
accept 30                  # srv-c's connection
expect open
connect 10.201.0.10:179    # ours, while srv-c waits in OpenSent: parked
swap                       # back to srv-c's connection
open id=10.201.0.20
expect keepalive
swap
expect notification 6/7    # srv-c rejected our connection
swap
keepalive
run 3
connect 10.201.0.10:179    # Established: refused
expect notification 6/7
swap
print checks
run 30
SCRIPT
    srv_c_conf n21 top='listen = ["0.0.0.0:179"]' r1=0 r2=0 "extra=$(rogue_neighbor)"
    srv_c_use gen-n21.toml
    wait_until 40 rogue_has "checks$" || { rogue_ok; fail "round 1: rogue script stuck: $(rogue_out | tail -n 3)"; }
    herald_established srv-c $ROGUE || fail "round 1: srv-c not Established"
    srv_c_inbound $ROGUE && fail "round 1: srv-c kept the rogue's connection despite the higher ID"
    [ "$(herald_peer srv-c $ROGUE .counters.incoming_rejected)" = 2 ] ||
        fail "round 1: expected 2 rejected connections"
    rogue_ok

    # Round 2: the rogue is higher (250.0.0.1): srv-c closes its own
    # connection with Cease 6/7 and continues on the rogue's.
    srv_c_use herald.toml   # no rogue neighbor while the next script starts
    rogue_start <<'SCRIPT'
accept 30
expect open
connect 10.201.0.10:179
swap
open id=250.0.0.1
expect notification 6/7    # srv-c gives up its connection
swap
expect open                # and answers on ours
open id=250.0.0.1
expect keepalive
keepalive
print checks
run 30
SCRIPT
    srv_c_use gen-n21.toml
    wait_until 40 rogue_has "checks$" || { rogue_ok; fail "round 2: rogue script stuck: $(rogue_out | tail -n 3)"; }
    wait_until 5 herald_established srv-c $ROGUE || fail "round 2: srv-c not Established"
    srv_c_inbound $ROGUE || fail "round 2: srv-c is not on the rogue's connection"
    [ "$(herald_peer srv-c $ROGUE .counters.established)" = 1 ] ||
        fail "round 2: the switch counted as an extra session"
    rogue_ok
}

scenario N15 full - "duplicate router ID in iBGP: Bad BGP Identifier"
scn_N15() {
    allow_flap srv-c
    allow_warn srv-c 'sent NOTIFICATION'
    trap n_restore EXIT
    local since
    since=$(now)
    frr_conf r1 'router bgp 64510' 'neighbor 10.201.0.10 remote-as 64510' >/dev/null
    srv_c_conf n15 asn=64510 r2=0 router_id=203.0.113.11
    srv_c_use gen-n15.toml
    wait_log srv-c "$since" 'NOTIFICATION notification=.*\(2/3\)' 15
    frr_established r1 10.201.0.10 && fail "session up with a duplicate router ID"
    true
}
