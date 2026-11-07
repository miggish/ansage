# R: routes and RIB.


scenario R1 default - "not transit: srv-c never passes routes between r1 and r2"
scn_R1() {
    local rib
    rib=$(bird_rib r2)
    grep -q '^10.201.1.0/24 r1 AS64510? ' <<<"$rib" || fail "r2: no 10.201.1.0/24 from r1"
    if grep -E '^(10.201.1.0/24|2001:db8:201:1::/64) ' <<<"$rib" | grep 64502 >/dev/null; then
        fail "r2: user1's subnet learned via srv-c (AS 64502):
$(grep -E '^(10.201.1.0/24|2001:db8:201:1::/64) ' <<<"$rib")"
    fi
    rib=$(frr_rib r1)
    grep -q '^10.201.2.0/24 10.201.0.3 64511 ' <<<"$rib" || fail "r1: no 10.201.2.0/24 from r2"
    if grep -E '^(10.201.2.0/24|2001:db8:201:2::/64) ' <<<"$rib" | grep 64502 >/dev/null; then
        fail "r1: user2's subnet learned via srv-c (AS 64502)"
    fi
    # srv-c sends exactly its own prefix per family to each router.
    local afi n
    for afi in ipv4Unicast ipv6Unicast; do
        n=$(frr r1 "show bgp summary json" | jq -r ".$afi.peers[\"10.201.0.10\"].pfxRcd")
        [ "$n" = 1 ] || fail "r1: $n $afi prefixes from srv-c, expected 1"
    done
    n=$(bird r2 show protocols all srv_c | grep -c 'Routes: *1 imported,' || true)
    [ "$n" = 2 ] || fail "r2: srv-c should send 1 route per family:
$(bird r2 show protocols all srv_c | grep Routes:)"
    # ... while it stores what it learns (import "all").
    local peer v4 v6
    for peer in 10.201.0.2 10.201.0.3; do
        read -r v4 v6 <<<"$(herald_received srv-c "$peer")"
        [ "$v4" -gt 0 ] 2>/dev/null && [ "$v6" -gt 0 ] || fail "srv-c: stored $v4/$v6 routes from $peer"
    done
}

scenario R2 default - "AS loop: srv-a drops its own prefix coming back via r1"
scn_R2() {
    # r1 sends 192.0.2.0/24 learned from r2 (path 64510 64511 64500) to srv-a.
    local adv
    adv=$(frr r1 "show bgp ipv4 unicast neighbors 10.201.11.10 advertised-routes json")
    jq -e '.advertisedRoutes["192.0.2.0/24"]' <<<"$adv" >/dev/null ||
        fail "r1 does not send 192.0.2.0/24 back to srv-a"
    log_has srv-a "" 'routes not eligible .*reason="AS loop"' || fail "srv-a: no AS loop drop logged"
    # Only the AS loop routes are missing from what srv-a stores.
    local v4 v6 sent4 sent6
    read -r v4 v6 <<<"$(herald_received srv-a 10.201.11.2)"
    sent4=$(frr r1 "show bgp summary json" | jq -r '.ipv4Unicast.peers["10.201.11.10"].pfxSnt')
    sent6=$(frr r1 "show bgp summary json" | jq -r '.ipv6Unicast.peers["10.201.11.10"].pfxSnt')
    [ "$v4" = $((sent4 - 1)) ] && [ "$v6" = $((sent6 - 1)) ] ||
        fail "srv-a stored $v4/$v6 of $sent4/$sent6 (expected all but the AS loop route)"
    # Its own prefix is in its RIB only as its own.
    local routes
    routes=$(herald_routes srv-a 192.0.2.0/24)
    [ "$routes" = "local - - best" ] || fail "srv-a: 192.0.2.0/24 candidates: $routes"
}

scenario R3 default - "import none: srv-b stores nothing"
scn_R3() {
    local exported
    exported=$(bird r2 show protocols all srv_b | grep -c 'Routes:.* [1-9][0-9]* exported' || true)
    [ "$exported" = 2 ] || fail "r2 exports nothing to srv-b, test is void"
    local stored
    stored=$(herald_received srv-b 10.201.12.2)
    [ "$stored" = "0 0" ] || fail "srv-b stored routes: $stored"
    stored=$(herald_show srv-b summary | jq -r '"\(.rib.prefixes_ipv4) \(.rib.prefixes_ipv6)"')
    [ "$stored" = "1 1" ] || fail "srv-b's RIB should hold only its own prefixes, has $stored"
}

scenario R4 default - "max-prefix: Cease with AFI/SAFI/limit, reconnect after max_prefix_restart"
scn_R4() {
    allow_flap srv-c
    allow_warn srv-c '90% of the prefix limit|maximum number of prefixes exceeded|sent NOTIFICATION'
    trap n_restore EXIT
    local afi fam since down next delay
    for afi in 1 2; do
        fam=ipv4
        [ "$afi" = 1 ] || fam=ipv6
        since=$(now)
        srv_c_conf "r4-$fam" r2_extra="max_prefixes_$fam = 3"
        srv_c_use "gen-r4-$fam.toml"
        wait_log srv-c "$since" "maximum number of prefixes exceeded, closing session peer=2 afi=Afi\\($afi\\) count=[0-9]+ limit=3" 15
        # RFC 4486 §4 data: AFI, SAFI 1, limit 3, as herald recorded it.
        local down_json
        down_json=$(herald_peer srv-c 10.201.0.3 .status.last_down)
        jq -e --arg data "$(printf '%04x0100000003' "$afi")" '.reason == "notification sent"
            and .notification.code == 6 and .notification.subcode == 1
            and .notification.data == $data' <<<"$down_json" >/dev/null ||
            fail "srv-c: last down is not a Cease 6/1 with AFI $afi, SAFI 1, limit 3: $(jq -c . <<<"$down_json")"
        log_has srv-c "$since" "90% of the prefix limit reached peer=2 afi=Afi\\($afi\\)" ||
            info "no 90% warning for $fam (the count jumped past it in one UPDATE)"
        # Reconnect after max_prefix_restart (5 s, jittered), not connect_retry.
        wait_until 10 eval "herald_logs srv-c '$since' | grep -A20 'sent NOTIFICATION notification=cease (6/1)' | grep 'addr=10.201.0.3:179.*connecting' >/dev/null"
        down=$(herald_logs srv-c "$since" | grep 'sent NOTIFICATION notification=cease (6/1)' | head -1 | cut -c1-26)
        next=$(herald_logs srv-c "$since" | grep 'addr=10.201.0.3:179.*connecting' |
            awk -v d="$down" 'substr($0, 1, 26) > d { print substr($0, 1, 26); exit }')
        delay=$(awk -v a="$(date -d "$down" +%s.%N)" -v b="$(date -d "$next" +%s.%N)" 'BEGIN { printf "%.2f", b - a }')
        measure "$fam max-prefix reconnect delay" "$delay"
        awk -v d="$delay" 'BEGIN { exit !(d >= 3.5 && d <= 6) }' || fail "reconnect after $delay s, expected ~5 s"
        # Meanwhile srv-c stays reachable for user2 via r1.
        http_is user2 198.51.100.10 srv-c || fail "user2 cannot reach srv-c via r1"
    done
}

# FRR route-map that sets the next hop of what r1 sends srv-c to srv-c's own address.
frr_own_next_hop() {
    local afi=$1 set=$2
    frr_conf r1 "route-map E2E-$afi permit 10" "$set" 'exit' 'router bgp 64510' \
        "address-family $afi unicast" "neighbor 10.201.0.10 route-map E2E-$afi out" >/dev/null
    frr r1 "clear bgp $afi unicast 10.201.0.10 soft out" >/dev/null
}
frr_own_next_hop_off() {
    local afi
    for afi in ipv4 ipv6; do
        frr_conf r1 'router bgp 64510' "address-family $afi unicast" \
            "no neighbor 10.201.0.10 route-map E2E-$afi out" >/dev/null 2>&1 || true
        frr_conf r1 "no route-map E2E-$afi" >/dev/null 2>&1 || true
        frr r1 "clear bgp $afi unicast 10.201.0.10 soft out" >/dev/null 2>&1 || true
    done
}

scenario R5 default - "IPv4 next hop is herald itself: route not used"
scn_R5() {
    trap frr_own_next_hop_off EXIT
    local since
    since=$(now)
    frr_own_next_hop ipv4 'set ip next-hop 10.201.0.10'
    wait_log srv-c "$since" 'routes not eligible peer=1 .*reason="next hop is our address"' 10
}

scenario R13 default - "IPv6 next hop is herald's next_hop_ipv6: route not used"
scn_R13() {
    trap frr_own_next_hop_off EXIT
    local since
    since=$(now)
    frr_own_next_hop ipv6 'set ipv6 next-hop global 2001:db8:201::10'
    wait_until 5 eval 'frr r1 "show bgp ipv6 unicast neighbors 10.201.0.10 advertised-routes json" | grep 2001:db8:201:1:: >/dev/null'
    wait_log srv-c "$since" 'routes not eligible peer=1 .*reason="next hop is our address"' 10
}

# Routes srv-c stores from r2 right now: "v4 v6" (herald's control socket).
srv_c_r2_counts() { herald_received srv-c 10.201.0.3; }
srv_c_r2_counts_are() { [ "$(srv_c_r2_counts)" = "$1" ]; }

# Restarts BIRD's srv_c session and waits for herald's End-of-RIB from it
# (only where the time of a fresh initial sync is measured).
srv_c_r2_resync() {
    local since
    since=$(now)
    bird r2 restart srv_c >/dev/null
    wait_log srv-c "$since" 'end of RIB from peer peer=2 afi=Afi\(2\)' "${1:-15}"
}

# BIRD variant with a static protocol "bulk" (disabled) of V4 /32s in
# 100.64.0.0/10 and V6 /64s in 2001:db8:ff00::/40, sent to srv_c only (not to
# r1, srv_b or the kernel).
bird_bulk() {
    on_sh r2 "sed -e '/^protocol bgp \(r1\|srv_b\)/,/^}/s/export all;/export where proto != \"bulk\";/' \
        -e 's/export where source != RTS_DEVICE;/export where source != RTS_DEVICE \&\& proto != \"bulk\";/' \
        /etc/bird.conf >/tmp/variant.conf
        awk -v n4=$1 -v n6=$2 'BEGIN {
            print \"protocol static bulk { disabled; ipv4;\"
            for (i = 0; i < n4; i++) printf \"route 100.%d.%d.%d/32 unreachable;\\n\", 64 + int(i / 65536), int(i / 256) % 256, i % 256
            print \"}\"
            print \"protocol static bulk6 { disabled; ipv6;\"
            for (i = 0; i < n6; i++) printf \"route 2001:db8:ff%02x:%x::/64 unreachable;\\n\", int(i / 65536), i % 65536
            print \"}\"
        }' >>/tmp/variant.conf
        sed -i 's/proto != \"bulk\"/proto != \"bulk\" \&\& proto != \"bulk6\"/' /tmp/variant.conf" ||
        fail "cannot write the bulk variant"
    local out
    out=$(bird r2 configure '"/tmp/variant.conf"')
    [[ $out == *Reconfigured* ]] || fail "BIRD rejected the bulk variant: $out"
}

bulk() { bird r2 "$1" bulk >/dev/null && bird r2 "$1" bulk6 >/dev/null; }

scenario R6 default - "churn: r2 announces/withdraws 1000+1000 prefixes 20 times"
scn_R6() {
    allow_flap srv-c
    trap 'bird_restore r2' EXIT
    local base i
    base=$(srv_c_r2_counts)
    bird_bulk 1000 1000
    wait_until 15 bird_established r2 srv_c
    local since
    since=$(now)
    for i in $(seq 20); do
        bulk enable
        sleep 0.3
        bulk disable
        sleep 0.3
    done
    sleep 2
    bird_established r2 srv_c || fail "srv_c session went down during churn"
    if log_has srv-c "$since" 'session down'; then fail "srv-c session flapped"; fi
    # Without a session restart: herald's live count is back at the baseline.
    poll_until 15 srv_c_r2_counts_are "$base" ||
        fail "srv-c counts $(srv_c_r2_counts) after churn, baseline $base"
}

scenario R7 full - "big inbound table: 100k IPv4 + 30k IPv6 from r2, withdraw all (R8), twice"
scn_R7() {
    allow_flap srv-c
    # herald keeps the memory of the big table; start srv-c
    # fresh afterwards so the next scenarios compare with the baseline.
    trap 'bird_restore r2; compose restart -t 2 srv-c >/dev/null 2>&1' EXIT
    local base start t round v4 v6 b4 b6 rss rss1=
    base=$(srv_c_r2_counts)
    read -r b4 b6 <<<"$base"
    bird_bulk 100000 30000
    for round in 1 2; do
        bulk enable
        start=$(now)
        srv_c_r2_resync 120
        t=$(elapsed "$start")
        measure "round $round: full table (130k) to End-of-RIB" "$t"
        read -r v4 v6 <<<"$(srv_c_r2_counts)"
        [ "$v4" = $((b4 + 100000)) ] && [ "$v6" = $((b6 + 30000)) ] ||
            fail "srv-c stored $v4/$v6, expected $((b4 + 100000))/$((b6 + 30000))"
        info "round $round with 130k routes: fds/RSS KiB $(herald_resources srv-c)"
        if [ "$round" = 1 ]; then
            # Keepalives flow under load: the session survives 30 s with hold 9.
            sleep 30
            bird_established r2 srv_c || fail "session down under load"
        fi
        # R8: withdraw everything at once.
        start=$(now)
        bulk disable
        # Until herald's live count is back (no session restart needed now).
        poll_until 60 srv_c_r2_counts_are "$base" ||
            fail "R8: counts $(srv_c_r2_counts) after withdrawing, baseline $base"
        measure "round $round: withdraw all until herald's count is back" "$(elapsed "$start")"
        rss=$(herald_resources srv-c | awk '{ print $2 }')
        measure "round $round: RSS after withdraw" "$rss" KiB
        # No growth from round to round (retained capacity is fine, a leak is not).
        if [ -n "$rss1" ]; then
            [ "$rss" -le $((rss1 * 11 / 10 + 1024)) ] || fail "RSS grew from $rss1 to $rss KiB between rounds"
        fi
        rss1=$rss
    done
}

# Announce list body: N4 IPv4 /24s in 100.64.0.0/10 and N6 IPv6 /48s in
# 2001:db8:1000::/36, plus srv-c's own service prefixes.
many_prefixes() {
    awk -v n4="$1" -v n6="$2" 'BEGIN {
        printf "\"198.51.100.0/24\", \"2001:db8:2::/48\""
        for (i = 0; i < n4; i++) printf ", \"100.%d.%d.0/24\"", 64 + int(i / 256), i % 256
        for (i = 0; i < n6; i++) printf ", \"2001:db8:1%03x::/48\"", i
    }'
}

pfx_rcvd() { frr r1 "show bgp summary json" | jq -r ".$1.peers[\"10.201.0.10\"].pfxRcd"; }
bird_srv_c_imported() { bird r2 show protocols all srv_c | awk '/Routes:/ { print $2 }' | paste -sd' '; }

scenario R9 full - "many own prefixes (5000 + 2000), r2 without extended messages (N10)"
scn_R9() {
    allow_flap srv-c
    trap n_restore EXIT
    bird_use r2 '/^protocol bgp srv_c/,/^}/s/passive on;/passive on;\n    enable extended messages off;/'
    srv_c_conf r9 announce="$(many_prefixes 5000 2000)"
    local start t
    start=$(now)
    srv_c_use gen-r9.toml
    wait_until 60 eval '[ "$(pfx_rcvd ipv4Unicast) $(pfx_rcvd ipv6Unicast)" = "5001 2001" ]'
    t=$(elapsed "$start")
    measure "7002 prefixes at r1" "$t"
    wait_until 60 eval '[ "$(bird_srv_c_imported)" = "5001 2001" ]'
    measure "7002 prefixes at r2 (no extended messages)" "$(elapsed "$start")"
    if bird r2 show protocols all srv_c | sed -n '/Local capabilities/,/Neighbor capabilities/p' | grep 'Extended message'; then
        fail "BIRD still announces extended messages"
    fi
    bird_established r2 srv_c || fail "srv_c session down"
}

scenario R10 default - "single family: IPv4 only announced, End-of-RIB for IPv6 still sent"
scn_R10() {
    allow_flap srv-c
    trap n_restore EXIT
    local mark
    mark=$(frr_log_mark r1)
    srv_c_conf r10 announce='"198.51.100.0/24"'
    srv_c_use gen-r10.toml
    wait_until 15 frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv6 Unicast from 10.201.0.10'
    frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv4 Unicast from 10.201.0.10' || fail "no IPv4 End-of-RIB"
    [ "$(pfx_rcvd ipv4Unicast) $(pfx_rcvd ipv6Unicast)" = "1 0" ] ||
        fail "r1 got $(pfx_rcvd ipv4Unicast)/$(pfx_rcvd ipv6Unicast) prefixes from srv-c, expected 1/0"
}

scenario R11 default - "nothing to announce: session up, only End-of-RIB"
scn_R11() {
    allow_flap srv-c
    trap n_restore EXIT
    local mark
    mark=$(frr_log_mark r1)
    srv_c_conf r11 announce=''
    srv_c_use gen-r11.toml
    wait_until 15 frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv6 Unicast from 10.201.0.10'
    frr_log_has r1 "$mark" 'rcvd End-of-RIB for IPv4 Unicast from 10.201.0.10' || fail "no IPv4 End-of-RIB"
    [ "$(pfx_rcvd ipv4Unicast) $(pfx_rcvd ipv6Unicast)" = "0 0" ] || fail "r1 got prefixes from srv-c"
    wait_until 5 bird_established r2 srv_c
}

# r1 stops sending user1's subnets to srv-c (outbound filter), or sends them again.
r12_filter() {
    local afi match prefix
    for afi in ipv4 ipv6; do
        if [ "$afi" = ipv4 ]; then match=ip prefix=10.201.1.0/24; else match=ipv6 prefix=2001:db8:201:1::/64; fi
        if [ "$1" = on ]; then
            frr_conf r1 "$match prefix-list E2E-R12 seq 5 permit $prefix" \
                "route-map E2E-R12-$afi deny 10" "match $match address prefix-list E2E-R12" 'exit' \
                "route-map E2E-R12-$afi permit 20" 'exit' 'router bgp 64510' \
                "address-family $afi unicast" "neighbor 10.201.0.10 route-map E2E-R12-$afi out" >/dev/null
        else
            frr_conf r1 'router bgp 64510' "address-family $afi unicast" \
                "no neighbor 10.201.0.10 route-map E2E-R12-$afi out" >/dev/null 2>&1 || true
            frr_conf r1 "no route-map E2E-R12-$afi" "no $match prefix-list E2E-R12" >/dev/null 2>&1 || true
        fi
        frr r1 "clear bgp $afi unicast 10.201.0.10 soft out" >/dev/null 2>&1 || true
    done
}

# herald_routes_are SERVER PREFIX EXPECTED: candidates equal EXPECTED (lines joined by "; ").
herald_routes_are() { [ "$(herald_routes "$1" "$2" | paste -sd';' | sed 's/;/; /g')" = "$3" ]; }

scenario R12 default - "same prefix from two peers: shorter path is best, falls back when withdrawn"
scn_R12() {
    trap 'r12_filter off' EXIT
    # srv-c learns user1's subnets from r1 (path 64510) and via r2 (64511 64510);
    # r2 keeps r1's next hop on the shared subnet.
    local both4="10.201.0.2 64510 10.201.0.2 best; 10.201.0.3 64511,64510 10.201.0.2 -"
    local both6="10.201.0.2 64510 2001:db8:201::2 best; 10.201.0.3 64511,64510 2001:db8:201::2 -"
    wait_until 5 herald_routes_are srv-c 10.201.1.0/24 "$both4"
    wait_until 5 herald_routes_are srv-c 2001:db8:201:1::/64 "$both6"
    local sessions
    sessions=$(herald_peer srv-c 10.201.0.2 .counters.established)
    r12_filter on
    wait_until 5 herald_routes_are srv-c 10.201.1.0/24 "10.201.0.3 64511,64510 10.201.0.2 best"
    wait_until 5 herald_routes_are srv-c 2001:db8:201:1::/64 "10.201.0.3 64511,64510 2001:db8:201::2 best"
    # The withdrawal did not reset the session.
    [ "$(herald_peer srv-c 10.201.0.2 .counters.established)" = "$sessions" ] ||
        fail "srv-c's session to r1 restarted"
    r12_filter off
    wait_until 5 herald_routes_are srv-c 10.201.1.0/24 "$both4"
    wait_until 5 herald_routes_are srv-c 2001:db8:201:1::/64 "$both6"
}
