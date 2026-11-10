# P: roles (RFC 9234), filters and re-export, `ansage test`.
#
# srv-c runs a generated config (srv_c_conf + srv_c_use) in which r1 is its
# provider and r2 its customer; BIRD (r2) gets the matching `local role`
# through a variant config (bird_use). Every scenario restores both on exit.

p_restore() {
    srv_c_use ansage.toml
    bird_restore r2
}

# BIRD's role towards srv-c: ROLE in BIRD's words (provider, customer, peer).
p_bird_role() {
    bird_use r2 "/^protocol bgp srv_c/,/^}/s/passive on;/passive on;\n    local role $1;/"
}

# srv-c with r1 as provider and r2 as customer; r2 gets every route the
# filter EXPORT (TOML of [filter.to-r2], default: accept all) lets through.
p_transit() {
    local filter=${1:-'[[filter.to-r2.rule]]
action = "accept"'}
    srv_c_conf p r1_extra='role = "provider"' \
        r2_extra='role = "customer"
export = "to-r2"' \
        extra="[filter.to-r2]
$filter"
}

# Routes r2 has from srv-c: "prefix" per line (sorted).
p_r2_from_c() { bird_rib r2 | awk '$2 == "srv_c" { print $1 }' | sort -u; }

scenario P1 default - "BGP Role: srv-c says r2 is a peer, BIRD local role peer: up, roles shown"
scn_P1() {
    allow_flap srv-c
    trap p_restore EXIT
    p_bird_role peer
    srv_c_conf p1 r2_extra='role = "peer"'
    srv_c_use gen-p1.toml
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
    [ "$(ansage_peer srv-c 10.201.0.3 .status.session.peer_role)" = peer ] ||
        fail "srv-c: r2's role: $(ansage_peer srv-c 10.201.0.3 .status.session.peer_role)"
    [ "$(ansage_peer srv-c 10.201.0.3 .neighbor.role)" = peer ] || fail "srv-c: configured role not shown"
    # srv-c's own routes go to a peer with OTC (RFC 9234 egress).
    bird r2 show route 198.51.100.0/24 protocol srv_c all | grep -Eqi 'otc.*64502' ||
        fail "r2: no OTC 64502 on srv-c's prefix:
$(bird r2 show route 198.51.100.0/24 protocol srv_c all)"
}

scenario P2 default - "BGP Role mismatch: BIRD says customer, srv-c says peer: Role Mismatch (2/11), no session"
scn_P2() {
    allow_flap srv-c
    allow_warn srv-c 'NOTIFICATION'
    trap p_restore EXIT
    p_bird_role customer
    srv_c_conf p2 r2_extra='role = "peer"'
    srv_c_use gen-p2.toml
    local since
    since=$(now)
    wait_log srv-c "$since" 'role mismatch|code=2 subcode=11|2/11' 20 ||
        fail "no role mismatch logged: $(ansage_logs srv-c "$since" | tail -n 5)"
    bird_established r2 srv_c && fail "session with mismatching roles came up"
    wait_until 15 frr_established r1 10.201.0.10 || fail "r1 should not care"
}

scenario P3 default - "re-export: r1 (provider) routes go to r2 (customer) with OTC, never back to r1"
scn_P3() {
    allow_flap srv-c
    trap p_restore EXIT
    p_bird_role customer
    p_transit
    srv_c_use gen-p.toml
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with r1"
    # user1's subnet: r1 -> srv-c -> r2 (r2 also has it from r1 directly).
    wait_until 10 eval 'p_r2_from_c | grep -qx 10.201.1.0/24' ||
        fail "r2 did not get r1's 10.201.1.0/24 via srv-c:
$(p_r2_from_c)"
    bird r2 show route 10.201.1.0/24 protocol srv_c all | grep -Eqi 'otc.*64510' ||
        fail "r2: no OTC 64510 (set by srv-c on ingress from its provider)"
    # r2's routes (customer) do not go to r1: its export is "own".
    local n
    n=$(frr r1 "show bgp summary json" | jq -r '.ipv4Unicast.peers["10.201.0.10"].pfxRcd')
    [ "$n" = 1 ] || fail "r1 got $n IPv4 prefixes from srv-c, expected only its own"
    # What `ansage test` says matches.
    local t
    t=$(on srv-c ansage test --json 10.201.1.0/24) || fail "ansage test failed"
    [ "$(jq -r '.exports[] | select(.neighbor == "10.201.0.3") | .sent' <<<"$t")" = true ] ||
        fail "ansage test: not sent to r2: $t"
    [ "$(jq -r '.exports[] | select(.neighbor == "10.201.0.2") | .reason' <<<"$t")" = "came from this neighbor" ] ||
        fail "ansage test: r1: $(jq -c '.exports[0]' <<<"$t")"
}

scenario P4 default - "shadow check: for every prefix srv-c has, ansage test predicts exactly what r2 receives"
scn_P4() {
    allow_flap srv-c
    trap p_restore EXIT
    p_bird_role customer
    # Only r1's /24s and srv-c's own prefixes; nothing longer, nothing IPv6.
    p_transit '[[filter.to-r2.rule]]
source = "own"
action = "accept"
[[filter.to-r2.rule]]
prefixes = ["10.0.0.0/8 ge 24 le 24"]
from_role = ["provider"]
action = "accept"'
    srv_c_use gen-p.toml
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
    wait_until 15 frr_established r1 10.201.0.10 || fail "no session with r1"
    wait_until 10 eval 'p_r2_from_c | grep -qx 10.201.1.0/24' || fail "r2 did not get 10.201.1.0/24"
    local prefixes predicted actual
    prefixes=$(ansage_show srv-c rib | jq -r '.routes[].prefix' | sort -u)
    [ "$(wc -l <<<"$prefixes")" -gt 4 ] || fail "too few prefixes to compare: $prefixes"
    predicted=$(for p in $prefixes; do
        on srv-c ansage test --json "$p" |
            jq -r --arg p "$p" 'select(.exports[] | .neighbor == "10.201.0.3" and .sent) | $p'
    done | sort -u)
    actual=$(p_r2_from_c)
    [ "$predicted" = "$actual" ] || fail "ansage test predicts:
$predicted
r2 has from srv-c:
$actual"
    info "$(wc -l <<<"$actual") prefixes, prediction = reality"
}

scenario P5 default - "filter reload: export and import change without a session reset (route refresh)"
scn_P5() {
    allow_flap srv-c
    trap p_restore EXIT
    p_bird_role customer
    p_transit
    srv_c_use gen-p.toml
    wait_until 15 bird_established r2 srv_c || fail "no session with r2"
    wait_until 10 eval 'p_r2_from_c | grep -qx 10.201.1.0/24' || fail "r2 did not get 10.201.1.0/24"
    local out refresh
    # Export: only our own routes now.
    p_transit '[[filter.to-r2.rule]]
source = "own"
action = "accept"'
    out=$(on srv-c ansage reload) || fail "reload failed: $out"
    grep -q '^Neighbors updated without reconnecting: 10.201.0.3:179$' <<<"$out" || fail "reload output: $out"
    wait_until 10 eval '! p_r2_from_c | grep -qx 10.201.1.0/24' || fail "r2 still has r1's route via srv-c"
    [ "$(ansage_peer srv-c 10.201.0.3 .counters.established)" = 1 ] || fail "r2's session was reset"
    # Import: a filter for r2 asks it for its routes again.
    refresh=$(ansage_peer srv-c 10.201.0.3 .counters.messages_out.route_refresh)
    srv_c_conf p r1_extra='role = "provider"' r2_import=from-r2 \
        r2_extra='role = "customer"
export = "to-r2"' \
        extra='[filter.to-r2]
[[filter.to-r2.rule]]
source = "own"
action = "accept"
[filter.from-r2]
[[filter.from-r2.rule]]
prefixes = ["10.201.2.0/24"]
action = "accept"'
    out=$(on srv-c ansage reload) || fail "reload failed: $out"
    wait_until 5 eval '[ "$(ansage_peer srv-c 10.201.0.3 .counters.messages_out.route_refresh)" -gt "${refresh:-0}" ]' ||
        fail "no ROUTE-REFRESH sent to r2"
    wait_until 10 eval '[ "$(ansage_received srv-c 10.201.0.3)" = "1 0" ]' ||
        fail "srv-c keeps $(ansage_received srv-c 10.201.0.3) routes from r2, expected only 10.201.2.0/24"
    [ "$(ansage_peer srv-c 10.201.0.3 .counters.established)" = 1 ] || fail "r2's session was reset"
}
