# Helpers for the ansage e2e tests, sourced by run.sh.
# Helpers take container names and addresses as
# arguments (no hardcoded r1/r2), so the network can grow later.

E2E_ENGINE=${E2E_ENGINE:-docker}
E2E_DIR=${E2E_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
E2E_COMPOSE_FILE=${E2E_COMPOSE_FILE:-$E2E_DIR/compose.yaml}
# Compose project = one copy of the network (`just e2e-up` starts E2E_JOBS of
# them, ansage-e2e-1..N, all with the same addresses).
E2E_PROJECT=${E2E_PROJECT:-ansage-e2e-1}

# All containers of the network, routers, ansage servers.
NODES=(r1 r2 srv-a srv-b srv-c user1 user2 rogue)
SERVERS=(srv-a srv-b srv-c)

# --- output ------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
else
    C_RED='' C_GREEN='' C_YELLOW='' C_DIM='' C_OFF=''
fi

log() { printf '%s    %s%s\n' "$C_DIM" "$*" "$C_OFF" >&2; }
info() { printf '    %s\n' "$*" >&2; }

# Fails the current scenario (each scenario runs in its own subshell).
fail() {
    printf '%s    FAIL: %s%s\n' "$C_RED" "$*" "$C_OFF" >&2
    exit 1
}

# Seconds since the epoch with microseconds.
now() { printf '%s' "$EPOCHREALTIME"; }
# Elapsed seconds since START, 2 decimals.
elapsed() { awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN { printf "%.2f", b - a }'; }

# --- engine ------------------------------------------------------------------

# Docker only. podman puts a macvlan network without a parent on the host's
# default interface, i.e. on the real LAN (seen 2026-11-02). Checked by
# version, as `docker` may be a podman wrapper.
if "$E2E_ENGINE" --version 2>/dev/null | grep -qi podman; then
    echo "e2e: $E2E_ENGINE is podman; the e2e network needs Docker (macvlan would land on the LAN)" >&2
    exit 2
fi

compose() { "$E2E_ENGINE" compose -p "$E2E_PROJECT" -f "$E2E_COMPOSE_FILE" "$@"; }

# Container of a service, by the compose labels.
container_of() {
    "$E2E_ENGINE" ps -a --filter "label=com.docker.compose.project=$E2E_PROJECT" \
        --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' 2>/dev/null | head -n 1
}

# Container name per service, cached (names survive recreation). Exec and logs
# go to the engine directly, cheaper than through compose.
declare -A E2E_CNAME=()
cname() {
    if [ -z "${E2E_CNAME[$1]:-}" ]; then
        E2E_CNAME[$1]=$(container_of "$1")
        [ -n "${E2E_CNAME[$1]}" ] || { echo "no container for service $1" >&2; return 1; }
    fi
    printf '%s' "${E2E_CNAME[$1]}"
}

# Runs a command in a container.
on() {
    local c
    c=$(cname "$1") || return 1
    shift
    "$E2E_ENGINE" exec -i "$c" "$@"
}

# Runs a command in a container in the background (exec -d).
on_bg() {
    local c
    c=$(cname "$1") || return 1
    shift
    "$E2E_ENGINE" exec -d "$c" "$@" >/dev/null
}

# Runs a shell snippet in a container.
on_sh() { on "$1" sh -c "$2"; }
# State field of a service's container, e.g. state_of srv-a ExitCode.
state_of() {
    local c
    c=$(container_of "$1")
    [ -n "$c" ] && "$E2E_ENGINE" inspect -f "{{.State.$2}}" "$c" 2>/dev/null
}
running() { [ "$(state_of "$1" Running)" = true ]; }

frr() {
    local router=$1
    shift
    on "$router" vtysh -c "$*"
}

# Several vtysh commands in one session, e.g. frr_conf r1 'router bgp 64510' 'neighbor ...'.
frr_conf() {
    local router=$1
    shift
    local args=(-c 'configure terminal')
    local c
    for c in "$@"; do args+=(-c "$c"); done
    on "$router" vtysh "${args[@]}"
}

bird() {
    local router=$1
    shift
    on "$router" birdc -s /run/bird.ctl "$@"
}

# --- waiting -----------------------------------------------------------------

# wait_until TIMEOUT CMD...: runs CMD every 200 ms until it succeeds.
# Fails the scenario with CMD's last output on timeout.
wait_until() {
    local timeout=$1
    shift
    local deadline out
    deadline=$(awk -v t="$EPOCHREALTIME" -v d="$timeout" 'BEGIN { printf "%.6f", t + d }')
    while :; do
        if out=$("$@" 2>&1); then
            return 0
        fi
        if awk -v t="$EPOCHREALTIME" -v d="$deadline" 'BEGIN { exit !(t > d) }'; then
            fail "timeout after ${timeout}s: $*${out:+
$out}"
        fi
        sleep 0.2
    done
}

# Like wait_until, but returns 1 instead of failing.
poll_until() {
    local timeout=$1
    shift
    local deadline
    deadline=$(awk -v t="$EPOCHREALTIME" -v d="$timeout" 'BEGIN { printf "%.6f", t + d }')
    until "$@" >/dev/null 2>&1; do
        if awk -v t="$EPOCHREALTIME" -v d="$deadline" 'BEGIN { exit !(t > d) }'; then
            return 1
        fi
        sleep 0.2
    done
}

# --- traffic -----------------------------------------------------------------

url_for() {
    case $1 in
    *:*) printf 'http://[%s]/' "$1" ;;
    *) printf 'http://%s/' "$1" ;;
    esac
}

# Prints the answer of the HTTP server at ADDR as seen from USER (empty if none).
http_get() { on "$1" curl -sg --max-time 1 "$(url_for "$2")" 2>/dev/null || true; }

http_is() { [ "$(http_get "$1" "$2")" = "$3" ]; }

# assert_http USER ADDR EXPECTED: retried for up to 3 s, as a route the
# router's RIB already shows may not be in its kernel yet (N4 failed once on
# 4 parallel copies). Failover timing is measured with probes, not here.
assert_http() {
    local got end=$((SECONDS + 3))
    while :; do
        got=$(http_get "$1" "$2")
        [ "$got" = "$3" ] && return 0
        [ $SECONDS -lt $end ] || break
        sleep 0.2
    done
    fail "$1 -> $2: expected answer '$3', got '${got:-<none>}'"
}

# assert_no_http USER ADDR
assert_no_http() {
    local got
    got=$(http_get "$1" "$2")
    [ -z "$got" ] || fail "$1 -> $2: expected no answer, got '$got'"
}

# Hops of a traceroute from USER to ADDR, space separated.
trace_hops() {
    local flag=-4
    case $2 in *:*) flag=-6 ;; esac
    on "$1" traceroute "$flag" -n -q 1 -w 1 -m 6 "$2" 2>/dev/null |
        awk 'NR > 1 || $1 ~ /^[0-9]+$/ { if ($1 ~ /^[0-9]+$/) print $2 }' | xargs
}

# assert_path USER ADDR HOP...: the traceroute hops must equal the list.
assert_path() {
    local user=$1 addr=$2
    shift 2
    local got
    got=$(trace_hops "$user" "$addr")
    [ "$got" = "$*" ] || fail "path $user -> $addr: expected '$*', got '$got'"
}

ping_ok() {
    local flag=-4
    case $2 in *:*) flag=-6 ;; esac
    on "$1" ping "$flag" -c 1 -W 1 "$2" >/dev/null 2>&1
}

# --- BGP state ---------------------------------------------------------------

# State of an FRR neighbor (Established, Active, ...).
frr_state() {
    frr "$1" "show bgp neighbors $2 json" | jq -r --arg n "$2" '.[$n].bgpState // "none"'
}

frr_established() { [ "$(frr_state "$1" "$2")" = Established ]; }

# State of a BIRD BGP protocol (Established, Active, ...).
bird_state() {
    bird "$1" show protocols "$2" | awk -v p="$2" '$1 == p { print $6; found = 1 } END { if (!found) print "none" }'
}

bird_established() { [ "$(bird_state "$1" "$2")" = Established ]; }

# FRR neighbor field (jq path below the neighbor object).
frr_neighbor() { frr "$1" "show bgp neighbors $2 json" | jq -r --arg n "$2" ".[\$n]$3"; }

# Normalized RIB of an FRR router: "prefix peer as_path next_hops best" per
# path, sorted (no timestamps, no versions).
frr_rib() {
    local afi
    for afi in ipv4 ipv6; do
        frr "$1" "show bgp $afi unicast json" | jq -r '
            .routes | to_entries[] | .key as $p | .value[] |
            [$p, (.peerId // "local"), (if .path == "" then "-" else .path end),
             ([.nexthops[]?.ip | if startswith("fe80:") then "fe80::LL" else . end] | join(",")), (if .bestpath == true or ((.bestpath | type) == "object" and .bestpath.overall) then "best" else "-" end)] |
            join(" ")'
    done | sort
}

# Normalized RIB of a BIRD router: "prefix protocol as_path via best" per route.
bird_rib() {
    bird "$1" show route | awk '
        function flush() { if (proto != "") print prefix, proto, path, via, best; proto = "" }
        /unicast \[/ {
            flush()
            if ($1 != "unicast") prefix = $1
            match($0, /\[[^] ]+/); proto = substr($0, RSTART + 1, RLENGTH - 1)
            best = ($0 ~ /\] \* \(/) ? "best" : "-"
            path = "-"
            if (match($0, /\[AS[^]]*\]$/)) path = substr($0, RSTART + 1, RLENGTH - 2)
            via = "-"
            next
        }
        /^\t(via|dev) / { via = (via == "-" ? "" : via ",") $2 }
        END { flush() }' | sort
}

# --- ansage ------------------------------------------------------------------

ansage_pid() { on "$1" pidof ansage; }

# "fds rss_kib" of the ansage process in a server container.
ansage_resources() {
    on_sh "$1" 'p=$(pidof ansage) && echo $(ls /proc/$p/fd | wc -l) $(awk "/^VmRSS/ { print \$2 }" /proc/$p/status)'
}

# ansage's own view over its control socket: ansage_show SERVER ARGS...
# prints the JSON reply of `ansage show ARGS`, e.g. ansage_show srv-c rib 10.201.1.0/24.
ansage_show() {
    local server=$1
    shift
    on "$server" ansage show --json "$@"
}

# One field of ansage's view of NEIGHBOR (ID or address): jq filter on the
# `show peer` object, e.g. ansage_peer srv-a 10.201.11.2 .status.backoff_ms.
ansage_peer() { ansage_show "$1" peer "$2" | jq -r ".[0]$3"; }

ansage_state() { ansage_peer "$1" "$2" .status.state; }
ansage_established() { [ "$(ansage_state "$1" "$2")" = Established ]; }

# Routes ansage stores from NEIGHBOR: "v4 v6" ("- -" while the session is down).
ansage_received() {
    ansage_peer "$1" "$2" '.rib | if . == null then "- -" else "\(.received_ipv4) \(.received_ipv6)" end'
}

# Normalized candidates ansage has for PREFIX: "source as_path next_hop best" per
# route, best first.
ansage_routes() {
    ansage_show "$1" rib "$2" | jq -r '.routes[] |
        [.source, ([.as_path[].asns[]] | map(tostring) | join(",") | if . == "" then "-" else . end),
         (.next_hop // "-"), (if .best then "best" else "-" end)] | join(" ")'
}

# ansage logs of a server since a timestamp (RFC 3339 or unix time).
ansage_logs() {
    local since=${2:-} c
    c=$(cname "$1") || return 1
    "$E2E_ENGINE" logs ${since:+--since "$since"} "$c" 2>&1
}

# assert_log SERVER SINCE REGEX: the log since SINCE must contain REGEX.
assert_log() {
    ansage_logs "$1" "$2" | grep -E "$3" >/dev/null || fail "$1: log has no line matching '$3'"
}

log_has() { ansage_logs "$1" "$2" | grep -E "$3" >/dev/null; }

# wait_log SERVER SINCE REGEX [TIMEOUT]: waits until the log since SINCE has REGEX.
wait_log() { wait_until "${4:-10}" log_has "$1" "$2" "$3"; }

# WARN/ERROR lines and panics that the current scenario expects, per server:
# allow_warn SERVER REGEX. Read by the invariant check after the scenario.
allow_warn() { printf '%s\t%s\n' "$1" "$2" >>"${COPY_DIR:-$RUN_DIR}/allow"; }

# Allows a whole session flap of SERVER: down + reconnect warnings.
allow_flap() {
    allow_warn "$1" 'session down'
    allow_warn "$1" 'connect failed'
    allow_warn "$1" 'read failed'
}

# --- router logs -------------------------------------------------------------

# FRR logs to a file (stdout logging stops after a while in the container).
# frr_log_mark ROUTER prints the current line count; frr_log ROUTER MARK prints
# the lines after it.
frr_log_mark() { on "$1" sh -c 'wc -l < /tmp/frr.log'; }
frr_log() { on "$1" tail -n +"$((${2:-0} + 1))" /tmp/frr.log; }
frr_log_has() { frr_log "$1" "$2" | grep -E "$3" >/dev/null; }

# BIRD logs to stderr: container logs since a timestamp.
bird_log() { ansage_logs "$1" "$2"; }
bird_log_has() { bird_log "$1" "$2" | grep -E "$3" >/dev/null; }

# --- probes ------------------------------------------------------------------

# probe_start USER ADDR NAME: background loop in USER, one HTTP request every
# 100 ms, logs "uptime answer" ("-" for no answer) to /tmp/probe.NAME.
# Uptime, not date: busybox date has no %N; /proc/uptime has 10 ms.
probe_start() {
    local url
    url=$(url_for "$2")
    on_bg "$1" sh -c "while :; do read t _ </proc/uptime; a=\$(curl -sg --max-time 0.3 $url); echo \"\$t \${a:--}\"; sleep 0.1; done >/tmp/probe.$3"
    # Wait for the first line, so the probe covers the action that follows.
    wait_until 5 on "$1" test -s "/tmp/probe.$3"
}

# probe_stop USER NAME: stops the loop and prints its log.
probe_stop() {
    on "$1" pkill -f "probe.$2" || true
    on "$1" cat "/tmp/probe.$2"
    on "$1" rm -f "/tmp/probe.$2"
}

# Longest time without any answer in a probe log (seconds, 2 decimals): from
# the last answer before the gap to the first answer after it. A gap at the
# end (no answer when the probe stopped) counts up to the last line.
probe_max_gap() {
    awk '$2 != "-" { if (last != "" && $1 - last > max) max = $1 - last; last = $1; ok = 1 }
         $2 == "-" { end = $1 }
         END { if (end > last && end - last > max) max = end - last; printf "%.2f", max + 0 }'
}

# Answers in order of appearance with how often they appeared in a row,
# e.g. "srv-a srv-b srv-a".
probe_sequence() { awk '$2 != prev { printf "%s%s", sep, $2; sep = " "; prev = $2 } END { print "" }'; }

# measure NAME VALUE [UNIT]: shows a measured value (default unit s) and
# appends it to RUN_DIR/timings.
measure() {
    info "measured $1: $2 ${3:-s}"
    printf '%s\t%s\t%s\t%s\n' "${SCN_ID:-?}" "$1" "$2" "${3:-s}" >>"$RUN_DIR/timings"
}

# assert_le NAME VALUE LIMIT: VALUE <= LIMIT (decimals allowed).
assert_le() {
    awk -v v="$2" -v l="$3" 'BEGIN { exit !(v <= l) }' || fail "$1: $2 s > limit $3 s"
}

# --- config variants ---------------------------------------------------------

# srv_c_conf NAME [key=value...]: writes gen-NAME.toml (in
# config/srv-c/gen/PROJECT/, one directory per copy of the network), srv-c's
# default config with changes. Keys: asn router_id hold_time announce (TOML
# array body), r1 / r2 (0 = leave the neighbor out), r1_asn r2_asn r1_addr
# r2_addr r2_port, r1_desc, r1_nh6 r2_nh6 (next_hop_ipv6, empty = none), r1_extra
# r2_extra (more TOML lines for the neighbor), connect_retry max_connect_retry,
# extra (TOML appended at the end, e.g. one more neighbor). top (top-level TOML
# lines, e.g. listen).
srv_c_conf() {
    local name=$1
    shift
    local -A c=(
        [asn]=64502 [router_id]=203.0.113.23 [hold_time]=9 [connect_retry]=1 [max_connect_retry]=8 [extra]='' [top]=''
        [announce]='"198.51.100.0/24", "2001:db8:2::/48"'
        [r1]=1 [r1_desc]='r1 (FRR)' [r1_asn]=64510 [r1_addr]=10.201.0.2 [r1_nh6]=2001:db8:201::10 [r1_extra]=''
        [r2]=1 [r2_asn]=64511 [r2_addr]=10.201.0.3 [r2_port]=179 [r2_nh6]=2001:db8:201::10 [r2_extra]=''
    )
    local kv
    for kv in "$@"; do c[${kv%%=*}]=${kv#*=}; done
    local nh1= nh2=
    [ -z "${c[r1_nh6]}" ] || nh1="next_hop_ipv6 = \"${c[r1_nh6]}\""
    [ -z "${c[r2_nh6]}" ] || nh2="next_hop_ipv6 = \"${c[r2_nh6]}\""
    {
        cat <<TOML
# Generated by the e2e scenario that uses it ($name).
asn = ${c[asn]}
router_id = "${c[router_id]}"
hold_time = ${c[hold_time]}
connect_retry = ${c[connect_retry]}
max_connect_retry = ${c[max_connect_retry]}
max_prefix_restart = 5
announce = [${c[announce]}]
${c[top]}
TOML
        [ "${c[r1]}" = 0 ] || cat <<TOML

[[neighbor]]
address = "${c[r1_addr]}"
asn = ${c[r1_asn]}
description = "${c[r1_desc]}"
$nh1
import = "all"
${c[r1_extra]}
TOML
        [ "${c[r2]}" = 0 ] || cat <<TOML

[[neighbor]]
address = "${c[r2_addr]}"
port = ${c[r2_port]}
asn = ${c[r2_asn]}
description = "r2 (BIRD)"
$nh2
import = "all"
${c[r2_extra]}
TOML
        printf '\n%s\n' "${c[extra]}"
    } >"$(srv_c_gen_dir)/gen-$name.toml"
}

srv_c_gen_dir() {
    mkdir -p "$E2E_DIR/config/srv-c/gen/$E2E_PROJECT"
    printf '%s' "$E2E_DIR/config/srv-c/gen/$E2E_PROJECT"
}

# srv_c_use FILE: recreates srv-c with config/srv-c/FILE (ansage.toml = default;
# gen-* files from srv_c_conf are taken from this copy's directory).
srv_c_use() {
    local f=$1
    case $f in gen-*) f=gen/$E2E_PROJECT/$f ;; esac
    SRV_C_CONFIG=$f compose up -d srv-c >/dev/null 2>&1 || fail "cannot start srv-c with $1"
    wait_until 10 running srv-c
}

# bird_use ROUTER SED_SCRIPT: runs BIRD with its config changed by SED_SCRIPT
# (written to /tmp/variant.conf in the container). bird_restore goes back.
bird_use() {
    on_sh "$1" "sed -e '$2' /etc/bird.conf >/tmp/variant.conf" || fail "cannot write the BIRD variant"
    local out
    out=$(bird "$1" configure '"/tmp/variant.conf"')
    [[ $out == *Reconfigured* || $out == *"Reconfiguration in progress"* ]] || fail "BIRD rejected the variant: $out"
}
bird_restore() { bird "$1" configure '"/etc/bird.conf"' >/dev/null; }

# --- rogue peer (examples/rogue.rs) ------------------------------------------

ROGUE=10.201.0.20
ROGUE_ASN=64520

# TOML for srv-c's neighbor entry for the rogue (srv_c_conf extra=...).
rogue_neighbor() {
    cat <<TOML
[[neighbor]]
address = "$ROGUE"
asn = ${1:-$ROGUE_ASN}
description = "rogue"
next_hop_ipv6 = "2001:db8:201::10"
import = "all"
TOML
}

# rogue_start: runs the script on stdin (see examples/rogue.rs) in the
# background in the rogue container, listening on port 179.
rogue_start() {
    rogue_stop  # reads nothing: stdin is the script
    on rogue sh -c 'cat >/tmp/rogue.script && rm -f /tmp/rogue.out /tmp/rogue.rc' || fail "cannot write the rogue script"
    on_bg rogue sh -c 'rogue /tmp/rogue.script >/tmp/rogue.out 2>&1; echo $? >/tmp/rogue.rc' </dev/null
    wait_until 5 on rogue grep -q listening /tmp/rogue.out
}

rogue_stop() { on rogue sh -c 'pkill -x rogue; true' </dev/null; }
rogue_out() { on rogue cat /tmp/rogue.out 2>/dev/null; }
rogue_done() { on rogue test -s /tmp/rogue.rc; }
rogue_has() { rogue_out | grep -E "$1" >/dev/null; }

# Fails the scenario if the script has failed so far (still running is fine).
rogue_ok() {
    rogue_save
    if rogue_done && [ "$(on rogue cat /tmp/rogue.rc)" != 0 ]; then
        fail "rogue script failed: $(rogue_out | tail -n 5)"
    fi
}

# rogue_wait TIMEOUT: waits until the script has finished successfully.
rogue_wait() {
    poll_until "$1" rogue_done || { rogue_save; fail "rogue script still running after $1 s: $(rogue_out | tail -n 3)"; }
    rogue_ok
}

# Keeps the rogue's log next to the scenario log.
rogue_save() { rogue_out >"$RUN_DIR/${SCN_ID:-rogue}.rogue" 2>&1 || true; }

# Seconds (rogue clock) of the first rogue log line matching REGEX.
rogue_time() { rogue_out | awk -v re="$1" '$0 ~ re { print $1; exit }'; }
