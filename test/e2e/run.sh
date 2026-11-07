#!/usr/bin/env bash
# herald e2e test runner.
#
#   e2e/run.sh [-l] [ID|GROUP...]     e.g. run.sh, run.sh B3 F, run.sh -l
#
# Expects the network to be up (`just e2e-up`). Runs preflight, takes a
# baseline (router RIBs, herald resources), then each selected scenario in its
# own subshell followed by the invariant check. Exits non-zero if anything
# failed (an xfail that fails is fine; an xfail that passes is reported).
#
# With E2E_JOBS > 1 it uses that many copies of the network (compose projects
# herald-e2e-1..N): one worker per copy takes scenarios from a shared queue,
# longest first (durations of the last run). Scenario output then goes only to
# out/<run>/<ID>.log; the console gets one result line per scenario.
#
# Environment:
#   E2E_ENGINE=docker          Docker CLI to use (default docker; podman is refused)
#   E2E_JOBS=1                 copies of the network to use (`just e2e*`: 4)
#   E2E_TIER=default|full      full also runs slow scenarios (default: default)
#   E2E_FAILFAST=1             stop at the first failure
#   E2E_IDLE=30                seconds of idle time in B8

set -uo pipefail

E2E_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$E2E_DIR/lib.sh"

E2E_TIER=${E2E_TIER:-default}
E2E_JOBS=${E2E_JOBS:-1}
RUN_DIR=$E2E_DIR/out/$(date +%Y%m%d-%H%M%S)
mkdir -p "$RUN_DIR"
# Per copy of the network: baseline, allow list, temporary RIB snapshots.
COPY_DIR=$RUN_DIR

# --- scenario registry -------------------------------------------------------

SCN_IDS=()
declare -A SCN_TIER SCN_XFAIL SCN_DESC

# scenario ID TIER XFAIL DESCRIPTION; the body is the function scn_ID.
# TIER: default or full. XFAIL: "-" or a short note on the known herald bug.
scenario() {
    SCN_IDS+=("$1")
    SCN_TIER[$1]=$2
    SCN_XFAIL[$1]=$3
    SCN_DESC[$1]=$4
}

for f in "$E2E_DIR"/scenarios/*.sh; do
    . "$f"
done

selected() {
    local id=$1 arg
    if [ "${#FILTER[@]}" -eq 0 ]; then
        [ "$E2E_TIER" = full ] || [ "${SCN_TIER[$id]}" = default ]
        return
    fi
    for arg in "${FILTER[@]}"; do
        # Exact ID, or group letter(s): "F" matches F1..F16.
        [ "$arg" = "$id" ] && return 0
        [[ $arg =~ ^[A-Z]+$ && $id =~ ^$arg[0-9]+$ ]] && return 0
    done
    return 1
}

# --- sessions ----------------------------------------------------------------

# Sessions that must be Established: "frr ROUTER NEIGHBOR" / "bird ROUTER PROTOCOL".
SESSIONS=(
    "frr r1 10.201.11.10"
    "frr r1 10.201.0.10"
    "frr r1 10.201.0.3"
    "bird r2 srv_b"
    "bird r2 srv_c"
    "bird r2 r1"
)

# The same sessions from herald's side (its control socket): "SERVER NEIGHBOR".
HERALD_SESSIONS=(
    "srv-a 10.201.11.2"
    "srv-b 10.201.12.2"
    "srv-c 10.201.0.2"
    "srv-c 10.201.0.3"
)

all_established() {
    local s kind router peer server
    for s in "${SESSIONS[@]}"; do
        read -r kind router peer <<<"$s"
        "${kind}_established" "$router" "$peer" || {
            echo "$router $peer: $("${kind}_state" "$router" "$peer")"
            return 1
        }
    done
    for s in "${HERALD_SESSIONS[@]}"; do
        read -r server peer <<<"$s"
        herald_established "$server" "$peer" || {
            echo "$server (herald) $peer: $(herald_state "$server" "$peer")"
            return 1
        }
    done
}

# --- baseline and invariants -------------------------------------------------

snapshot_ribs() {
    frr_rib r1 >"$1/rib.r1"
    bird_rib r2 >"$1/rib.r2"
}

ribs_equal_baseline() {
    local tmp
    tmp=$(mktemp -d "$COPY_DIR/rib.XXXX")
    snapshot_ribs "$tmp"
    if diff -u "$COPY_DIR/baseline/rib.r1" "$tmp/rib.r1" && diff -u "$COPY_DIR/baseline/rib.r2" "$tmp/rib.r2"; then
        rm -r "$tmp"
        return 0
    fi
    rm -r "$tmp"
    return 1
}

anycast_ok() {
    http_is user1 192.0.2.10 srv-a && http_is user1 2001:db8:1::10 srv-a &&
        http_is user2 192.0.2.10 srv-b && http_is user2 2001:db8:1::10 srv-b &&
        http_is user1 198.51.100.10 srv-c && http_is user2 2001:db8:2::10 srv-c
}

preflight() {
    local n
    for n in "${NODES[@]}"; do
        running "$n" || fail "container $n is not running (just e2e-up)"
    done
    wait_until 60 all_established
    local r
    for r in r1 r2; do
        if on "$r" ip route show default | grep . >/dev/null; then fail "$r has a default route"; fi
        if on "$r" ip -6 route show default | grep . >/dev/null; then fail "$r has an IPv6 default route"; fi
    done
    for n in "${NODES[@]}"; do
        if on "$n" ip -6 addr show tentative | grep inet6 >/dev/null; then fail "$n has tentative IPv6 addresses"; fi
    done
    wait_until 20 anycast_ok
}

take_baseline() {
    mkdir -p "$COPY_DIR/baseline"
    # Let the RIBs settle: two equal snapshots in a row, 1 s apart.
    local prev
    prev=$(mktemp -d "$COPY_DIR/rib.XXXX")
    snapshot_ribs "$prev"
    while sleep 1; do
        snapshot_ribs "$COPY_DIR/baseline"
        if cmp -s "$prev/rib.r1" "$COPY_DIR/baseline/rib.r1" && cmp -s "$prev/rib.r2" "$COPY_DIR/baseline/rib.r2"; then
            break
        fi
        snapshot_ribs "$prev"
    done
    rm -r "$prev"
    local s
    for s in "${SERVERS[@]}"; do
        herald_resources "$s" >"$COPY_DIR/baseline/res.$s"
    done
}

# Unexpected WARN/ERROR lines and panics in herald logs since $1.
check_logs() {
    local since=$1 s bad allow
    for s in "${SERVERS[@]}"; do
        allow=$(awk -F'\t' -v s="$s" '$1 == s { print $2 }' "$COPY_DIR/allow" 2>/dev/null | paste -sd'|')
        bad=$(herald_logs "$s" "$since" | grep -E ' (WARN|ERROR) |panicked' |
            { if [ -n "$allow" ]; then grep -vE "$allow"; else cat; fi } || true)
        [ -z "$bad" ] || fail "$s: unexpected log lines:
$bad"
    done
}

# fds and RSS of each herald within bounds of the baseline (leak check).
check_resources() {
    local s base_fd base_rss fd rss
    for s in "${SERVERS[@]}"; do
        read -r base_fd base_rss <"$COPY_DIR/baseline/res.$s"
        read -r fd rss < <(herald_resources "$s") || fail "$s: herald is not running"
        [ "$fd" -le $((base_fd + 4)) ] || fail "$s: $fd open fds, baseline $base_fd"
        [ "$rss" -le $((base_rss * 3 / 2 + 4096)) ] || fail "$s: RSS $rss KiB, baseline $base_rss KiB"
    done
}

invariants() {
    local since=$1 n
    for n in "${NODES[@]}"; do
        running "$n" || fail "invariant: container $n is not running"
    done
    wait_until 30 all_established
    poll_until 30 ribs_equal_baseline || fail "invariant: router RIBs differ from the baseline:
$(ribs_equal_baseline)"
    wait_until 10 anycast_ok
    check_logs "$since"
    check_resources
}

# Collects state for debugging a failed scenario.
dump_state() {
    local file=$1 since=$2 n
    {
        echo "== r1 RIB"
        frr_rib r1
        echo "== r2 RIB"
        bird_rib r2
        echo "== r1 summary"
        frr r1 "show bgp summary"
        echo "== r2 protocols"
        bird r2 show protocols
        for n in "${SERVERS[@]}"; do
            echo "== $n herald show summary / peers"
            on "$n" herald show summary 2>&1
            on "$n" herald show peers 2>&1
        done
        for n in "${NODES[@]}"; do
            echo "== $n routes"
            on "$n" ip route 2>&1
            on "$n" ip -6 route 2>&1
        done
        for n in "${SERVERS[@]}"; do
            echo "== $n log since scenario start"
            herald_logs "$n" "$since"
        done
    } >"$file" 2>&1
}

# --- main --------------------------------------------------------------------

LIST=0
FILTER=()
for arg in "$@"; do
    case $arg in
    -l | --list) LIST=1 ;;
    -h | --help)
        sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
        exit 0
        ;;
    *) FILTER+=("$arg") ;;
    esac
done

if [ "$LIST" = 1 ]; then
    for id in "${SCN_IDS[@]}"; do
        printf '%-4s %-7s %s%s\n' "$id" "${SCN_TIER[$id]}" "${SCN_DESC[$id]}" \
            "$([ "${SCN_XFAIL[$id]}" = - ] || printf ' [xfail: %s]' "${SCN_XFAIL[$id]}")"
    done
    exit 0
fi

# One scenario with its invariant check, on the current copy. Prints the
# result line and appends "STATUS ID SECONDS COPY" to RUN_DIR/results.
run_scenario() {
    local id=$1 since rc t xf status
    : >"$COPY_DIR/allow"
    since=$(now)
    SCN_ID=$id
    if [ "$E2E_JOBS" = 1 ]; then
        printf '%-4s %s\n' "$id" "${SCN_DESC[$id]}"
    else
        printf '%-4s %s [copy %s]\n' "$id" "${SCN_DESC[$id]}" "$COPY" >"$RUN_DIR/$id.log"
    fi
    (
        set -e
        "scn_$id"
    ) 2>&1 | out_to "$RUN_DIR/$id.log"
    rc=${PIPESTATUS[0]}
    if [ "$rc" = 0 ]; then
        (invariants "$since") 2>&1 | out_to "$RUN_DIR/$id.log"
        rc=${PIPESTATUS[0]}
        [ "$rc" = 0 ] || echo "    (invariant check)" | out_to "$RUN_DIR/$id.log"
    fi
    t=$(elapsed "$since")
    xf=${SCN_XFAIL[$id]}
    local tag=""
    [ "$E2E_JOBS" = 1 ] || tag=" [copy $COPY]"
    if [ "$rc" = 0 ] && [ "$xf" = - ]; then
        status=PASS
        echo "${C_GREEN}PASS${C_OFF} $id (${t} s)$tag"
    elif [ "$rc" = 0 ]; then
        status=XPASS
        echo "${C_YELLOW}XPASS${C_OFF} $id (${t} s)$tag: known bug fixed? remove the xfail marker ($xf)"
    elif [ "$xf" != - ]; then
        status=XFAIL
        echo "${C_YELLOW}XFAIL${C_OFF} $id (${t} s)$tag: $xf"
    else
        status=FAIL
        dump_state "$RUN_DIR/$id.dump" "$since"
        # In parallel runs the details are only in the log: show the reason.
        [ "$E2E_JOBS" = 1 ] || grep -E 'FAIL:|timeout after' "$RUN_DIR/$id.log" | head -n 3
        echo "${C_RED}FAIL${C_OFF} $id (${t} s)$tag, state in $RUN_DIR/$id.dump"
    fi
    printf '%s %s %s %s\n' "$status" "$id" "$t" "${COPY:-1}" >>"$RUN_DIR/results"
    printf '%s\t%s\n' "$id" "$t" >>"$RUN_DIR/durations"
    if [ "$status" = XFAIL ] || [ "$status" = FAIL ]; then
        # A failure may leave the network broken; restore before going on.
        (wait_until 60 all_established && poll_until 30 ribs_equal_baseline) >/dev/null 2>&1 || true
    fi
    [ "$status" != FAIL ]
}

# Scenario output: on the console too when running alone.
out_to() {
    if [ "$E2E_JOBS" = 1 ]; then tee -a "$1"; else cat >>"$1"; fi
}

# Selected scenarios, longest first by the durations of the last run that has
# them (unknown: 30 s), so the long ones do not end up last on one copy.
ordered_ids() {
    local last id
    last=$(ls -t "$E2E_DIR"/out/*/durations 2>/dev/null | grep -v "^$RUN_DIR/" | head -n 1)
    for id in "${SCN_IDS[@]}"; do
        selected "$id" || continue
        printf '%s\t%s\n' "$id" "$(awk -F'\t' -v i="$id" '$1 == i { d = $2 } END { print d == "" ? 30 : d }' "${last:-/dev/null}")"
    done | sort -t$'\t' -k2,2 -rn | cut -f1
}

# Next scenario from the shared queue (empty: none left).
queue_pop() {
    flock "$RUN_DIR/queue.lock" sh -c 'id=$(head -n 1 "$1") && [ -n "$id" ] && sed -i 1d "$1" && echo "$id"' _ "$RUN_DIR/queue"
}

# Fills the container name cache in this shell (`on` resolves in a subshell,
# where the cache would not stick).
cache_names() {
    local n
    for n in "${NODES[@]}"; do cname "$n" >/dev/null 2>&1 || true; done
}

# One copy: preflight, baseline, then scenarios from the queue until empty.
worker() {
    COPY=$1
    E2E_PROJECT=herald-e2e-$COPY
    COPY_DIR=$RUN_DIR/copy-$COPY
    mkdir -p "$COPY_DIR"
    cache_names
    if ! (preflight) >"$COPY_DIR/preflight.log" 2>&1; then
        echo "${C_RED}copy $COPY: preflight failed${C_OFF} ($(tail -n 1 "$COPY_DIR/preflight.log"))"
        echo "PREFLIGHT - - $COPY" >>"$RUN_DIR/results"
        return 1
    fi
    take_baseline
    local id
    while id=$(queue_pop); do
        if ! run_scenario "$id" && [ -n "${E2E_FAILFAST:-}" ]; then
            flock "$RUN_DIR/queue.lock" truncate -s 0 "$RUN_DIR/queue"
        fi
    done
}

echo "e2e run: engine $E2E_ENGINE, tier $E2E_TIER, copies $E2E_JOBS, output $RUN_DIR"
start=$(now)
if [ "$E2E_JOBS" = 1 ]; then
    COPY=1
    cache_names
    if ! (preflight); then
        echo "${C_RED}preflight failed${C_OFF}"
        exit 2
    fi
    take_baseline
    echo "preflight ok, baseline taken ($(elapsed "$start") s)"
    for id in "${SCN_IDS[@]}"; do
        selected "$id" || continue
        run_scenario "$id" || [ -z "${E2E_FAILFAST:-}" ] || break
    done
else
    ordered_ids >"$RUN_DIR/queue"
    echo "$(wc -l <"$RUN_DIR/queue") scenarios on $E2E_JOBS copies"
    for k in $(seq "$E2E_JOBS"); do
        worker "$k" &
    done
    wait
fi

PASS=() FAILED=() XFAIL=() XPASS=() NOTRUN=()
while read -r status id _ copy; do
    case $status in
    PASS) PASS+=("$id") ;;
    FAIL) FAILED+=("$id") ;;
    XFAIL) XFAIL+=("$id") ;;
    XPASS) XPASS+=("$id") ;;
    PREFLIGHT) FAILED+=("preflight:copy-$copy") ;;
    esac
done < <(cat "$RUN_DIR/results" 2>/dev/null)
if [ -s "$RUN_DIR/queue" ] && [ -z "${E2E_FAILFAST:-}" ]; then
    mapfile -t NOTRUN <"$RUN_DIR/queue"
fi

echo
echo "${#PASS[@]} passed, ${#FAILED[@]} failed, ${#XFAIL[@]} xfail, ${#XPASS[@]} xpass ($(elapsed "$start") s)"
[ "${#FAILED[@]}" = 0 ] || echo "failed: ${FAILED[*]}"
[ "${#XFAIL[@]}" = 0 ] || echo "xfail:  ${XFAIL[*]}"
[ "${#XPASS[@]}" = 0 ] || echo "xpass:  ${XPASS[*]}"
[ "${#NOTRUN[@]}" = 0 ] || echo "not run (no working copy left): ${NOTRUN[*]}"
[ "${#FAILED[@]}" = 0 ] && [ "${#XPASS[@]}" = 0 ] && [ "${#NOTRUN[@]}" = 0 ]
