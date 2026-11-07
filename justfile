build-dev:
    cargo build

build:
    cargo build --release

watch:
    cargo watch -cx run

# --- Lab: BIRD 3 in Docker, host network, listening on 127.0.0.2:179 ---

lab-up:
    docker build -q -t herald-lab-bird -f test/lab/Containerfile test/lab
    -docker rm -f herald-lab-bird >/dev/null 2>&1
    docker run -d --name herald-lab-bird --network host -v {{justfile_directory()}}/test/lab/bird.conf:/etc/bird.conf:ro herald-lab-bird

lab-down:
    docker rm -f herald-lab-bird

lab-logs:
    docker logs -f herald-lab-bird

birdc *args:
    docker exec herald-lab-bird birdc -s /run/bird.ctl {{args}}

# BIRD asks herald to resend its routes (ROUTE-REFRESH).
lab-refresh:
    docker exec herald-lab-bird birdc -s /run/bird.ctl reload bgp in herald

lab-run:
    RUST_LOG=herald=debug cargo run -- --config test/lab/herald.toml

# Asks the lab herald (`just lab-run`), e.g. `just lab-show summary`, `just lab-show rib --json`.
lab-show *args:
    cargo run -q -- --config test/lab/herald.toml show {{args}}

# --- netlink: herald's netlink code against the real kernel ---

# Installs, moves and removes routes in a throwaway user + network namespace
# (no root needed, the host's routing table is not touched).
netlink-demo:
    cargo build -q --example netlink
    unshare -rn sh -ec 'ip link set lo up; ip link add d0 type dummy; ip link set d0 up; ip addr add 10.0.0.1/24 dev d0; {{justfile_directory()}}/target/debug/examples/netlink demo d0'

# Reads the host's state, e.g. `just netlink routes --protocol 186`, `just netlink lookup 1.1.1.1`.
netlink *args:
    cargo run -q --example netlink -- {{args}}

# --- e2e: herald + FRR + BIRD in containers ---
# Docker only (E2E_ENGINE, default docker): podman puts a macvlan network
# without a parent on the host's default interface, i.e. on the real LAN.

e2e_engine := env_var_or_default("E2E_ENGINE", "docker")
e2e_file := justfile_directory() / "test/e2e/compose.yaml"
# Copies of the network (compose projects herald-e2e-1..N, same addresses);
# run.sh spreads the scenarios over them.
e2e_jobs := env_var_or_default("E2E_JOBS", "4")
# Copy for e2e-sh / e2e-logs.
e2e_project := env_var_or_default("E2E_PROJECT", "herald-e2e-1")

# Refuses podman, also behind a `docker` wrapper.
e2e-engine:
    @if {{e2e_engine}} --version 2>/dev/null | grep -qi podman; then echo "e2e: {{e2e_engine}} is podman; the e2e network needs Docker (macvlan would land on the LAN)" >&2; exit 2; fi

e2e-build:
    cargo build --release --target x86_64-unknown-linux-musl --bin herald --example rogue

# Builds the images once, then starts E2E_JOBS copies.
e2e-up: e2e-engine e2e-build
    {{e2e_engine}} compose -p herald-e2e-1 -f {{e2e_file}} build -q
    for k in $(seq {{e2e_jobs}}); do {{e2e_engine}} compose -p herald-e2e-$k -f {{e2e_file}} up -d --quiet-pull; done

# Stops every copy (also ones from a run with more copies).
e2e-down:
    for p in $({{e2e_engine}} compose ls -a -q | grep -E '^herald-e2e(-[0-9]+)?$'); do {{e2e_engine}} compose -p $p -f {{e2e_file}} down -t 2; done

e2e-sh name:
    {{e2e_engine}} compose -p {{e2e_project}} -f {{e2e_file}} exec {{name}} sh

e2e-logs name:
    {{e2e_engine}} compose -p {{e2e_project}} -f {{e2e_file}} logs -f {{name}}

# Runs the default tier, or the given scenarios / groups (e.g. `just e2e F4 R`).
e2e *args: e2e-up
    E2E_ENGINE={{e2e_engine}} E2E_JOBS={{e2e_jobs}} test/e2e/run.sh {{args}}

# Everything, including slow scenarios.
e2e-full *args: e2e-up
    E2E_ENGINE={{e2e_engine}} E2E_JOBS={{e2e_jobs}} E2E_TIER=full test/e2e/run.sh {{args}}

# dist/install.sh against systemd 252 and 255 in (unprivileged) containers.
install-test: e2e-engine e2e-build
    test/e2e/install/run.sh

# --- fuzzing: cargo-fuzz on nightly, targets in test/fuzz ---

fuzz_dir := "test/fuzz"

fuzz-list:
    cargo +nightly fuzz list --fuzz-dir {{fuzz_dir}}

# Runs a fuzz target on its corpus (test/fuzz/corpus/TARGET), libFuzzer flags
# after the name, e.g. `just fuzz decode -max_total_time=120 -max_len=4200`.
fuzz target *args:
    mkdir -p {{fuzz_dir}}/corpus/{{target}}
    cargo +nightly fuzz run --fuzz-dir {{fuzz_dir}} {{target}} {{fuzz_dir}}/corpus/{{target}} -- {{args}}
