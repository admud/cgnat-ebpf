#!/bin/bash
# CGNAT A/B benchmark harness
#
# Compares cgnat XDP mode against iptables and nftables NAT in the same
# namespace topology and emits CSV + JSON reports.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

NS_CGNAT="ns_cgnat"
NS_INTERNAL_1="ns_internal_1"
NS_INTERNAL_2="ns_internal_2"
NS_EXTERNAL="ns_external"

INTERNAL_SUBNET="10.0.0.0/24"
INTERNAL_HOST_1="10.0.0.1"
INTERNAL_HOST_2="10.0.0.2"
EXTERNAL_IP="203.0.113.1"
EXTERNAL_GW="203.0.113.254"

PING_COUNT="${PING_COUNT:-200}"
PING_INTERVAL="${PING_INTERVAL:-0.01}"
TCP_DURATION="${TCP_DURATION:-8}"
UDP_DURATION="${UDP_DURATION:-8}"
UDP_BW="${UDP_BW:-0}"
UDP_LEN="${UDP_LEN:-1200}"
CONNECT_ATTEMPTS="${CONNECT_ATTEMPTS:-2000}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-0.20}"
CONNECT_PORT="${CONNECT_PORT:-9090}"
CONNECT_SERVER_DURATION="${CONNECT_SERVER_DURATION:-8}"
BENCH_DISABLE_OFFLOADS="${BENCH_DISABLE_OFFLOADS:-1}"

MODES=("cgnat" "iptables" "nftables")

if [[ $# -gt 0 ]]; then
    case "$1" in
        --modes)
            shift
            if [[ $# -eq 0 ]]; then
                echo "--modes requires a comma-separated list (cgnat,iptables,nftables)"
                exit 1
            fi
            IFS=',' read -r -a MODES <<< "$1"
            ;;
        -h|--help|help)
            cat <<USAGE
Usage: sudo ./tests/bench_compare.sh [--modes cgnat,iptables,nftables]

Environment overrides:
  PING_COUNT=200          ICMP packets per mode
  PING_INTERVAL=0.01      ICMP interval seconds
  TCP_DURATION=8          iperf3 TCP duration seconds
  UDP_DURATION=8          iperf3 UDP duration seconds
  UDP_BW=0                iperf3 UDP bandwidth (0 = line-rate)
  UDP_LEN=1200            iperf3 UDP payload length
  CONNECT_ATTEMPTS=2000   tiny TCP connect attempts per mode
  CONNECT_TIMEOUT=0.20    connect timeout seconds
  CONNECT_PORT=9090       tiny TCP connect target port
USAGE
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
fi

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Run as root (sudo)."
        exit 1
    fi
}

require_commands() {
    local missing=0
    local cmds=(ip iptables nft iperf3 tcpdump nc ping python3 awk sed grep sort date uname timeout)
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Missing command: $cmd"
            missing=1
        fi
    done
    if [[ $missing -ne 0 ]]; then
        exit 1
    fi
}

resolve_bpftool() {
    if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
        echo "$(command -v bpftool)"
        return 0
    fi

    local candidate
    while IFS= read -r candidate; do
        if "$candidate" version >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done < <(find /usr/lib -type f -path '*/linux-tools-*/bpftool' 2>/dev/null | sort)

    echo ""
}

cpu_snapshot() {
    awk '/^cpu /{busy=$2+$3+$4+$6+$7+$8; total=busy+$5+$9+$10; print busy, total; exit}' /proc/stat
}

cpu_util_pct() {
    local busy1="$1"
    local total1="$2"
    local busy2="$3"
    local total2="$4"

    python3 - "$busy1" "$total1" "$busy2" "$total2" <<'PY'
import sys
b1, t1, b2, t2 = map(float, sys.argv[1:])
db = b2 - b1
dt = t2 - t1
if dt <= 0:
    print("null")
else:
    print(f"{(db / dt) * 100.0:.3f}")
PY
}

cleanup_background() {
    pkill -x cgnat 2>/dev/null || true
    pkill -x iperf3 2>/dev/null || true
    pkill -x tcpdump 2>/dev/null || true
    pkill -x nc 2>/dev/null || true
}

cleanup_namespaces() {
    "$PROJECT_DIR/tests/setup_test_env.sh" cleanup >/dev/null 2>&1 || true
}

cleanup_all() {
    cleanup_background
    cleanup_namespaces
}

trap cleanup_all EXIT

setup_namespaces() {
    "$PROJECT_DIR/tests/setup_test_env.sh" setup >/dev/null
}

detach_xdp() {
    ip netns exec "$NS_CGNAT" ip link set dev veth_ext_a xdp off 2>/dev/null || true
    ip netns exec "$NS_CGNAT" ip link set dev br_int xdp off 2>/dev/null || true
}

flush_rules() {
    ip netns exec "$NS_CGNAT" iptables -F >/dev/null 2>&1 || true
    ip netns exec "$NS_CGNAT" iptables -t nat -F >/dev/null 2>&1 || true
    ip netns exec "$NS_CGNAT" iptables -P FORWARD ACCEPT >/dev/null 2>&1 || true
    ip netns exec "$NS_CGNAT" nft flush ruleset >/dev/null 2>&1 || true
}

disable_offloads() {
    if [[ "$BENCH_DISABLE_OFFLOADS" != "1" ]]; then
        return 0
    fi

    # In SKB-mode + veth testbeds, GRO/GSO/TSO can produce oversized frames
    # that trigger frequent BPF_FIB_LKUP_RET_FRAG_NEEDED and distort throughput.
    local pairs=(
        "$NS_INTERNAL_1 veth_int1_a"
        "$NS_INTERNAL_2 veth_int2_a"
        "$NS_CGNAT veth_int1_b"
        "$NS_CGNAT veth_int2_b"
        "$NS_CGNAT veth_ext_a"
        "$NS_EXTERNAL veth_ext_b"
    )

    local item ns iface
    for item in "${pairs[@]}"; do
        ns="${item%% *}"
        iface="${item##* }"
        ip netns exec "$ns" ethtool -K "$iface" gro off gso off tso off lro off >/dev/null 2>&1 || true
    done
}

configure_iptables_nat() {
    flush_rules
    ip netns exec "$NS_CGNAT" iptables -P FORWARD ACCEPT
    ip netns exec "$NS_CGNAT" iptables -t nat -A POSTROUTING -s "$INTERNAL_SUBNET" -o veth_ext_a -j SNAT --to-source "$EXTERNAL_IP"
}

configure_nftables_nat() {
    flush_rules
    ip netns exec "$NS_CGNAT" nft add table ip nat
    ip netns exec "$NS_CGNAT" nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
    ip netns exec "$NS_CGNAT" nft add rule ip nat postrouting ip saddr "$INTERNAL_SUBNET" oifname "veth_ext_a" snat to "$EXTERNAL_IP"

    ip netns exec "$NS_CGNAT" nft add table ip filter
    ip netns exec "$NS_CGNAT" nft 'add chain ip filter forward { type filter hook forward priority 0; policy accept; }'
}

start_cgnat() {
    local mode="$1"
    CGNAT_LOG="$TMP_DIR/${mode}-cgnat.log"
    CGNAT_PIDFILE="$TMP_DIR/${mode}-cgnat.pid"

    rm -f "$CGNAT_LOG" "$CGNAT_PIDFILE"

    ip netns exec "$NS_CGNAT" bash -lc "mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf; exec '$PROJECT_DIR/target/release/cgnat' run -e veth_ext_a -i br_int -E $EXTERNAL_IP -I $INTERNAL_SUBNET --skb-mode --stats-interval 0 --gc-interval 1" >"$CGNAT_LOG" 2>&1 &
    echo $! > "$CGNAT_PIDFILE"
    sleep 2

    CGNAT_PID="$(cat "$CGNAT_PIDFILE")"
    if ! kill -0 "$CGNAT_PID" 2>/dev/null; then
        echo "Failed to start cgnat for mode=$mode"
        tail -n 80 "$CGNAT_LOG" || true
        return 1
    fi
}

stop_cgnat() {
    if [[ -n "${CGNAT_PID:-}" ]] && kill -0 "$CGNAT_PID" 2>/dev/null; then
        kill "$CGNAT_PID" 2>/dev/null || true
        sleep 1
    fi
    CGNAT_PID=""
}

warm_up_arp() {
    ip netns exec "$NS_INTERNAL_1" ping -n -c 2 -W 1 "$EXTERNAL_GW" >/dev/null 2>&1 || true
}

verify_snat_dnat() {
    local mode="$1"
    local ext_cap="$TMP_DIR/${mode}-verify-ext.cap"
    local int_cap="$TMP_DIR/${mode}-verify-int.cap"

    rm -f "$ext_cap" "$int_cap"

    ip netns exec "$NS_EXTERNAL" timeout 8 tcpdump -n -i veth_ext_b icmp -c 2 >"$ext_cap" 2>&1 &
    local tcpdump_ext_pid=$!
    ip netns exec "$NS_INTERNAL_1" timeout 8 tcpdump -n -i veth_int1_a icmp -c 2 >"$int_cap" 2>&1 &
    local tcpdump_int_pid=$!

    sleep 0.6
    ip netns exec "$NS_INTERNAL_1" ping -n -c 1 -W 1 "$EXTERNAL_GW" >/dev/null 2>&1 || true

    wait "$tcpdump_ext_pid" 2>/dev/null || true
    wait "$tcpdump_int_pid" 2>/dev/null || true

    if grep -q "IP $EXTERNAL_IP > $EXTERNAL_GW: ICMP echo request" "$ext_cap" && \
       grep -q "IP $EXTERNAL_GW > $INTERNAL_HOST_1: ICMP echo reply" "$int_cap"; then
        echo "true"
    else
        echo "false"
    fi
}

verify_hairpin_cgnat() {
    local mode="$1"
    local message="HAIRPIN_BENCH_${mode}_$$"
    local out_file="$TMP_DIR/${mode}-hairpin.out"

    if [[ -z "${BPFTL:-}" ]]; then
        echo "n/a"
        return 0
    fi

    if [[ -z "${CGNAT_PID:-}" ]] || ! kill -0 "$CGNAT_PID" 2>/dev/null; then
        echo "false"
        return 0
    fi

    if ! nsenter -t "$CGNAT_PID" -m test -e /sys/fs/bpf/cgnat/NAT_BINDINGS; then
        echo "false"
        return 0
    fi

    # Static mapping: 203.0.113.1:8888 -> 10.0.0.2:8888 (TCP)
    local reverse_key="01 71 00 cb  b8 22 06 00"
    local binding_key="02 00 00 0a  b8 22 06 00"
    local binding_val="01 71 00 cb  b8 22 00 00"

    if ! nsenter -t "$CGNAT_PID" -m "$BPFTL" map update pinned /sys/fs/bpf/cgnat/NAT_REVERSE key hex $reverse_key value hex $binding_key >/dev/null 2>&1; then
        echo "false"
        return 0
    fi

    if ! nsenter -t "$CGNAT_PID" -m "$BPFTL" map update pinned /sys/fs/bpf/cgnat/NAT_BINDINGS key hex $binding_key value hex $binding_val >/dev/null 2>&1; then
        echo "false"
        return 0
    fi

    rm -f "$out_file"
    ip netns exec "$NS_INTERNAL_2" timeout 8 nc -l -p 8888 >"$out_file" 2>/dev/null &
    local server_pid=$!

    sleep 0.6
    set +e
    echo "$message" | ip netns exec "$NS_INTERNAL_1" timeout 3 nc "$EXTERNAL_IP" 8888 >/dev/null 2>&1
    set -e

    sleep 0.8
    kill "$server_pid" 2>/dev/null || true

    if grep -q "$message" "$out_file" 2>/dev/null; then
        echo "true"
    else
        echo "false"
    fi
}

run_icmp_latency() {
    local mode="$1"
    local out_file="$TMP_DIR/${mode}-ping.out"
    local cpu_b1 cpu_t1 cpu_b2 cpu_t2

    read -r cpu_b1 cpu_t1 < <(cpu_snapshot)
    set +e
    ip netns exec "$NS_INTERNAL_1" ping -n -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$EXTERNAL_GW" >"$out_file" 2>&1
    set -e
    read -r cpu_b2 cpu_t2 < <(cpu_snapshot)

    ICMP_CPU_PCT="$(cpu_util_pct "$cpu_b1" "$cpu_t1" "$cpu_b2" "$cpu_t2")"

    read -r ICMP_SENT ICMP_RECV ICMP_LOSS_PCT ICMP_AVG_MS ICMP_P50_MS ICMP_P95_MS ICMP_P99_MS < <(
        python3 - "$out_file" <<'PY'
import re
import sys

path = sys.argv[1]
text = open(path, 'r', encoding='utf-8', errors='ignore').read()

m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received,.*?([0-9.]+)% packet loss", text)
sent = int(m.group(1)) if m else 0
recv = int(m.group(2)) if m else 0
loss = float(m.group(3)) if m else 100.0

times = [float(x) for x in re.findall(r"time=([0-9.]+)\s*ms", text)]
if not times:
    print(sent, recv, f"{loss:.3f}", "null", "null", "null", "null")
    sys.exit(0)

times.sort()

def pct(values, p):
    if not values:
        return None
    idx = max(0, min(len(values) - 1, int(round((len(values) - 1) * p))))
    return values[idx]

avg = sum(times) / len(times)
p50 = pct(times, 0.50)
p95 = pct(times, 0.95)
p99 = pct(times, 0.99)

print(
    sent,
    recv,
    f"{loss:.3f}",
    f"{avg:.3f}",
    f"{p50:.3f}",
    f"{p95:.3f}",
    f"{p99:.3f}",
)
PY
    )
}

run_tcp_throughput() {
    local mode="$1"
    local srv_json="$TMP_DIR/${mode}-iperf-tcp-server.json"
    local cli_json="$TMP_DIR/${mode}-iperf-tcp-client.json"
    local cpu_b1 cpu_t1 cpu_b2 cpu_t2

    rm -f "$srv_json" "$cli_json"

    ip netns exec "$NS_EXTERNAL" bash -lc "iperf3 -s -1 -J > '$srv_json'" >/dev/null 2>&1 &
    local iperf_server_pid=$!

    sleep 0.6
    read -r cpu_b1 cpu_t1 < <(cpu_snapshot)
    set +e
    ip netns exec "$NS_INTERNAL_1" iperf3 -c "$EXTERNAL_GW" -t "$TCP_DURATION" -J >"$cli_json" 2>/dev/null
    local rc=$?
    set -e
    read -r cpu_b2 cpu_t2 < <(cpu_snapshot)
    wait "$iperf_server_pid" 2>/dev/null || true

    TCP_CPU_PCT="$(cpu_util_pct "$cpu_b1" "$cpu_t1" "$cpu_b2" "$cpu_t2")"

    if [[ $rc -ne 0 ]]; then
        TCP_MBPS="null"
        TCP_RETRANS="null"
        return 0
    fi

    read -r TCP_MBPS TCP_RETRANS < <(
        python3 - "$cli_json" <<'PY'
import json
import sys

obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
end = obj.get('end', {})
sum_sent = end.get('sum_sent', {})
sum_recv = end.get('sum_received', {})

bps = sum_recv.get('bits_per_second')
if bps is None:
    bps = sum_sent.get('bits_per_second')

retrans = sum_sent.get('retransmits')

if bps is None:
    mbps = 'null'
else:
    mbps = f"{bps / 1_000_000.0:.3f}"

if retrans is None:
    retrans = 'null'

print(mbps, retrans)
PY
    )
}

run_udp_throughput() {
    local mode="$1"
    local srv_json="$TMP_DIR/${mode}-iperf-udp-server.json"
    local cli_json="$TMP_DIR/${mode}-iperf-udp-client.json"
    local cpu_b1 cpu_t1 cpu_b2 cpu_t2

    rm -f "$srv_json" "$cli_json"

    ip netns exec "$NS_EXTERNAL" bash -lc "iperf3 -s -1 -J > '$srv_json'" >/dev/null 2>&1 &
    local iperf_server_pid=$!

    sleep 0.6
    read -r cpu_b1 cpu_t1 < <(cpu_snapshot)
    set +e
    ip netns exec "$NS_INTERNAL_1" iperf3 -u -c "$EXTERNAL_GW" -b "$UDP_BW" -l "$UDP_LEN" -t "$UDP_DURATION" -J >"$cli_json" 2>/dev/null
    local rc=$?
    set -e
    read -r cpu_b2 cpu_t2 < <(cpu_snapshot)
    wait "$iperf_server_pid" 2>/dev/null || true

    UDP_CPU_PCT="$(cpu_util_pct "$cpu_b1" "$cpu_t1" "$cpu_b2" "$cpu_t2")"

    if [[ $rc -ne 0 ]]; then
        UDP_MBPS="null"
        UDP_LOSS_PCT="null"
        UDP_JITTER_MS="null"
        return 0
    fi

    read -r UDP_MBPS UDP_LOSS_PCT UDP_JITTER_MS < <(
        python3 - "$cli_json" <<'PY'
import json
import sys

obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
end = obj.get('end', {})
summary = end.get('sum') or end.get('sum_received') or end.get('sum_sent') or {}

bps = summary.get('bits_per_second')
loss = summary.get('lost_percent')
jitter = summary.get('jitter_ms')

mbps = 'null' if bps is None else f"{bps / 1_000_000.0:.3f}"
loss_s = 'null' if loss is None else f"{float(loss):.3f}"
jitter_s = 'null' if jitter is None else f"{float(jitter):.3f}"

print(mbps, loss_s, jitter_s)
PY
    )
}

run_connect_rate() {
    local mode="$1"
    local srv_json="$TMP_DIR/${mode}-connect-server.json"
    local cli_json="$TMP_DIR/${mode}-connect-client.json"
    local cpu_b1 cpu_t1 cpu_b2 cpu_t2

    rm -f "$srv_json" "$cli_json"

    ip netns exec "$NS_EXTERNAL" env BENCH_HOST="$EXTERNAL_GW" BENCH_PORT="$CONNECT_PORT" BENCH_DURATION="$CONNECT_SERVER_DURATION" BENCH_MAX_ACCEPT="$CONNECT_ATTEMPTS" python3 -u - >"$srv_json" <<'PY' &
import json
import os
import socket
import time

host = os.environ["BENCH_HOST"]
port = int(os.environ["BENCH_PORT"])
duration = float(os.environ["BENCH_DURATION"])
max_accept = int(os.environ["BENCH_MAX_ACCEPT"])

accepted = 0
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(4096)
s.settimeout(0.2)

end = time.time() + duration
while time.time() < end and accepted < max_accept:
    try:
        conn, _ = s.accept()
        accepted += 1
        conn.close()
    except socket.timeout:
        continue

s.close()
print(json.dumps({"accepted": accepted}))
PY
    local server_pid=$!

    sleep 0.6
    read -r cpu_b1 cpu_t1 < <(cpu_snapshot)
    ip netns exec "$NS_INTERNAL_1" env TARGET_HOST="$EXTERNAL_GW" TARGET_PORT="$CONNECT_PORT" ATTEMPTS="$CONNECT_ATTEMPTS" TIMEOUT="$CONNECT_TIMEOUT" python3 - >"$cli_json" <<'PY'
import json
import os
import socket
import time

host = os.environ["TARGET_HOST"]
port = int(os.environ["TARGET_PORT"])
attempts = int(os.environ["ATTEMPTS"])
timeout_s = float(os.environ["TIMEOUT"])

success = 0
start = time.time()
for _ in range(attempts):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((host, port))
        success += 1
    except Exception:
        pass
    finally:
        sock.close()

elapsed = max(time.time() - start, 1e-9)
print(json.dumps({
    "attempts": attempts,
    "success": success,
    "elapsed_s": elapsed,
    "cps": success / elapsed,
}))
PY
    read -r cpu_b2 cpu_t2 < <(cpu_snapshot)

    wait "$server_pid" 2>/dev/null || true

    CONNECT_CPU_PCT="$(cpu_util_pct "$cpu_b1" "$cpu_t1" "$cpu_b2" "$cpu_t2")"

    read -r CONNECT_ATTEMPTS_OUT CONNECT_SUCCESS CONNECT_SUCCESS_PCT CONNECT_CPS < <(
        python3 - "$cli_json" "$srv_json" <<'PY'
import json
import sys

client = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
_ = json.load(open(sys.argv[2], 'r', encoding='utf-8'))

attempts = int(client.get('attempts', 0))
success = int(client.get('success', 0))
elapsed = float(client.get('elapsed_s', 0.0))
cps = float(client.get('cps', 0.0))

if attempts <= 0:
    success_pct = 0.0
else:
    success_pct = (success / attempts) * 100.0

print(attempts, success, f"{success_pct:.3f}", f"{cps:.3f}")
PY
    )
}

run_mode() {
    local mode="$1"
    echo
    echo "=== Benchmark mode: $mode ==="

    setup_namespaces
    disable_offloads
    detach_xdp
    flush_rules

    CGNAT_PID=""
    case "$mode" in
        cgnat)
            start_cgnat "$mode"
            ;;
        iptables)
            configure_iptables_nat
            ;;
        nftables)
            configure_nftables_nat
            ;;
        *)
            echo "Unknown mode: $mode"
            return 1
            ;;
    esac

    warm_up_arp

    SNAT_DNAT_OK="$(verify_snat_dnat "$mode")"
    if [[ "$mode" == "cgnat" ]]; then
        HAIRPIN_OK="$(verify_hairpin_cgnat "$mode")"
    else
        HAIRPIN_OK="n/a"
    fi

    run_icmp_latency "$mode"
    run_tcp_throughput "$mode"
    run_udp_throughput "$mode"
    run_connect_rate "$mode"

    stop_cgnat
    cleanup_namespaces

    echo "$mode,$SNAT_DNAT_OK,$HAIRPIN_OK,$ICMP_SENT,$ICMP_RECV,$ICMP_LOSS_PCT,$ICMP_AVG_MS,$ICMP_P50_MS,$ICMP_P95_MS,$ICMP_P99_MS,$ICMP_CPU_PCT,$TCP_MBPS,$TCP_RETRANS,$TCP_CPU_PCT,$UDP_MBPS,$UDP_LOSS_PCT,$UDP_JITTER_MS,$UDP_CPU_PCT,$CONNECT_ATTEMPTS_OUT,$CONNECT_SUCCESS,$CONNECT_SUCCESS_PCT,$CONNECT_CPS,$CONNECT_CPU_PCT" >> "$OUT_CSV"

    echo "mode=$mode snat_dnat_ok=$SNAT_DNAT_OK hairpin_ok=$HAIRPIN_OK tcp_mbps=$TCP_MBPS udp_mbps=$UDP_MBPS icmp_p95_ms=$ICMP_P95_MS connect_cps=$CONNECT_CPS"
}

require_root
require_commands
BPFTL="$(resolve_bpftool)"

mkdir -p "$PROJECT_DIR/bench"
TS="$(date +%Y%m%d-%H%M%S)"
TMP_DIR="$(mktemp -d /tmp/cgnat-bench.XXXXXX)"
OUT_CSV="$PROJECT_DIR/bench/results-$TS.csv"
OUT_JSON="$PROJECT_DIR/bench/results-$TS.json"

cat > "$OUT_CSV" <<'CSV'
mode,snat_dnat_ok,hairpin_ok,icmp_sent,icmp_recv,icmp_loss_pct,icmp_avg_ms,icmp_p50_ms,icmp_p95_ms,icmp_p99_ms,icmp_cpu_pct,tcp_mbps,tcp_retransmits,tcp_cpu_pct,udp_mbps,udp_loss_pct,udp_jitter_ms,udp_cpu_pct,tcp_connect_attempts,tcp_connect_success,tcp_connect_success_pct,tcp_connect_cps,tcp_connect_cpu_pct
CSV

for mode in "${MODES[@]}"; do
    run_mode "$mode"
done

python3 - "$OUT_CSV" "$OUT_JSON" <<'PY'
import csv
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone

csv_path, json_path = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(csv_path, newline="", encoding="utf-8")))

def to_float(value):
    if value in (None, "", "null", "n/a"):
        return None
    try:
        return float(value)
    except ValueError:
        return None

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "host": socket.gethostname(),
    "kernel": subprocess.check_output(["uname", "-r"], text=True).strip(),
    "rows": rows,
}

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)

metrics = [
    ("tcp_mbps", True, "TCP throughput (Mbps)"),
    ("udp_mbps", True, "UDP throughput (Mbps)"),
    ("icmp_p95_ms", False, "ICMP p95 latency (ms)"),
    ("tcp_connect_cps", True, "TCP connect rate (cps)"),
]

print("\n=== Leaderboard ===")
for key, higher_is_better, label in metrics:
    ranked = []
    for row in rows:
        value = to_float(row.get(key))
        if value is None:
            continue
        ranked.append((row["mode"], value))
    if not ranked:
        print(f"{label}: no data")
        continue
    ranked.sort(key=lambda x: x[1], reverse=higher_is_better)
    winner, score = ranked[0]
    print(f"{label}: {winner} ({score:.3f})")

print(f"\nCSV: {csv_path}")
print(f"JSON: {json_path}")
PY

if [[ -n "${SUDO_USER:-}" ]]; then
    chown "${SUDO_USER}:${SUDO_USER}" "$OUT_CSV" "$OUT_JSON" 2>/dev/null || true
fi

echo
echo "Benchmark complete."
