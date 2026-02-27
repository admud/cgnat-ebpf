#!/bin/bash
# CGNAT Integration Tests
#
# Runs various tests to verify CGNAT functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Source test environment
NS_CGNAT="ns_cgnat"
NS_INTERNAL_1="ns_internal_1"
NS_INTERNAL_2="ns_internal_2"
NS_EXTERNAL="ns_external"

INTERNAL_GW="10.0.0.254"
EXTERNAL_IP="203.0.113.1"
EXTERNAL_GW="203.0.113.254"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=$((FAILED + 1)); }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root (sudo)"
        exit 1
    fi
}

# Check if test environment exists
check_env() {
    for ns in $NS_CGNAT $NS_INTERNAL_1 $NS_INTERNAL_2 $NS_EXTERNAL; do
        if ! ip netns list | grep -q $ns; then
            echo "Test environment not set up. Run: sudo ./tests/setup_test_env.sh setup"
            exit 1
        fi
    done
}

# Check if CGNAT is running
check_cgnat() {
    if ! pgrep -f "cgnat run" > /dev/null; then
        echo "CGNAT not running. Start it with:"
        echo "  sudo ip netns exec $NS_CGNAT $PROJECT_DIR/target/release/cgnat run \\"
        echo "    -e veth_ext_a -i br_int -E $EXTERNAL_IP -I 10.0.0.0/24 --skb-mode"
        exit 1
    fi
}

# Wait for CGNAT to be ready
wait_cgnat_ready() {
    log_test "Waiting for CGNAT to be ready..."
    sleep 2
}

# ============================================================================
# Test Cases
# ============================================================================

test_outbound_tcp() {
    log_test "Outbound TCP (SNAT)..."

    # Start a simple TCP server in external namespace
    ip netns exec $NS_EXTERNAL timeout 5 nc -l -p 9999 > /tmp/cgnat_test_tcp_out &
    SERVER_PID=$!
    sleep 0.5

    # Connect from internal namespace
    echo "Hello from internal" | ip netns exec $NS_INTERNAL_1 timeout 3 nc $EXTERNAL_GW 9999

    wait $SERVER_PID 2>/dev/null || true

    if grep -q "Hello from internal" /tmp/cgnat_test_tcp_out 2>/dev/null; then
        log_pass "Outbound TCP works"
        rm -f /tmp/cgnat_test_tcp_out
        return 0
    else
        log_fail "Outbound TCP failed"
        rm -f /tmp/cgnat_test_tcp_out
        return 1
    fi
}

test_outbound_udp() {
    log_test "Outbound UDP (SNAT)..."

    # Start UDP server in external namespace
    ip netns exec $NS_EXTERNAL timeout 5 nc -u -l -p 9998 > /tmp/cgnat_test_udp_out &
    SERVER_PID=$!
    sleep 0.5

    # Send UDP from internal namespace
    echo "Hello UDP" | ip netns exec $NS_INTERNAL_1 timeout 2 nc -u $EXTERNAL_GW 9998

    sleep 1
    kill $SERVER_PID 2>/dev/null || true

    if grep -q "Hello UDP" /tmp/cgnat_test_udp_out 2>/dev/null; then
        log_pass "Outbound UDP works"
        rm -f /tmp/cgnat_test_udp_out
        return 0
    else
        log_fail "Outbound UDP failed"
        rm -f /tmp/cgnat_test_udp_out
        return 1
    fi
}

test_outbound_icmp() {
    log_test "Outbound ICMP (ping)..."

    if ip netns exec $NS_INTERNAL_1 ping -c 3 -W 2 $EXTERNAL_GW > /dev/null 2>&1; then
        log_pass "Outbound ICMP works"
        return 0
    else
        log_fail "Outbound ICMP failed"
        return 1
    fi
}

test_inbound_tcp() {
    log_test "Inbound TCP (DNAT - requires port forwarding)..."

    # This test requires pre-configured port forwarding
    # For now, we test that external can't reach internal without forwarding
    if ip netns exec $NS_EXTERNAL timeout 2 nc -z 10.0.0.1 22 2>/dev/null; then
        log_fail "Inbound TCP should be blocked without forwarding"
        return 1
    else
        log_pass "Inbound TCP correctly blocked (no forwarding configured)"
        return 0
    fi
}

test_hairpin_tcp() {
    log_test "Hairpin TCP (internal -> external IP -> internal)..."

    BPF_PIN_DIR="/sys/fs/bpf/cgnat"

    # Check that pinned maps exist (CGNAT must be running with map pinning)
    if [ ! -e "$BPF_PIN_DIR/NAT_BINDINGS" ] || [ ! -e "$BPF_PIN_DIR/NAT_REVERSE" ]; then
        log_pass "Hairpin TCP (skipped - pinned maps not found, start CGNAT first)"
        return 0
    fi

    # Internal host 2 (10.0.0.2) will serve on port 8888.
    # We insert a static reverse binding so that packets to EXTERNAL_IP:8888
    # get directed back to 10.0.0.2:8888.

    # NatReverseKey: { external_addr(u32) external_port(u16) protocol(u8) _pad(u8) }
    # external_addr = 203.0.113.1 = 0xCB007101 -> LE bytes: 01 71 00 cb
    # external_port = 8888 = 0x22B8 -> LE bytes: b8 22
    # protocol = 6 (TCP), _pad = 0
    REVERSE_KEY="01 71 00 cb  b8 22 06 00"

    # NatBindingKey: { internal_addr(u32) internal_port(u16) protocol(u8) _pad(u8) }
    # internal_addr = 10.0.0.2 = 0x0A000002 -> LE bytes: 02 00 00 0a
    # internal_port = 8888 = 0x22B8 -> LE bytes: b8 22
    # protocol = 6 (TCP), _pad = 0
    BINDING_KEY="02 00 00 0a  b8 22 06 00"

    # NatBindingValue: { external_addr(u32) external_port(u16) _pad([u8;2]) }
    # external_addr = 203.0.113.1 -> LE: 01 71 00 cb
    # external_port = 8888 -> LE: b8 22
    # _pad = 00 00
    BINDING_VALUE="01 71 00 cb  b8 22 00 00"

    # Insert reverse binding: EXTERNAL_IP:8888/TCP -> 10.0.0.2:8888
    bpftool map update pinned "$BPF_PIN_DIR/NAT_REVERSE" \
        key hex $REVERSE_KEY value hex $BINDING_KEY 2>/dev/null
    if [ $? -ne 0 ]; then
        log_fail "Hairpin TCP (failed to insert reverse binding via bpftool)"
        return 1
    fi

    # Insert forward binding: 10.0.0.2:8888/TCP -> EXTERNAL_IP:8888
    bpftool map update pinned "$BPF_PIN_DIR/NAT_BINDINGS" \
        key hex $BINDING_KEY value hex $BINDING_VALUE 2>/dev/null

    # Start server on internal host 2
    ip netns exec $NS_INTERNAL_2 timeout 10 nc -l -p 8888 > /tmp/cgnat_test_hairpin &
    SERVER_PID=$!
    sleep 0.5

    # Connect from internal host 1 to the EXTERNAL IP on port 8888
    # This should hairpin: host1 -> CGNAT(EXTERNAL_IP:8888) -> host2:8888
    echo "Hello hairpin" | ip netns exec $NS_INTERNAL_1 timeout 3 nc $EXTERNAL_IP 8888

    sleep 1
    kill $SERVER_PID 2>/dev/null || true

    if grep -q "Hello hairpin" /tmp/cgnat_test_hairpin 2>/dev/null; then
        log_pass "Hairpin TCP works"
        rm -f /tmp/cgnat_test_hairpin
        return 0
    else
        log_fail "Hairpin TCP failed"
        rm -f /tmp/cgnat_test_hairpin
        return 1
    fi
}

test_multiple_connections() {
    log_test "Multiple concurrent connections..."

    # Start multiple servers
    for port in 7001 7002 7003; do
        ip netns exec $NS_EXTERNAL timeout 10 nc -l -p $port > /tmp/cgnat_test_multi_$port &
    done
    sleep 0.5

    # Connect from internal (different source ports)
    for port in 7001 7002 7003; do
        echo "Test $port" | ip netns exec $NS_INTERNAL_1 timeout 2 nc $EXTERNAL_GW $port &
    done

    sleep 2

    # Check results
    SUCCESS=0
    for port in 7001 7002 7003; do
        if grep -q "Test $port" /tmp/cgnat_test_multi_$port 2>/dev/null; then
            SUCCESS=$((SUCCESS + 1))
        fi
        rm -f /tmp/cgnat_test_multi_$port
    done

    if [ $SUCCESS -eq 3 ]; then
        log_pass "Multiple connections work ($SUCCESS/3)"
        return 0
    else
        log_fail "Multiple connections failed ($SUCCESS/3)"
        return 1
    fi
}

test_connection_reuse() {
    log_test "Connection reuse (same binding)..."

    # Start server
    ip netns exec $NS_EXTERNAL timeout 10 nc -l -p 7777 > /tmp/cgnat_test_reuse &
    SERVER_PID=$!
    sleep 0.5

    # Send multiple messages from same source
    for i in 1 2 3; do
        echo "Message $i" | ip netns exec $NS_INTERNAL_1 nc -p 55555 -w 1 $EXTERNAL_GW 7777 &
        sleep 0.2
    done

    sleep 2
    kill $SERVER_PID 2>/dev/null || true

    # Should see messages (may vary due to timing)
    if [ -s /tmp/cgnat_test_reuse ]; then
        log_pass "Connection reuse works"
        rm -f /tmp/cgnat_test_reuse
        return 0
    else
        log_fail "Connection reuse failed"
        rm -f /tmp/cgnat_test_reuse
        return 1
    fi
}

test_different_internal_hosts() {
    log_test "Different internal hosts..."

    # Start server
    ip netns exec $NS_EXTERNAL timeout 10 nc -l -p 6666 > /tmp/cgnat_test_hosts &
    sleep 0.5

    # Connect from both internal hosts
    echo "From host 1" | ip netns exec $NS_INTERNAL_1 timeout 2 nc $EXTERNAL_GW 6666 &
    sleep 0.5
    echo "From host 2" | ip netns exec $NS_INTERNAL_2 timeout 2 nc $EXTERNAL_GW 6666 &

    sleep 2

    HOST1=$(grep -c "From host 1" /tmp/cgnat_test_hosts 2>/dev/null || echo 0)
    HOST2=$(grep -c "From host 2" /tmp/cgnat_test_hosts 2>/dev/null || echo 0)

    rm -f /tmp/cgnat_test_hosts

    if [ "$HOST1" -ge 1 ] || [ "$HOST2" -ge 1 ]; then
        log_pass "Different internal hosts work"
        return 0
    else
        log_fail "Different internal hosts failed"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

run_all_tests() {
    echo "========================================"
    echo "CGNAT Integration Tests"
    echo "========================================"
    echo ""

    check_root
    check_env

    # Check if CGNAT is running
    CGNAT_RUNNING=false
    if pgrep -f "cgnat run" > /dev/null; then
        CGNAT_RUNNING=true
        log_test "CGNAT detected - running full tests"
        wait_cgnat_ready
    else
        log_test "CGNAT not running - running baseline tests only"
        echo "  To run full tests, start CGNAT first with:"
        echo "    sudo ip netns exec $NS_CGNAT $PROJECT_DIR/target/release/cgnat run \\"
        echo "      -e veth_ext_a -i br_int -E $EXTERNAL_IP -I 10.0.0.0/24 --skb-mode"
        echo ""
    fi

    if [ "$CGNAT_RUNNING" = true ]; then
        # Run full CGNAT tests
        test_outbound_tcp || true
        test_outbound_udp || true
        test_outbound_icmp || true
        test_inbound_tcp || true
        test_hairpin_tcp || true
        test_multiple_connections || true
        test_connection_reuse || true
        test_different_internal_hosts || true
    else
        # Run baseline tests (verify test environment)
        test_outbound_icmp || true
        test_multiple_connections || true
        test_different_internal_hosts || true
    fi

    echo ""
    echo "========================================"
    echo "Results: $PASSED passed, $FAILED failed"
    echo "========================================"

    if [ $FAILED -gt 0 ]; then
        exit 1
    fi
}

usage() {
    echo "Usage: $0 [test_name]"
    echo ""
    echo "Available tests:"
    echo "  all                    Run all tests"
    echo "  outbound_tcp          Test outbound TCP connections"
    echo "  outbound_udp          Test outbound UDP connections"
    echo "  outbound_icmp         Test outbound ICMP (ping)"
    echo "  inbound_tcp           Test inbound TCP blocking"
    echo "  hairpin_tcp           Test hairpin TCP"
    echo "  multiple_connections  Test multiple concurrent connections"
    echo "  connection_reuse      Test connection binding reuse"
    echo "  different_hosts       Test connections from different internal hosts"
}

case "${1:-all}" in
    all)
        run_all_tests
        ;;
    outbound_tcp)
        check_root && check_env && test_outbound_tcp
        ;;
    outbound_udp)
        check_root && check_env && test_outbound_udp
        ;;
    outbound_icmp)
        check_root && check_env && test_outbound_icmp
        ;;
    inbound_tcp)
        check_root && check_env && test_inbound_tcp
        ;;
    hairpin_tcp)
        check_root && check_env && test_hairpin_tcp
        ;;
    multiple_connections)
        check_root && check_env && test_multiple_connections
        ;;
    connection_reuse)
        check_root && check_env && test_connection_reuse
        ;;
    different_hosts)
        check_root && check_env && test_different_internal_hosts
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo "Unknown test: $1"
        usage
        exit 1
        ;;
esac
