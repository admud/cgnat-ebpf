#!/bin/bash
# CGNAT Test Environment Setup
#
# Creates network namespaces and veth pairs for testing:
#
#   ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
#   │  ns_internal_1  │     │    ns_cgnat     │     │   ns_external   │
#   │                 │     │                 │     │                 │
#   │   10.0.0.1/24  ├─────┤ 10.0.0.254/24  │     │                 │
#   │   (veth_int1)   │     │  (veth_int)     │     │                 │
#   └─────────────────┘     │                 │     │                 │
#                           │ 203.0.113.1/24 ├─────┤ 203.0.113.254/24│
#   ┌─────────────────┐     │  (veth_ext)     │     │  (veth_wan)     │
#   │  ns_internal_2  │     │                 │     │                 │
#   │                 │     │                 │     │  Web server:    │
#   │   10.0.0.2/24  ├─────┤                 │     │  :8080          │
#   │   (veth_int2)   │     └─────────────────┘     └─────────────────┘
#   └─────────────────┘

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
NS_CGNAT="ns_cgnat"
NS_INTERNAL_1="ns_internal_1"
NS_INTERNAL_2="ns_internal_2"
NS_EXTERNAL="ns_external"

INTERNAL_SUBNET="10.0.0.0/24"
INTERNAL_GW="10.0.0.254"
EXTERNAL_IP="203.0.113.1"
EXTERNAL_SUBNET="203.0.113.0/24"
EXTERNAL_GW="203.0.113.254"

cleanup() {
    log_info "Cleaning up test environment..."

    # Delete namespaces (this also removes veth pairs)
    for ns in $NS_CGNAT $NS_INTERNAL_1 $NS_INTERNAL_2 $NS_EXTERNAL; do
        ip netns del $ns 2>/dev/null || true
    done

    # Delete any lingering veth pairs
    ip link del veth_cgnat_int 2>/dev/null || true
    ip link del veth_cgnat_ext 2>/dev/null || true
    ip link del veth_int1 2>/dev/null || true
    ip link del veth_int2 2>/dev/null || true

    log_info "Cleanup complete"
}

setup() {
    log_info "Setting up test environment..."

    # Create namespaces
    log_info "Creating network namespaces..."
    ip netns add $NS_CGNAT
    ip netns add $NS_INTERNAL_1
    ip netns add $NS_INTERNAL_2
    ip netns add $NS_EXTERNAL

    # Create bridge in CGNAT namespace for internal network
    log_info "Creating internal bridge..."
    ip netns exec $NS_CGNAT ip link add br_int type bridge
    ip netns exec $NS_CGNAT ip link set br_int up
    ip netns exec $NS_CGNAT ip addr add $INTERNAL_GW/24 dev br_int

    # Create veth pair for internal client 1
    log_info "Creating veth pairs for internal clients..."
    ip link add veth_int1_a type veth peer name veth_int1_b
    ip link set veth_int1_a netns $NS_INTERNAL_1
    ip link set veth_int1_b netns $NS_CGNAT

    ip netns exec $NS_INTERNAL_1 ip link set veth_int1_a up
    ip netns exec $NS_INTERNAL_1 ip addr add 10.0.0.1/24 dev veth_int1_a
    ip netns exec $NS_INTERNAL_1 ip route add default via $INTERNAL_GW

    ip netns exec $NS_CGNAT ip link set veth_int1_b master br_int
    ip netns exec $NS_CGNAT ip link set veth_int1_b up

    # Create veth pair for internal client 2
    ip link add veth_int2_a type veth peer name veth_int2_b
    ip link set veth_int2_a netns $NS_INTERNAL_2
    ip link set veth_int2_b netns $NS_CGNAT

    ip netns exec $NS_INTERNAL_2 ip link set veth_int2_a up
    ip netns exec $NS_INTERNAL_2 ip addr add 10.0.0.2/24 dev veth_int2_a
    ip netns exec $NS_INTERNAL_2 ip route add default via $INTERNAL_GW

    ip netns exec $NS_CGNAT ip link set veth_int2_b master br_int
    ip netns exec $NS_CGNAT ip link set veth_int2_b up

    # Create veth pair for external network
    log_info "Creating external network..."
    ip link add veth_ext_a type veth peer name veth_ext_b
    ip link set veth_ext_a netns $NS_CGNAT
    ip link set veth_ext_b netns $NS_EXTERNAL

    ip netns exec $NS_CGNAT ip link set veth_ext_a up
    ip netns exec $NS_CGNAT ip addr add $EXTERNAL_IP/24 dev veth_ext_a

    ip netns exec $NS_EXTERNAL ip link set veth_ext_b up
    ip netns exec $NS_EXTERNAL ip addr add $EXTERNAL_GW/24 dev veth_ext_b
    ip netns exec $NS_EXTERNAL ip route add $INTERNAL_SUBNET via $EXTERNAL_IP

    # Enable IP forwarding in CGNAT namespace (for testing without XDP)
    ip netns exec $NS_CGNAT sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Bring up loopback in all namespaces
    for ns in $NS_CGNAT $NS_INTERNAL_1 $NS_INTERNAL_2 $NS_EXTERNAL; do
        ip netns exec $ns ip link set lo up
    done

    log_info "Test environment setup complete!"
    log_info ""
    log_info "Namespace layout:"
    log_info "  $NS_INTERNAL_1: 10.0.0.1/24 (client 1)"
    log_info "  $NS_INTERNAL_2: 10.0.0.2/24 (client 2)"
    log_info "  $NS_CGNAT: internal=br_int($INTERNAL_GW), external=veth_ext_a($EXTERNAL_IP)"
    log_info "  $NS_EXTERNAL: $EXTERNAL_GW/24 (simulated internet)"
    log_info ""
    log_info "To run CGNAT in the test environment:"
    log_info "  sudo ip netns exec $NS_CGNAT ./target/release/cgnat run \\"
    log_info "    -e veth_ext_a -i br_int -E $EXTERNAL_IP -I $INTERNAL_SUBNET"
}

verify() {
    log_info "Verifying test environment..."

    # Check namespaces exist
    for ns in $NS_CGNAT $NS_INTERNAL_1 $NS_INTERNAL_2 $NS_EXTERNAL; do
        if ! ip netns list | grep -q $ns; then
            log_error "Namespace $ns not found"
            return 1
        fi
    done

    # Test basic connectivity (without NAT)
    log_info "Testing internal connectivity..."
    if ip netns exec $NS_INTERNAL_1 ping -c 1 -W 1 $INTERNAL_GW > /dev/null 2>&1; then
        log_info "  ✓ Internal 1 -> CGNAT gateway"
    else
        log_error "  ✗ Internal 1 -> CGNAT gateway failed"
    fi

    if ip netns exec $NS_INTERNAL_2 ping -c 1 -W 1 $INTERNAL_GW > /dev/null 2>&1; then
        log_info "  ✓ Internal 2 -> CGNAT gateway"
    else
        log_error "  ✗ Internal 2 -> CGNAT gateway failed"
    fi

    log_info "Testing external connectivity..."
    if ip netns exec $NS_CGNAT ping -c 1 -W 1 $EXTERNAL_GW > /dev/null 2>&1; then
        log_info "  ✓ CGNAT -> External"
    else
        log_error "  ✗ CGNAT -> External failed"
    fi

    log_info "Verification complete"
}

start_test_server() {
    log_info "Starting test HTTP server in external namespace..."
    ip netns exec $NS_EXTERNAL python3 -m http.server 8080 --bind $EXTERNAL_GW &
    echo $! > /tmp/cgnat_test_server.pid
    log_info "Server started on $EXTERNAL_GW:8080 (PID: $(cat /tmp/cgnat_test_server.pid))"
}

stop_test_server() {
    if [ -f /tmp/cgnat_test_server.pid ]; then
        kill $(cat /tmp/cgnat_test_server.pid) 2>/dev/null || true
        rm /tmp/cgnat_test_server.pid
        log_info "Test server stopped"
    fi
}

show_status() {
    log_info "Current network namespace status:"
    echo ""
    for ns in $NS_CGNAT $NS_INTERNAL_1 $NS_INTERNAL_2 $NS_EXTERNAL; do
        if ip netns list | grep -q $ns; then
            echo "=== $ns ==="
            ip netns exec $ns ip addr show 2>/dev/null | grep -E "inet |link/"
            echo ""
        fi
    done
}

usage() {
    echo "Usage: $0 {setup|cleanup|verify|status|server-start|server-stop}"
    echo ""
    echo "Commands:"
    echo "  setup         Create test network namespaces and veth pairs"
    echo "  cleanup       Remove all test namespaces and interfaces"
    echo "  verify        Test basic connectivity in the test environment"
    echo "  status        Show current namespace and interface status"
    echo "  server-start  Start HTTP test server in external namespace"
    echo "  server-stop   Stop HTTP test server"
}

# Main
case "${1:-}" in
    setup)
        cleanup
        setup
        verify
        ;;
    cleanup)
        stop_test_server
        cleanup
        ;;
    verify)
        verify
        ;;
    status)
        show_status
        ;;
    server-start)
        start_test_server
        ;;
    server-stop)
        stop_test_server
        ;;
    *)
        usage
        exit 1
        ;;
esac
