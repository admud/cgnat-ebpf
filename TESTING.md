# CGNAT Testing Guide

This document describes how to test the CGNAT implementation using network namespaces.

## Prerequisites

- Linux kernel 5.15+
- Root access (sudo)
- Built CGNAT binary (`make build`)
- Basic networking tools (ip, nc, ping)

## Test Environment Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  ns_internal_1  │     │    ns_cgnat     │     │   ns_external   │
│                 │     │                 │     │                 │
│   10.0.0.1/24  ├─────┤ 10.0.0.254/24  │     │                 │
│   (client 1)    │     │  (br_int)       │     │                 │
└─────────────────┘     │                 │     │                 │
                        │ 203.0.113.1/24 ├─────┤ 203.0.113.254/24│
┌─────────────────┐     │  (veth_ext_a)   │     │  (internet)     │
│  ns_internal_2  │     │                 │     │                 │
│                 │     │   [CGNAT XDP    │     │                 │
│   10.0.0.2/24  ├─────┤    Program]     │     │                 │
│   (client 2)    │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Quick Start

### 1. Build the Project

```bash
make build
```

### 2. Set Up Test Environment

```bash
sudo ./tests/setup_test_env.sh setup
```

This creates:
- 4 network namespaces (ns_cgnat, ns_internal_1, ns_internal_2, ns_external)
- Virtual ethernet pairs connecting them
- Proper IP addressing and routing

### 3. Run CGNAT

In terminal 1:
```bash
make test-run
```

Or manually:
```bash
sudo ip netns exec ns_cgnat ./target/release/cgnat run \
    -e veth_ext_a -i br_int -E 203.0.113.1 -I 10.0.0.0/24 --skb-mode
```

### 4. Run Tests

In terminal 2:
```bash
make test-integration
```

Or run individual tests:
```bash
sudo ./tests/run_tests.sh outbound_icmp
sudo ./tests/run_tests.sh outbound_tcp
sudo ./tests/run_tests.sh multiple_connections
```

### 5. Clean Up

```bash
make test-cleanup
```

## Manual Testing

### Test Outbound Connectivity

From internal namespace to external:

```bash
# ICMP
sudo ip netns exec ns_internal_1 ping 203.0.113.254

# TCP
sudo ip netns exec ns_external nc -l -p 8080 &
sudo ip netns exec ns_internal_1 nc 203.0.113.254 8080

# UDP
sudo ip netns exec ns_external nc -u -l -p 9000 &
sudo ip netns exec ns_internal_1 nc -u 203.0.113.254 9000
```

### Monitor CGNAT Statistics

The CGNAT daemon prints statistics every 5 seconds by default:

```
=== CGNAT Statistics ===
Packets: 150 total (30 pps), 12000 bytes (19200 bps)
NAT: 145 hits, 5 misses (96.7% hit rate)
Direction: 80 outbound, 65 inbound, 5 hairpin
ICMP: 20, Dropped: 0
Ports: 5 allocated, 5 success, 0 failures
```

### Test Hairpinning

Hairpinning allows internal hosts to reach other internal hosts via the external IP:

```bash
# Start server on internal host 2
sudo ip netns exec ns_internal_2 nc -l -p 8888 &

# Connect from internal host 1 via external IP
# (requires port forwarding to be set up)
sudo ip netns exec ns_internal_1 nc 203.0.113.1 8888
```

## Troubleshooting

### CGNAT fails to attach XDP

If you see "Driver mode failed", try SKB mode:
```bash
./target/release/cgnat run ... --skb-mode
```

### No connectivity

1. Verify test environment:
   ```bash
   sudo ./tests/setup_test_env.sh verify
   ```

2. Check interfaces exist:
   ```bash
   sudo ./tests/setup_test_env.sh status
   ```

3. Check CGNAT is running:
   ```bash
   pgrep -a cgnat
   ```

### Debug with tcpdump

Capture traffic in namespaces:
```bash
# External interface
sudo ip netns exec ns_cgnat tcpdump -i veth_ext_a -n

# Internal interface
sudo ip netns exec ns_cgnat tcpdump -i br_int -n
```

## Test Cases

| Test | Description | Expected Result |
|------|-------------|-----------------|
| outbound_icmp | Ping from internal to external | Success |
| outbound_tcp | TCP connection from internal to external | Success |
| outbound_udp | UDP from internal to external | Success |
| inbound_tcp | TCP to external IP without forwarding | Blocked |
| hairpin_tcp | Internal to internal via external IP | Success (with forwarding) |
| multiple_connections | Concurrent connections | All succeed |
| connection_reuse | Same binding for same src:port | Binding reused |
| different_hosts | Connections from multiple internal hosts | Each gets unique binding |

## Performance Testing

For performance testing, use `iperf3`:

```bash
# Server in external namespace
sudo ip netns exec ns_external iperf3 -s

# Client in internal namespace
sudo ip netns exec ns_internal_1 iperf3 -c 203.0.113.254
```

Compare with and without CGNAT to measure overhead.
