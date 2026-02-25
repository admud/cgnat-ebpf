# cgnat-ebpf

A pure eBPF/XDP Carrier-Grade NAT (CGNAT) implementation with native hairpinning support.

## Motivation

Existing eBPF NAT implementations like [einat-ebpf](https://github.com/EHfive/einat-ebpf) have limitations:

- **Hairpinning requires kernel hacks** - Uses TC (Traffic Control) hooks which process packets after the kernel routing decision. When a packet is destined for a local IP, Linux routes it via the `local` table directly to localhost, bypassing the network interface entirely. The eBPF program never sees these packets.

- **Workarounds are fragile** - The current solution involves policy-based routing manipulation:
  ```bash
  # Reprioritize routing tables
  ip rule add pref 200 lookup local
  ip rule del pref 0 lookup local
  # Force packets out the external interface
  ip rule add from <internal_subnet> lookup <custom_table>
  ```
  Plus manual ARP entries. This is kernel-dependent and error-prone.

- **Not 100% eBPF** - Relies on kernel conntrack and routing subsystems.

## Goals

Build a CGNAT that is:

1. **100% eBPF/XDP** - Bypass the kernel networking stack entirely
2. **Native hairpinning** - Use `XDP_REDIRECT` to handle hairpin scenarios without routing hacks
3. **High performance** - XDP processes packets before the kernel, achieving 10M+ pps
4. **RFC compliant** - Follow NAT behavioral requirements

## Architecture

### Why XDP over TC

| Aspect | TC (Traffic Control) | XDP (eXpress Data Path) |
|--------|----------------------|-------------------------|
| Hook point | After routing decision | Before kernel sees packet |
| Hairpinning | Requires routing hacks | `XDP_REDIRECT` to any interface |
| Performance | ~2M pps | ~10M+ pps |
| Kernel bypass | Partial | Complete |

### Hairpinning with XDP_REDIRECT

When Client A (10.0.0.1) wants to reach Client B (10.0.0.2) via the public IP (203.0.113.1:port):

```
┌─────────────────────────────────────────────────────────────────┐
│                        XDP Program                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Packet arrives: src=10.0.0.1 dst=203.0.113.1:port           │
│  2. Lookup: 203.0.113.1:port maps to internal 10.0.0.2:8080     │
│  3. Rewrite: src=203.0.113.1 dst=10.0.0.2:8080                  │
│  4. XDP_REDIRECT → internal interface RX queue                   │
│                                                                  │
│  Kernel routing stack: NEVER INVOLVED                            │
└─────────────────────────────────────────────────────────────────┘
```

### Connection Tracking

Implement stateful connection tracking entirely in eBPF maps:

```
┌────────────────────┐     ┌────────────────────┐
│   NAT Binding Map  │     │  Connection Table  │
├────────────────────┤     ├────────────────────┤
│ internal_ip:port   │────▶│ state (NEW/EST/FIN)│
│ external_ip:port   │     │ timeout            │
│ protocol           │     │ packet/byte counts │
└────────────────────┘     └────────────────────┘
```

## RFC Compliance

### Primary References

- **[RFC 5508](https://datatracker.ietf.org/doc/html/rfc5508)** - NAT Behavioral Requirements for ICMP
  - ICMP Query session handling
  - ICMP Error forwarding with embedded payload translation
  - Hairpinning requirements for ICMP

- **[RFC 7857](https://datatracker.ietf.org/doc/html/rfc7857)** - Updates to NAT Behavioral Requirements
  - Endpoint-Independent Mapping (EIM)
  - Endpoint-Independent Filtering (EIF)
  - Address pooling requirements
  - Port allocation recommendations

### Additional RFCs

- **[RFC 4787](https://datatracker.ietf.org/doc/html/rfc4787)** - NAT Behavioral Requirements for UDP
- **[RFC 5382](https://datatracker.ietf.org/doc/html/rfc5382)** - NAT Behavioral Requirements for TCP
- **[RFC 6146](https://datatracker.ietf.org/doc/html/rfc6146)** - Stateful NAT64 (future consideration)
- **[RFC 6888](https://datatracker.ietf.org/doc/html/rfc6888)** - Common Requirements for CGNAT

## Implementation Plan

### Phase 1: Core NAT
- [ ] XDP program skeleton with interface attachment
- [ ] Basic packet parsing (Ethernet, IP, TCP/UDP)
- [ ] NAT binding map structure
- [ ] Outbound SNAT (source NAT)
- [ ] Inbound DNAT (destination NAT)

### Phase 2: Hairpinning
- [ ] Detect hairpin scenarios (dst matches external IP)
- [ ] Implement `XDP_REDIRECT` for hairpin packets
- [ ] Handle both directions of hairpin flows

### Phase 3: Connection Tracking
- [ ] Stateful connection table in eBPF maps
- [ ] TCP state machine tracking
- [ ] UDP timeout handling
- [ ] ICMP session tracking

### Phase 4: ICMP Support (RFC 5508)
- [ ] ICMP Query mapping
- [ ] ICMP Error translation (rewrite embedded headers)
- [ ] ICMP hairpinning

### Phase 5: Compliance & Hardening
- [ ] Port allocation per RFC 7857
- [ ] Endpoint-Independent Mapping/Filtering modes
- [ ] Logging and metrics export
- [ ] Configuration interface

## Project Structure

```
cgnat-ebpf/
├── cgnat-common/     # Shared types between userspace and eBPF
├── cgnat-ebpf/       # XDP eBPF program (compiled to BPF bytecode)
├── cgnat/            # Userspace loader and CLI
├── Makefile          # Build automation
└── README.md
```

## Development

### Prerequisites

- Linux kernel 5.15+ (for BPF features)
- Rust nightly toolchain
- bpf-linker
- clang/llvm (for BPF compilation)

### Setup

```bash
# Install Rust nightly and dependencies
make deps

# Or manually:
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

### Building

```bash
# Build everything (eBPF + userspace)
make build

# Debug build
make debug

# Build only eBPF program
make build-ebpf

# Build only userspace
make build-user
```

### Running

```bash
# Run with sudo (XDP requires CAP_NET_ADMIN)
sudo ./target/release/cgnat \
    -e eth0 \              # External interface
    -i eth1 \              # Internal interface
    -E 203.0.113.1 \       # External (public) IP
    -I 10.0.0.0/8          # Internal subnet

# Or use make
make run ARGS="-e eth0 -i eth1 -E 203.0.113.1 -I 10.0.0.0/8"
```

### Testing

```bash
# TODO: Network namespace based tests
# Will create isolated test environments with veth pairs
```

## References

- [einat-ebpf](https://github.com/EHfive/einat-ebpf) - Reference implementation (limitations documented above)
- [einat-ebpf Issue #4](https://github.com/EHfive/einat-ebpf/issues/4) - Hairpinning routing problem
- [Aya](https://aya-rs.dev/) - Rust eBPF framework
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - Learning XDP

## License

MIT OR Apache-2.0
