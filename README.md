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

## Implementation Status

### Phase 1: Core NAT ✅
- [x] XDP program skeleton with interface attachment
- [x] Basic packet parsing (Ethernet, IP, TCP/UDP)
- [x] NAT binding map structure
- [x] Outbound SNAT (source NAT)
- [x] Inbound DNAT (destination NAT)

### Phase 2: Hairpinning ✅
- [x] Detect hairpin scenarios (dst matches external IP)
- [x] Implement `XDP_REDIRECT` for hairpin packets
- [x] Handle both directions of hairpin flows

### Phase 3: Connection Tracking ✅
- [x] Stateful connection table in eBPF maps
- [x] TCP state machine tracking (SYN, ESTABLISHED, FIN, etc.)
- [x] UDP timeout handling
- [x] ICMP session tracking

### Phase 4: ICMP Support (RFC 5508) ✅
- [x] ICMP Query mapping (echo request/reply)
- [x] ICMP Error translation (rewrite embedded headers)
- [x] ICMP hairpinning

### Phase 5: Compliance & Hardening ✅
- [x] Port allocation in eBPF with atomic counter
- [x] Per-CPU statistics collection
- [x] Incremental checksum updates (RFC 1624)
- [ ] Endpoint-Independent Mapping/Filtering modes (future)
- [ ] Binding expiration/cleanup (future)

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

---

## Research & Discussion Notes

### Existing eBPF/XDP NAT Implementations

| Project | Organization | Scale | Notes |
|---------|--------------|-------|-------|
| [Katran](https://github.com/facebookincubator/katran) | Meta/Facebook | Millions of connections | L4 load balancer with XDP, handles Facebook's traffic |
| [Cilium](https://github.com/cilium/cilium) | Isovalent/Cisco | Kubernetes clusters | Full NAT in eBPF, replaces kube-proxy + iptables |
| [einat-ebpf](https://github.com/EHfive/einat-ebpf) | Open source | Home/small ISP | Full Cone NAT, but has hairpinning limitations (uses TC hooks) |
| [eBPF BNG](https://markgascoyne.co.uk/posts/ebpf-bng/) | Open source | ISP edge (OLT) | Includes NAT44/CGNAT module, proposed as future of ISP edge |

### What ISPs Use Today

Most production CGNAT deployments use:
- **Dedicated appliances**: A10, F5, Juniper ($50K-$500K)
- **DPDK-based solutions**: VPP, custom implementations (100+ Gbps)
- **Kernel netfilter**: iptables/nftables with conntrack (simplest but slowest)

### Performance Comparison

| Approach | Packets/sec (per core) | Latency | Source |
|----------|------------------------|---------|--------|
| iptables/nftables | ~1-2M pps | ~10-50μs | Industry benchmarks |
| **XDP** | **10-26M pps** | **<1μs** | [Cloudflare](https://blog.cloudflare.com/how-to-drop-10-million-packets/) |
| DPDK | 20-40M pps | <1μs | Various |
| Hardware appliance | Line rate | <1μs | Vendor specs |

### Why XDP is Faster

```
Traditional iptables path:
  NIC → Driver → sk_buff allocation → netfilter hooks → conntrack → NAT → routing → output

XDP path:
  NIC → Driver → XDP program (NAT here) → redirect/TX
              ↑
              No sk_buff, no conntrack, no routing stack
```

From [Cilium's documentation](https://docs.cilium.io/en/latest/reference-guides/bpf/index.html):
> XDP hooks into a very early ingress path at the driver layer, where it operates with direct access to the packet's DMA buffer. This is effectively as low-level as it can get.

### Cost Comparison

| Solution | Cost | Throughput |
|----------|------|------------|
| A10 Thunder CGN | $100K-$500K | 100 Gbps |
| Juniper MX CGNAT | $50K-$200K | 40 Gbps |
| **Commodity server + XDP** | **$5K-$15K** | **40-100 Gbps** |

### Our Implementation vs Production Requirements

| Feature | This Project | Production-Ready |
|---------|--------------|------------------|
| Basic SNAT/DNAT | ✅ | ✅ |
| Hairpinning (XDP_REDIRECT) | ✅ | ✅ |
| Port allocation (eBPF atomic) | ✅ | ✅ |
| Checksums (RFC 1624) | ✅ | ✅ |
| ICMP translation (RFC 5508) | ✅ | ✅ |
| Connection tracking | ✅ (basic) | Needs timeout/cleanup |
| Logging (RFC 6888) | ❌ | Required for ISPs |
| Port Block Allocation | ❌ | Reduces logging overhead |
| Multiple external IPs | ❌ | Required at scale |
| ALGs (FTP, SIP) | ❌ | Sometimes needed |
| HA/Failover | ❌ | Critical for production |

### Why Isn't Everyone Using eBPF/XDP for CGNAT?

1. **Maturity**: DPDK and hardware appliances have 10+ years of production hardening
2. **Features**: Full RFC compliance (logging, port block allocation, ALGs) is complex
3. **Expertise**: eBPF development requires specialized skills
4. **Support**: Vendors provide 24/7 support; open source doesn't

### The Industry Trend

From the [eBPF BNG article](https://markgascoyne.co.uk/posts/ebpf-bng/):
> For edge deployment (10-40 Gbps per OLT), eBPF/XDP is simpler and sufficient... This is the future of ISP edge infrastructure.

The industry is moving toward eBPF/XDP for:
- **Edge/access networks**: Where cost matters more than peak performance
- **Cloud-native**: Kubernetes, containers (Cilium dominates here)
- **DDoS mitigation**: XDP's speed is unmatched for packet filtering

### Key Research Sources

- [Cloudflare - How to drop 10 million packets per second](https://blog.cloudflare.com/how-to-drop-10-million-packets/)
- [Cilium BPF/XDP Reference Guide](https://docs.cilium.io/en/latest/reference-guides/bpf/index.html)
- [einat-ebpf - eBPF Full Cone NAT](https://github.com/EHfive/einat-ebpf)
- [eBPF BNG - Killing the ISP Appliance](https://markgascoyne.co.uk/posts/ebpf-bng/)
- [iptables vs eBPF - Why Kubernetes is Moving On](https://medium.com/@sahilsheikh6897/iptables-vs-ebpf-why-kubernetes-networking-is-moving-on-769487bf1ee7)
- [Tigera - eBPF: When and When Not to Use It](https://www.tigera.io/blog/ebpf-when-and-when-not-to-use-it/)

---

## Future Work

- [ ] Binding expiration and cleanup (userspace timer + eBPF map iteration)
- [ ] Multiple external IP address pool support
- [ ] Port Block Allocation (PBA) per RFC 7422 to reduce logging
- [ ] Logging infrastructure for compliance (RFC 6888)
- [ ] Endpoint-Independent Mapping/Filtering mode configuration
- [ ] Performance benchmarking suite
- [ ] HA/failover with state synchronization
