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

### Latest Benchmark Summary (February 28, 2026)

`tests/bench_compare.sh` was run in `cgnat`, `iptables`, and `nftables` modes on the namespace/veth testbed
with `--skb-mode` and offloads disabled (`BENCH_DISABLE_OFFLOADS=1`).

3-run mean results:

| Mode | TCP Throughput (Mbps) | UDP Throughput (Mbps) | TCP Connect Rate (cps) |
|------|------------------------|------------------------|-------------------------|
| cgnat | 2980.9 | 1229.5 | 12162.3 |
| iptables | 2762.9 | 1140.4 | 10710.3 |
| nftables | 2774.6 | 1141.2 | 12574.3 |

Observed delta (mean):
- cgnat TCP throughput vs iptables: `+7.9%`
- cgnat TCP throughput vs nftables: `+7.4%`
- cgnat UDP throughput vs iptables/nftables: `+~7.8%`

Notes:
- These numbers are useful for regression tracking and MVP signal.
- This environment is generic XDP (`skb`) on a virtualized setup, not native driver XDP on physical NICs.
- Do not present these as production line-rate claims until validated on target hardware.

Reproduce:
```bash
sudo env PING_COUNT=20 TCP_DURATION=5 UDP_DURATION=5 CONNECT_ATTEMPTS=300 \
  BENCH_DISABLE_OFFLOADS=1 ./tests/bench_compare.sh --modes cgnat,iptables,nftables
```

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

## Market Context & Fundraising Readiness

### The Opportunity

IPv4 exhaustion is complete — all five Regional Internet Registries have depleted their free pools. Over 17% of eyeball ASes and 90%+ of cellular ASes now rely on CGNAT ([Cloudflare 2024 research](https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/)). There are ~16,870 ISPs worldwide, and CGNAT is a must-have, not a nice-to-have.

**Cost arbitrage drives adoption:**

| Approach | Cost per 10K subscribers |
|----------|--------------------------|
| Buy IPv4 addresses ($15–52/IP) | ~$250,000 |
| Hardware CGNAT (A10 Thunder) | $63,000–$445,000 |
| Software CGNAT on commodity x86 | ~$10,000–$25,000 |

Software-defined CGNAT on commodity hardware represents a **10–25x cost reduction** vs. dedicated appliances.

### eBPF/XDP is Investor-Validated

| Company | Technology | Outcome |
|---------|-----------|---------|
| Isovalent (Cilium) | eBPF/XDP | Acquired by Cisco for ~$650M (32x ARR), raised $69M total |
| Tigera (Calico) | eBPF dataplane | $43M raised, 8M+ nodes/day |
| NFWare | VPP/DPDK vCGNAT | $3.9M raised, 100+ ISP customers |
| Groundcover | eBPF observability | $60M raised through Series B |

NFWare is the closest comp — they validated the software CGNAT market with $3.9M in funding and bootstrapped to 100+ ISP customers. Their approach uses VPP/DPDK (kernel bypass). Our eBPF/XDP approach stays in-kernel, which is architecturally simpler and aligns with the direction Cilium proved at scale.

### Current PoC Status

**What works (strong for seed stage):**
- Full SNAT/DNAT/hairpin via pure XDP — no kernel routing hacks
- Stateful TCP/UDP/ICMP connection tracking in eBPF maps
- A/B benchmark suite proving parity or better vs. iptables/nftables on equal footing
- RFC 5508 (ICMP), RFC 1624 (checksums) compliance

**What's needed before raising:**
1. **Bare-metal benchmarks on real NICs** (ConnectX-5 or E810) — the veth/SKB numbers (3 Gbps) are valid for regression testing but don't show XDP's true capability. On real hardware, expect 10–40 Gbps/server (matching a $63K appliance on a $5K server).
2. **One ISP design partner or LOI** — every funded company in this space had a named customer at seed (NFWare had Telefonica, RtBrick had Deutsche Telekom, DriveNets had AT&T).

**What can wait (build with funding):**
- Multi-IP pools, Port Block Allocation, RFC 6888 logging, HA/failover
- These are expected gaps at seed stage

### Performance on Real Hardware (Projected)

The veth/SKB benchmark environment uses generic XDP — the slowest execution mode. On real hardware with native XDP:

| Config | Throughput | Source |
|--------|-----------|--------|
| This PoC (veth/SKB mode) | 3 Gbps | Measured |
| XDP native, single core, ConnectX-5 | 8–10 Mpps (~30–40 Gbps) | [CoNEXT 2018 XDP paper](https://dl.acm.org/doi/10.1145/3281411.3281443) |
| XDP redirect, multi-core | 80–100+ Mpps | [Mellanox mlx5 benchmarks](https://patchwork.ozlabs.org/patch/1017382/) |
| NFWare vCGNAT (VPP, x86) | 231 Gbps | [Intel builder report](https://builders.intel.com/docs/networkbuilders/nfware-provides-high-performance-virtual-carrier-grade-nat.pdf) |

XDP achieves ~80% of DPDK throughput while staying fully in-kernel — no dedicated cores, no kernel bypass, simpler operations model.

### Target Raise

Based on comps: **$2M–$4M pre-seed/seed** with bare-metal validation and one ISP pilot. Capital-efficient path modeled on NFWare ($3.9M total → 100+ customers).

## Next Steps: Bare-Metal Benchmarking

The veth/SKB benchmarks prove correctness and relative advantage. To generate investor-ready numbers (10–40 Gbps), we need native XDP on real NICs.

### Hardware Options

**Cloud (cheapest, fastest to set up):**
- **Hetzner dedicated** (~€40–60/month) — Intel X710 (i40e driver), full native XDP. Best value.
- **AWS c5n.xlarge** (~$0.50–1.00/hr) — ENA driver supports XDP native mode. Two instances in same placement group.
- **GCP c2-standard-8** — gVNIC supports XDP.

**Bare metal (best numbers):**
- Any machine with two physical NICs that support XDP native mode
- Supported NICs: Intel i40e (X710), Intel ice (E810), Mellanox mlx5 (ConnectX-5/6)

### Test Topology

```
Machine A (traffic gen)          Machine B (CGNAT)                Machine C (server)
  10.0.0.1/24                      10.0.0.254 (internal)
  iperf3 client  ──── NIC ──────── NIC1          NIC2 ──── NIC ──  203.0.113.254
                                   203.0.113.1 (external)            iperf3 server
```

Or two machines with Machine B having two NICs (internal + external).

### Run

```bash
# Native mode (no --skb-mode flag)
sudo ./target/release/cgnat run \
    -e eth1 -i eth0 -E 203.0.113.1 -I 10.0.0.0/24
```

### Target Numbers

| Metric | Target | Would prove |
|--------|--------|-------------|
| TCP throughput (single core) | 10+ Gbps | Matches $63K A10 appliance |
| TCP throughput (multi-core) | 30–40 Gbps | Matches $200K+ appliance |
| Packets per second | 5+ Mpps | XDP advantage over iptables |
| Retransmits | ~0 | No packet corruption |

These numbers on a $5K server vs. a $63K appliance is the pitch slide.

## Future Work

- [ ] Bare-metal benchmark on native XDP with real NICs
- [ ] Binding expiration and cleanup (userspace timer + eBPF map iteration)
- [ ] Multiple external IP address pool support
- [ ] Port Block Allocation (PBA) per RFC 7422 to reduce logging
- [ ] Logging infrastructure for compliance (RFC 6888)
- [ ] Endpoint-Independent Mapping/Filtering mode configuration
- [x] Performance benchmarking suite (`tests/bench_compare.sh`)
- [ ] HA/failover with state synchronization
