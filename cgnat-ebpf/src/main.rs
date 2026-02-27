//! CGNAT XDP eBPF Program
//!
//! This is the core packet processing logic that runs in the kernel.
//! It handles:
//! - Outbound SNAT (internal -> external)
//! - Inbound DNAT (external -> internal)
//! - Hairpinning via XDP_REDIRECT
//! - ICMP handling per RFC 5508
//! - Connection state tracking

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_FIB_LOOKUP_OUTPUT},
    helpers::{bpf_fib_lookup, bpf_ktime_get_ns},
    macros::{map, xdp},
    maps::{Array, DevMap, HashMap, PerCpuArray},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::debug;
use cgnat_common::{
    ConnState, NatBindingKey, NatBindingValue, NatConfig, NatReverseKey, NatStats, PortAllocState,
    TcpState,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ============================================================================
// BPF Maps
// ============================================================================

/// NAT binding table: internal addr:port -> external addr:port
#[map]
static NAT_BINDINGS: HashMap<NatBindingKey, NatBindingValue> =
    HashMap::with_max_entries(1 << 20, 0); // 1M entries

/// Reverse NAT table: external addr:port -> internal addr:port
#[map]
static NAT_REVERSE: HashMap<NatReverseKey, NatBindingKey> = HashMap::with_max_entries(1 << 20, 0);

/// Connection state tracking
#[map]
static CONN_TRACK: HashMap<NatBindingKey, ConnState> = HashMap::with_max_entries(1 << 20, 0);

/// Port allocation state (single entry).
///
/// Uses `read_volatile`/`write_volatile` instead of true atomics because:
/// - `next_port`: collisions from concurrent CPUs are benign — the retry
///   loop in `allocate_binding` handles duplicates via BPF_NOEXIST.
/// - `allocated_count`: approximate is fine for stats display; userspace GC
///   periodically resets it to the true count.
/// - `alloc_failures`/`alloc_success`: monotonic counters where a lost
///   increment is acceptable for diagnostics.
#[map]
static PORT_ALLOC: Array<PortAllocState> = Array::with_max_entries(1, 0);

/// Configuration (single entry)
#[map]
static CONFIG: Array<NatConfig> = Array::with_max_entries(1, 0);

/// Device map for XDP_REDIRECT
/// Size increased to 4096 to support high interface indices
#[map]
static DEVMAP: DevMap = DevMap::with_max_entries(4096, 0);

/// Per-CPU statistics
#[map]
static STATS: PerCpuArray<NatStats> = PerCpuArray::with_max_entries(1, 0);

// ============================================================================
// Constants
// ============================================================================

/// Maximum port allocation attempts before giving up
const MAX_PORT_ALLOC_ATTEMPTS: u32 = 64;

/// BPF map insert flags
const BPF_NOEXIST: u64 = 1; // Only insert if key doesn't exist (atomic)

/// BPF FIB lookup return codes
const BPF_FIB_LKUP_RET_SUCCESS: i64 = 0;

/// Address family for FIB lookup
const AF_INET: u8 = 2;

/// ICMP types
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;

/// TCP flags
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// ============================================================================
// Entry Point
// ============================================================================

#[xdp]
pub fn cgnat_xdp(ctx: XdpContext) -> u32 {
    match try_cgnat_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS, // On error, let kernel handle it
    }
}

#[inline(always)]
fn try_cgnat_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let config = CONFIG.get(0).ok_or(())?;

    // Update stats
    update_stats(|s| s.packets_total += 1);

    // Parse Ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // Only process IPv4
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse IPv4 header
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };
    let total_len = u16::from_be(unsafe { (*ipv4hdr).tot_len }) as usize;

    // Track bytes
    update_stats(|s| s.bytes_total += total_len as u64);

    // Determine packet direction and action
    let is_from_internal = is_internal_addr(src_addr, config);
    let is_to_external = dst_addr == config.external_addr;

    match (is_from_internal, is_to_external) {
        // Outbound: internal -> external (SNAT needed)
        (true, false) => {
            update_stats(|s| s.packets_outbound += 1);
            handle_outbound(&ctx, ipv4hdr, protocol, config)
        }

        // Hairpin: internal -> external_addr (redirect back to internal)
        (true, true) => {
            update_stats(|s| s.packets_hairpin += 1);
            handle_hairpin(&ctx, ipv4hdr, protocol, config)
        }

        // Inbound: external -> external_addr (DNAT needed)
        (false, true) => {
            update_stats(|s| s.packets_inbound += 1);
            handle_inbound(&ctx, ipv4hdr, protocol, config)
        }

        // Pass through: external -> external (not our traffic)
        (false, false) => Ok(xdp_action::XDP_PASS),
    }
}

// ============================================================================
// Outbound (SNAT)
// ============================================================================

/// Handle outbound packets: internal -> external
/// Perform SNAT: rewrite source IP and port
#[inline(always)]
fn handle_outbound(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    protocol: IpProto,
    config: &NatConfig,
) -> Result<u32, ()> {
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    match protocol {
        IpProto::Tcp => handle_outbound_tcp(ctx, ipv4hdr, src_addr, dst_addr, config),
        IpProto::Udp => handle_outbound_udp(ctx, ipv4hdr, src_addr, dst_addr, config),
        IpProto::Icmp => {
            update_stats(|s| s.packets_icmp += 1);
            handle_outbound_icmp(ctx, ipv4hdr, src_addr, config)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn handle_outbound_tcp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    src_addr: u32,
    _dst_addr: u32,
    config: &NatConfig,
) -> Result<u32, ()> {
    let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let src_port = u16::from_be(unsafe { (*tcphdr).source });
    let tcp_flags = get_tcp_flags(tcphdr);

    // Build NAT key
    let key = NatBindingKey {
        internal_addr: src_addr,
        internal_port: src_port,
        protocol: IpProto::Tcp as u8,
        _pad: 0,
    };

    // Look up or allocate binding
    let binding = match unsafe { NAT_BINDINGS.get(&key) } {
        Some(b) => {
            update_stats(|s| s.packets_nat_hit += 1);
            *b
        }
        None => {
            update_stats(|s| s.packets_nat_miss += 1);
            allocate_binding(&key, config)?
        }
    };

    // Update connection state
    update_conn_state(&key, tcp_flags, true)?;

    // Save old values for checksum update
    let old_src_addr = unsafe { (*ipv4hdr).src_addr };
    let old_src_port = unsafe { (*tcphdr).source };

    // Perform SNAT
    unsafe {
        (*ipv4hdr).src_addr = binding.external_addr.to_be();
        (*tcphdr).source = binding.external_port.to_be();
    }

    // Update checksums
    update_ip_checksum(ipv4hdr)?;
    update_l4_checksum_incremental(
        tcphdr as *mut u8,
        old_src_addr,
        binding.external_addr.to_be(),
        old_src_port,
        binding.external_port.to_be(),
        true, // is_tcp
    )?;

    redirect_to_external(ctx, config)
}

#[inline(always)]
fn handle_outbound_udp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    src_addr: u32,
    _dst_addr: u32,
    config: &NatConfig,
) -> Result<u32, ()> {
    let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let src_port = u16::from_be(unsafe { (*udphdr).source });

    // Build NAT key
    let key = NatBindingKey {
        internal_addr: src_addr,
        internal_port: src_port,
        protocol: IpProto::Udp as u8,
        _pad: 0,
    };

    // Look up or allocate binding
    let binding = match unsafe { NAT_BINDINGS.get(&key) } {
        Some(b) => {
            update_stats(|s| s.packets_nat_hit += 1);
            *b
        }
        None => {
            update_stats(|s| s.packets_nat_miss += 1);
            allocate_binding(&key, config)?
        }
    };

    // Update connection state (UDP is simpler)
    update_conn_state_udp(&key)?;

    // Save old values
    let old_src_addr = unsafe { (*ipv4hdr).src_addr };
    let old_src_port = unsafe { (*udphdr).source };

    // Perform SNAT
    unsafe {
        (*ipv4hdr).src_addr = binding.external_addr.to_be();
        (*udphdr).source = binding.external_port.to_be();
    }

    // Update checksums
    update_ip_checksum(ipv4hdr)?;

    // UDP checksum is optional for IPv4, but if non-zero we should update it
    let udp_check = unsafe { (*udphdr).check };
    if udp_check != 0 {
        update_l4_checksum_incremental(
            udphdr as *mut u8,
            old_src_addr,
            binding.external_addr.to_be(),
            old_src_port,
            binding.external_port.to_be(),
            false, // is_tcp
        )?;
    }

    redirect_to_external(ctx, config)
}

#[inline(always)]
fn handle_outbound_icmp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    src_addr: u32,
    config: &NatConfig,
) -> Result<u32, ()> {
    let icmphdr: *mut IcmpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let icmp_type = unsafe { (*icmphdr).type_ };

    match icmp_type {
        ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
            // Use ICMP ID as "port" for NAT binding
            let icmp_id = unsafe { u16::from_be((*icmphdr).un.echo.id) };

            let key = NatBindingKey {
                internal_addr: src_addr,
                internal_port: icmp_id,
                protocol: IpProto::Icmp as u8,
                _pad: 0,
            };

            let binding = match unsafe { NAT_BINDINGS.get(&key) } {
                Some(b) => *b,
                None => allocate_binding(&key, config)?,
            };

            // Rewrite source IP and ICMP ID
            let old_id = unsafe { (*icmphdr).un.echo.id };
            unsafe {
                (*ipv4hdr).src_addr = binding.external_addr.to_be();
                (*icmphdr).un.echo.id = binding.external_port.to_be();
            }

            // Update checksums
            update_ip_checksum(ipv4hdr)?;
            update_icmp_checksum_incremental(icmphdr, old_id, binding.external_port.to_be())?;

            redirect_to_external(ctx, config)
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED => {
            // ICMP error - need to translate embedded packet
            handle_icmp_error_outbound(ctx, ipv4hdr, icmphdr, config)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ============================================================================
// Inbound (DNAT)
// ============================================================================

/// Handle inbound packets: external -> external_addr
/// Perform DNAT: rewrite destination IP and port
#[inline(always)]
fn handle_inbound(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    protocol: IpProto,
    config: &NatConfig,
) -> Result<u32, ()> {
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    match protocol {
        IpProto::Tcp => handle_inbound_tcp(ctx, ipv4hdr, dst_addr, config),
        IpProto::Udp => handle_inbound_udp(ctx, ipv4hdr, dst_addr, config),
        IpProto::Icmp => {
            update_stats(|s| s.packets_icmp += 1);
            handle_inbound_icmp(ctx, ipv4hdr, config)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn handle_inbound_tcp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    dst_addr: u32,
    config: &NatConfig,
) -> Result<u32, ()> {
    let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let dst_port = u16::from_be(unsafe { (*tcphdr).dest });
    let tcp_flags = get_tcp_flags(tcphdr);

    // Look up reverse NAT binding
    let key = NatReverseKey {
        external_addr: dst_addr,
        external_port: dst_port,
        protocol: IpProto::Tcp as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_REVERSE.get(&key) } {
        Some(b) => {
            update_stats(|s| s.packets_nat_hit += 1);
            *b
        }
        None => {
            update_stats(|s| {
                s.packets_nat_miss += 1;
                s.packets_dropped += 1;
            });
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // Update connection state
    update_conn_state(&binding, tcp_flags, false)?;

    // Save old values
    let old_dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let old_dst_port = unsafe { (*tcphdr).dest };

    // Perform DNAT
    unsafe {
        (*ipv4hdr).dst_addr = binding.internal_addr.to_be();
        (*tcphdr).dest = binding.internal_port.to_be();
    }

    // Update checksums
    update_ip_checksum(ipv4hdr)?;
    update_l4_checksum_incremental(
        tcphdr as *mut u8,
        old_dst_addr,
        binding.internal_addr.to_be(),
        old_dst_port,
        binding.internal_port.to_be(),
        true,
    )?;

    // Redirect to internal interface
    redirect_to_internal(ctx, config)
}

#[inline(always)]
fn handle_inbound_udp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    dst_addr: u32,
    config: &NatConfig,
) -> Result<u32, ()> {
    let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let dst_port = u16::from_be(unsafe { (*udphdr).dest });

    // Look up reverse NAT binding
    let key = NatReverseKey {
        external_addr: dst_addr,
        external_port: dst_port,
        protocol: IpProto::Udp as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_REVERSE.get(&key) } {
        Some(b) => {
            update_stats(|s| s.packets_nat_hit += 1);
            *b
        }
        None => {
            update_stats(|s| {
                s.packets_nat_miss += 1;
                s.packets_dropped += 1;
            });
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // Save old values
    let old_dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let old_dst_port = unsafe { (*udphdr).dest };

    // Perform DNAT
    unsafe {
        (*ipv4hdr).dst_addr = binding.internal_addr.to_be();
        (*udphdr).dest = binding.internal_port.to_be();
    }

    // Update checksums
    update_ip_checksum(ipv4hdr)?;

    let udp_check = unsafe { (*udphdr).check };
    if udp_check != 0 {
        update_l4_checksum_incremental(
            udphdr as *mut u8,
            old_dst_addr,
            binding.internal_addr.to_be(),
            old_dst_port,
            binding.internal_port.to_be(),
            false,
        )?;
    }

    redirect_to_internal(ctx, config)
}

#[inline(always)]
fn handle_inbound_icmp(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    config: &NatConfig,
) -> Result<u32, ()> {
    let icmphdr: *mut IcmpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let icmp_type = unsafe { (*icmphdr).type_ };
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    match icmp_type {
        ICMP_ECHO_REPLY | ICMP_ECHO_REQUEST => {
            let icmp_id = unsafe { u16::from_be((*icmphdr).un.echo.id) };

            let key = NatReverseKey {
                external_addr: dst_addr,
                external_port: icmp_id,
                protocol: IpProto::Icmp as u8,
                _pad: 0,
            };

            let binding = match unsafe { NAT_REVERSE.get(&key) } {
                Some(b) => *b,
                None => {
                    update_stats(|s| s.packets_dropped += 1);
                    return Ok(xdp_action::XDP_DROP);
                }
            };

            // Rewrite destination IP and ICMP ID
            let old_id = unsafe { (*icmphdr).un.echo.id };
            unsafe {
                (*ipv4hdr).dst_addr = binding.internal_addr.to_be();
                (*icmphdr).un.echo.id = binding.internal_port.to_be();
            }

            update_ip_checksum(ipv4hdr)?;
            update_icmp_checksum_incremental(icmphdr, old_id, binding.internal_port.to_be())?;

            redirect_to_internal(ctx, config)
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED => {
            handle_icmp_error_inbound(ctx, ipv4hdr, icmphdr, config)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ============================================================================
// Hairpinning
// ============================================================================

/// Handle hairpin packets: internal client -> external_addr -> internal server
#[inline(always)]
fn handle_hairpin(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    protocol: IpProto,
    config: &NatConfig,
) -> Result<u32, ()> {
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            (
                u16::from_be(unsafe { (*udphdr).source }),
                u16::from_be(unsafe { (*udphdr).dest }),
            )
        }
        IpProto::Icmp => {
            let icmphdr: *const IcmpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let icmp_id = unsafe { u16::from_be((*icmphdr).un.echo.id) };
            (icmp_id, icmp_id)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Look up destination mapping (who owns external_addr:dst_port?)
    let reverse_key = NatReverseKey {
        external_addr: config.external_addr,
        external_port: dst_port,
        protocol: protocol as u8,
        _pad: 0,
    };

    let dst_binding = match unsafe { NAT_REVERSE.get(&reverse_key) } {
        Some(b) => *b,
        None => {
            update_stats(|s| s.packets_dropped += 1);
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // For hairpin, we also need a binding for the source (for return traffic)
    let src_key = NatBindingKey {
        internal_addr: src_addr,
        internal_port: src_port,
        protocol: protocol as u8,
        _pad: 0,
    };

    let src_binding = match unsafe { NAT_BINDINGS.get(&src_key) } {
        Some(b) => *b,
        None => allocate_binding(&src_key, config)?,
    };

    // Save old values
    let old_src_addr = unsafe { (*ipv4hdr).src_addr };
    let old_dst_addr = unsafe { (*ipv4hdr).dst_addr };

    // Rewrite packet for hairpin:
    // src: internal_client:port -> external_addr:allocated_port (SNAT)
    // dst: external_addr:dst_port -> internal_server:port (DNAT)
    unsafe {
        (*ipv4hdr).src_addr = src_binding.external_addr.to_be();
        (*ipv4hdr).dst_addr = dst_binding.internal_addr.to_be();
    }

    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let old_src_port = unsafe { (*tcphdr).source };
            let old_dst_port = unsafe { (*tcphdr).dest };
            unsafe {
                (*tcphdr).source = src_binding.external_port.to_be();
                (*tcphdr).dest = dst_binding.internal_port.to_be();
            }
            update_tcp_checksum_hairpin(
                tcphdr,
                old_src_addr,
                src_binding.external_addr.to_be(),
                old_dst_addr,
                dst_binding.internal_addr.to_be(),
                old_src_port,
                src_binding.external_port.to_be(),
                old_dst_port,
                dst_binding.internal_port.to_be(),
            )?;
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*udphdr).source = src_binding.external_port.to_be();
                (*udphdr).dest = dst_binding.internal_port.to_be();
                // Zero out UDP checksum (optional for IPv4)
                (*udphdr).check = 0;
            }
        }
        IpProto::Icmp => {
            let icmphdr: *mut IcmpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let old_id = unsafe { (*icmphdr).un.echo.id };
            unsafe {
                (*icmphdr).un.echo.id = dst_binding.internal_port.to_be();
            }
            update_icmp_checksum_incremental(icmphdr, old_id, dst_binding.internal_port.to_be())?;
        }
        _ => {}
    }

    update_ip_checksum(ipv4hdr)?;

    debug!(
        ctx,
        "Hairpin: {} -> {}", src_addr, dst_binding.internal_addr
    );

    redirect_to_internal(ctx, config)
}

// ============================================================================
// ICMP Error Handling (RFC 5508)
// ============================================================================

/// Handle outbound ICMP errors - translate embedded packet
#[inline(always)]
fn handle_icmp_error_outbound(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    icmphdr: *mut IcmpHdr,
    config: &NatConfig,
) -> Result<u32, ()> {
    // ICMP error contains: ICMP header (8 bytes) + original IP header + 8 bytes of original L4
    let inner_ip_offset = EthHdr::LEN + Ipv4Hdr::LEN + 8; // 8 = ICMP header
    let inner_ipv4: *mut Ipv4Hdr = ptr_at_mut(ctx, inner_ip_offset)?;

    // The embedded packet has our internal address as DESTINATION (it was coming TO us)
    let inner_dst_addr = u32::from_be(unsafe { (*inner_ipv4).dst_addr });
    let inner_protocol = unsafe { (*inner_ipv4).proto };

    let inner_dst_port = match inner_protocol {
        IpProto::Tcp => {
            let inner_tcp: *const TcpHdr = ptr_at(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*inner_tcp).dest })
        }
        IpProto::Udp => {
            let inner_udp: *const UdpHdr = ptr_at(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*inner_udp).dest })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Look up binding for the embedded packet
    let key = NatBindingKey {
        internal_addr: inner_dst_addr,
        internal_port: inner_dst_port,
        protocol: inner_protocol as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_BINDINGS.get(&key) } {
        Some(b) => *b,
        None => return Ok(xdp_action::XDP_DROP),
    };

    // Rewrite embedded packet destination
    unsafe {
        (*inner_ipv4).dst_addr = binding.external_addr.to_be();
    }

    // Rewrite embedded L4 destination port
    match inner_protocol {
        IpProto::Tcp => {
            let inner_tcp: *mut TcpHdr = ptr_at_mut(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            unsafe {
                (*inner_tcp).dest = binding.external_port.to_be();
            }
        }
        IpProto::Udp => {
            let inner_udp: *mut UdpHdr = ptr_at_mut(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            unsafe {
                (*inner_udp).dest = binding.external_port.to_be();
            }
        }
        _ => {}
    }

    // Use the same external address
    unsafe {
        (*ipv4hdr).src_addr = config.external_addr.to_be();
    }

    update_ip_checksum(ipv4hdr)?;
    update_icmp_checksum_error(ctx, icmphdr)?;

    redirect_to_external(ctx, config)
}

/// Handle inbound ICMP errors - translate embedded packet
#[inline(always)]
fn handle_icmp_error_inbound(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    icmphdr: *mut IcmpHdr,
    config: &NatConfig,
) -> Result<u32, ()> {
    let inner_ip_offset = EthHdr::LEN + Ipv4Hdr::LEN + 8;
    let inner_ipv4: *mut Ipv4Hdr = ptr_at_mut(ctx, inner_ip_offset)?;

    // The embedded packet has external address as SOURCE (it was going FROM us)
    let inner_src_addr = u32::from_be(unsafe { (*inner_ipv4).src_addr });
    let inner_protocol = unsafe { (*inner_ipv4).proto };

    let inner_src_port = match inner_protocol {
        IpProto::Tcp => {
            let inner_tcp: *const TcpHdr = ptr_at(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*inner_tcp).source })
        }
        IpProto::Udp => {
            let inner_udp: *const UdpHdr = ptr_at(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*inner_udp).source })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Look up reverse binding
    let key = NatReverseKey {
        external_addr: inner_src_addr,
        external_port: inner_src_port,
        protocol: inner_protocol as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_REVERSE.get(&key) } {
        Some(b) => *b,
        None => return Ok(xdp_action::XDP_DROP),
    };

    // Rewrite embedded packet source
    unsafe {
        (*inner_ipv4).src_addr = binding.internal_addr.to_be();
    }

    // Rewrite embedded L4 source port
    match inner_protocol {
        IpProto::Tcp => {
            let inner_tcp: *mut TcpHdr = ptr_at_mut(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            unsafe {
                (*inner_tcp).source = binding.internal_port.to_be();
            }
        }
        IpProto::Udp => {
            let inner_udp: *mut UdpHdr = ptr_at_mut(ctx, inner_ip_offset + Ipv4Hdr::LEN)?;
            unsafe {
                (*inner_udp).source = binding.internal_port.to_be();
            }
        }
        _ => {}
    }

    // Rewrite outer destination IP
    unsafe {
        (*ipv4hdr).dst_addr = binding.internal_addr.to_be();
    }

    update_ip_checksum(ipv4hdr)?;
    update_icmp_checksum_error(ctx, icmphdr)?;

    redirect_to_internal(ctx, config)
}

// ============================================================================
// Port Allocation
// ============================================================================

/// Allocate a new NAT binding with an external port
#[inline(always)]
fn allocate_binding(key: &NatBindingKey, config: &NatConfig) -> Result<NatBindingValue, ()> {
    let port_state = PORT_ALLOC.get_ptr_mut(0).ok_or(())?;

    let port_range = (config.port_max - config.port_min + 1) as u32;
    if port_range == 0 {
        return Err(());
    }

    // Try to allocate a port
    for _attempt in 0..MAX_PORT_ALLOC_ATTEMPTS {
        // Atomic increment of next_port
        let current = unsafe { core::ptr::read_volatile(&(*port_state).next_port) };
        let next = current.wrapping_add(1);
        unsafe {
            core::ptr::write_volatile(&mut (*port_state).next_port, next);
        }

        // Calculate actual port number
        let port_offset = current % port_range;
        let port = config.port_min + port_offset as u16;

        // Check if this port is already in use (check reverse map)
        let reverse_key = NatReverseKey {
            external_addr: config.external_addr,
            external_port: port,
            protocol: key.protocol,
            _pad: 0,
        };

        if unsafe { NAT_REVERSE.get(&reverse_key).is_some() } {
            // Port in use, try next
            continue;
        }

        // Port is free, create bindings
        let binding = NatBindingValue {
            external_addr: config.external_addr,
            external_port: port,
            _pad: [0; 2],
        };

        // Insert into both maps using BPF_NOEXIST for atomic "insert if not exists"
        // This prevents race conditions where two CPUs might try to allocate the same port
        if NAT_BINDINGS.insert(key, &binding, BPF_NOEXIST).is_err() {
            // Key already exists (race condition) or map error - try next port
            continue;
        }

        if NAT_REVERSE.insert(&reverse_key, key, BPF_NOEXIST).is_err() {
            // Reverse entry already exists (race) - rollback the forward binding
            let _ = NAT_BINDINGS.remove(key);
            continue;
        }

        // Initialize connection state (use BPF_NOEXIST for consistency)
        let conn_state = ConnState {
            last_seen: unsafe { bpf_ktime_get_ns() },
            packets_out: 1,
            packets_in: 0,
            bytes_out: 0,
            bytes_in: 0,
            tcp_state: TcpState::None as u8,
            flags: 0,
            _pad: [0; 6],
        };
        let _ = CONN_TRACK.insert(key, &conn_state, BPF_NOEXIST);

        // Update stats (volatile, not atomic — see PORT_ALLOC comment above).
        // Races here are benign: GC periodically corrects allocated_count.
        unsafe {
            let allocated = core::ptr::read_volatile(&(*port_state).allocated_count);
            core::ptr::write_volatile(&mut (*port_state).allocated_count, allocated + 1);
            let success = core::ptr::read_volatile(&(*port_state).alloc_success);
            core::ptr::write_volatile(&mut (*port_state).alloc_success, success + 1);
        }

        return Ok(binding);
    }

    // Failed to allocate after max attempts
    unsafe {
        let failures = core::ptr::read_volatile(&(*port_state).alloc_failures);
        core::ptr::write_volatile(&mut (*port_state).alloc_failures, failures + 1);
    }

    Err(())
}

// ============================================================================
// Connection State Tracking
// ============================================================================

/// Update TCP connection state based on flags
#[inline(always)]
fn update_conn_state(key: &NatBindingKey, tcp_flags: u8, is_outbound: bool) -> Result<(), ()> {
    let state = CONN_TRACK.get_ptr_mut(key).ok_or(())?;

    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        (*state).last_seen = now;
        if is_outbound {
            (*state).packets_out += 1;
        } else {
            (*state).packets_in += 1;
        }
    }

    // TCP state machine
    let current_state = unsafe { (*state).tcp_state };
    let new_state = match (
        current_state,
        tcp_flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST),
    ) {
        // New connection
        (s, TCP_SYN) if s == TcpState::None as u8 && is_outbound => TcpState::SynSent as u8,
        // SYN-ACK received
        (s, f)
            if s == TcpState::SynSent as u8
                && (f & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
                && !is_outbound =>
        {
            TcpState::SynReceived as u8
        }
        // ACK for SYN-ACK
        (s, f) if s == TcpState::SynReceived as u8 && (f & TCP_ACK) != 0 && is_outbound => {
            TcpState::Established as u8
        }
        // FIN sent
        (s, f) if s == TcpState::Established as u8 && (f & TCP_FIN) != 0 => {
            TcpState::FinWait1 as u8
        }
        // RST received - connection closed
        (_, f) if (f & TCP_RST) != 0 => TcpState::Closed as u8,
        // No change
        (s, _) => s,
    };

    unsafe {
        (*state).tcp_state = new_state;
    }

    Ok(())
}

/// Update UDP connection state (simpler - just timestamp)
#[inline(always)]
fn update_conn_state_udp(key: &NatBindingKey) -> Result<(), ()> {
    if let Some(state) = CONN_TRACK.get_ptr_mut(key) {
        unsafe {
            (*state).last_seen = bpf_ktime_get_ns();
            (*state).packets_out += 1;
        }
    }
    Ok(())
}

// ============================================================================
// Checksum Functions
// ============================================================================

/// Update IP header checksum (full recalculation)
#[inline(always)]
fn update_ip_checksum(ipv4hdr: *mut Ipv4Hdr) -> Result<(), ()> {
    unsafe {
        (*ipv4hdr).check = 0;
        (*ipv4hdr).check = compute_ip_checksum(ipv4hdr);
    }
    Ok(())
}

/// Compute IP header checksum
#[inline(always)]
fn compute_ip_checksum(ipv4hdr: *const Ipv4Hdr) -> u16 {
    let mut sum: u32 = 0;
    let hdr = ipv4hdr as *const u16;

    // IP header is 20 bytes = 10 u16 words (assuming no options)
    // Unroll for verifier
    sum += unsafe { *hdr.add(0) } as u32;
    sum += unsafe { *hdr.add(1) } as u32;
    sum += unsafe { *hdr.add(2) } as u32;
    sum += unsafe { *hdr.add(3) } as u32;
    sum += unsafe { *hdr.add(4) } as u32;
    sum += unsafe { *hdr.add(5) } as u32;
    sum += unsafe { *hdr.add(6) } as u32;
    sum += unsafe { *hdr.add(7) } as u32;
    sum += unsafe { *hdr.add(8) } as u32;
    sum += unsafe { *hdr.add(9) } as u32;

    // Fold 32-bit sum to 16 bits
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    !sum as u16
}

/// Incremental L4 checksum update for address/port changes
#[inline(always)]
fn update_l4_checksum_incremental(
    l4hdr: *mut u8,
    old_addr: u32,
    new_addr: u32,
    old_port: u16,
    new_port: u16,
    is_tcp: bool,
) -> Result<(), ()> {
    // Get checksum offset (16 for TCP, 6 for UDP)
    let check_offset = if is_tcp { 16 } else { 6 };
    let check_ptr = unsafe { (l4hdr as *mut u16).add(check_offset / 2) };

    let old_check = unsafe { *check_ptr };
    if old_check == 0 && !is_tcp {
        // UDP with zero checksum - leave it
        return Ok(());
    }

    // RFC 1624 incremental checksum update
    let mut sum = (!old_check) as u32;

    // Subtract old values
    sum += (!(old_addr >> 16) as u16) as u32;
    sum += (!(old_addr & 0xFFFF) as u16) as u32;
    sum += (!old_port) as u32;

    // Add new values
    sum += ((new_addr >> 16) as u16) as u32;
    sum += ((new_addr & 0xFFFF) as u16) as u32;
    sum += new_port as u32;

    // Fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    let new_check = !sum as u16;
    unsafe {
        *check_ptr = if new_check == 0 && !is_tcp {
            0xFFFF
        } else {
            new_check
        };
    }

    Ok(())
}

/// Incremental TCP checksum update for hairpin where both src and dst change
/// Uses RFC 1624 approach for multiple field changes
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn update_tcp_checksum_hairpin(
    tcphdr: *mut TcpHdr,
    old_src_addr: u32,
    new_src_addr: u32,
    old_dst_addr: u32,
    new_dst_addr: u32,
    old_src_port: u16,
    new_src_port: u16,
    old_dst_port: u16,
    new_dst_port: u16,
) -> Result<(), ()> {
    let old_check = unsafe { (*tcphdr).check };

    // RFC 1624 incremental update for all changed fields
    let mut sum = (!old_check) as u32;

    // Subtract old values, add new values for src addr
    sum += (!(old_src_addr >> 16) as u16) as u32;
    sum += (!(old_src_addr & 0xFFFF) as u16) as u32;
    sum += ((new_src_addr >> 16) as u16) as u32;
    sum += ((new_src_addr & 0xFFFF) as u16) as u32;

    // Subtract old values, add new values for dst addr
    sum += (!(old_dst_addr >> 16) as u16) as u32;
    sum += (!(old_dst_addr & 0xFFFF) as u16) as u32;
    sum += ((new_dst_addr >> 16) as u16) as u32;
    sum += ((new_dst_addr & 0xFFFF) as u16) as u32;

    // Subtract old values, add new values for src port
    sum += (!old_src_port) as u32;
    sum += new_src_port as u32;

    // Subtract old values, add new values for dst port
    sum += (!old_dst_port) as u32;
    sum += new_dst_port as u32;

    // Fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    unsafe {
        (*tcphdr).check = !sum as u16;
    }

    Ok(())
}

/// Update ICMP checksum incrementally for ID change only
/// This is used for echo request/reply where only the ID field changes
#[inline(always)]
fn update_icmp_checksum_incremental(
    icmphdr: *mut IcmpHdr,
    old_id: u16,
    new_id: u16,
) -> Result<(), ()> {
    let old_check = unsafe { (*icmphdr).checksum };

    // RFC 1624 incremental update: ~new_check = ~old_check + ~old_value + new_value
    let mut sum = (!old_check) as u32;
    sum += (!old_id) as u32;
    sum += new_id as u32;

    // Fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    unsafe {
        (*icmphdr).checksum = !sum as u16;
    }

    Ok(())
}

/// Update ICMP checksum for error messages (full recalculation with bounded payload)
/// ICMP error messages contain: 8-byte header + IP header + 8 bytes of original L4
#[inline(always)]
fn update_icmp_checksum_error(ctx: &XdpContext, icmphdr: *mut IcmpHdr) -> Result<(), ()> {
    // Calculate ICMP message length from IP total length
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let ip_total = u16::from_be(unsafe { (*ipv4hdr).tot_len }) as usize;
    let icmp_len = ip_total.saturating_sub(Ipv4Hdr::LEN);

    // Cap at reasonable size for verifier (ICMP error = 8 + 20 + 8 = 36 bytes typical)
    let icmp_len = if icmp_len > 64 { 64 } else { icmp_len };

    unsafe {
        (*icmphdr).checksum = 0;
    }

    let mut sum: u32 = 0;
    let icmp_bytes = icmphdr as *const u8;
    let data_end = ctx.data_end();

    // Process in 16-bit words with bounds checking
    let mut i = 0usize;
    while i + 1 < icmp_len {
        let ptr = unsafe { icmp_bytes.add(i) } as usize;
        if ptr + 2 > data_end {
            break;
        }
        let word = unsafe { *(icmp_bytes.add(i) as *const u16) };
        sum += word as u32;
        i += 2;
    }

    // Handle odd byte
    if i < icmp_len {
        let ptr = unsafe { icmp_bytes.add(i) } as usize;
        if ptr < data_end {
            let byte = unsafe { *icmp_bytes.add(i) };
            sum += (byte as u32) << 8;
        }
    }

    // Fold
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    unsafe {
        (*icmphdr).checksum = !sum as u16;
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if address is in internal subnet
#[inline(always)]
fn is_internal_addr(addr: u32, config: &NatConfig) -> bool {
    (addr & config.internal_mask) == config.internal_subnet
}

/// Perform FIB lookup to get next-hop MAC addresses and rewrite Ethernet header
/// Returns Ok(()) on success, Err(()) if lookup fails
#[inline(always)]
fn fib_lookup_and_rewrite_macs(
    ctx: &XdpContext,
    dst_addr: u32, // destination IP in host byte order
    ifindex: u32,  // output interface index
) -> Result<(), ()> {
    // Get IP header for protocol info
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let protocol = unsafe { (*ipv4hdr).proto };
    let tot_len = u16::from_be(unsafe { (*ipv4hdr).tot_len });

    // Set up FIB lookup parameters
    let mut fib_params: bpf_fib_lookup_param_t = unsafe { mem::zeroed() };
    fib_params.family = AF_INET;
    fib_params.l4_protocol = protocol as u8;
    fib_params.ifindex = ifindex;
    fib_params.__bindgen_anon_1.tot_len = tot_len;

    // Set destination address (in network byte order for FIB lookup)
    // Note: ipv4_src is in __bindgen_anon_3, ipv4_dst is in __bindgen_anon_4
    fib_params.__bindgen_anon_3.ipv4_src = 0; // Let kernel fill in
    fib_params.__bindgen_anon_4.ipv4_dst = dst_addr.to_be();

    // Perform FIB lookup
    let ret = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr() as *mut _,
            &mut fib_params as *mut _,
            mem::size_of::<bpf_fib_lookup_param_t>() as i32,
            BPF_FIB_LOOKUP_OUTPUT, // Skip src address lookup, just get MACs
        )
    };

    if ret == BPF_FIB_LKUP_RET_SUCCESS {
        // Rewrite Ethernet header with resolved MACs
        let ethhdr: *mut EthHdr = ptr_at_mut(ctx, 0)?;
        unsafe {
            // Set source MAC to our interface's MAC (filled by FIB lookup)
            (*ethhdr).src_addr = fib_params.smac;
            // Set destination MAC to next-hop MAC (filled by FIB lookup)
            (*ethhdr).dst_addr = fib_params.dmac;
        }

        Ok(())
    } else {
        // FIB lookup failed (ret={}) - fall back to kernel path.
        // NO_NEIGH (7) means neighbor not in ARP table; kernel will resolve ARP
        // and subsequent packets will use XDP once the entry is cached.
        debug!(ctx, "FIB lookup failed: ret={}, dst={:i}", ret, dst_addr);
        Err(())
    }
}

/// Redirect packet to internal interface with proper L2 MAC rewrite
#[inline(always)]
fn redirect_to_internal(ctx: &XdpContext, config: &NatConfig) -> Result<u32, ()> {
    // Get destination IP from the (already modified) IP header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    // Perform FIB lookup and rewrite MACs
    // If FIB lookup fails, fall back to XDP_PASS to let kernel handle it
    if fib_lookup_and_rewrite_macs(ctx, dst_addr, config.internal_ifindex).is_err() {
        return Ok(xdp_action::XDP_PASS);
    }

    DEVMAP
        .redirect(config.internal_ifindex, 0)
        .map_err(|_| ())?;
    Ok(xdp_action::XDP_REDIRECT)
}

/// Redirect packet to external interface with proper L2 MAC rewrite
#[inline(always)]
fn redirect_to_external(ctx: &XdpContext, config: &NatConfig) -> Result<u32, ()> {
    // Get destination IP from the (already modified) IP header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    // Perform FIB lookup and rewrite MACs
    // If FIB lookup fails, fall back to XDP_PASS to let kernel handle it
    if fib_lookup_and_rewrite_macs(ctx, dst_addr, config.external_ifindex).is_err() {
        return Ok(xdp_action::XDP_PASS);
    }

    DEVMAP
        .redirect(config.external_ifindex, 0)
        .map_err(|_| ())?;
    Ok(xdp_action::XDP_REDIRECT)
}

/// Get TCP flags from header
#[inline(always)]
fn get_tcp_flags(tcphdr: *const TcpHdr) -> u8 {
    // TCP flags are in the 13th byte (offset 12)
    unsafe { *((tcphdr as *const u8).add(13)) }
}

/// Update per-CPU statistics
#[inline(always)]
fn update_stats<F: FnOnce(&mut NatStats)>(f: F) {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        f(unsafe { &mut *stats });
    }
}

/// Get pointer at offset (const)
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// Get pointer at offset (mut)
#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
