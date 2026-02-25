//! CGNAT XDP eBPF Program
//!
//! This is the core packet processing logic that runs in the kernel.
//! It handles:
//! - Outbound SNAT (internal -> external)
//! - Inbound DNAT (external -> internal)
//! - Hairpinning via XDP_REDIRECT

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, DevMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use cgnat_common::{NatBindingKey, NatBindingValue, NatConfig, NatReverseKey, ConnState};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// NAT binding table: internal addr:port -> external addr:port
#[map]
static NAT_BINDINGS: HashMap<NatBindingKey, NatBindingValue> =
    HashMap::with_max_entries(1 << 20, 0); // 1M entries

/// Reverse NAT table: external addr:port -> internal addr:port
#[map]
static NAT_REVERSE: HashMap<NatReverseKey, NatBindingKey> =
    HashMap::with_max_entries(1 << 20, 0);

/// Connection state tracking
#[map]
static CONN_TRACK: HashMap<NatBindingKey, ConnState> =
    HashMap::with_max_entries(1 << 20, 0);

/// Configuration (single entry)
#[map]
static CONFIG: Array<NatConfig> = Array::with_max_entries(1, 0);

/// Device map for XDP_REDIRECT
#[map]
static DEVMAP: DevMap = DevMap::with_max_entries(256, 0);

#[xdp]
pub fn cgnat_xdp(ctx: XdpContext) -> u32 {
    match try_cgnat_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS, // On error, let kernel handle it
    }
}

#[inline(always)]
fn try_cgnat_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let config = unsafe { CONFIG.get(0).ok_or(())? };

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

    // Determine packet direction and action
    let is_from_internal = is_internal_addr(src_addr, config);
    let is_to_external = dst_addr == config.external_addr;

    match (is_from_internal, is_to_external) {
        // Outbound: internal -> external (SNAT needed)
        (true, false) => handle_outbound(&ctx, ipv4hdr, protocol, config),

        // Hairpin: internal -> external_addr (redirect back to internal)
        (true, true) => handle_hairpin(&ctx, ipv4hdr, protocol, config),

        // Inbound: external -> external_addr (DNAT needed)
        (false, true) => handle_inbound(&ctx, ipv4hdr, protocol, config),

        // Pass through: external -> external (not our traffic)
        (false, false) => Ok(xdp_action::XDP_PASS),
    }
}

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
        _ => return Ok(xdp_action::XDP_PASS), // TODO: Handle ICMP
    };

    // Look up or create NAT binding
    let key = NatBindingKey {
        internal_addr: src_addr,
        internal_port: src_port,
        protocol: protocol as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_BINDINGS.get(&key) } {
        Some(b) => *b,
        None => {
            // TODO: Allocate new binding from userspace or eBPF
            // For now, pass to userspace for allocation
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // Perform SNAT: rewrite source IP and port
    unsafe {
        (*ipv4hdr).src_addr = binding.external_addr.to_be();
    }

    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*tcphdr).source = binding.external_port.to_be();
            }
            update_tcp_checksum(ipv4hdr, tcphdr)?;
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*udphdr).source = binding.external_port.to_be();
                // UDP checksum is optional for IPv4, set to 0
                (*udphdr).check = 0;
            }
        }
        _ => {}
    }

    update_ip_checksum(ipv4hdr)?;

    // Redirect to external interface
    Ok(xdp_action::XDP_TX)
}

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

    let dst_port = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Look up reverse NAT binding
    let key = NatReverseKey {
        external_addr: dst_addr,
        external_port: dst_port,
        protocol: protocol as u8,
        _pad: 0,
    };

    let binding = match unsafe { NAT_REVERSE.get(&key) } {
        Some(b) => *b,
        None => {
            // No binding found, drop or pass
            return Ok(xdp_action::XDP_DROP);
        }
    };

    // Perform DNAT: rewrite destination IP and port
    unsafe {
        (*ipv4hdr).dst_addr = binding.internal_addr.to_be();
    }

    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*tcphdr).dest = binding.internal_port.to_be();
            }
            update_tcp_checksum(ipv4hdr, tcphdr)?;
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*udphdr).dest = binding.internal_port.to_be();
                (*udphdr).check = 0;
            }
        }
        _ => {}
    }

    update_ip_checksum(ipv4hdr)?;

    // Redirect to internal interface
    unsafe {
        DEVMAP.redirect(config.internal_ifindex, 0).map_err(|_| ())?;
    }
    Ok(xdp_action::XDP_REDIRECT)
}

/// Handle hairpin packets: internal client -> external_addr -> internal server
/// This is the key feature that requires XDP_REDIRECT
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
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // Look up the destination mapping (who owns external_addr:dst_port?)
    let reverse_key = NatReverseKey {
        external_addr: config.external_addr,
        external_port: dst_port,
        protocol: protocol as u8,
        _pad: 0,
    };

    let dst_binding = match unsafe { NAT_REVERSE.get(&reverse_key) } {
        Some(b) => *b,
        None => return Ok(xdp_action::XDP_DROP), // No such port mapping
    };

    // Rewrite packet for hairpin:
    // src: internal_client -> external_addr (SNAT)
    // dst: external_addr:port -> internal_server (DNAT)
    unsafe {
        (*ipv4hdr).src_addr = config.external_addr.to_be();
        (*ipv4hdr).dst_addr = dst_binding.internal_addr.to_be();
    }

    match protocol {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                // Source port needs NAT binding for the client
                // For hairpin, we may need to allocate a binding for return traffic
                (*tcphdr).dest = dst_binding.internal_port.to_be();
            }
            update_tcp_checksum(ipv4hdr, tcphdr)?;
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe {
                (*udphdr).dest = dst_binding.internal_port.to_be();
                (*udphdr).check = 0;
            }
        }
        _ => {}
    }

    update_ip_checksum(ipv4hdr)?;

    // XDP_REDIRECT back to internal interface - this is the magic!
    // The packet never leaves the XDP program, kernel routing is bypassed
    unsafe {
        DEVMAP.redirect(config.internal_ifindex, 0).map_err(|_| ())?;
    }

    info!(ctx, "Hairpin: {} -> {}", src_addr, dst_binding.internal_addr);

    Ok(xdp_action::XDP_REDIRECT)
}

/// Check if an address is in the internal subnet
#[inline(always)]
fn is_internal_addr(addr: u32, config: &NatConfig) -> bool {
    (addr & config.internal_mask) == config.internal_subnet
}

/// Get a pointer to data at offset (immutable)
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

/// Get a pointer to data at offset (mutable)
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

/// Update IP header checksum after modification
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
    for i in 0..10 {
        sum += unsafe { *hdr.add(i) } as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Update TCP checksum (simplified - full implementation needed)
#[inline(always)]
fn update_tcp_checksum(_ipv4hdr: *mut Ipv4Hdr, _tcphdr: *mut TcpHdr) -> Result<(), ()> {
    // TODO: Implement proper incremental TCP checksum update
    // For now, rely on hardware offload or implement full recalculation
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
