//! CGNAT Userspace Controller
//!
//! Loads the XDP program and manages NAT bindings.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, DevMap, HashMap},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use cgnat_common::{NatBindingKey, NatBindingValue, NatConfig, NatReverseKey};
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "cgnat", about = "eBPF/XDP CGNAT implementation")]
struct Args {
    /// External interface name (e.g., eth0)
    #[arg(short = 'e', long)]
    external_iface: String,

    /// Internal interface name (e.g., eth1)
    #[arg(short = 'i', long)]
    internal_iface: String,

    /// External (public) IP address
    #[arg(short = 'E', long)]
    external_addr: Ipv4Addr,

    /// Internal subnet in CIDR notation (e.g., 10.0.0.0/8)
    #[arg(short = 'I', long)]
    internal_subnet: String,

    /// Minimum port for NAT allocation (default: 1024)
    #[arg(long, default_value = "1024")]
    port_min: u16,

    /// Maximum port for NAT allocation (default: 65535)
    #[arg(long, default_value = "65535")]
    port_max: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Parse internal subnet
    let (subnet_addr, subnet_mask) = parse_cidr(&args.internal_subnet)?;

    info!("Starting CGNAT");
    info!("  External interface: {}", args.external_iface);
    info!("  Internal interface: {}", args.internal_iface);
    info!("  External address: {}", args.external_addr);
    info!("  Internal subnet: {}", args.internal_subnet);

    // Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/cgnat-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/cgnat-ebpf"
    ))?;

    // Set up logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get interface indices
    let external_ifindex = get_ifindex(&args.external_iface)?;
    let internal_ifindex = get_ifindex(&args.internal_iface)?;

    // Configure the program
    let config = NatConfig {
        external_addr: u32::from(args.external_addr),
        internal_subnet: u32::from(subnet_addr),
        internal_mask: subnet_mask,
        external_ifindex,
        internal_ifindex,
        port_min: args.port_min,
        port_max: args.port_max,
        ..Default::default()
    };

    // Write config to map
    let mut config_map: Array<_, NatConfig> = Array::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.set(0, config, 0)?;

    // Set up device map for XDP_REDIRECT
    let mut devmap: DevMap<_> = DevMap::try_from(bpf.map_mut("DEVMAP").unwrap())?;
    devmap.set(external_ifindex, external_ifindex, None, 0)?;
    devmap.set(internal_ifindex, internal_ifindex, None, 0)?;

    // Attach XDP program to both interfaces
    let program: &mut Xdp = bpf.program_mut("cgnat_xdp").unwrap().try_into()?;
    program.load()?;

    // Use SKB mode for compatibility, can switch to DRV mode for performance
    program.attach(&args.external_iface, XdpFlags::SKB_MODE)
        .context("Failed to attach to external interface")?;
    info!("Attached XDP to external interface: {}", args.external_iface);

    program.attach(&args.internal_iface, XdpFlags::SKB_MODE)
        .context("Failed to attach to internal interface")?;
    info!("Attached XDP to internal interface: {}", args.internal_iface);

    info!("CGNAT running. Press Ctrl+C to exit.");

    // Wait for shutdown signal
    signal::ctrl_c().await?;

    info!("Shutting down...");
    Ok(())
}

/// Parse CIDR notation (e.g., "10.0.0.0/8") into address and mask
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR notation: {}", cidr);
    }

    let addr: Ipv4Addr = parts[0].parse()?;
    let prefix_len: u32 = parts[1].parse()?;

    if prefix_len > 32 {
        anyhow::bail!("Invalid prefix length: {}", prefix_len);
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    Ok((addr, mask))
}

/// Get interface index by name
fn get_ifindex(name: &str) -> Result<u32> {
    let index = nix::net::if_::if_nametoindex(name)
        .with_context(|| format!("Failed to get index for interface: {}", name))?;
    Ok(index)
}
