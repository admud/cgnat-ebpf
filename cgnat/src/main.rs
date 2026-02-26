//! CGNAT Userspace Controller
//!
//! Loads the XDP program and manages NAT bindings.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, DevMap, PerCpuArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use cgnat_common::{NatConfig, NatStats, PortAllocState};
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;

#[derive(Debug, Parser)]
#[command(name = "cgnat", about = "eBPF/XDP CGNAT implementation")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the CGNAT daemon
    Run {
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

        /// Print statistics every N seconds (0 to disable)
        #[arg(long, default_value = "5")]
        stats_interval: u64,

        /// Use SKB mode instead of driver mode (more compatible but slower)
        #[arg(long)]
        skb_mode: bool,
    },
    /// Show current statistics
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    match args.command {
        Commands::Run {
            external_iface,
            internal_iface,
            external_addr,
            internal_subnet,
            port_min,
            port_max,
            stats_interval,
            skb_mode,
        } => {
            run_cgnat(
                external_iface,
                internal_iface,
                external_addr,
                internal_subnet,
                port_min,
                port_max,
                stats_interval,
                skb_mode,
            )
            .await
        }
        Commands::Stats => {
            println!("Stats command not implemented in standalone mode");
            println!("Use 'run' command with --stats-interval to see live stats");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_cgnat(
    external_iface: String,
    internal_iface: String,
    external_addr: Ipv4Addr,
    internal_subnet: String,
    port_min: u16,
    port_max: u16,
    stats_interval: u64,
    skb_mode: bool,
) -> Result<()> {
    // Parse internal subnet
    let (subnet_addr, subnet_mask) = parse_cidr(&internal_subnet)?;

    // Validate port range
    if port_min > port_max {
        anyhow::bail!(
            "Invalid port range: port_min ({}) must be <= port_max ({})",
            port_min,
            port_max
        );
    }
    if port_min == 0 {
        anyhow::bail!("Invalid port_min: must be > 0 (port 0 is reserved)");
    }

    info!("Starting CGNAT");
    info!("  External interface: {}", external_iface);
    info!("  Internal interface: {}", internal_iface);
    info!("  External address: {}", external_addr);
    info!("  Internal subnet: {}", internal_subnet);
    info!("  Port range: {}-{}", port_min, port_max);

    // Load eBPF program
    // Load eBPF bytecode (built separately in cgnat-ebpf crate)
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../cgnat-ebpf/target/bpfel-unknown-none/debug/cgnat-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../cgnat-ebpf/target/bpfel-unknown-none/release/cgnat-ebpf"
    ))?;

    // Set up logging
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Get interface indices
    let external_ifindex = get_ifindex(&external_iface)?;
    let internal_ifindex = get_ifindex(&internal_iface)?;

    info!(
        "Interface indices: external={}, internal={}",
        external_ifindex, internal_ifindex
    );

    // Configure the program
    let config = NatConfig {
        external_addr: u32::from(external_addr),
        internal_subnet: u32::from(subnet_addr),
        internal_mask: subnet_mask,
        external_ifindex,
        internal_ifindex,
        port_min,
        port_max,
        ..Default::default()
    };

    // Write config to map
    let mut config_map: Array<_, NatConfig> = Array::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config_map.set(0, config, 0)?;

    // Initialize port allocation state
    let mut port_alloc: Array<_, PortAllocState> =
        Array::try_from(bpf.map_mut("PORT_ALLOC").unwrap())?;
    port_alloc.set(
        0,
        PortAllocState {
            next_port: 0,
            allocated_count: 0,
            alloc_failures: 0,
            alloc_success: 0,
        },
        0,
    )?;

    // Set up device map for XDP_REDIRECT
    let mut devmap: DevMap<_> = DevMap::try_from(bpf.map_mut("DEVMAP").unwrap())?;
    devmap.set(external_ifindex, external_ifindex, None, 0)?;
    devmap.set(internal_ifindex, internal_ifindex, None, 0)?;

    // Attach XDP program to both interfaces
    let program: &mut Xdp = bpf.program_mut("cgnat_xdp").unwrap().try_into()?;
    program.load()?;

    let xdp_flags = if skb_mode {
        info!("Using SKB mode (generic XDP)");
        XdpFlags::SKB_MODE
    } else {
        info!("Using driver mode (native XDP)");
        XdpFlags::default()
    };

    // Try to attach, fall back to SKB mode if driver mode fails
    match program.attach(&external_iface, xdp_flags) {
        Ok(_) => info!("Attached XDP to external interface: {}", external_iface),
        Err(e) if !skb_mode => {
            warn!("Driver mode failed ({}), falling back to SKB mode", e);
            program
                .attach(&external_iface, XdpFlags::SKB_MODE)
                .context("Failed to attach to external interface")?;
            info!(
                "Attached XDP (SKB mode) to external interface: {}",
                external_iface
            );
        }
        Err(e) => return Err(e).context("Failed to attach to external interface"),
    }

    match program.attach(&internal_iface, xdp_flags) {
        Ok(_) => info!("Attached XDP to internal interface: {}", internal_iface),
        Err(e) if !skb_mode => {
            warn!("Driver mode failed ({}), falling back to SKB mode", e);
            program
                .attach(&internal_iface, XdpFlags::SKB_MODE)
                .context("Failed to attach to internal interface")?;
            info!(
                "Attached XDP (SKB mode) to internal interface: {}",
                internal_iface
            );
        }
        Err(e) => return Err(e).context("Failed to attach to internal interface"),
    }

    info!("CGNAT running. Press Ctrl+C to exit.");

    // Main loop with stats printing
    let mut stats_ticker = interval(Duration::from_secs(stats_interval.max(1)));
    let mut last_stats = NatStats::default();

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
            _ = stats_ticker.tick(), if stats_interval > 0 => {
                // Get stats
                if let Ok(stats_map) = PerCpuArray::<_, NatStats>::try_from(bpf.map("STATS").unwrap()) {
                    if let Ok(port_alloc_map) = Array::<_, PortAllocState>::try_from(bpf.map("PORT_ALLOC").unwrap()) {
                        print_stats(&stats_map, &port_alloc_map, stats_interval, &mut last_stats);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Print statistics once
fn print_stats(
    stats_map: &PerCpuArray<&aya::maps::MapData, NatStats>,
    port_alloc_map: &Array<&aya::maps::MapData, PortAllocState>,
    interval_secs: u64,
    last_stats: &mut NatStats,
) {
    // Aggregate per-CPU stats
    let mut total = NatStats::default();
    if let Ok(per_cpu_values) = stats_map.get(&0, 0) {
        for cpu_stats in per_cpu_values.iter() {
            total.packets_total += cpu_stats.packets_total;
            total.packets_nat_hit += cpu_stats.packets_nat_hit;
            total.packets_nat_miss += cpu_stats.packets_nat_miss;
            total.packets_outbound += cpu_stats.packets_outbound;
            total.packets_inbound += cpu_stats.packets_inbound;
            total.packets_hairpin += cpu_stats.packets_hairpin;
            total.packets_dropped += cpu_stats.packets_dropped;
            total.packets_icmp += cpu_stats.packets_icmp;
            total.bytes_total += cpu_stats.bytes_total;
        }
    }

    // Get port allocation stats
    let port_alloc = port_alloc_map.get(&0, 0).unwrap_or_default();

    // Calculate rates
    let pps = total
        .packets_total
        .saturating_sub(last_stats.packets_total)
        .checked_div(interval_secs)
        .unwrap_or(0);
    let bps = total
        .bytes_total
        .saturating_sub(last_stats.bytes_total)
        .saturating_mul(8)
        .checked_div(interval_secs)
        .unwrap_or(0);

    println!("\n=== CGNAT Statistics ===");
    println!(
        "Packets: {} total ({} pps), {} bytes ({} bps)",
        total.packets_total, pps, total.bytes_total, bps
    );
    println!(
        "NAT: {} hits, {} misses ({:.1}% hit rate)",
        total.packets_nat_hit,
        total.packets_nat_miss,
        if total.packets_nat_hit + total.packets_nat_miss > 0 {
            total.packets_nat_hit as f64 / (total.packets_nat_hit + total.packets_nat_miss) as f64
                * 100.0
        } else {
            0.0
        }
    );
    println!(
        "Direction: {} outbound, {} inbound, {} hairpin",
        total.packets_outbound, total.packets_inbound, total.packets_hairpin
    );
    println!(
        "ICMP: {}, Dropped: {}",
        total.packets_icmp, total.packets_dropped
    );
    println!(
        "Ports: {} allocated, {} success, {} failures",
        port_alloc.allocated_count, port_alloc.alloc_success, port_alloc.alloc_failures
    );

    *last_stats = total;
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
