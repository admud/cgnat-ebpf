//! CGNAT Userspace Controller
//!
//! Loads the XDP program and manages NAT bindings.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, DevMap, HashMap, PerCpuArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use cgnat_common::{
    ConnState, NatBindingKey, NatBindingValue, NatConfig, NatReverseKey, NatStats, PortAllocState,
};
use clap::{Parser, Subcommand};
use log::{info, warn};
use nix::time::{clock_gettime, ClockId};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;

/// Pin path for BPF maps (used by bpftool for debugging/testing)
const BPF_PIN_DIR: &str = "/sys/fs/bpf/cgnat";

/// Timeout constants (nanoseconds) matching bpf_ktime_get_ns() clock
const UDP_TIMEOUT_NS: u64 = 300 * 1_000_000_000; // 5 minutes
const TCP_ESTABLISHED_TIMEOUT_NS: u64 = 7200 * 1_000_000_000; // 2 hours
const TCP_TRANSITORY_TIMEOUT_NS: u64 = 240 * 1_000_000_000; // 4 minutes

/// TCP states from cgnat_common::TcpState
const TCP_STATE_ESTABLISHED: u8 = 3;
const TCP_STATE_CLOSED: u8 = 10;
const TCP_STATE_TIME_WAIT: u8 = 9;

/// Protocol numbers
const IPPROTO_TCP: u8 = 6;

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

        /// Run garbage collection every N seconds (default: 30)
        #[arg(long, default_value = "30")]
        gc_interval: u64,

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
            gc_interval,
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
                gc_interval,
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
    gc_interval: u64,
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
    info!("  GC interval: {}s", gc_interval);

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

    // Pin maps for external inspection (bpftool, tests)
    pin_maps(&mut bpf)?;

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

    // Main loop with stats printing and GC
    let mut stats_ticker = interval(Duration::from_secs(stats_interval.max(1)));
    let mut gc_ticker = interval(Duration::from_secs(gc_interval.max(1)));
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
            _ = gc_ticker.tick(), if gc_interval > 0 => {
                if let Err(e) = run_gc(&mut bpf) {
                    warn!("GC error: {:#}", e);
                }
            }
        }
    }

    // Cleanup pinned maps
    unpin_maps();

    Ok(())
}

/// Pin NAT maps to /sys/fs/bpf/cgnat/ for external inspection
fn pin_maps(bpf: &mut Ebpf) -> Result<()> {
    let pin_dir = Path::new(BPF_PIN_DIR);
    if !pin_dir.exists() {
        std::fs::create_dir_all(pin_dir)
            .with_context(|| format!("Failed to create pin dir: {}", BPF_PIN_DIR))?;
    }

    for name in &["NAT_BINDINGS", "NAT_REVERSE", "CONN_TRACK"] {
        let pin_path = pin_dir.join(name);
        // Remove stale pin if it exists
        let _ = std::fs::remove_file(&pin_path);
        if let Some(map) = bpf.map(name) {
            map.pin(&pin_path)
                .with_context(|| format!("Failed to pin map {} to {:?}", name, pin_path))?;
            info!("Pinned map {} to {:?}", name, pin_path);
        }
    }

    Ok(())
}

/// Remove pinned maps on shutdown
fn unpin_maps() {
    let pin_dir = Path::new(BPF_PIN_DIR);
    for name in &["NAT_BINDINGS", "NAT_REVERSE", "CONN_TRACK"] {
        let _ = std::fs::remove_file(pin_dir.join(name));
    }
    let _ = std::fs::remove_dir(pin_dir);
    info!("Cleaned up pinned maps");
}

/// Run garbage collection: scan CONN_TRACK for expired bindings and remove them.
///
/// Uses a phased approach to avoid borrow checker issues:
/// 1. Collect all keys and their conn state from CONN_TRACK
/// 2. Determine which are expired
/// 3. For expired entries, look up the binding value to reconstruct reverse keys
/// 4. Batch delete from all three maps
fn run_gc(bpf: &mut Ebpf) -> Result<()> {
    let now_ns = {
        let ts = clock_gettime(ClockId::CLOCK_MONOTONIC)
            .context("clock_gettime(CLOCK_MONOTONIC)")?;
        ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64
    };

    // Phase 1: Collect all CONN_TRACK keys and values
    let conn_track: HashMap<_, NatBindingKey, ConnState> =
        HashMap::try_from(bpf.map("CONN_TRACK").unwrap())?;

    let mut expired_keys: Vec<NatBindingKey> = Vec::new();
    let keys: Vec<NatBindingKey> = conn_track.keys().filter_map(|k| k.ok()).collect();

    for key in &keys {
        let state = match conn_track.get(key, 0) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let age_ns = now_ns.saturating_sub(state.last_seen);
        let is_expired = if key.protocol == IPPROTO_TCP {
            match state.tcp_state {
                TCP_STATE_CLOSED | TCP_STATE_TIME_WAIT => true, // Immediate cleanup
                TCP_STATE_ESTABLISHED => age_ns > TCP_ESTABLISHED_TIMEOUT_NS,
                _ => age_ns > TCP_TRANSITORY_TIMEOUT_NS, // SYN_SENT, FIN_WAIT, etc.
            }
        } else {
            age_ns > UDP_TIMEOUT_NS
        };

        if is_expired {
            expired_keys.push(*key);
        }
    }

    if expired_keys.is_empty() {
        return Ok(());
    }

    // Phase 2: Look up binding values to reconstruct reverse keys
    let nat_bindings: HashMap<_, NatBindingKey, NatBindingValue> =
        HashMap::try_from(bpf.map("NAT_BINDINGS").unwrap())?;

    let mut reverse_keys: Vec<NatReverseKey> = Vec::new();
    for key in &expired_keys {
        if let Ok(binding) = nat_bindings.get(key, 0) {
            reverse_keys.push(NatReverseKey {
                external_addr: binding.external_addr,
                external_port: binding.external_port,
                protocol: key.protocol,
                _pad: 0,
            });
        }
    }

    // Phase 3: Batch delete from all three maps
    let mut conn_track_mut: HashMap<_, NatBindingKey, ConnState> =
        HashMap::try_from(bpf.map_mut("CONN_TRACK").unwrap())?;
    for key in &expired_keys {
        let _ = conn_track_mut.remove(key);
    }

    let mut nat_bindings_mut: HashMap<_, NatBindingKey, NatBindingValue> =
        HashMap::try_from(bpf.map_mut("NAT_BINDINGS").unwrap())?;
    for key in &expired_keys {
        let _ = nat_bindings_mut.remove(key);
    }

    let mut nat_reverse_mut: HashMap<_, NatReverseKey, NatBindingKey> =
        HashMap::try_from(bpf.map_mut("NAT_REVERSE").unwrap())?;
    for key in &reverse_keys {
        let _ = nat_reverse_mut.remove(key);
    }

    // Correct allocated_count in PORT_ALLOC
    let removed = expired_keys.len() as u32;
    let mut port_alloc: Array<_, PortAllocState> =
        Array::try_from(bpf.map_mut("PORT_ALLOC").unwrap())?;
    if let Ok(mut state) = port_alloc.get(&0, 0) {
        state.allocated_count = state.allocated_count.saturating_sub(removed);
        let _ = port_alloc.set(0, state, 0);
    }

    info!("GC: removed {} expired bindings", removed);

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
