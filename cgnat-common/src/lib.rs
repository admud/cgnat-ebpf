//! Shared types between userspace and eBPF programs.
//!
//! This crate is `no_std` compatible for use in eBPF programs.

#![no_std]

/// NAT binding key - identifies a connection from the internal side
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatBindingKey {
    /// Internal (private) IPv4 address
    pub internal_addr: u32,
    /// Internal port
    pub internal_port: u16,
    /// Protocol (IPPROTO_TCP = 6, IPPROTO_UDP = 17)
    pub protocol: u8,
    /// Padding for alignment
    pub _pad: u8,
}

/// NAT binding value - the external mapping
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatBindingValue {
    /// External (public) IPv4 address
    pub external_addr: u32,
    /// External port
    pub external_port: u16,
    /// Padding for alignment
    pub _pad: [u8; 2],
}

/// Reverse NAT lookup key - for inbound packets
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatReverseKey {
    /// External (public) IPv4 address
    pub external_addr: u32,
    /// External port
    pub external_port: u16,
    /// Protocol
    pub protocol: u8,
    /// Padding
    pub _pad: u8,
}

/// Connection state for stateful tracking
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnState {
    /// Last packet timestamp (nanoseconds)
    pub last_seen: u64,
    /// Packets in->out
    pub packets_out: u64,
    /// Packets out->in
    pub packets_in: u64,
    /// Bytes in->out
    pub bytes_out: u64,
    /// Bytes out->in
    pub bytes_in: u64,
    /// TCP state (for TCP connections)
    pub tcp_state: u8,
    /// Flags
    pub flags: u8,
    /// Padding
    pub _pad: [u8; 6],
}

/// TCP connection states
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    None = 0,
    SynSent = 1,
    SynReceived = 2,
    Established = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    CloseWait = 6,
    Closing = 7,
    LastAck = 8,
    TimeWait = 9,
    Closed = 10,
}

/// Port allocation state (for atomic port counter)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PortAllocState {
    /// Next port to try (wraps around within port_min..port_max)
    pub next_port: u32,
    /// Number of ports currently allocated
    pub allocated_count: u32,
    /// Number of allocation failures (port exhaustion)
    pub alloc_failures: u64,
    /// Number of successful allocations
    pub alloc_success: u64,
}

/// Statistics counters
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NatStats {
    /// Total packets processed
    pub packets_total: u64,
    /// Packets that matched NAT bindings
    pub packets_nat_hit: u64,
    /// Packets that missed (no binding)
    pub packets_nat_miss: u64,
    /// Outbound packets (SNAT)
    pub packets_outbound: u64,
    /// Inbound packets (DNAT)
    pub packets_inbound: u64,
    /// Hairpin packets
    pub packets_hairpin: u64,
    /// Dropped packets
    pub packets_dropped: u64,
    /// ICMP packets processed
    pub packets_icmp: u64,
    /// Bytes processed (total)
    pub bytes_total: u64,
}

/// Configuration passed to eBPF program
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NatConfig {
    /// External IPv4 address for SNAT
    pub external_addr: u32,
    /// Internal subnet (network address)
    pub internal_subnet: u32,
    /// Internal subnet mask
    pub internal_mask: u32,
    /// External interface index (for XDP_REDIRECT)
    pub external_ifindex: u32,
    /// Internal interface index (for hairpin XDP_REDIRECT)
    pub internal_ifindex: u32,
    /// Minimum port for allocation
    pub port_min: u16,
    /// Maximum port for allocation
    pub port_max: u16,
    /// UDP timeout in seconds (reserved for future use — GC currently uses hardcoded constants)
    pub udp_timeout: u32,
    /// TCP established timeout in seconds (reserved — see above)
    pub tcp_established_timeout: u32,
    /// TCP transitory timeout in seconds (reserved — see above)
    pub tcp_transitory_timeout: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            external_addr: 0,
            internal_subnet: 0,
            internal_mask: 0,
            external_ifindex: 0,
            internal_ifindex: 0,
            port_min: 1024,
            port_max: 65535,
            udp_timeout: 300,              // 5 minutes
            tcp_established_timeout: 7200, // 2 hours
            tcp_transitory_timeout: 240,   // 4 minutes
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NatBindingKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NatBindingValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NatReverseKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NatConfig {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortAllocState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NatStats {}
