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
    /// UDP timeout in seconds
    pub udp_timeout: u32,
    /// TCP established timeout in seconds
    pub tcp_established_timeout: u32,
    /// TCP transitory timeout in seconds
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
            udp_timeout: 300,           // 5 minutes
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
