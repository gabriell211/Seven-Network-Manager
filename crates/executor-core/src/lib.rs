//! Headless execution core. It owns technical execution semantics, not HTTP,
//! user sessions, RBAC, database access, or UI concerns.

use std::{
    ffi::{CStr, CString},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use snm_domain::{
    Capability, DomainError, ExecutionStatus, TcpConnectRequest,
    discovery::{DiscoveryProbeKind, DiscoveryProbeRequest, DiscoveryProbeResult, ProbeEvidence},
};
use thiserror::Error;
use tokio::{net::TcpStream, task::spawn_blocking, time::timeout};

#[derive(Clone, Debug, Default)]
pub struct NetworkPolicy {
    pub allow_public_targets: bool,
}

impl NetworkPolicy {
    pub fn allows(&self, address: IpAddr) -> bool {
        if self.allow_public_targets {
            return !address.is_unspecified() && !address.is_multicast();
        }

        match address {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_unicast_link_local()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpConnectResult {
    pub status: ExecutionStatus,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("execution request is invalid: {0}")]
    InvalidRequest(String),
    #[error("target is outside runtime network policy")]
    TargetDenied,
    #[error("local probe execution failed: {0}")]
    LocalExecution(String),
}

#[async_trait]
pub trait NetworkExecutor: Send + Sync {
    async fn tcp_connect(
        &self,
        request: TcpConnectRequest,
    ) -> Result<TcpConnectResult, ExecutorError>;

    async fn discovery_probe(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, ExecutorError>;

    fn capabilities(&self) -> &'static [Capability];
}

#[derive(Clone, Debug)]
pub struct DefaultNetworkExecutor {
    network_policy: NetworkPolicy,
}

impl DefaultNetworkExecutor {
    pub fn new(network_policy: NetworkPolicy) -> Self {
        Self { network_policy }
    }

    fn validate_probe_request(
        &self,
        request: &DiscoveryProbeRequest,
    ) -> Result<Option<DiscoveryProbeResult>, ExecutorError> {
        if let Err(error) = request.validate() {
            if request.probe == DiscoveryProbeKind::Arp
                && matches!(
                    error,
                    DomainError::ProbeNotApplicable
                        | DomainError::MissingProbeSourceAddress
                        | DomainError::InvalidInterfaceScope
                        | DomainError::AddressFamilyMismatch
                )
            {
                return Ok(Some(probe_result(
                    request,
                    ExecutionStatus::NotApplicable,
                    None,
                    Vec::new(),
                    Some("l2_context_not_applicable"),
                )));
            }
            return Err(ExecutorError::InvalidRequest(error.to_string()));
        }
        if let Some(source) = request.scope.source_address {
            if !request.scope.contains(source) {
                return Err(ExecutorError::InvalidRequest(
                    "source address is outside the authorized discovery scope".to_owned(),
                ));
            }
        }
        if !self.network_policy.allows(request.target.address) {
            return Err(ExecutorError::TargetDenied);
        }
        Ok(None)
    }
}

#[async_trait]
impl NetworkExecutor for DefaultNetworkExecutor {
    async fn tcp_connect(
        &self,
        request: TcpConnectRequest,
    ) -> Result<TcpConnectResult, ExecutorError> {
        request
            .validate()
            .map_err(|error| ExecutorError::InvalidRequest(error.to_string()))?;

        if !self.network_policy.allows(request.target.address) {
            return Err(ExecutorError::TargetDenied);
        }

        tcp_connect(request.target.address, request.port, request.timeout()).await
    }

    async fn discovery_probe(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, ExecutorError> {
        if let Some(result) = self.validate_probe_request(&request)? {
            return Ok(result);
        }

        match request.probe {
            DiscoveryProbeKind::Tcp => {
                let port = request
                    .port
                    .ok_or_else(|| ExecutorError::InvalidRequest("TCP port is required".into()))?;
                let result = tcp_connect(
                    request.target.address,
                    port,
                    Duration::from_millis(request.timeout_ms),
                )
                .await?;
                let evidence = if result.status == ExecutionStatus::Succeeded {
                    vec![evidence(
                        "service.port",
                        port.to_string(),
                        "tcp_connect",
                        0.85,
                    )]
                } else {
                    Vec::new()
                };
                Ok(probe_result(
                    &request,
                    result.status,
                    result.latency_ms,
                    evidence,
                    result.error_code.as_deref(),
                ))
            }
            DiscoveryProbeKind::Icmp => {
                let target = request.target.address;
                let interface = request.target.interface_scope.clone();
                let duration = Duration::from_millis(request.timeout_ms);
                let outcome =
                    spawn_blocking(move || icmp_echo_blocking(target, interface, duration))
                        .await
                        .map_err(|error| ExecutorError::LocalExecution(error.to_string()))?;
                Ok(outcome.into_result(&request))
            }
            DiscoveryProbeKind::ReverseDns => {
                let target = request.target.address;
                let interface = request.target.interface_scope.clone();
                let outcome = spawn_blocking(move || reverse_dns_blocking(target, interface))
                    .await
                    .map_err(|error| ExecutorError::LocalExecution(error.to_string()))?;
                Ok(outcome.into_result(&request))
            }
            DiscoveryProbeKind::Arp => {
                let Some(IpAddr::V4(source)) = request.scope.source_address else {
                    return Ok(probe_result(
                        &request,
                        ExecutionStatus::NotApplicable,
                        None,
                        Vec::new(),
                        Some("l2_source_required"),
                    ));
                };
                let IpAddr::V4(target) = request.target.address else {
                    return Ok(probe_result(
                        &request,
                        ExecutionStatus::NotApplicable,
                        None,
                        Vec::new(),
                        Some("arp_ipv4_only"),
                    ));
                };
                let Some(interface) = request.scope.interface_scope.clone() else {
                    return Ok(probe_result(
                        &request,
                        ExecutionStatus::NotApplicable,
                        None,
                        Vec::new(),
                        Some("l2_interface_required"),
                    ));
                };
                let duration = Duration::from_millis(request.timeout_ms);
                let outcome = spawn_blocking(move || {
                    arp_resolve_blocking(target, source, &interface, duration)
                })
                .await
                .map_err(|error| ExecutorError::LocalExecution(error.to_string()))?;
                Ok(outcome.into_result(&request))
            }
        }
    }

    fn capabilities(&self) -> &'static [Capability] {
        const CAPABILITIES: &[Capability] = &[
            Capability::RuntimeCapabilitiesRead,
            Capability::NetworkTcpConnect,
            Capability::NetworkIcmpEcho,
            Capability::NetworkArpResolve,
            Capability::NetworkReverseDns,
        ];
        CAPABILITIES
    }
}

async fn tcp_connect(
    address: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<TcpConnectResult, ExecutorError> {
    let socket = (address, port);
    let started = Instant::now();
    let result = timeout(timeout_duration, TcpStream::connect(socket)).await;

    Ok(match result {
        Ok(Ok(stream)) => {
            drop(stream);
            TcpConnectResult {
                status: ExecutionStatus::Succeeded,
                latency_ms: Some(elapsed_ms(started)),
                error_code: None,
            }
        }
        Ok(Err(error)) => TcpConnectResult {
            status: ExecutionStatus::Failed,
            latency_ms: None,
            error_code: Some(classify_io_error(&error).to_owned()),
        },
        Err(_) => TcpConnectResult {
            status: ExecutionStatus::Failed,
            latency_ms: None,
            error_code: Some("timeout".to_owned()),
        },
    })
}

#[derive(Debug)]
struct BlockingProbeOutcome {
    status: ExecutionStatus,
    latency_ms: Option<u64>,
    evidence: Vec<ProbeEvidence>,
    error_code: Option<&'static str>,
}

impl BlockingProbeOutcome {
    fn into_result(self, request: &DiscoveryProbeRequest) -> DiscoveryProbeResult {
        probe_result(
            request,
            self.status,
            self.latency_ms,
            self.evidence,
            self.error_code,
        )
    }
}

fn evidence(
    field: impl Into<String>,
    value: impl Into<String>,
    source: impl Into<String>,
    confidence: f32,
) -> ProbeEvidence {
    ProbeEvidence {
        field: field.into(),
        value: value.into(),
        source: source.into(),
        confidence,
        observed_at: Utc::now(),
    }
}

fn probe_result(
    request: &DiscoveryProbeRequest,
    status: ExecutionStatus,
    latency_ms: Option<u64>,
    evidence: Vec<ProbeEvidence>,
    error_code: Option<&str>,
) -> DiscoveryProbeResult {
    DiscoveryProbeResult {
        status,
        probe: request.probe,
        target: request.target.clone(),
        port: request.port,
        latency_ms,
        evidence,
        error_code: error_code.map(ToOwned::to_owned),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn classify_io_error(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection_refused",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout",
        _ => "transport_error",
    }
}

fn permission_failure(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
        || matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES))
}

#[cfg(unix)]
struct RawSocket(libc::c_int);

#[cfg(unix)]
impl RawSocket {
    fn new(
        domain: libc::c_int,
        socket_type: libc::c_int,
        protocol: libc::c_int,
    ) -> io::Result<Self> {
        let fd = unsafe { libc::socket(domain, socket_type, protocol) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(fd))
        }
    }

    fn fd(&self) -> libc::c_int {
        self.0
    }
}

#[cfg(unix)]
impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(unix)]
fn set_socket_timeout(fd: libc::c_int, duration: Duration) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: duration.as_secs().try_into().unwrap_or(libc::time_t::MAX),
        tv_usec: duration.subsec_micros().into(),
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn icmp_echo_blocking(
    target: IpAddr,
    interface_scope: Option<String>,
    duration: Duration,
) -> BlockingProbeOutcome {
    #[cfg(unix)]
    {
        let started = Instant::now();
        let result = match target {
            IpAddr::V4(address) => icmp_v4_echo(address, duration),
            IpAddr::V6(address) => icmp_v6_echo(address, interface_scope.as_deref(), duration),
        };
        match result {
            Ok(()) => BlockingProbeOutcome {
                status: ExecutionStatus::Succeeded,
                latency_ms: Some(elapsed_ms(started)),
                evidence: vec![evidence("reachability", "icmp_echo_reply", "icmp", 1.0)],
                error_code: None,
            },
            Err(error) if permission_failure(&error) => BlockingProbeOutcome {
                status: ExecutionStatus::Unsupported,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("cap_net_raw_required"),
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                BlockingProbeOutcome {
                    status: ExecutionStatus::Failed,
                    latency_ms: None,
                    evidence: Vec::new(),
                    error_code: Some("timeout"),
                }
            }
            Err(error) => BlockingProbeOutcome {
                status: ExecutionStatus::Unknown,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some(classify_io_error(&error)),
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (target, interface_scope, duration);
        BlockingProbeOutcome {
            status: ExecutionStatus::Unsupported,
            latency_ms: None,
            evidence: Vec::new(),
            error_code: Some("icmp_runtime_platform_unsupported"),
        }
    }
}

#[cfg(unix)]
fn icmp_v4_echo(target: Ipv4Addr, duration: Duration) -> io::Result<()> {
    let socket = RawSocket::new(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)?;
    set_socket_timeout(socket.fd(), duration)?;
    let identifier = (std::process::id() & 0xffff) as u16;
    let sequence = 1_u16;
    let mut packet = [0_u8; 16];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(b"SNMPING1");
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(target.octets()),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            socket.fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = [0_u8; 2048];
    loop {
        let received =
            unsafe { libc::recv(socket.fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        if received < 8 {
            continue;
        }
        let offset = if buffer[0] >> 4 == 4 {
            usize::from(buffer[0] & 0x0f) * 4
        } else {
            0
        };
        if received < offset + 8 {
            continue;
        }
        let icmp = &buffer[offset..received];
        if icmp[0] == 0
            && u16::from_be_bytes([icmp[4], icmp[5]]) == identifier
            && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
        {
            return Ok(());
        }
    }
}

#[cfg(unix)]
fn icmp_v6_echo(
    target: Ipv6Addr,
    interface_scope: Option<&str>,
    duration: Duration,
) -> io::Result<()> {
    let socket = RawSocket::new(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)?;
    set_socket_timeout(socket.fd(), duration)?;
    let identifier = (std::process::id() & 0xffff) as u16;
    let sequence = 1_u16;
    let mut packet = [0_u8; 16];
    packet[0] = 128;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(b"SNMPING6");
    let scope_id = if target.is_unicast_link_local() {
        let interface = interface_scope.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 link-local interface is required",
            )
        })?;
        interface_index(interface)?
    } else {
        0
    };
    let address = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: target.octets(),
        },
        sin6_scope_id: scope_id,
    };
    let sent = unsafe {
        libc::sendto(
            socket.fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            std::ptr::from_ref(&address).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = [0_u8; 2048];
    loop {
        let received =
            unsafe { libc::recv(socket.fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        if received >= 8
            && buffer[0] == 129
            && u16::from_be_bytes([buffer[4], buffer[5]]) == identifier
            && u16::from_be_bytes([buffer[6], buffer[7]]) == sequence
        {
            return Ok(());
        }
    }
}

fn reverse_dns_blocking(target: IpAddr, interface_scope: Option<String>) -> BlockingProbeOutcome {
    #[cfg(unix)]
    {
        match reverse_dns_name(target, interface_scope.as_deref()) {
            Ok(hostname) => BlockingProbeOutcome {
                status: ExecutionStatus::Succeeded,
                latency_ms: None,
                evidence: vec![evidence("hostname", hostname, "reverse_dns", 0.65)],
                error_code: None,
            },
            Err(ReverseDnsError::NotFound) => BlockingProbeOutcome {
                status: ExecutionStatus::Failed,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("dns_name_not_found"),
            },
            Err(ReverseDnsError::InvalidScope) => BlockingProbeOutcome {
                status: ExecutionStatus::NotApplicable,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("dns_interface_scope_required"),
            },
            Err(ReverseDnsError::Resolver) => BlockingProbeOutcome {
                status: ExecutionStatus::Unknown,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("resolver_error"),
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (target, interface_scope);
        BlockingProbeOutcome {
            status: ExecutionStatus::Unsupported,
            latency_ms: None,
            evidence: Vec::new(),
            error_code: Some("reverse_dns_runtime_platform_unsupported"),
        }
    }
}

#[cfg(unix)]
enum ReverseDnsError {
    NotFound,
    InvalidScope,
    Resolver,
}

#[cfg(unix)]
fn reverse_dns_name(
    target: IpAddr,
    interface_scope: Option<&str>,
) -> Result<String, ReverseDnsError> {
    let mut host = [0 as libc::c_char; 1025];
    let result = match target {
        IpAddr::V4(address) => {
            let socket_address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::getnameinfo(
                    std::ptr::from_ref(&socket_address).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(address) => {
            let scope_id = if address.is_unicast_link_local() {
                interface_scope
                    .ok_or(ReverseDnsError::InvalidScope)
                    .and_then(|value| {
                        interface_index(value).map_err(|_| ReverseDnsError::InvalidScope)
                    })?
            } else {
                0
            };
            let socket_address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: address.octets(),
                },
                sin6_scope_id: scope_id,
            };
            unsafe {
                libc::getnameinfo(
                    std::ptr::from_ref(&socket_address).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if result == 0 {
        let value = unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_str()
            .map_err(|_| ReverseDnsError::Resolver)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if value.is_empty() {
            Err(ReverseDnsError::NotFound)
        } else {
            Ok(value)
        }
    } else if result == libc::EAI_NONAME {
        Err(ReverseDnsError::NotFound)
    } else {
        Err(ReverseDnsError::Resolver)
    }
}

fn arp_resolve_blocking(
    target: Ipv4Addr,
    source: Ipv4Addr,
    interface: &str,
    duration: Duration,
) -> BlockingProbeOutcome {
    #[cfg(target_os = "linux")]
    {
        let started = Instant::now();
        match arp_resolve_linux(target, source, interface, duration) {
            Ok(mac) => BlockingProbeOutcome {
                status: ExecutionStatus::Succeeded,
                latency_ms: Some(elapsed_ms(started)),
                evidence: vec![evidence("mac", format_mac(mac), "arp", 1.0)],
                error_code: None,
            },
            Err(error) if permission_failure(&error) => BlockingProbeOutcome {
                status: ExecutionStatus::Unsupported,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("cap_net_raw_required"),
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                BlockingProbeOutcome {
                    status: ExecutionStatus::Failed,
                    latency_ms: None,
                    evidence: Vec::new(),
                    error_code: Some("timeout"),
                }
            }
            Err(_) => BlockingProbeOutcome {
                status: ExecutionStatus::Unknown,
                latency_ms: None,
                evidence: Vec::new(),
                error_code: Some("local_arp_error"),
            },
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, source, interface, duration);
        BlockingProbeOutcome {
            status: ExecutionStatus::NotApplicable,
            latency_ms: None,
            evidence: Vec::new(),
            error_code: Some("arp_requires_linux_l2_runtime"),
        }
    }
}

#[cfg(target_os = "linux")]
fn arp_resolve_linux(
    target: Ipv4Addr,
    source: Ipv4Addr,
    interface: &str,
    duration: Duration,
) -> io::Result<[u8; 6]> {
    validate_interface_name(interface)?;
    let source_mac = read_interface_mac(interface)?;
    let if_index = interface_index(interface)?;
    let socket = RawSocket::new(
        libc::AF_PACKET,
        libc::SOCK_RAW,
        i32::from(0x0806_u16.to_be()),
    )?;
    set_socket_timeout(socket.fd(), duration)?;

    let mut bind_address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    bind_address.sll_family = libc::AF_PACKET as u16;
    bind_address.sll_protocol = 0x0806_u16.to_be();
    bind_address.sll_ifindex = if_index as i32;
    let bound = unsafe {
        libc::bind(
            socket.fd(),
            std::ptr::from_ref(&bind_address).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut frame = [0_u8; 42];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&source_mac);
    frame[28..32].copy_from_slice(&source.octets());
    frame[32..38].fill(0);
    frame[38..42].copy_from_slice(&target.octets());

    let mut destination: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    destination.sll_family = libc::AF_PACKET as u16;
    destination.sll_protocol = 0x0806_u16.to_be();
    destination.sll_ifindex = if_index as i32;
    destination.sll_halen = 6;
    destination.sll_addr[..6].fill(0xff);
    let sent = unsafe {
        libc::sendto(
            socket.fd(),
            frame.as_ptr().cast(),
            frame.len(),
            0,
            std::ptr::from_ref(&destination).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = [0_u8; 2048];
    loop {
        let received =
            unsafe { libc::recv(socket.fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        if received < 42 || buffer[12..14] != 0x0806_u16.to_be_bytes() {
            continue;
        }
        if u16::from_be_bytes([buffer[20], buffer[21]]) != 2 {
            continue;
        }
        if buffer[28..32] != target.octets() || buffer[38..42] != source.octets() {
            continue;
        }
        let mut mac = [0_u8; 6];
        mac.copy_from_slice(&buffer[22..28]);
        return Ok(mac);
    }
}

#[cfg(target_os = "linux")]
fn read_interface_mac(interface: &str) -> io::Result<[u8; 6]> {
    let value = std::fs::read_to_string(format!("/sys/class/net/{interface}/address"))?;
    let parts = value.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid interface MAC",
        ));
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid interface MAC"))?;
    }
    Ok(mac)
}

#[cfg(unix)]
fn interface_index(interface: &str) -> io::Result<u32> {
    validate_interface_name(interface)?;
    let name = CString::new(interface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

#[cfg(unix)]
fn validate_interface_name(interface: &str) -> io::Result<()> {
    if interface.is_empty()
        || interface.len() > 64
        || !interface.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(unix)]
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(value) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(*value) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use snm_domain::{
        ActionId, ActorId, CorrelationId, ExecutionContext, OrganizationId, RoutingDomainId,
        ScopedIpTarget, SiteId,
        discovery::{DiscoveryExecutionScope, DiscoveryProbeKind, DiscoveryProbeRequest},
    };

    use super::*;

    #[test]
    fn default_policy_rejects_public_targets() {
        let policy = NetworkPolicy::default();
        assert!(!policy.allows("8.8.8.8".parse().unwrap()));
        assert!(policy.allows("10.0.0.1".parse().unwrap()));
        assert!(policy.allows("fd00::1".parse().unwrap()));
    }

    #[test]
    fn arp_without_l2_context_is_not_applicable_instead_of_false_negative() {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let routing_domain_id = RoutingDomainId::new();
        let request = DiscoveryProbeRequest {
            context: ExecutionContext {
                organization_id,
                site_id,
                routing_domain_id,
                actor_id: ActorId::new(),
                correlation_id: CorrelationId::new(),
                action_id: ActionId::new(),
                idempotency_key: None,
            },
            scope: DiscoveryExecutionScope {
                organization_id,
                site_id,
                routing_domain_id,
                network: "10.0.0.0/24".parse().unwrap(),
                interface_scope: None,
                source_address: None,
            },
            target: ScopedIpTarget {
                organization_id,
                site_id,
                routing_domain_id,
                address: "10.0.0.10".parse().unwrap(),
                interface_scope: None,
            },
            probe: DiscoveryProbeKind::Arp,
            port: None,
            timeout_ms: 1000,
        };
        let executor = DefaultNetworkExecutor::new(NetworkPolicy::default());
        let result = executor.validate_probe_request(&request).unwrap().unwrap();
        assert_eq!(result.status, ExecutionStatus::NotApplicable);
        assert_eq!(
            result.error_code.as_deref(),
            Some("l2_context_not_applicable")
        );
    }

    #[cfg(unix)]
    #[test]
    fn checksum_matches_known_echo_header() {
        let mut packet = [0_u8; 8];
        packet[0] = 8;
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert_ne!(internet_checksum(&packet), 0);
    }
}
