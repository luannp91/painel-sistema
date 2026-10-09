//! Análise de conexões e portas escutando por processo.
//!
//! Tipos + regras puras. Coleta real dos sockets acontece em
//! `sysinfo::sockets` (por SO), que produz um [`SocketSnapshot`].
//!
//! Sem I/O.

use std::net::IpAddr;

use serde::Serialize;

use super::mitre;
use super::types::{Finding, FindingKind};

/// Protocolo de transporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Estado de uma conexão TCP (UDP sempre `Listen` por convenção —
/// UDP é sem estado no SO).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Listen,
    Established,
    TimeWait,
    CloseWait,
    SynSent,
    SynRecv,
    Other,
}

/// Conexão observada, associada ao PID dono do socket.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: ConnectionState,
}

/// Porta escutando (bind), associada ao PID dono.
#[derive(Debug, Clone, Serialize)]
pub struct ListeningPort {
    pub pid: u32,
    pub protocol: Protocol,
    pub bind_addr: IpAddr,
    pub port: u16,
}

/// Conjunto de sockets observados no SO num ciclo.
///
/// Produzido por `sysinfo::sockets::collect`, consumido pelo
/// [`super::engine::Engine`] e serializado no `SecuritySnapshot`.
#[derive(Debug, Default, Clone, Serialize)]
pub struct SocketSnapshot {
    pub listening: Vec<ListeningPort>,
    pub connections: Vec<NetworkConnection>,
}

impl SocketSnapshot {
    pub fn is_empty(&self) -> bool {
        self.listening.is_empty() && self.connections.is_empty()
    }

    pub fn total(&self) -> usize {
        self.listening.len() + self.connections.len()
    }
}

// ---------------------------------------------------------------------------
// Regras
// ---------------------------------------------------------------------------

/// Acima disso, escutar é incomum para serviços de sistema.
const UNUSUAL_PORT_THRESHOLD: u16 = 10_000;

/// Portas baixas conhecidas — nunca sinalizadas como "porta alta".
const WELL_KNOWN_PORTS: &[u16] = &[
    22, 53, 80, 123, 137, 138, 139, 143, 443, 445, 465, 587, 993, 995,
];

/// Portas remotas de serviços sensíveis. Conexão ESTABELECIDA pra
/// IP público nestas portas é anômala em workstation — pode indicar
/// C2, exfiltração ou movimento lateral.
///
/// A lista é conservadora. A ideia não é bloquear, só elevar o score
/// e chamar atenção.
const SENSITIVE_REMOTE_PORTS: &[u16] = &[
    21,   // FTP
    23,   // Telnet
    25,   // SMTP (evitar relay)
    445,  // SMB (ransomware clássico)
    1433, // MSSQL
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5985, // WinRM HTTP
    5986, // WinRM HTTPS
];

/// Sinaliza porta alta escutando que não é de sistema.
///
/// `#[must_use]`: o caller precisa decidir se descarta ou agrega.
#[must_use]
pub fn check_listening(port: &ListeningPort) -> Option<Finding> {
    if WELL_KNOWN_PORTS.contains(&port.port) {
        return None;
    }
    if port.port < UNUSUAL_PORT_THRESHOLD {
        return None;
    }
    Some(Finding::new(
        FindingKind::UnusualListeningPort,
        format!(
            "PID {} escutando em {:?} {}:{}",
            port.pid, port.protocol, port.bind_addr, port.port
        ),
    ))
}

/// Sinaliza conexão estabelecida para IP público em porta de destino
/// suspeita. Ignora endereços privados/loopback.
///
/// Duas regras, em ordem de prioridade:
///
/// 1. **Porta sensível** (`SENSITIVE_REMOTE_PORTS`) → `SuspiciousRemotePort`
///    (peso 25, T1021 Remote Services).
/// 2. **Porta alta incomum** (fora de `COMMON_OUT`) → `ExternalConnection`
///    (peso 15, T1071).
#[must_use]
pub fn check_connection(conn: &NetworkConnection) -> Option<Finding> {
    if conn.state != ConnectionState::Established {
        return None;
    }
    let remote = conn.remote_addr?;
    let rport = conn.remote_port?;

    if !is_public_ip(remote) {
        return None;
    }

    if SENSITIVE_REMOTE_PORTS.contains(&rport) {
        return Some(Finding::with_technique(
            FindingKind::SuspiciousRemotePort,
            format!("conexão estabelecida para {remote}:{rport} (porta de serviço sensível)"),
            mitre::REMOTE_SERVICES,
        ));
    }

    const COMMON_OUT: &[u16] = &[53, 80, 123, 443, 8080, 8443];
    if COMMON_OUT.contains(&rport) {
        return None;
    }

    Some(Finding::new(
        FindingKind::ExternalConnection,
        format!("conexão estabelecida para {remote}:{rport}"),
    ))
}

/// `true` se o IP não é privado, loopback, link-local, multicast nem
/// documentação.
#[must_use]
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()),
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn conn(remote: IpAddr, rport: u16, state: ConnectionState) -> NetworkConnection {
        NetworkConnection {
            pid: 42,
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            local_port: 55555,
            remote_addr: Some(remote),
            remote_port: Some(rport),
            state,
        }
    }

    fn listening(port: u16) -> ListeningPort {
        ListeningPort {
            pid: 42,
            protocol: Protocol::Tcp,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
        }
    }

    #[test]
    fn listening_on_well_known_ok() {
        assert!(check_listening(&listening(443)).is_none());
        assert!(check_listening(&listening(22)).is_none());
    }

    #[test]
    fn listening_on_low_port_ignored() {
        assert!(check_listening(&listening(3000)).is_none());
    }

    #[test]
    fn listening_on_high_port_flagged() {
        let f = check_listening(&listening(44444)).unwrap();
        assert_eq!(f.kind, FindingKind::UnusualListeningPort);
        assert_eq!(f.weight, 20);
    }

    #[test]
    fn established_to_public_common_port_ok() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            ConnectionState::Established,
        );
        assert!(check_connection(&c).is_none());
    }

    #[test]
    fn established_to_public_uncommon_port_flagged() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            4444,
            ConnectionState::Established,
        );
        let f = check_connection(&c).unwrap();
        assert_eq!(f.kind, FindingKind::ExternalConnection);
        assert_eq!(f.weight, 15);
    }

    #[test]
    fn established_to_private_ignored() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            4444,
            ConnectionState::Established,
        );
        assert!(check_connection(&c).is_none());
    }

    #[test]
    fn non_established_ignored() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            4444,
            ConnectionState::SynSent,
        );
        assert!(check_connection(&c).is_none());
    }

    #[test]
    fn loopback_and_linklocal_not_public() {
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn socket_snapshot_helpers() {
        let mut s = SocketSnapshot::default();
        assert!(s.is_empty());
        assert_eq!(s.total(), 0);

        s.listening.push(listening(44444));
        assert!(!s.is_empty());
        assert_eq!(s.total(), 1);
    }

    // --- Bloco E: porta remota sensível ----------------------------------

    #[test]
    fn rdp_to_public_ip_flagged_as_sensitive() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            3389,
            ConnectionState::Established,
        );
        let f = check_connection(&c).unwrap();
        assert_eq!(f.kind, FindingKind::SuspiciousRemotePort);
        assert_eq!(f.weight, 25);
        assert_eq!(f.technique, Some(mitre::REMOTE_SERVICES));
    }

    #[test]
    fn smb_to_public_ip_flagged_as_sensitive() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            445,
            ConnectionState::Established,
        );
        let f = check_connection(&c).unwrap();
        assert_eq!(f.kind, FindingKind::SuspiciousRemotePort);
    }

    #[test]
    fn sensitive_port_to_private_ip_ignored() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            3389,
            ConnectionState::Established,
        );
        assert!(check_connection(&c).is_none());
    }

    #[test]
    fn mssql_to_public_ip_flagged_as_sensitive() {
        let c = conn(
            IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)),
            1433,
            ConnectionState::Established,
        );
        let f = check_connection(&c).unwrap();
        assert_eq!(f.kind, FindingKind::SuspiciousRemotePort);
    }
}
