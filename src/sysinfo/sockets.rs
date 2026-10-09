//! Coletor cross-platform de sockets TCP/UDP.
//!
//! Alimenta o motor de análise (`security::network`) com dados reais
//! do SO. Cada plataforma tem um backend:
//!
//! - **Windows:** `GetExtendedTcpTable` / `GetExtendedUdpTable` com
//!   `TCP_TABLE_OWNER_PID_ALL` / `UDP_TABLE_OWNER_PID`.
//! - **Linux:** parse de `/proc/net/{tcp,tcp6,udp,udp6}` + mapeamento
//!   inode→pid via `/proc/<pid>/fd`.
//! - **macOS:** stub documentado — coleta real via `libproc` fica pra
//!   uma iteração futura.
//!
//! Falhas são silenciosas (log em debug). Ausência de dados de rede
//! não deve quebrar o ciclo de análise.

use crate::security::network::SocketSnapshot;

/// Coleta os sockets do SO. Nunca entra em pânico.
#[must_use]
pub fn collect() -> SocketSnapshot {
    imp::collect()
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_ESTAB,
        MIB_TCP_STATE_LISTEN, MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT,
        MIB_TCP_STATE_TIME_WAIT, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    use crate::security::network::{
        ConnectionState, ListeningPort, NetworkConnection, Protocol, SocketSnapshot,
    };

    pub fn collect() -> SocketSnapshot {
        let mut snap = SocketSnapshot::default();
        collect_tcp(&mut snap);
        collect_udp(&mut snap);
        snap
    }

    // -----------------------------------------------------------------
    // TCP
    // -----------------------------------------------------------------

    fn collect_tcp(snap: &mut SocketSnapshot) {
        if let Some(buf) = query_tcp(AF_INET as u32) {
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let n = unsafe { (*table).dwNumEntries as usize };
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };
            for row in rows {
                handle_tcp_v4(row, snap);
            }
        }
        if let Some(buf) = query_tcp(AF_INET6 as u32) {
            let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let n = unsafe { (*table).dwNumEntries as usize };
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };
            for row in rows {
                handle_tcp_v6(row, snap);
            }
        }
    }

    fn handle_tcp_v4(row: &MIB_TCPROW_OWNER_PID, snap: &mut SocketSnapshot) {
        push_tcp(
            row.dwOwningPid,
            IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
            parse_port(row.dwLocalPort),
            IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr))),
            parse_port(row.dwRemotePort),
            map_state(row.dwState),
            snap,
        );
    }

    fn handle_tcp_v6(row: &MIB_TCP6ROW_OWNER_PID, snap: &mut SocketSnapshot) {
        push_tcp(
            row.dwOwningPid,
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            parse_port(row.dwLocalPort),
            IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
            parse_port(row.dwRemotePort),
            map_state(row.dwState),
            snap,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn push_tcp(
        pid: u32,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        state: ConnectionState,
        snap: &mut SocketSnapshot,
    ) {
        let remote_zero = match remote_addr {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        };

        if state == ConnectionState::Listen {
            snap.listening.push(ListeningPort {
                pid,
                protocol: Protocol::Tcp,
                bind_addr: local_addr,
                port: local_port,
            });
        } else if !remote_zero && remote_port != 0 {
            snap.connections.push(NetworkConnection {
                pid,
                protocol: Protocol::Tcp,
                local_addr,
                local_port,
                remote_addr: Some(remote_addr),
                remote_port: Some(remote_port),
                state,
            });
        }
    }

    // -----------------------------------------------------------------
    // UDP (sempre tratado como listening — sem estado no SO)
    // -----------------------------------------------------------------

    fn collect_udp(snap: &mut SocketSnapshot) {
        if let Some(buf) = query_udp(AF_INET as u32) {
            let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let n = unsafe { (*table).dwNumEntries as usize };
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };
            for row in rows {
                push_udp_v4(row, snap);
            }
        }
        if let Some(buf) = query_udp(AF_INET6 as u32) {
            let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
            let n = unsafe { (*table).dwNumEntries as usize };
            let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };
            for row in rows {
                push_udp_v6(row, snap);
            }
        }
    }

    fn push_udp_v4(row: &MIB_UDPROW_OWNER_PID, snap: &mut SocketSnapshot) {
        snap.listening.push(ListeningPort {
            pid: row.dwOwningPid,
            protocol: Protocol::Udp,
            bind_addr: IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
            port: parse_port(row.dwLocalPort),
        });
    }

    fn push_udp_v6(row: &MIB_UDP6ROW_OWNER_PID, snap: &mut SocketSnapshot) {
        snap.listening.push(ListeningPort {
            pid: row.dwOwningPid,
            protocol: Protocol::Udp,
            bind_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port: parse_port(row.dwLocalPort),
        });
    }

    // -----------------------------------------------------------------
    // Queries de buffer
    // -----------------------------------------------------------------

    /// Duas chamadas: primeira com null só pega o tamanho; segunda com
    /// buffer dimensionado. Alocado como Vec<u32> pra garantir alinhamento
    /// 4 exigido pelas structs MIB_*.
    fn query_tcp(family: u32) -> Option<Vec<u32>> {
        let mut size: u32 = 0;
        let ret = unsafe {
            GetExtendedTcpTable(
                ptr::null_mut(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let words = (size as usize).div_ceil(4);
        let mut buf: Vec<u32> = vec![0; words];
        let ret = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if ret != NO_ERROR {
            return None;
        }
        Some(buf)
    }

    fn query_udp(family: u32) -> Option<Vec<u32>> {
        let mut size: u32 = 0;
        let ret = unsafe {
            GetExtendedUdpTable(
                ptr::null_mut(),
                &mut size,
                0,
                family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let words = (size as usize).div_ceil(4);
        let mut buf: Vec<u32> = vec![0; words];
        let ret = unsafe {
            GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                family,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if ret != NO_ERROR {
            return None;
        }
        Some(buf)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /// Windows guarda a porta em network byte order nos 16 bits baixos.
    fn parse_port(raw: u32) -> u16 {
        u16::from_be((raw & 0xFFFF) as u16)
    }

    fn map_state(raw: u32) -> ConnectionState {
        // windows-sys 0.61 expõe MIB_TCP_STATE_* como i32; dwState é u32.
        match raw as i32 {
            MIB_TCP_STATE_LISTEN => ConnectionState::Listen,
            MIB_TCP_STATE_ESTAB => ConnectionState::Established,
            MIB_TCP_STATE_TIME_WAIT => ConnectionState::TimeWait,
            MIB_TCP_STATE_CLOSE_WAIT => ConnectionState::CloseWait,
            MIB_TCP_STATE_SYN_SENT => ConnectionState::SynSent,
            MIB_TCP_STATE_SYN_RCVD => ConnectionState::SynRecv,
            _ => ConnectionState::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::HashMap;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::security::network::{
        ConnectionState, ListeningPort, NetworkConnection, Protocol, SocketSnapshot,
    };

    pub fn collect() -> SocketSnapshot {
        let inode_map = build_inode_map();
        let mut snap = SocketSnapshot::default();

        for (path, proto, is_v6) in [
            ("/proc/net/tcp", Protocol::Tcp, false),
            ("/proc/net/tcp6", Protocol::Tcp, true),
            ("/proc/net/udp", Protocol::Udp, false),
            ("/proc/net/udp6", Protocol::Udp, true),
        ] {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines().skip(1) {
                if let Some(entry) = parse_line(line, proto, is_v6, &inode_map) {
                    let is_udp = proto == Protocol::Udp;

                    if entry.state == ConnectionState::Listen || is_udp {
                        snap.listening.push(ListeningPort {
                            pid: entry.pid,
                            protocol: proto,
                            bind_addr: entry.local_addr,
                            port: entry.local_port,
                        });
                    }
                    if !is_udp
                        && entry.state != ConnectionState::Listen
                        && entry.remote_addr.is_some()
                    {
                        snap.connections.push(NetworkConnection {
                            pid: entry.pid,
                            protocol: proto,
                            local_addr: entry.local_addr,
                            local_port: entry.local_port,
                            remote_addr: entry.remote_addr,
                            remote_port: entry.remote_port,
                            state: entry.state,
                        });
                    }
                }
            }
        }

        snap
    }

    struct Entry {
        pid: u32,
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: Option<IpAddr>,
        remote_port: Option<u16>,
        state: ConnectionState,
    }

    fn parse_line(
        line: &str,
        proto: Protocol,
        is_v6: bool,
        inode_map: &HashMap<u64, u32>,
    ) -> Option<Entry> {
        // Colunas: sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        // Inode é sempre index 9.
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            return None;
        }

        let (local_addr, local_port) = parse_addr_port(f[1], is_v6)?;
        let (remote_addr, remote_port) = parse_addr_port(f[2], is_v6)?;
        let state = parse_state(f[3], proto);

        let inode: u64 = f[9].parse().ok()?;
        let pid = inode_map.get(&inode).copied().unwrap_or(0);

        let remote_zero = match remote_addr {
            IpAddr::V4(a) => a.is_unspecified(),
            IpAddr::V6(a) => a.is_unspecified(),
        };

        Some(Entry {
            pid,
            local_addr,
            local_port,
            remote_addr: if remote_zero { None } else { Some(remote_addr) },
            remote_port: if remote_port == 0 {
                None
            } else {
                Some(remote_port)
            },
            state,
        })
    }

    /// `/proc/net/*`: `ADDR:PORT` com `ADDR` em hex.
    /// IPv4: 8 chars, u32 little-endian (host byte order em x86).
    /// IPv6: 32 chars, 4 grupos u32 little-endian (bytes invertidos em cada grupo).
    fn parse_addr_port(s: &str, is_v6: bool) -> Option<(IpAddr, u16)> {
        let (addr_hex, port_hex) = s.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        let addr = if is_v6 {
            let raw = hex::decode(addr_hex).ok()?;
            if raw.len() != 16 {
                return None;
            }
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&raw[i * 4..i * 4 + 4]);
                bytes[i * 4..i * 4 + 4].reverse();
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(raw.to_be()))
        };

        Some((addr, port))
    }

    fn parse_state(hex: &str, proto: Protocol) -> ConnectionState {
        if proto == Protocol::Udp {
            return ConnectionState::Listen;
        }
        match u32::from_str_radix(hex, 16).unwrap_or(0) {
            0x01 => ConnectionState::Established,
            0x02 => ConnectionState::SynSent,
            0x03 => ConnectionState::SynRecv,
            0x06 => ConnectionState::TimeWait,
            0x08 => ConnectionState::CloseWait,
            0x0A => ConnectionState::Listen,
            _ => ConnectionState::Other,
        }
    }

    /// Mapeia inode de socket → PID caminhando `/proc/<pid>/fd`.
    /// Custa uma passada em /proc por ciclo (~2s). Aceitável para desktop;
    /// se virar gargalo em servidor com muitos fds, otimizar depois.
    fn build_inode_map() -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let Ok(proc_dir) = fs::read_dir("/proc") else {
            return map;
        };
        for entry in proc_dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let fd_dir = format!("/proc/{}/fd", pid);
            let Ok(fds) = fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let s = target.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[")
                    && let Some(inode_str) = rest.strip_suffix(']')
                    && let Ok(inode) = inode_str.parse::<u64>()
                {
                    map.insert(inode, pid);
                }
            }
        }
        map
    }
}

// ---------------------------------------------------------------------------
// macOS — stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use crate::security::network::SocketSnapshot;

    /// Coleta real via `libproc::proc_pidfdinfo` fica pra iteração
    /// futura. Retorna vazio — o motor segue funcionando, só sem
    /// findings de rede no macOS.
    pub fn collect() -> SocketSnapshot {
        SocketSnapshot::default()
    }
}

// ---------------------------------------------------------------------------
// Fallback (BSDs, etc.)
// ---------------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    use crate::security::network::SocketSnapshot;

    pub fn collect() -> SocketSnapshot {
        SocketSnapshot::default()
    }
}
