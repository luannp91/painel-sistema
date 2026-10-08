use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sysinfo::{Disks, Networks, Pid, Process, System, Users};

use super::types::*;
use crate::security::baseline::BaselineSnapshot;
use crate::security::engine::{Engine, SecuritySnapshot};
use crate::security::types::ProcessFacts;

/// CPU acima disso conta para o streak de "sustained high".
const CPU_HIGH_THRESHOLD: f32 = 80.0;

/// Streak consecutivo (em ciclos) para marcar `cpu_sustained_high`.
const CPU_STREAK_LIMIT: u32 = 5;

pub struct Collector {
    system: System,
    networks: Networks,
    disks: Disks,
    users: Users,
    engine: Engine,
    /// pid → ciclos consecutivos com CPU acima do threshold.
    cpu_streaks: HashMap<u32, u32>,
}

impl Collector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        // Primeira leitura de CPU precisa de um delta
        std::thread::sleep(Duration::from_millis(300));
        system.refresh_cpu_all();

        Self {
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            users: Users::new_with_refreshed_list(),
            engine: Engine::with_defaults(now_ms()),
            cpu_streaks: HashMap::new(),
        }
    }

    pub fn collect(&mut self) -> SystemSnapshot {
        self.system.refresh_memory();
        self.system.refresh_cpu_all();
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        self.networks.refresh();
        self.disks.refresh();

        SystemSnapshot {
            os: self.collect_os(),
            host: self.collect_host(),
            cpu: self.collect_cpu(),
            memory: self.collect_memory(),
            swap: self.collect_swap(),
            disk: self.collect_disk(),
            processes: self.collect_processes(),
            network: self.collect_network(),
            timestamp_ms: now_ms(),
        }
    }

    /// Roda o motor de segurança sobre TODOS os processos. Chamar logo
    /// após [`collect`] para dados frescos.
    pub fn collect_security(&mut self) -> SecuritySnapshot {
        let now = now_ms();
        let Self {
            system,
            users,
            cpu_streaks,
            engine,
            ..
        } = self;

        let owned: Vec<ProcessData> = system
            .processes()
            .iter()
            .map(|(pid, p)| extract_process_data(system, users, pid, p, cpu_streaks))
            .collect();

        let facts: Vec<ProcessFacts<'_>> = owned.iter().map(ProcessData::as_facts).collect();

        engine.analyze_batch(&facts, now)
    }

    /// Snapshot do baseline atual, pronto pra persistir.
    pub fn baseline_snapshot(&self) -> BaselineSnapshot {
        self.engine.baseline().snapshot()
    }

    /// Restaura baseline persistido. Chamado uma vez, no boot.
    pub fn restore_baseline(&mut self, snap: BaselineSnapshot) {
        let config = self.engine.config().baseline.clone();
        let restored = crate::security::baseline::Baseline::restore(config, snap, now_ms());
        self.engine.replace_baseline(restored);
    }

    fn collect_os(&self) -> OsInfo {
        OsInfo {
            name: System::name().unwrap_or_else(|| "Windows".into()),
            version: System::os_version().unwrap_or_else(|| "desconhecida".into()),
            kernel: System::kernel_version().unwrap_or_else(|| "—".into()),
            arch: System::cpu_arch().unwrap_or_else(|| "desconhecida".into()),
            family: System::long_os_version().unwrap_or_else(|| "Windows".into()),
        }
    }

    fn collect_host(&self) -> HostInfo {
        let hostname = System::host_name().unwrap_or_else(|| "localhost".into());
        let username = self
            .users
            .list()
            .first()
            .map(|u| u.name().to_string())
            .unwrap_or_else(|| "—".into());

        HostInfo {
            hostname,
            username,
            uptime_seconds: System::uptime(),
        }
    }

    fn collect_cpu(&self) -> CpuInfo {
        let cpus = self.system.cpus();
        let brand = cpus
            .first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_else(|| "Desconhecida".into());

        let frequency_mhz = cpus.first().map(|c| c.frequency()).unwrap_or(0);

        let per_core_usage: Vec<f32> = cpus.iter().map(|c| round2(c.cpu_usage())).collect();

        CpuInfo {
            brand,
            cores_logical: cpus.len(),
            cores_physical: num_cpus::get_physical(),
            frequency_mhz,
            usage_percent: round2(self.system.global_cpu_usage()),
            per_core_usage,
        }
    }

    fn collect_memory(&self) -> MemoryInfo {
        let total = self.system.total_memory();
        let used = self.system.used_memory();
        let free = self.system.free_memory();
        let available = self.system.available_memory();
        MemoryInfo {
            total,
            used,
            free,
            available,
            percent: pct(used, total),
        }
    }

    fn collect_swap(&self) -> SwapInfo {
        let total = self.system.total_swap();
        let used = self.system.used_swap();
        let free = self.system.free_swap();
        SwapInfo {
            total,
            used,
            free,
            percent: pct(used, total),
        }
    }

    fn collect_disk(&self) -> DiskInfo {
        let mut total = 0u64;
        let mut free = 0u64;
        let mut mounts = Vec::new();

        for d in self.disks.list() {
            let t = d.total_space();
            let f = d.available_space();
            total += t;
            free += f;
            mounts.push(MountInfo {
                name: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                fs: d.file_system().to_string_lossy().into_owned(),
                total: t,
                free: f,
            });
        }

        let used = total.saturating_sub(free);
        DiskInfo {
            total,
            free,
            used,
            percent: pct(used, total),
            mounts,
        }
    }

    fn collect_processes(&self) -> ProcessesInfo {
        let processes = self.system.processes();
        let count = processes.len();

        let mut entries: Vec<ProcessEntry> = processes
            .iter()
            .map(|(pid, p)| ProcessEntry {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().into_owned(),
                memory_bytes: p.memory(),
                cpu_percent: round2(p.cpu_usage()),
            })
            .collect();

        entries.sort_by_key(|a| std::cmp::Reverse(a.memory_bytes));
        entries.truncate(10);

        ProcessesInfo {
            count,
            top_memory: entries,
        }
    }

    fn collect_network(&self) -> NetworkInfo {
        let mut rx = 0u64;
        let mut tx = 0u64;
        let mut interfaces = Vec::new();

        for (name, data) in self.networks.list() {
            let r = data.total_received();
            let t = data.total_transmitted();
            rx += r;
            tx += t;
            interfaces.push(InterfaceInfo {
                name: name.to_string(),
                rx_bytes: r,
                tx_bytes: t,
            });
        }

        NetworkInfo {
            rx_bytes: rx,
            tx_bytes: tx,
            interfaces,
        }
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Ponte sysinfo → security (owned)
// ---------------------------------------------------------------------------

struct ProcessData {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    exe_path: Option<String>,
    cmdline: String,
    parent_name: Option<String>,
    user: Option<String>,
    cpu_sustained_high: bool,
}

impl ProcessData {
    fn as_facts(&self) -> ProcessFacts<'_> {
        ProcessFacts {
            pid: self.pid,
            parent_pid: self.parent_pid,
            name: &self.name,
            exe_path: self.exe_path.as_deref(),
            cmdline: &self.cmdline,
            parent_name: self.parent_name.as_deref(),
            user: self.user.as_deref(),
            cpu_sustained_high: self.cpu_sustained_high,
        }
    }
}

fn extract_process_data(
    system: &System,
    users: &Users,
    pid: &Pid,
    p: &Process,
    cpu_streaks: &mut HashMap<u32, u32>,
) -> ProcessData {
    let pid_u32 = pid.as_u32();

    let cpu_percent = p.cpu_usage();
    let streak = cpu_streaks.entry(pid_u32).or_insert(0);
    if cpu_percent > CPU_HIGH_THRESHOLD {
        *streak = streak.saturating_add(1);
    } else {
        *streak = 0;
    }
    let cpu_sustained_high = *streak >= CPU_STREAK_LIMIT;

    let parent_pid = p.parent().map(Pid::as_u32);
    let parent_name = p.parent().and_then(|ppid| {
        system
            .process(ppid)
            .map(|pp| pp.name().to_string_lossy().into_owned())
    });

    let exe_path = p.exe().map(|path| path.to_string_lossy().into_owned());

    let cmdline = p
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");

    let user = p
        .user_id()
        .and_then(|uid| users.get_user_by_id(uid))
        .map(|u| u.name().to_string());

    ProcessData {
        pid: pid_u32,
        parent_pid,
        name: p.name().to_string_lossy().into_owned(),
        exe_path,
        cmdline,
        parent_name,
        user,
        cpu_sustained_high,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn round2(v: f32) -> f32 {
    (v * 100.0).round() / 100.0
}

fn pct(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        round2(used as f32 * 100.0 / total as f32)
    }
}
