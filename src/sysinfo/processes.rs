use serde::Serialize;
use std::time::Duration;

use sysinfo::{Pid, ProcessesToUpdate, System, Users};

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub status: String,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub cpu_percent: f32,
    pub disk_read_bytes: u64,
    pub disk_written_bytes: u64,
    pub run_time_seconds: u64,
    pub start_time: u64,
}

pub struct ProcessCollector {
    system: System,
    users: Users,
}

impl ProcessCollector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        // CPU% precisa de 2 leituras com intervalo
        std::thread::sleep(Duration::from_millis(200));
        system.refresh_processes(ProcessesToUpdate::All, true);

        Self {
            system,
            users: Users::new_with_refreshed_list(),
        }
    }

    pub fn list(&mut self) -> Vec<ProcessEntry> {
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        let mut procs: Vec<ProcessEntry> = self
            .system
            .processes()
            .iter()
            .map(|(pid, p)| {
                let user = p
                    .user_id()
                    .and_then(|uid| self.users.get_user_by_id(uid))
                    .map(|u| u.name().to_string());

                let cmd: Vec<String> = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect();

                let exe = p.exe().map(|e| e.to_string_lossy().into_owned());

                let status = format!("{:?}", p.status());

                ProcessEntry {
                    pid: pid.as_u32(),
                    parent: p.parent().map(|pp| pp.as_u32()),
                    name: p.name().to_string_lossy().into_owned(),
                    exe,
                    cmd,
                    user,
                    status,
                    memory_bytes: p.memory(),
                    virtual_memory_bytes: p.virtual_memory(),
                    cpu_percent: (p.cpu_usage() * 100.0).round() / 100.0,
                    disk_read_bytes: p.disk_usage().read_bytes,
                    disk_written_bytes: p.disk_usage().written_bytes,
                    run_time_seconds: p.run_time(),
                    start_time: p.start_time(),
                }
            })
            .collect();

        // Ordena por memória desc (mais pesados primeiro)
        procs.sort_by_key(|a| std::cmp::Reverse(a.memory_bytes));
        procs
    }

    /// Encerra o processo. Retorna Ok(nome) se conseguiu, Err(mensagem) caso contrário.
    pub fn kill(&mut self, pid: u32) -> Result<String, String> {
        let p = Pid::from_u32(pid);

        // Garante que temos a versão mais recente do processo em cache
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        let process = self
            .system
            .process(p)
            .ok_or_else(|| format!("Processo {} não encontrado", pid))?;

        let name = process.name().to_string_lossy().into_owned();

        // Proteção: não mata PID 0 (System Idle) nem PID 4 (System)
        if pid == 0 || pid == 4 {
            return Err(format!(
                "PID {} é crítico do sistema — operação bloqueada",
                pid
            ));
        }

        if process.kill() {
            Ok(name)
        } else {
            Err(format!(
                "Não foi possível encerrar '{}' (PID {}). Permissão negada?",
                name, pid
            ))
        }
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}
