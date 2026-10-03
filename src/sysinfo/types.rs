use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SystemSnapshot {
    pub os: OsInfo,
    pub host: HostInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub swap: SwapInfo,
    pub disk: DiskInfo,
    pub processes: ProcessesInfo,
    pub network: NetworkInfo,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub kernel: String,
    pub arch: String,
    pub family: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub hostname: String,
    pub username: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuInfo {
    pub brand: String,
    pub cores_logical: usize,
    pub cores_physical: usize,
    pub frequency_mhz: u64,
    pub usage_percent: f32,
    pub per_core_usage: Vec<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub available: u64,
    pub percent: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwapInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub percent: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub percent: f32,
    pub mounts: Vec<MountInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MountInfo {
    pub name: String,
    pub mount_point: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessesInfo {
    pub count: usize,
    pub top_memory: Vec<ProcessEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkInfo {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub interfaces: Vec<InterfaceInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
