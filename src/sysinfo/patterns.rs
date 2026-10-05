use serde::Serialize;
use std::collections::VecDeque;

use crate::settings::{PatternSettings, ThresholdSettings};
use crate::sysinfo::types::SystemSnapshot;

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub timestamp_ms: u64,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub disk_percent: f32,
    pub disk_used: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub proc_count: usize,
    pub swap_percent: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pattern {
    pub id: String,
    pub kind: String,
    pub level: String,
    pub title: String,
    pub detail: String,
    pub value: f64,
    pub threshold: f64,
    pub first_detected_ms: u64,
    pub last_detected_ms: u64,
    pub occurrences: u32,
}

pub struct PatternDetector {
    history: VecDeque<Sample>,
    last_net_rx: u64,
    last_net_tx: u64,
    last_proc_count: usize,
    active_patterns: Vec<Pattern>,
    limits: PatternSettings,
    thr: ThresholdSettings,
}

impl PatternDetector {
    pub fn new_with_settings(limits: &PatternSettings, thr: &ThresholdSettings) -> Self {
        Self {
            history: VecDeque::with_capacity(limits.history_capacity),
            last_net_rx: 0,
            last_net_tx: 0,
            last_proc_count: 0,
            active_patterns: Vec::new(),
            limits: limits.clone(),
            thr: thr.clone(),
        }
    }

    pub fn push(&mut self, snap: &SystemSnapshot) -> (Vec<Pattern>, Sample) {
        let net_rx = snap.network.rx_bytes.saturating_sub(self.last_net_rx);
        let net_tx = snap.network.tx_bytes.saturating_sub(self.last_net_tx);
        self.last_net_rx = snap.network.rx_bytes;
        self.last_net_tx = snap.network.tx_bytes;

        let proc_delta = if self.last_proc_count > 0 {
            (snap.processes.count as i64 - self.last_proc_count as i64).unsigned_abs() as usize
        } else {
            0
        };
        self.last_proc_count = snap.processes.count;

        let sample = Sample {
            timestamp_ms: snap.timestamp_ms,
            cpu_percent: snap.cpu.usage_percent,
            mem_percent: snap.memory.percent,
            disk_percent: snap.disk.percent,
            disk_used: snap.disk.used,
            net_rx,
            net_tx,
            proc_count: snap.processes.count,
            swap_percent: snap.swap.percent,
        };

        if self.history.len() >= self.limits.history_capacity {
            self.history.pop_front();
        }
        self.history.push_back(sample.clone());

        let detected = self.detect(proc_delta, snap.timestamp_ms);
        self.update_active(&detected, snap.timestamp_ms);
        (detected, sample)
    }

    fn detect(&self, proc_delta: usize, now_ms: u64) -> Vec<Pattern> {
        let mut patterns = Vec::new();
        let h = &self.history;

        /* -------- CPU spike -------- */
        let spike_n = self.thr.cpu.spike_readings.max(1);
        if h.len() >= spike_n {
            let recent: Vec<f32> = h
                .iter()
                .rev()
                .take(spike_n)
                .map(|s| s.cpu_percent)
                .collect();
            if recent.iter().all(|&v| v > self.thr.cpu.spike_percent) {
                let avg = recent.iter().sum::<f32>() / recent.len() as f32;
                patterns.push(Pattern {
                    id: format!("cpu_spike_{}", now_ms),
                    kind: "cpu_spike".into(),
                    level: "Error".into(),
                    title: "CPU sobrecarregada".into(),
                    detail: format!("Média de {:.1}% nas últimas {} leituras", avg, spike_n),
                    value: avg as f64,
                    threshold: self.thr.cpu.spike_percent as f64,
                    first_detected_ms: now_ms,
                    last_detected_ms: now_ms,
                    occurrences: 1,
                });
            }
        }

        /* -------- CPU sustained -------- */
        let sus_n = self.thr.cpu.sustained_readings.max(2);
        if h.len() >= sus_n {
            let avg: f32 = h
                .iter()
                .rev()
                .take(sus_n)
                .map(|s| s.cpu_percent)
                .sum::<f32>()
                / sus_n as f32;
            if avg > self.thr.cpu.sustained_percent {
                patterns.push(Pattern {
                    id: format!("cpu_sustained_{}", now_ms),
                    kind: "cpu_sustained".into(),
                    level: "Warning".into(),
                    title: "CPU em uso contínuo".into(),
                    detail: format!("Média de {:.1}% nas últimas {} leituras", avg, sus_n),
                    value: avg as f64,
                    threshold: self.thr.cpu.sustained_percent as f64,
                    first_detected_ms: now_ms,
                    last_detected_ms: now_ms,
                    occurrences: 1,
                });
            }
        }

        /* -------- Memória crítica -------- */
        if let Some(s) = h.back()
            && s.mem_percent > self.thr.memory.critical_percent
        {
            patterns.push(Pattern {
                id: format!("mem_pressure_{}", now_ms),
                kind: "memory_pressure".into(),
                level: "Error".into(),
                title: "Memória crítica".into(),
                detail: format!("{:.1}% em uso", s.mem_percent),
                value: s.mem_percent as f64,
                threshold: self.thr.memory.critical_percent as f64,
                first_detected_ms: now_ms,
                last_detected_ms: now_ms,
                occurrences: 1,
            });
        }

        /* -------- Vazamento de memória -------- */
        let gr_n = self.thr.memory.growth_readings.max(2);
        if h.len() >= gr_n {
            let pts: Vec<(f64, f64)> = h
                .iter()
                .rev()
                .take(gr_n)
                .enumerate()
                .map(|(i, s)| (i as f64 * 2.0, s.mem_percent as f64))
                .collect();
            if let Some(slope_per_s) = linreg_slope(&pts) {
                let slope_per_min = slope_per_s * 60.0;
                if slope_per_min > self.thr.memory.growth_percent_per_min {
                    patterns.push(Pattern {
                        id: format!("mem_growth_{}", now_ms),
                        kind: "memory_growth".into(),
                        level: "Warning".into(),
                        title: "Memória em crescimento".into(),
                        detail: format!(
                            "Tendência de +{:.2}%/min — possível vazamento",
                            slope_per_min
                        ),
                        value: slope_per_min,
                        threshold: self.thr.memory.growth_percent_per_min,
                        first_detected_ms: now_ms,
                        last_detected_ms: now_ms,
                        occurrences: 1,
                    });
                }
            }
        }

        /* -------- Disco crítico + enchendo -------- */
        if let Some(s) = h.back() {
            if s.disk_percent > self.thr.disk.critical_percent {
                patterns.push(Pattern {
                    id: format!("disk_pressure_{}", now_ms),
                    kind: "disk_pressure".into(),
                    level: "Error".into(),
                    title: "Disco quase cheio".into(),
                    detail: format!("{:.1}% em uso", s.disk_percent),
                    value: s.disk_percent as f64,
                    threshold: self.thr.disk.critical_percent as f64,
                    first_detected_ms: now_ms,
                    last_detected_ms: now_ms,
                    occurrences: 1,
                });
            }

            if h.len() >= 150
                && let Some(old) = h.iter().rev().nth(149)
            {
                let delta = s.disk_used.saturating_sub(old.disk_used);
                let threshold_bytes = self.thr.disk.filling_mb_per_5min * 1024 * 1024;
                if delta > threshold_bytes {
                    patterns.push(Pattern {
                        id: format!("disk_filling_{}", now_ms),
                        kind: "disk_filling".into(),
                        level: "Warning".into(),
                        title: "Disco enchendo rapidamente".into(),
                        detail: format!("+{} nos últimos 5 min", fmt_bytes(delta)),
                        value: delta as f64 / (1024.0 * 1024.0),
                        threshold: self.thr.disk.filling_mb_per_5min as f64,
                        first_detected_ms: now_ms,
                        last_detected_ms: now_ms,
                        occurrences: 1,
                    });
                }
            }
        }

        /* -------- Swap em uso -------- */
        if let Some(s) = h.back()
            && s.swap_percent > self.thr.swap.active_percent
        {
            patterns.push(Pattern {
                id: format!("swap_active_{}", now_ms),
                kind: "swap_activity".into(),
                level: "Warning".into(),
                title: "Swap em uso".into(),
                detail: format!("{:.1}% da swap em uso", s.swap_percent),
                value: s.swap_percent as f64,
                threshold: self.thr.swap.active_percent as f64,
                first_detected_ms: now_ms,
                last_detected_ms: now_ms,
                occurrences: 1,
            });
        }

        /* -------- Picos de rede -------- */
        if h.len() >= 50 {
            let recent = h.back().unwrap();
            let avg_rx: f64 = h
                .iter()
                .rev()
                .skip(1)
                .take(49)
                .map(|s| s.net_rx as f64)
                .sum::<f64>()
                / 49.0;
            let avg_tx: f64 = h
                .iter()
                .rev()
                .skip(1)
                .take(49)
                .map(|s| s.net_tx as f64)
                .sum::<f64>()
                / 49.0;
            let min_baseline = self.thr.network.min_baseline_bytes as f64;
            let mult = self.thr.network.burst_multiplier;

            if avg_rx > min_baseline && recent.net_rx as f64 > avg_rx * mult {
                patterns.push(Pattern {
                    id: format!("net_rx_burst_{}", now_ms),
                    kind: "network_burst_rx".into(),
                    level: "Warning".into(),
                    title: "Pico de download".into(),
                    detail: format!(
                        "{} recebidos ({}× a média)",
                        fmt_bytes(recent.net_rx),
                        mult as u32
                    ),
                    value: recent.net_rx as f64,
                    threshold: avg_rx * mult,
                    first_detected_ms: now_ms,
                    last_detected_ms: now_ms,
                    occurrences: 1,
                });
            }
            if avg_tx > min_baseline && recent.net_tx as f64 > avg_tx * mult {
                patterns.push(Pattern {
                    id: format!("net_tx_burst_{}", now_ms),
                    kind: "network_burst_tx".into(),
                    level: "Warning".into(),
                    title: "Pico de upload".into(),
                    detail: format!(
                        "{} enviados ({}× a média)",
                        fmt_bytes(recent.net_tx),
                        mult as u32
                    ),
                    value: recent.net_tx as f64,
                    threshold: avg_tx * mult,
                    first_detected_ms: now_ms,
                    last_detected_ms: now_ms,
                    occurrences: 1,
                });
            }
        }

        /* -------- Churn de processos -------- */
        if proc_delta > self.thr.processes.churn_max_delta {
            patterns.push(Pattern {
                id: format!("proc_churn_{}", now_ms),
                kind: "process_churn".into(),
                level: "Information".into(),
                title: "Alta variação de processos".into(),
                detail: format!(
                    "{} processos criados/destruídos no último intervalo",
                    proc_delta
                ),
                value: proc_delta as f64,
                threshold: self.thr.processes.churn_max_delta as f64,
                first_detected_ms: now_ms,
                last_detected_ms: now_ms,
                occurrences: 1,
            });
        }

        /* -------- Muitos processos -------- */
        if let Some(s) = h.back()
            && s.proc_count > self.thr.processes.high_count
        {
            patterns.push(Pattern {
                id: format!("proc_high_{}", now_ms),
                kind: "high_process_count".into(),
                level: "Warning".into(),
                title: "Muitos processos em execução".into(),
                detail: format!("{} processos ativos", s.proc_count),
                value: s.proc_count as f64,
                threshold: self.thr.processes.high_count as f64,
                first_detected_ms: now_ms,
                last_detected_ms: now_ms,
                occurrences: 1,
            });
        }

        patterns
    }

    fn update_active(&mut self, detected: &[Pattern], now_ms: u64) {
        let active_window_ms = self.limits.active_window_seconds * 1000;
        let max_age_ms = self.limits.max_age_seconds * 1000;

        for p in detected {
            let existing = self.active_patterns.iter_mut().rev().find(|e| {
                e.kind == p.kind && now_ms.saturating_sub(e.last_detected_ms) < active_window_ms
            });

            if let Some(e) = existing {
                e.value = p.value;
                e.detail = p.detail.clone();
                e.level = p.level.clone();
                e.last_detected_ms = now_ms;
                e.occurrences = e.occurrences.saturating_add(1);
            } else {
                self.active_patterns.push(p.clone());
            }
        }

        self.active_patterns
            .retain(|p| now_ms.saturating_sub(p.last_detected_ms) < max_age_ms);

        if self.active_patterns.len() > self.limits.max_patterns {
            let excess = self.active_patterns.len() - self.limits.max_patterns;
            self.active_patterns.drain(0..excess);
        }
    }

    pub fn latest(&self, max: usize) -> Vec<Pattern> {
        let mut out: Vec<Pattern> = self
            .active_patterns
            .iter()
            .rev()
            .take(max)
            .cloned()
            .collect();
        out.sort_by_key(|p| std::cmp::Reverse(p.last_detected_ms));
        out
    }

    pub fn samples(&self, n: usize) -> Vec<Sample> {
        self.history
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

fn linreg_slope(points: &[(f64, f64)]) -> Option<f64> {
    let n = points.len() as f64;
    if n < 2.0 {
        return None;
    }
    let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();
    let denom = n * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-9 {
        return None;
    }
    Some((n * sum_xy - sum_x * sum_y) / denom)
}

pub fn fmt_bytes(n: u64) -> String {
    if n == 0 {
        return "0 B".into();
    }
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", v, U[i])
}
