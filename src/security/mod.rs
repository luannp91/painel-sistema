//! Motor de detecção de segurança (EDR-lite userspace).
//!
//! Módulo puro nesta fase: sem I/O, sem `sysinfo`, sem `rusqlite`.
//! Recebe fatos já coletados e devolve [`types::SuspicionReport`].
//!
//! Estrutura atual:
//! - [`types`] — [`types::ProcessFacts`], [`types::Finding`], [`types::SuspicionReport`], [`types::Severity`]
//! - [`mitre`] — mapeamento para MITRE ATT&CK
//! - [`heuristics`] — funções puras de detecção
//!
//! Fases posteriores acrescentam `baseline`, `lineage`, `integrity`,
//! `network`, `persistence` e `response`.

// Enquanto o motor não está ligado ao runtime (Fase 2 liga `analyze`
// ao coletor, Fase 4 expõe via API), nada fora dos testes unitários
// deste módulo referencia os tipos. `#[expect]` silencia o dead_code
// e — diferente de `#[allow]` — avisa se um dia o lint deixar de ser
// necessário, forçando a remoção da anotação.
#![expect(dead_code)]

pub mod heuristics;
pub mod mitre;
pub mod types;
