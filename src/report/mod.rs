//! Reporteadores: transforman los hallazgos en distintos formatos de salida.

pub mod json;
pub mod markdown;
pub mod sarif;

/// Formato de salida seleccionable desde la CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Markdown legible para humanos.
    Md,
    /// JSON compacto para consumo por el LLM.
    Json,
    /// SARIF 2.1.0 para GitHub Code Scanning / CI.
    Sarif,
}
