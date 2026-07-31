//! Wasp — auditor de seguridad OWASP.
//!
//! El crate expone el núcleo del harness (modelo de hallazgos, normalizadores,
//! recorrido de repositorio, orquestación de escáneres y reporteadores) para que
//! tanto el binario `wasp` como los tests de integración lo consuman.

pub mod cli;
pub mod dedupe;
pub mod detect;
pub mod gate;
pub mod model;
pub mod normalize;
pub mod orchestrator;
pub mod report;
pub mod walker;

/// Nombre del producto, usado en cabeceras de reportes.
pub const PRODUCT: &str = "Wasp";

/// Versión semántica tomada de `Cargo.toml` en tiempo de compilación.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
