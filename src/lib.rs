//! Wasp — auditor de seguridad OWASP.
//!
//! El crate expone el núcleo del harness (modelo de hallazgos, normalizadores,
//! recorrido de repositorio, orquestación de escáneres y reporteadores) para que
//! tanto el binario `wasp` como los tests de integración lo consuman.

/// Nombre del producto, usado en cabeceras de reportes.
pub const PRODUCT: &str = "Wasp";

/// Versión semántica tomada de `Cargo.toml` en tiempo de compilación.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
