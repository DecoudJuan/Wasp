//! Definición de la CLI (clap) y despacho de comandos.

use crate::model::Severity;
use crate::report::{self, Format};
use crate::{detect, gate, orchestrator};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Código de salida cuando `--fail-on` detecta hallazgos en/sobre el umbral.
pub const EXIT_GATE_FAILED: i32 = 2;

#[derive(Parser)]
#[command(
    name = "wasp",
    version,
    about = "Auditor de seguridad OWASP para cualquier repositorio"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Reporta qué escáneres externos están disponibles en el sistema.
    Doctor,
    /// Escanea un repositorio/carpeta y emite el reporte en el formato elegido.
    Scan {
        /// Ruta del repositorio o carpeta a auditar.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Formato de salida.
        #[arg(short, long, value_enum, default_value_t = Format::Md)]
        format: Format,
        /// Archivo de salida (por defecto: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Modo CI: falla (exit 2) si hay hallazgos en o sobre esta severidad.
        #[arg(long, value_enum)]
        fail_on: Option<Severity>,
    },
}

impl Cli {
    /// Ejecuta el comando y devuelve el código de salida del proceso.
    pub fn run(self) -> Result<i32> {
        match self.command {
            Command::Doctor => run_doctor().map(|()| 0),
            Command::Scan {
                path,
                format,
                output,
                fail_on,
            } => run_scan(path, format, output, fail_on),
        }
    }
}

fn run_doctor() -> Result<()> {
    println!("{} — diagnóstico de escáneres\n", crate::PRODUCT);
    let mut disponibles = 0;
    for estado in detect::doctor() {
        let (marca, texto) = if estado.available {
            disponibles += 1;
            ("[ok]", "disponible")
        } else {
            ("[--]", "no encontrado")
        };
        match estado.path {
            Some(path) => println!(
                "  {marca} {:<9} {texto} ({})",
                estado.tool.as_str(),
                path.display()
            ),
            None => println!("  {marca} {:<9} {texto}", estado.tool.as_str()),
        }
    }
    println!("\n{disponibles}/3 escáneres disponibles.");
    if disponibles == 0 {
        println!(
            "Sugerencia: instalá al menos gitleaks (binario Go, funciona en Windows) para empezar."
        );
    }
    Ok(())
}

fn run_scan(
    path: PathBuf,
    format: Format,
    output: Option<PathBuf>,
    fail_on: Option<Severity>,
) -> Result<i32> {
    let outcome = orchestrator::scan(&path);

    // Aviso de herramientas omitidas por stderr (no contamina la salida principal).
    if !outcome.skipped.is_empty() {
        let nombres: Vec<&str> = outcome.skipped.iter().map(|t| t.as_str()).collect();
        eprintln!(
            "Aviso: escáneres no instalados y omitidos: {}",
            nombres.join(", ")
        );
    }
    for (tool, err) in &outcome.errors {
        eprintln!("Aviso: {} falló: {}", tool.as_str(), err);
    }

    let rendered = match format {
        Format::Md => report::markdown::render(&outcome.findings),
        Format::Json => report::json::compact(&outcome.findings)?,
        Format::Sarif => report::sarif::to_sarif(&outcome.findings)?,
    };

    match output {
        Some(path) => {
            std::fs::write(&path, rendered)
                .with_context(|| format!("escribiendo reporte en {}", path.display()))?;
            eprintln!("Reporte escrito en {}", path.display());
        }
        None => println!("{rendered}"),
    }

    // Modo CI: evaluar la puerta de severidad.
    if let Some(threshold) = fail_on {
        let n = gate::count_at_or_above(&outcome.findings, threshold);
        if n > 0 {
            eprintln!(
                "FALLA CI: {n} hallazgo(s) en o sobre severidad '{}'.",
                threshold.as_str()
            );
            return Ok(EXIT_GATE_FAILED);
        }
        eprintln!(
            "OK CI: sin hallazgos en o sobre severidad '{}'.",
            threshold.as_str()
        );
    }

    Ok(0)
}
