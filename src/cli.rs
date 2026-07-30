//! Definición de la CLI (clap) y despacho de comandos.

use crate::detect;
use anyhow::Result;
use clap::{Parser, Subcommand};

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
}

impl Cli {
    /// Ejecuta el comando seleccionado.
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Doctor => run_doctor(),
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
