use clap::Parser;
use wasp::cli::Cli;

fn main() -> anyhow::Result<()> {
    let code = Cli::parse().run()?;
    std::process::exit(code);
}
