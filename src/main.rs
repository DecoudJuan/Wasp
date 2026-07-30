use clap::Parser;
use wasp::cli::Cli;

fn main() -> anyhow::Result<()> {
    Cli::parse().run()
}
