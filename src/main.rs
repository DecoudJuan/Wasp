use wasp::{version, PRODUCT};

fn main() {
    // Fase 0: punto de entrada mínimo. La CLI real (clap) llega en fases posteriores.
    println!("{} v{}", PRODUCT, version());
}
