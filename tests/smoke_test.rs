//! Test de humo de la Fase 0: el crate compila y expone su identidad básica.

#[test]
fn expone_nombre_de_producto() {
    assert_eq!(wasp::PRODUCT, "Wasp");
}

#[test]
fn expone_una_version_no_vacia() {
    assert!(!wasp::version().is_empty());
}
