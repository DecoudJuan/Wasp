# CLAUDE.md — Guía para trabajar en Wasp

## Qué es Wasp
Auditor de seguridad OWASP. Dos piezas que colaboran:
- **`wasp` (CLI Rust):** harness determinista que recorre el repo, orquesta
  escáneres OSS (Semgrep/Gitleaks/Trivy), normaliza a un modelo `Finding` único,
  deduplica y **comprime** la salida (JSON compacto, SARIF, Markdown).
- **Skill `wasp`** (`.claude/skills/wasp/SKILL.md`): Claude como auditor senior que
  hace triage de los findings leyendo solo snippets, no el repo entero.

**Principio rector:** las herramientas baratas encuentran candidatos; el LLM solo
gasta tokens confirmando y explicando lo de alto valor.

## Metodología innegociable: TDD red → green → refactor
1. **Red:** escribí el test que falla *antes* del código de producción.
2. **Green:** el mínimo código para que pase.
3. **Refactor:** limpiá sin romper tests.

Los tests **no dependen** de tener los escáneres instalados: se parsean fixtures
JSON en `tests/fixtures/`. Nunca introduzcas un test que requiera semgrep/gitleaks/
trivy en la ruta para pasar en CI.

## Comandos
```bash
cargo test                     # unit + integración
cargo clippy -- -D warnings    # linter estricto (CI lo exige)
cargo fmt                      # formateo (CI verifica --check)
cargo run -- doctor            # ver escáneres disponibles
```

## Estructura
- `src/lib.rs` — API del crate (bin y tests la consumen).
- `src/model.rs` — `Finding` y tipos asociados.
- `src/normalize.rs` — salida cruda de cada tool → `Vec<Finding>`.
- `src/walker.rs`, `src/detect.rs` — recorrido y detección.
- `src/orchestrator/` — invocación de escáneres con degradación con gracia.
- `src/report/` — JSON compacto / SARIF / Markdown.
- `tests/` — tests de integración + `fixtures/`.

## Convenciones
- Código y comentarios en español (consistente con el repo).
- Todo hallazgo lleva `fingerprint` estable (hash de archivo+línea+regla) para
  dedupe idempotente.
- Degradación con gracia: la ausencia de un escáner es un aviso, nunca un error fatal.

## Docs vivas
Al cerrar cada fase: actualizá `ROADMAP.md` (marca la fase), y `README.md`/este
archivo si cambió el uso o la arquitectura.

## Entorno
- Windows 11, Rust estable. Semgrep nativo en Windows es problemático → tratarlo
  como opcional (WSL/pipx/Docker). Gitleaks y Trivy corren nativos.
