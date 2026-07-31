# Roadmap — Wasp

Cada fase se desarrolla con **TDD (red → green → refactor)** y mantiene las docs
(`README.md`, `ROADMAP.md`, `CLAUDE.md`) actualizadas.

Leyenda: ✅ hecho · 🚧 en curso · ⬜ pendiente

- ✅ **Fase 0 — Scaffolding**
  - `cargo init` (lib + bin), `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`
  - Esqueleto de `README` / `ROADMAP` / `CLAUDE.md`
  - CI (fmt + clippy + test)
  - Test de humo en verde

- ✅ **Fase 1 — Modelo + normalizadores** *(el corazón)*
  - `model.rs`: `Finding`, `Severity`, `Confidence`, `Location`, `fingerprint`, `parse_cwe`
  - `normalize.rs`: parsers Semgrep / Gitleaks / Trivy desde **fixtures JSON**
  - TDD: fixture → `Vec<Finding>` esperado (4 tests + 2 unit en verde)

- ✅ **Fase 2 — Walker + detección**
  - `walker.rs`: recorrido respetando `.gitignore` (crate `ignore`, `require_git(false)`)
  - `detect.rs`: detección de stack (`Stack`) + disponibilidad de escáneres (`find_in_paths`, `doctor`)
  - `cli.rs` + `wasp doctor` operativo

- ✅ **Fase 3 — Orquestación**
  - `orchestrator/{semgrep,gitleaks,trivy}.rs`: `build_command` + `run`
  - `orchestrator::scan` → `ScanOutcome` (ran/skipped/errors) con degradación con gracia
  - Tests independientes del entorno (contabilidad + flags de comando)

- ✅ **Fase 4 — Reporters**
  - `report/json.rs` (compacto para LLM), `report/sarif.rs` (SARIF 2.1.0), `report/markdown.rs`
  - Comando `wasp scan <ruta> --format md|json|sarif [-o archivo]` operativo
  - Reporte por stdout, avisos de escáneres omitidos por stderr

- ✅ **Fase 5 — Dedupe + severidad**
  - `dedupe.rs`: dedupe idempotente por `fingerprint` + `sort_by_severity`
  - Aplicados en `orchestrator::scan` → salida consistente en todos los formatos

- ✅ **Fase 6 — Skill Claude (auditor senior)**
  - `.claude/skills/wasp/SKILL.md`: rol de auditor senior, flujo scan→triage→reporte,
    ahorro de tokens (solo snippets), mapeo OWASP/CWE, remediación y fallback sin escáneres

- ✅ **Fase 7 — Pulido + docs finales**
  - Fixture `tests/fixtures/vuln_repo/` + test e2e adaptativo (con/sin escáneres)
  - README: instalación de escáneres (winget/brew/pipx), ejemplos y uso de la skill

- ✅ **Modo CI — `--fail-on <severidad>`**
  - `gate.rs`: `max_severity`, `fails`, `count_at_or_above` (lógica pura)
  - `wasp scan --fail-on high` devuelve exit code 2 si hay hallazgos en/sobre el umbral

- ✅ **Cache incremental — `--incremental`**
  - `cache.rs`: `ScanCache`, `relativize`, `diff_files`, `merge_incremental`, `hash_tree`, `head_commit`
  - `walker::walk_all` (incluye ocultos, excluye `.git/`) para huellas fieles al alcance de los escáneres
  - `orchestrator::scan_changed` re-escanea solo el diff vía staging temporal; rutas normalizadas a relativas
  - Medido en repo real: ~142s (completo) → ~6s (1 archivo cambiado)

## Ideas futuras (post-1.0)
- Reglas Semgrep propias específicas del stack de Darwin
- Baseline / supresión de findings aceptados
- Cache incremental scoped a subdirectorio (hoy asume raíz == alcance)
