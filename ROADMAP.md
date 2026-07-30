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

- 🚧 **Fase 2 — Walker + detección**
  - `walker.rs`: recorrido respetando `.gitignore` (crate `ignore`)
  - `detect.rs`: detección de stack + disponibilidad de escáneres
  - `wasp doctor`

- ⬜ **Fase 3 — Orquestación**
  - `orchestrator/{semgrep,gitleaks,trivy}.rs`: invocación + tolerancia a ausencia
  - Integración con `tests/fixtures/vuln_repo/`

- ⬜ **Fase 4 — Reporters**
  - `report/json.rs` (compacto para LLM), `report/sarif.rs` (SARIF 2.1.0), `report/markdown.rs`

- ⬜ **Fase 5 — Dedupe + severidad**
  - `dedupe.rs`: merge idempotente por `fingerprint`
  - Normalización de severidad entre herramientas

- ⬜ **Fase 6 — Skill Claude (auditor senior)**
  - `.claude/skills/wasp/SKILL.md`: workflow de auditoría, triage, OWASP/CWE, remediación

- ⬜ **Fase 7 — Pulido + docs finales**
  - Guía de instalación de escáneres (nota Windows/WSL), ejemplos, cierre de ROADMAP

## Ideas futuras (post-1.0)
- Cache incremental por commit (solo re-escanear diffs)
- Modo CI que falla el build por severidad configurable
- Reglas Semgrep propias específicas del stack de Darwin
- Baseline / supresión de findings aceptados
