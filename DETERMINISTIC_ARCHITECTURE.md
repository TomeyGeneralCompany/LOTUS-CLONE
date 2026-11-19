# LOTUS-CLONE: Deterministic (Qwen-Free) Security Engine

This standalone clone starts from verified PR #233 (`37ad946e`) and replaces the Qwen/Ollama inference hot-loop with three deterministic core capabilities while preserving existing Semgrep, Slither, `@solidity-parser/parser`, controller scheduling, and 4-language verifier infrastructure.

## Core Capabilities (`packages/security-solver/src/deterministic/`)

1. **Common Program-Facts Representation (`program-facts.ts`)**
   - Language-agnostic IR (`ProgramFactsGraph`, `ProgramSymbol`, `ProgramFact`, `ProgramEdge`) normalizing entry points, auth guards, state writes, value transfers, mint/burn, privileged primitives, initializers, HTML/path/command/SQL/deserialization sinks, and Semgrep/Slither leads.
   - Pluggable `ProgramFactsAdapter` interface with built-in adapters (`solidity-ast`, `javascript-structural`, `python-structural`, `java-structural`, `static-leads`) and runtime catalog probing (`EXTERNAL_ADAPTER_CATALOG`, `detectAvailableAdapters`) for incremental integration of:
     - **MIT**: Tree-sitter, Z3, Mythril, fast-check, LibCST, Babel Parser
     - **Apache-2.0**: Joern, JavaParser
     - **MIT/Apache-2.0**: Foundry (`forge`)

2. **Hypothesis Engine (`hypothesis-engine.ts`)**
   - Synthesizes deduplicated, calibrated-priority `SecurityHypothesis[]` with falsification criteria, source witnesses, and probe/adapter recommendations.
   - Drives `ANALYZE` lead evaluation (`evaluateAnalysisLead`) deterministically with zero LLM calls.

3. **Deterministic Analysis & Review Driver (`analysis-review-driver.ts`)**
   - `LOCAL_MODEL_ADAPTER=deterministic` (default whenever `AUTOHACK_OLLAMA_URL` is unset).
   - Replaces Qwen across:
     - `local-ollama-runner.ts` (`ANALYZE`, `REVIEW`, `REPORT`, navigation)
     - `evidence-only-review.ts` (independent evidence review without `postOllamaChat`)
     - `packages/security-analyzer/src/assessor.ts` (program & finding scoring without `runClaude`)

## Side-by-Side A/B Benchmarking

- **Deterministic (Qwen-free, zero Ollama required):**
  ```bash
  LOCAL_MODEL_ADAPTER=deterministic npx tsx scripts/test-deterministic-lotus.ts
  ```
- **Legacy Qwen/Ollama (opt-in for A/B comparison):**
  ```bash
  LOCAL_MODEL_ADAPTER=ollama AUTOHACK_OLLAMA_URL=http://127.0.0.1:11434/api/chat ...
  ```
