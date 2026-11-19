# Deterministic LOTUS Architecture (Zero-Qwen)

`LOTUS-CLONE` replaces Qwen / Ollama LLM dependencies with a deterministic, tool-backed analysis and review stack while preserving existing Semgrep, Slither, `@solidity-parser/parser`, controller scheduling, and the 4-language isolated verifier.

## Three Core Capabilities

1. **Common Program-Facts IR** (`packages/security-solver/src/deterministic/program-facts.ts`):
   Normalizes AST/CST symbols, authorization guards, sinks, CPG taint flows, SMT feasibility proofs, symbolic issues, and fuzzing counterexamples into a single `ProgramFactsGraph` (`symbols`, `facts`, `edges`).
2. **Deterministic Hypothesis Engine** (`packages/security-solver/src/deterministic/hypothesis-engine.ts`):
   Synthesizes ranked, falsifiable, source-grounded security hypotheses from `ProgramFactsGraph`, boosts leads corroborated by fast-check / Foundry / Mythril / Joern / Z3 SAT witnesses, and prunes paths proven `UNSAT` by Z3.
3. **Deterministic Analysis & Review Driver** (`packages/security-solver/src/deterministic/analysis-review-driver.ts`):
   Replaces Ollama/Qwen in `local-ollama-runner.ts` (`ANALYZE`, `REVIEW`, `REPORT`), `evidence-only-review.ts`, `packages/security-analyzer/src/assessor.ts`, and `claude-runner.ts` (`spawnComprehensiveReview`, `deverbosifyReport`).

## Integrated Tool Adapters (12 / 12)

| Adapter | License | Role | Implementation |
|---|---|---|---|
| **Semgrep** | LGPL-2.1 | Pattern & rule static lead scanning | Existing `scripts/source-static.py` + `staticLeadsFactsAdapter` |
| **Slither** | AGPL-3.0 | Bounded Solidity static & dataflow analysis | Existing `scripts/source-static.py` + `staticLeadsFactsAdapter` |
| **@solidity-parser/parser** | MIT | Solidity AST & symbol/guard extraction | `solidityAstFactsAdapter` |
| **@babel/parser** | MIT | JavaScript/TypeScript/JSX AST extraction | `adapters/babel-adapter.ts` |
| **fast-check** | MIT | JS/TS property-based security fuzzing & shrinking | `adapters/fastcheck-adapter.ts` |
| **LibCST** | MIT | Python CST symbol, decorator, guard & sink analysis | `scripts/adapters/libcst_facts.py` + `adapters/libcst-adapter.ts` |
| **Tree-sitter** | MIT | Error-tolerant multi-language CST structural analysis | `scripts/adapters/treesitter_facts.py` + `adapters/treesitter-adapter.ts` |
| **Z3** | MIT | SMT constraint feasibility & counterexample witnesses | `scripts/adapters/z3_feasibility.py` + `adapters/z3-adapter.ts` |
| **Foundry (`forge`)** | MIT/Apache-2.0 | Solidity stateful fuzzing & invariant testing | `adapters/foundry-adapter.ts` |
| **JavaParser** | Apache-2.0 | Java AST parsing, Spring/JAX-RS annotations & sinks | `scripts/adapters/JavaParserFacts.java` + `adapters/javaparser-adapter.ts` |
| **Mythril** | MIT | Bounded EVM bytecode symbolic execution (SWC) | `adapters/mythril-adapter.ts` |
| **Joern** | Apache-2.0 | Code Property Graphs & interprocedural taint flows | `scripts/adapters/joern_cpg_facts.sc` + `adapters/joern-adapter.ts` |

## Mode Selection

- Default in `LOTUS-CLONE` (when `AUTOHACK_OLLAMA_URL` is unset): `LOCAL_MODEL_ADAPTER=deterministic` (zero LLM calls).
- Explicit opt-in A/B comparison: set `LOCAL_MODEL_ADAPTER=ollama` and `AUTOHACK_OLLAMA_URL=http://127.0.0.1:11434/api/chat`.
