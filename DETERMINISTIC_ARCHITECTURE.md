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

## Hardening Guarantees

1. **Closed-Loop Analytical Escalation** (`packages/security-solver/src/deterministic/specialized-escalation.ts`):
   During `ANALYZE`, `driveDeterministicAuditTurn` runs `runClosedLoopLeadAnalysis`: it evaluates the initial lead, selectively invokes specialized adapters (`Z3`, `Joern`, `Mythril`, `Foundry`, and isolated `fast-check`) bounded per lead and cached by `(leadId, path, sha256)`, merges newly returned `ProgramFact`s and `ProgramEdge`s into `ProgramFactsGraph`, and reconsiders the lead (`assess_lead` ↔ `defer_lead`). For example, a Z3 `smt_unsat_guard` proof flips an `assess_lead` to `defer_lead`, while a Joern `taint_flow`, Mythril `symbolic_finding`, Foundry `foundry_invariant_violated`, or isolated `fast-check` `property_counterexample` flips a `defer_lead` to `assess_lead`.
2. **Typed, Independently Verified Deterministic Review** (`evaluateDeterministicEvidenceReview`):
   Consumes LOTUS's typed `DeterministicReviewEvidence` (`ControllerReviewGrounds`, `replay`, `entryReplay`, `chainEvidence`, typed `securityImpact`, and `analyzerFacts`) directly with zero regex extraction from serialized prompt text. Fails closed if typed evidence or `sourceDigest` is missing. A positive replay marker alone never approves a finding as a security vulnerability — both independent replay and typed verified security impact are required.
3. **Bubblewrap Isolation for `fast-check`** (`adapters/fastcheck-adapter.ts`, `scripts/source-reproduction.py`, `scripts/reproduction-runtime/probe.cjs`):
   Zero use of Node's `node:vm` (`vm.createContext`). `fast-check` generates and shrinks inputs in the trusted controller while delegating all untrusted JavaScript execution to LOTUS's `bubblewrap` (`bwrap --unshare-all --cap-drop ALL --clearenv` + resource limits) isolated reproduction runtime (`kind=javascript_property_batch`), failing closed (`blocked_no_sandbox`) whenever no isolated sandbox is available.
