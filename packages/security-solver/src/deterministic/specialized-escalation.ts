/**
 * Closed-Loop Specialized Analytical Escalation Engine.
 *
 * Connects LOTUS's deterministic driver to specialized analytical adapters
 * (Z3, Joern, Mythril, Foundry, isolated fast-check via bubblewrap) inside a
 * single closed investigation loop:
 *
 *   1. Evaluate active lead on existing ProgramFactsGraph -> initialDecision
 *   2. Identify whether specialized analyzers can refine, prove, or refute the lead
 *   3. Invoke bounded specialized analyzers (cached by lead + file + sha256)
 *   4. Merge returned ProgramFacts and ProgramEdges into ProgramFactsGraph
 *   5. Re-evaluate the lead -> finalDecision (may flip assess_lead <-> defer_lead)
 */
import type { SourceSnapshot } from "../controller-solidity-experiment-planner";
import type {
  FactLanguage,
  ProgramEdge,
  ProgramFact,
  ProgramFactsGraph,
} from "./program-facts";
import {
  evaluateAnalysisLead,
  type LeadAnalysisDecision,
  type LeadAnalysisInput,
} from "./hypothesis-engine";
import {
  checkGuardFeasibilityFact,
  isZ3Available,
} from "./adapters/z3-adapter";
import {
  isJoernAvailable,
  runJoernCpgAnalysis,
} from "./adapters/joern-adapter";
import {
  isMythrilAvailable,
  runMythrilSymbolicAnalysis,
} from "./adapters/mythril-adapter";
import {
  isFoundryAvailable,
  runFoundrySolidityTest,
} from "./adapters/foundry-adapter";
import {
  isIsolatedJsSandboxAvailable,
  runFastCheckJsProbe,
  type FastCheckSecurityProperty,
  type IsolatedJsBatchEvaluator,
} from "./adapters/fastcheck-adapter";

export type EscalationAdapterName = "z3" | "joern" | "mythril" | "foundry" | "fast-check";

export interface EscalationStepRecord {
  adapter: EscalationAdapterName;
  attempted: boolean;
  reason: string;
  status: "executed" | "unavailable" | "skipped" | "error";
  factsAdded: number;
  edgesAdded: number;
  elapsedMs: number;
  detail?: string;
}

export interface EscalationCacheEntry {
  facts: ProgramFact[];
  edges: ProgramEdge[];
  steps: EscalationStepRecord[];
}

export type EscalationCache = Map<string, EscalationCacheEntry>;

export interface SpecializedEscalationHooks {
  runZ3?: (input: {
    file: string;
    line: number;
    language: FactLanguage;
    symbol?: string;
    constraints: readonly string[];
    variables?: Record<string, "int" | "uint256" | "bool">;
  }) => ProgramFact | null;
  runJoern?: (input: {
    sources: readonly SourceSnapshot[];
    lead: LeadAnalysisInput;
  }) => {
    status: "completed" | "unavailable" | "error";
    facts: ProgramFact[];
    edges: ProgramEdge[];
    error?: string;
  };
  runMythril?: (input: {
    file: string;
    contractSource: string;
    lead: LeadAnalysisInput;
  }) => {
    status: "completed" | "unavailable" | "error";
    facts: ProgramFact[];
    error?: string;
  };
  runFoundry?: (input: {
    file: string;
    contractSource: string;
    lead: LeadAnalysisInput;
  }) => {
    status: "completed" | "unavailable" | "error";
    facts: ProgramFact[];
    error?: string;
  };
  isolatedJsEvaluator?: IsolatedJsBatchEvaluator;
}

export interface ClosedLoopLeadInput {
  graph: ProgramFactsGraph;
  lead: LeadAnalysisInput;
  sources: readonly SourceSnapshot[];
  cache?: EscalationCache;
  hooks?: SpecializedEscalationHooks;
  enableSpecializedEscalation?: boolean;
  maxEscalations?: number;
  repositoryDir?: string;
}

export interface ClosedLoopLeadResult {
  initialDecision: LeadAnalysisDecision;
  finalDecision: LeadAnalysisDecision;
  updatedGraph: ProgramFactsGraph;
  reconsidered: boolean;
  escalatedAdapters: EscalationAdapterName[];
  addedFacts: ProgramFact[];
  addedEdges: ProgramEdge[];
  steps: EscalationStepRecord[];
  fromCache: boolean;
}

function detectLanguageFromPath(filePath: string): FactLanguage {
  const low = filePath.toLowerCase();
  if (low.endsWith(".sol")) return "solidity";
  if (/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/.test(low)) return "javascript";
  if (low.endsWith(".py")) return "python";
  if (low.endsWith(".java")) return "java";
  return "unknown";
}

function shortSymbolName(selector: string): string {
  const parts = selector.split(/[.#]/).filter(Boolean);
  return parts[parts.length - 1] || selector;
}

/**
 * Extract the source slice corresponding to the target function/method so guard
 * extraction operates on the active lead rather than unrelated code.
 */
function extractTargetFunctionSlice(
  sourceCode: string,
  selector: string,
  fallbackExcerpt?: string,
): { body: string; startLine: number } {
  const name = shortSymbolName(selector).replace(/[^A-Za-z0-9_$]/g, "");
  if (name && sourceCode) {
    const lines = sourceCode.split(/\r?\n/);
    const defRe = new RegExp(
      `\\b(?:function|def|public|private|protected|internal|external|async)?\\s*${name}\\s*\\(`,
    );
    for (let i = 0; i < lines.length; i++) {
      if (defRe.test(lines[i])) {
        const windowEnd = Math.min(lines.length, i + 45);
        return {
          body: lines.slice(i, windowEnd).join("\n"),
          startLine: i + 1,
        };
      }
    }
  }
  return {
    body: fallbackExcerpt || sourceCode.slice(0, 3000),
    startLine: 1,
  };
}

const SIMPLE_COMPARISON_RE =
  /^([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=|==|!=|<|>)\s*(-?\d+|[A-Za-z_][A-Za-z0-9_]*)(?:\s*([+\-])\s*(\d+))?$/;

const RESERVED_IDENTIFIERS = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "None",
  "True",
  "False",
  "this",
  "self",
  "msg",
  "tx",
  "block",
  "address",
  "require",
  "assert",
  "if",
  "return",
]);

/**
 * Extract Z3-compatible linear comparison constraints from require/assert/if
 * guards in the target function and existing constraint_guard facts.
 */
export function extractNumericGuardConstraints(
  sourceCode: string,
  selector: string,
  language: FactLanguage,
  existingFacts: readonly ProgramFact[],
  fallbackExcerpt?: string,
): {
  constraints: string[];
  variables: Record<string, "int" | "uint256" | "bool">;
  line: number;
} {
  const { body, startLine } = extractTargetFunctionSlice(sourceCode, selector, fallbackExcerpt);
  const rawExprs: string[] = [];

  // Pull expressions from existing constraint_guard facts first
  for (const f of existingFacts) {
    if (f.kind === "constraint_guard" && f.detail) {
      const m = /\(([^)]+)\)/.exec(f.detail);
      if (m) rawExprs.push(m[1]);
    }
  }

  // Pull require(...), assert(...), and if (...) conditions from target function body
  const guardPatterns = [
    /\brequire\s*\(([^,;)]+)/g,
    /\bassert\s*\(([^,;)]+)/g,
    /\bif\s*\(([^)]+)\)/g,
    /\bif\s+([^:\n]+):/g,
  ];
  for (const re of guardPatterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      if (m[1]) rawExprs.push(m[1]);
    }
  }

  const constraints: string[] = [];
  const seen = new Set<string>();
  const variables: Record<string, "int" | "uint256" | "bool"> = {};

  for (const expr of rawExprs) {
    const parts = expr.split(/&&|\band\b/i);
    for (const rawPart of parts) {
      const cleaned = rawPart.trim().replace(/^\(+|\)+$/g, "").trim();
      const match = SIMPLE_COMPARISON_RE.exec(cleaned);
      if (!match) continue;
      const lhs = match[1];
      const op = match[2];
      const rhs = match[3];
      const arithOp = match[4];
      const arithNum = match[5];
      if (RESERVED_IDENTIFIERS.has(lhs)) continue;
      if (/^[A-Za-z_]/.test(rhs) && RESERVED_IDENTIFIERS.has(rhs)) continue;

      const normalized = arithOp && arithNum
        ? `${lhs} ${op} ${rhs} ${arithOp} ${arithNum}`
        : `${lhs} ${op} ${rhs}`;
      if (seen.has(normalized)) continue;
      seen.add(normalized);
      constraints.push(normalized);

      const varType: "int" | "uint256" = language === "solidity" ? "uint256" : "int";
      variables[lhs] = varType;
      if (/^[A-Za-z_]/.test(rhs)) {
        variables[rhs] = varType;
      }
    }
  }

  return { constraints: constraints.slice(0, 12), variables, line: startLine };
}

/**
 * Immutably merge newly discovered specialized analyzer facts and edges into a
 * ProgramFactsGraph so re-evaluation sees every new symbol/file fact.
 */
export function mergeFactsIntoGraph(
  graph: ProgramFactsGraph,
  newFacts: readonly ProgramFact[],
  newEdges: readonly ProgramEdge[],
): ProgramFactsGraph {
  if (newFacts.length === 0 && newEdges.length === 0) {
    return graph;
  }

  const seenFactIds = new Set(graph.facts.map((f) => f.id));
  const mergedFacts = [...graph.facts];
  const adaptersUsed = new Set(graph.adaptersUsed);
  for (const f of newFacts) {
    if (!seenFactIds.has(f.id)) {
      seenFactIds.add(f.id);
      mergedFacts.push(f);
      adaptersUsed.add(f.adapter);
    }
  }

  const edgeKey = (e: ProgramEdge) => `${e.from}|${e.kind}|${e.to}|${e.file}|${e.line}`;
  const seenEdges = new Set(graph.edges.map(edgeKey));
  const mergedEdges = [...graph.edges];
  for (const e of newEdges) {
    const key = edgeKey(e);
    if (!seenEdges.has(key)) {
      seenEdges.add(key);
      mergedEdges.push(e);
    }
  }

  const byFile = new Map<string, { symbols: ProgramFactsGraph["symbols"]; facts: ProgramFact[] }>();
  for (const [file, entry] of graph.byFile.entries()) {
    byFile.set(file, { symbols: [...entry.symbols], facts: [...entry.facts] });
  }
  for (const f of newFacts) {
    const existing = byFile.get(f.file) || { symbols: [], facts: [] };
    if (!existing.facts.some((x) => x.id === f.id)) {
      existing.facts.push(f);
    }
    byFile.set(f.file, existing);
  }

  const bySymbol = new Map<string, ProgramFact[]>();
  for (const [sym, list] of graph.bySymbol.entries()) {
    bySymbol.set(sym, [...list]);
  }
  for (const f of newFacts) {
    if (!f.symbol) continue;
    const list = bySymbol.get(f.symbol) || [];
    if (!list.some((x) => x.id === f.id)) {
      list.push(f);
    }
    bySymbol.set(f.symbol, list);
  }

  return {
    ...graph,
    adaptersUsed: [...adaptersUsed].sort(),
    facts: mergedFacts,
    edges: mergedEdges,
    byFile,
    bySymbol,
  };
}

function chooseJsFastCheckProperty(
  facts: readonly ProgramFact[],
  sourceBody: string,
): FastCheckSecurityProperty {
  if (facts.some((f) => f.kind === "sink_html") || /innerHTML|text\/html|<[a-z]/i.test(sourceBody)) {
    return "no_raw_html_reflection";
  }
  if (facts.some((f) => f.kind === "sink_path") || /\bpath\.(?:join|resolve)\b|readFile/i.test(sourceBody)) {
    return "no_path_traversal";
  }
  if (/__proto__|constructor\.prototype|Object\.assign|merge/i.test(sourceBody)) {
    return "no_prototype_pollution";
  }
  return "no_raw_html_reflection";
}

function buildSynthesizedFoundryProbe(
  sourceCode: string,
  file: string,
  selector: string,
): { contractFileName: string; testContractSource: string } | null {
  const contractMatch = /\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b/.exec(sourceCode);
  if (!contractMatch) return null;
  const contractName = contractMatch[1];
  const fnName = shortSymbolName(selector);
  // Look for a single-address setter with a corresponding getter (e.g., setOperator(address) / operator())
  const setterRe = new RegExp(`\\bfunction\\s+${fnName}\\s*\\(\\s*address\\s+[A-Za-z_][A-Za-z0-9_]*\\s*\\)`);
  if (!setterRe.test(sourceCode)) return null;
  const roleMatch = /\baddress\s+public\s+(owner|admin|administrator|operator|manager|guardian|controller|authority)\b/.exec(sourceCode);
  if (!roleMatch) return null;
  const roleGetter = roleMatch[1];
  const contractFileName = file.split("/").pop() || `${contractName}.sol`;
  const testContractSource = `// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.9.0;

import "../src/${contractFileName}";
import "./Vm.sol";

contract LotusClosedLoopFoundryTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    ${contractName} target;

    function setUp() public {
        target = new ${contractName}();
    }

    function testFuzz_UnauthorizedCallerCannotMutateRole(address attacker, address newRole) public {
        vm.assume(attacker != address(this) && attacker != address(0));
        vm.assume(newRole != address(this) && newRole != address(0));
        address beforeRole = target.${roleGetter}();
        vm.prank(attacker);
        try target.${fnName}(newRole) {
            require(target.${roleGetter}() == beforeRole, "UNAUTHORIZED_ROLE_MUTATION");
        } catch {}
    }
}
`;
  return { contractFileName, testContractSource };
}

/**
 * Execute one closed-loop deterministic lead analysis:
 *   evaluate -> escalate to specialized analyzers -> merge facts -> reconsider.
 */
export function runClosedLoopLeadAnalysis(input: ClosedLoopLeadInput): ClosedLoopLeadResult {
  const initialDecision = evaluateAnalysisLead(input.graph, input.lead);
  const enableEscalation =
    input.enableSpecializedEscalation ??
    (process.env.LOTUS_DISABLE_ESCALATION !== "1");

  if (!enableEscalation) {
    return {
      initialDecision,
      finalDecision: initialDecision,
      updatedGraph: input.graph,
      reconsidered: false,
      escalatedAdapters: [],
      addedFacts: [],
      addedEdges: [],
      steps: [],
      fromCache: false,
    };
  }

  const targetSource = input.sources.find((s) => s.path === input.lead.path);
  const cacheKey = `${input.lead.leadId}|${input.lead.path}|${targetSource?.sha256 || ""}`;

  if (input.cache?.has(cacheKey)) {
    const cached = input.cache.get(cacheKey)!;
    const mergedGraph = mergeFactsIntoGraph(input.graph, cached.facts, cached.edges);
    const finalDecision = evaluateAnalysisLead(mergedGraph, input.lead);
    const reconsidered = finalDecision.action !== initialDecision.action;
    if (reconsidered) {
      finalDecision.answer = `${finalDecision.answer} [Reconsidered ${initialDecision.action} -> ${finalDecision.action} from cached escalation]`.slice(0, 680);
    }
    return {
      initialDecision,
      finalDecision,
      updatedGraph: mergedGraph,
      reconsidered,
      escalatedAdapters: cached.steps.filter((s) => s.status === "executed").map((s) => s.adapter),
      addedFacts: cached.facts,
      addedEdges: cached.edges,
      steps: cached.steps,
      fromCache: true,
    };
  }

  const language = detectLanguageFromPath(input.lead.path);
  const fileFacts = input.graph.byFile.get(input.lead.path)?.facts || [];
  const symbolFacts = fileFacts.filter(
    (f) =>
      !f.symbol ||
      f.symbol === input.lead.selector ||
      f.symbol.endsWith("." + input.lead.selector) ||
      input.lead.selector.endsWith("." + f.symbol),
  );
  const recommended = new Set<string>(
    initialDecision.matchedHypotheses.flatMap((h) => h.recommendedAdapters),
  );
  const needsDeeper =
    initialDecision.action === "defer_lead" ||
    initialDecision.matchedHypotheses.some((h) => h.disposition === "needs_deeper_analysis");

  const maxEscalations = Math.max(1, Math.min(input.maxEscalations ?? 3, 5));
  let escalationsRun = 0;
  const addedFacts: ProgramFact[] = [];
  const addedEdges: ProgramEdge[] = [];
  const steps: EscalationStepRecord[] = [];
  const escalatedAdapters: EscalationAdapterName[] = [];

  // 1. Z3 SMT Guard Feasibility — runs whenever numeric comparison guards exist
  //    (can prove UNSAT and flip assess_lead -> defer_lead, or SAT witness).
  const extractedGuards = extractNumericGuardConstraints(
    targetSource?.content || "",
    input.lead.selector,
    language,
    symbolFacts,
    input.lead.sourceExcerpt,
  );
  if (extractedGuards.constraints.length >= 2) {
    if (!input.hooks?.runZ3 && !isZ3Available()) {
      steps.push({
        adapter: "z3",
        attempted: false,
        reason: "tool_unavailable",
        status: "unavailable",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
        detail: "Z3 SMT solver is unavailable on host; guard feasibility was not evaluated.",
      });
    } else if (escalationsRun >= maxEscalations) {
      steps.push({
        adapter: "z3",
        attempted: false,
        reason: "escalation_budget_exhausted",
        status: "skipped",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
      });
    } else {
      escalationsRun++;
      const t0 = Date.now();
      try {
        const z3Input = {
          file: input.lead.path,
          line: extractedGuards.line,
          language,
          symbol: input.lead.selector,
          constraints: extractedGuards.constraints,
          variables: extractedGuards.variables,
        };
        const z3Fact = input.hooks?.runZ3
          ? input.hooks.runZ3(z3Input)
          : checkGuardFeasibilityFact(z3Input);
        const elapsedMs = Date.now() - t0;
        if (z3Fact) {
          addedFacts.push({
            ...z3Fact,
            symbol: z3Fact.symbol || input.lead.selector,
          });
          escalatedAdapters.push("z3");
          steps.push({
            adapter: "z3",
            attempted: true,
            reason: `Checked ${extractedGuards.constraints.length} guard constraint(s)`,
            status: "executed",
            factsAdded: 1,
            edgesAdded: 0,
            elapsedMs,
            detail: z3Fact.detail,
          });
        } else {
          steps.push({
            adapter: "z3",
            attempted: true,
            reason: `Checked ${extractedGuards.constraints.length} guard constraint(s)`,
            status: "executed",
            factsAdded: 0,
            edgesAdded: 0,
            elapsedMs,
            detail: "Z3 returned unknown/no new fact",
          });
        }
      } catch (err) {
        steps.push({
          adapter: "z3",
          attempted: true,
          reason: "Z3 guard feasibility check",
          status: "error",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs: Date.now() - t0,
          detail: String(err instanceof Error ? err.message : err).slice(0, 200),
        });
      }
    }
  }

  // Stop further positive escalations if Z3 already proved the guard UNSAT
  const provedUnsat = addedFacts.some((f) => f.kind === "smt_unsat_guard");

  // 2. Isolated fast-check (bubblewrap) for JavaScript targets
  if (
    !provedUnsat &&
    language === "javascript" &&
    targetSource &&
    (needsDeeper ||
      recommended.has("fast-check") ||
      symbolFacts.some((f) => f.kind === "sink_html" || f.kind === "sink_path"))
  ) {
    if (!input.hooks?.isolatedJsEvaluator && !isIsolatedJsSandboxAvailable()) {
      steps.push({
        adapter: "fast-check",
        attempted: false,
        reason: "tool_unavailable",
        status: "unavailable",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
        detail: "Isolated bubblewrap sandbox is unavailable on host; JS property probe was not executed.",
      });
    } else if (escalationsRun >= maxEscalations) {
      steps.push({
        adapter: "fast-check",
        attempted: false,
        reason: "escalation_budget_exhausted",
        status: "skipped",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
      });
    } else {
      escalationsRun++;
      const t0 = Date.now();
      const property = chooseJsFastCheckProperty(symbolFacts, targetSource.content);
      const res = runFastCheckJsProbe({
        file: input.lead.path,
        symbol: shortSymbolName(input.lead.selector),
        sourceCode: targetSource.content,
        repositoryDir: input.repositoryDir,
        property,
        numRuns: 16,
        seed: 1337,
        timeoutMs: 10_000,
        isolatedEvaluator: input.hooks?.isolatedJsEvaluator,
      });
      const elapsedMs = Date.now() - t0;
      if (res.status === "counterexample_found" || res.status === "property_held") {
        const normalizedFacts = res.fact
          ? [
              {
                ...res.fact,
                file: input.lead.path,
                symbol: input.lead.selector,
              },
            ]
          : [];
        addedFacts.push(...normalizedFacts);
        escalatedAdapters.push("fast-check");
        steps.push({
          adapter: "fast-check",
          attempted: true,
          reason: `Isolated ${res.isolation} property probe (${property})`,
          status: "executed",
          factsAdded: normalizedFacts.length,
          edgesAdded: 0,
          elapsedMs,
          detail: res.counterexample ? `Counterexample: ${res.counterexample.slice(0, 120)}` : res.detail,
        });
      } else {
        const blocked = res.status === "blocked_no_sandbox";
        steps.push({
          adapter: "fast-check",
          attempted: !blocked,
          reason: blocked ? "tool_unavailable" : `Isolated property probe (${property})`,
          status: blocked ? "unavailable" : "error",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs,
          detail: res.detail,
        });
      }
    }
  }

  // 3. Joern CPG taint-flow escalation for Java / Python / JavaScript targets
  if (
    !provedUnsat &&
    (language === "java" || language === "python" || language === "javascript") &&
    targetSource &&
    (needsDeeper || recommended.has("joern"))
  ) {
    if (!input.hooks?.runJoern && !isJoernAvailable()) {
      steps.push({
        adapter: "joern",
        attempted: false,
        reason: "tool_unavailable",
        status: "unavailable",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
        detail: `Joern CLI is unavailable on host; CPG taint/dataflow escalation for ${language} was not executed.`,
      });
    } else if (escalationsRun >= maxEscalations) {
      steps.push({
        adapter: "joern",
        attempted: false,
        reason: "escalation_budget_exhausted",
        status: "skipped",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
      });
    } else {
      escalationsRun++;
      const t0 = Date.now();
      const joernRes = input.hooks?.runJoern
        ? input.hooks.runJoern({ sources: [targetSource], lead: input.lead })
        : runJoernCpgAnalysis({ sources: [targetSource] }, 45_000);
      const elapsedMs = Date.now() - t0;
      if (joernRes.status === "completed") {
        const normalizedFacts = joernRes.facts.map((f) => ({
          ...f,
          file: f.file || input.lead.path,
          symbol: f.symbol || input.lead.selector,
        }));
        addedFacts.push(...normalizedFacts);
        addedEdges.push(...joernRes.edges);
        escalatedAdapters.push("joern");
        steps.push({
          adapter: "joern",
          attempted: true,
          reason: `CPG taint/dataflow escalation for ${language} lead`,
          status: "executed",
          factsAdded: normalizedFacts.length,
          edgesAdded: joernRes.edges.length,
          elapsedMs,
        });
      } else {
        const unavail = joernRes.status === "unavailable";
        steps.push({
          adapter: "joern",
          attempted: !unavail,
          reason: unavail ? "tool_unavailable" : `CPG taint/dataflow escalation for ${language} lead`,
          status: unavail ? "unavailable" : "error",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs,
          detail: joernRes.error,
        });
      }
    }
  }

  // 4. Mythril EVM symbolic escalation for Solidity targets
  if (
    !provedUnsat &&
    language === "solidity" &&
    targetSource &&
    (needsDeeper || recommended.has("mythril"))
  ) {
    if (!input.hooks?.runMythril && !isMythrilAvailable()) {
      steps.push({
        adapter: "mythril",
        attempted: false,
        reason: "tool_unavailable",
        status: "unavailable",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
        detail: "Mythril is unavailable on host; EVM symbolic analysis was not executed.",
      });
    } else if (escalationsRun >= maxEscalations) {
      steps.push({
        adapter: "mythril",
        attempted: false,
        reason: "escalation_budget_exhausted",
        status: "skipped",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
      });
    } else {
      escalationsRun++;
      const t0 = Date.now();
      const mythRes = input.hooks?.runMythril
        ? input.hooks.runMythril({
            file: input.lead.path,
            contractSource: targetSource.content,
            lead: input.lead,
          })
        : runMythrilSymbolicAnalysis({
            file: input.lead.path,
            contractSource: targetSource.content,
            executionTimeoutSec: 15,
            maxDepth: 12,
            timeoutMs: 30_000,
          });
      const elapsedMs = Date.now() - t0;
      if (mythRes.status === "completed") {
        const normalizedFacts = mythRes.facts.map((f) => ({
          ...f,
          file: f.file || input.lead.path,
          symbol: f.symbol || input.lead.selector,
        }));
        addedFacts.push(...normalizedFacts);
        escalatedAdapters.push("mythril");
        steps.push({
          adapter: "mythril",
          attempted: true,
          reason: "EVM symbolic analysis escalation for Solidity lead",
          status: "executed",
          factsAdded: normalizedFacts.length,
          edgesAdded: 0,
          elapsedMs,
        });
      } else {
        const unavail = mythRes.status === "unavailable";
        steps.push({
          adapter: "mythril",
          attempted: !unavail,
          reason: unavail ? "tool_unavailable" : "EVM symbolic analysis escalation for Solidity lead",
          status: unavail ? "unavailable" : "error",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs,
          detail: mythRes.error,
        });
      }
    }
  }

  // 5. Foundry stateful fuzzing escalation for Solidity targets
  if (
    !provedUnsat &&
    language === "solidity" &&
    targetSource &&
    (needsDeeper || recommended.has("foundry"))
  ) {
    if (!input.hooks?.runFoundry && !isFoundryAvailable()) {
      steps.push({
        adapter: "foundry",
        attempted: false,
        reason: "tool_unavailable",
        status: "unavailable",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
        detail: "Foundry (forge) is unavailable on host; stateful Solidity fuzz escalation was not executed.",
      });
    } else if (escalationsRun >= maxEscalations) {
      steps.push({
        adapter: "foundry",
        attempted: false,
        reason: "escalation_budget_exhausted",
        status: "skipped",
        factsAdded: 0,
        edgesAdded: 0,
        elapsedMs: 0,
      });
    } else if (input.hooks?.runFoundry) {
      escalationsRun++;
      const t0 = Date.now();
      const fRes = input.hooks.runFoundry({
        file: input.lead.path,
        contractSource: targetSource.content,
        lead: input.lead,
      });
      const elapsedMs = Date.now() - t0;
      if (fRes.status === "completed") {
        const normalizedFacts = fRes.facts.map((f) => ({
          ...f,
          file: f.file || input.lead.path,
          symbol: f.symbol || input.lead.selector,
        }));
        addedFacts.push(...normalizedFacts);
        escalatedAdapters.push("foundry");
        steps.push({
          adapter: "foundry",
          attempted: true,
          reason: "Foundry stateful invariant escalation",
          status: "executed",
          factsAdded: normalizedFacts.length,
          edgesAdded: 0,
          elapsedMs,
        });
      } else {
        const unavail = fRes.status === "unavailable";
        steps.push({
          adapter: "foundry",
          attempted: !unavail,
          reason: unavail ? "tool_unavailable" : "Foundry stateful invariant escalation",
          status: unavail ? "unavailable" : "error",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs,
          detail: fRes.error,
        });
      }
    } else {
      const synthesized = buildSynthesizedFoundryProbe(
        targetSource.content,
        input.lead.path,
        input.lead.selector,
      );
      if (synthesized) {
        escalationsRun++;
        const t0 = Date.now();
        const fRes = runFoundrySolidityTest({
          file: input.lead.path,
          contractSource: targetSource.content,
          contractFileName: synthesized.contractFileName,
          testContractSource: synthesized.testContractSource,
          fuzzRuns: 32,
          timeoutMs: 45_000,
        });
        const elapsedMs = Date.now() - t0;
        if (fRes.status === "completed") {
          const normalizedFacts = fRes.facts.map((f) => ({
            ...f,
            file: input.lead.path,
            symbol: input.lead.selector,
          }));
          addedFacts.push(...normalizedFacts);
          escalatedAdapters.push("foundry");
          steps.push({
            adapter: "foundry",
            attempted: true,
            reason: "Synthesized Foundry unauthorized role-mutation fuzz probe",
            status: "executed",
            factsAdded: normalizedFacts.length,
            edgesAdded: 0,
            elapsedMs,
          });
        } else {
          const unavail = fRes.status === "unavailable";
          steps.push({
            adapter: "foundry",
            attempted: !unavail,
            reason: unavail ? "tool_unavailable" : "Synthesized Foundry probe",
            status: unavail ? "unavailable" : "error",
            factsAdded: 0,
            edgesAdded: 0,
            elapsedMs,
            detail: fRes.error,
          });
        }
      } else {
        steps.push({
          adapter: "foundry",
          attempted: false,
          reason: "no_synthesized_probe",
          status: "skipped",
          factsAdded: 0,
          edgesAdded: 0,
          elapsedMs: 0,
          detail: "No source-grounded Foundry probe template matched this Solidity lead.",
        });
      }
    }
  }

  // Merge newly discovered facts/edges into the ProgramFactsGraph and RECONSIDER the lead
  const updatedGraph = mergeFactsIntoGraph(input.graph, addedFacts, addedEdges);
  const finalDecision =
    addedFacts.length > 0 || addedEdges.length > 0
      ? evaluateAnalysisLead(updatedGraph, input.lead)
      : initialDecision;

  const reconsidered = finalDecision.action !== initialDecision.action;
  if (reconsidered) {
    finalDecision.answer = `${finalDecision.answer} [Reconsidered ${initialDecision.action} -> ${finalDecision.action} after specialized escalation: ${escalatedAdapters.join(", ")}]`.slice(
      0,
      680,
    );
  }

  if (input.cache) {
    input.cache.set(cacheKey, {
      facts: addedFacts,
      edges: addedEdges,
      steps,
    });
  }

  return {
    initialDecision,
    finalDecision,
    updatedGraph,
    reconsidered,
    escalatedAdapters,
    addedFacts,
    addedEdges,
    steps,
    fromCache: false,
  };
}
