/**
 * Deterministic Hypothesis Engine.
 *
 * Consumes normalized ProgramFactsGraph entries (from AST parsers, Semgrep,
 * Slither, and future Tree-sitter / Joern / Z3 / Mythril / Foundry adapters)
 * and synthesizes ranked, falsifiable, source-grounded security hypotheses
 * without invoking any LLM.
 */
import { createHash } from "node:crypto";
import type {
  FactLanguage,
  ProgramFact,
  ProgramFactsGraph,
  ProgramSymbol,
} from "./program-facts";

export type HypothesisCategory =
  | "privileged_primitive"
  | "minting"
  | "value_extraction"
  | "reinitialization"
  | "access_control"
  | "injection_html"
  | "path_traversal"
  | "command_or_eval"
  | "deserialization"
  | "sql_injection"
  | "static_triage";

export type HypothesisDisposition =
  | "ready_for_experiment"
  | "needs_deeper_analysis"
  | "guarded_control"
  | "low_signal_deferred";

export interface HypothesisWitness {
  file: string;
  line: number;
  symbol?: string;
  factKind: ProgramFact["kind"];
  detail: string;
}

export interface SecurityHypothesis {
  id: string;
  language: FactLanguage;
  file: string;
  line: number;
  selector: string;
  category: HypothesisCategory;
  priority: number;
  disposition: HypothesisDisposition;
  statement: string;
  falsification: string;
  rationale: string;
  recommendedProbeKind?: "solidity_sequence" | "html_reflection" | "path_construction";
  recommendedAdapters: string[];
  witnesses: HypothesisWitness[];
}

export interface LeadAnalysisInput {
  leadId: string;
  path: string;
  selector: string;
  sourceEvidence: string;
  sourceExcerpt?: string;
  rule?: string;
  message?: string;
}

export interface LeadAnalysisDecision {
  action: "assess_lead" | "defer_lead";
  leadId: string;
  path: string;
  query: string;
  hypothesis: string;
  answer: string;
  matchedHypotheses: SecurityHypothesis[];
}

function hypothesisId(file: string, selector: string, category: HypothesisCategory): string {
  return createHash("sha256")
    .update(`${file}|${selector}|${category}`)
    .digest("hex")
    .slice(0, 32);
}

function toWitness(fact: ProgramFact): HypothesisWitness {
  return {
    file: fact.file,
    line: fact.line,
    symbol: fact.symbol,
    factKind: fact.kind,
    detail: fact.detail,
  };
}

export function generateHypotheses(graph: ProgramFactsGraph): SecurityHypothesis[] {
  const results: SecurityHypothesis[] = [];
  const seen = new Set<string>();

  const pushUnique = (h: SecurityHypothesis) => {
    if (seen.has(h.id)) return;
    seen.add(h.id);
    results.push(h);
  };

  // Group facts per symbol (and per file for symbol-less facts)
  const symbolMap = new Map<string, ProgramSymbol>();
  for (const sym of graph.symbols) {
    if (sym.kind === "function" || sym.kind === "method") {
      symbolMap.set(`${sym.file}|${sym.qualifiedName}`, sym);
    }
  }

  for (const [, sym] of symbolMap) {
    const fileBucket = graph.byFile.get(sym.file);
    const symFacts = (fileBucket?.facts || []).filter((f) => f.symbol === sym.qualifiedName);
    if (!symFacts.length) continue;

    const hasAuthGuard = symFacts.some((f) => f.kind === "auth_guard");
    const staticFindings = symFacts.filter((f) => f.kind === "static_finding");
    const staticBoost = staticFindings.length ? 8 : 0;

    // 1. Privileged primitives (delegatecall / selfdestruct)
    const privFacts = symFacts.filter((f) => f.kind === "privileged_primitive");
    if (privFacts.length) {
      const priority = Math.min(100, (hasAuthGuard ? 62 : 98) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "privileged_primitive"),
        language: sym.language,
        file: sym.file,
        line: privFacts[0].line,
        selector: sym.qualifiedName,
        category: "privileged_primitive",
        priority,
        disposition: sym.language === "solidity" ? "ready_for_experiment" : "needs_deeper_analysis",
        statement: hasAuthGuard
          ? `Unauthorized caller ($account1) must not execute privileged primitive in ${sym.qualifiedName}; authorized caller may.`
          : `Unauthorized caller ($account1) may invoke unguarded privileged primitive (delegatecall/selfdestruct) in ${sym.qualifiedName}.`,
        falsification: `Execute ${sym.qualifiedName} from unauthorized sender ($account1); hypothesis is falsified if the call reverts with authorization failure and state/code remain intact.`,
        rationale: `${sym.file}:${privFacts[0].line} (${sym.qualifiedName}) invokes delegatecall/selfdestruct${hasAuthGuard ? " behind an authorization guard" : " without a detected authorization modifier or sender check"}.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: sym.language === "solidity" ? ["solidity-ast", "slither", "foundry", "mythril"] : ["joern"],
        witnesses: [...privFacts, ...staticFindings].map(toWitness),
      });
    }

    // 2. Mint / burn operations
    const mintFacts = symFacts.filter((f) => f.kind === "mint_or_burn");
    if (mintFacts.length) {
      const priority = Math.min(100, (hasAuthGuard ? 58 : 95) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "minting"),
        language: sym.language,
        file: sym.file,
        line: mintFacts[0].line,
        selector: sym.qualifiedName,
        category: "minting",
        priority,
        disposition: hasAuthGuard ? "guarded_control" : "ready_for_experiment",
        statement: `Unauthorized caller ($account1) must not mint or burn supply via ${sym.qualifiedName}; authorized minter/owner may.`,
        falsification: `Invoke ${sym.qualifiedName} as $account1 and verify transaction reverts and totalSupply/balances remain unchanged.`,
        rationale: `${sym.file}:${mintFacts[0].line} (${sym.qualifiedName}) calls mint/burn${hasAuthGuard ? " with explicit auth guard" : " without a detected authorization guard"}.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: ["solidity-ast", "slither", "foundry"],
        witnesses: [...mintFacts, ...staticFindings].map(toWitness),
      });
    }

    // 3. Value extraction (ETH / ERC20 transfer / withdraw / sweep)
    const transferFacts = symFacts.filter((f) => f.kind === "value_transfer");
    if (transferFacts.length) {
      const priority = Math.min(100, (hasAuthGuard ? 52 : 90) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "value_extraction"),
        language: sym.language,
        file: sym.file,
        line: transferFacts[0].line,
        selector: sym.qualifiedName,
        category: "value_extraction",
        priority,
        disposition: hasAuthGuard ? "guarded_control" : "ready_for_experiment",
        statement: `Unauthorized caller ($account1) must not extract ETH or held ERC20 tokens via ${sym.qualifiedName}.`,
        falsification: `Fund contract and invoke ${sym.qualifiedName} as $account1; falsified if unauthorized extraction reverts or attacker balance does not increase.`,
        rationale: `${sym.file}:${transferFacts[0].line} (${sym.qualifiedName}) performs value transfer${hasAuthGuard ? " under an authorization guard" : " without a detected caller restriction"}.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: ["solidity-ast", "slither", "foundry", "z3"],
        witnesses: [...transferFacts, ...staticFindings].map(toWitness),
      });
    }

    // 4. Initializers / re-initialization
    const initFacts = symFacts.filter((f) => f.kind === "initializer");
    if (initFacts.length) {
      const guarded = Boolean(initFacts[0].metadata?.hasInitModifier || initFacts[0].metadata?.isAuthGuarded);
      const priority = Math.min(100, (guarded ? 44 : 92) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "reinitialization"),
        language: sym.language,
        file: sym.file,
        line: initFacts[0].line,
        selector: sym.qualifiedName,
        category: "reinitialization",
        priority,
        disposition: guarded ? "guarded_control" : "ready_for_experiment",
        statement: `Unauthorized caller ($account1) must not re-initialize ${sym.qualifiedName} after initial setup; deployer authority must persist.`,
        falsification: `Call ${sym.qualifiedName} from $account0 then re-call from $account1; falsified if second call reverts and owner/admin remains $account0.`,
        rationale: `${sym.file}:${initFacts[0].line} (${sym.qualifiedName}) is an initializer${guarded ? " guarded by initializer/auth modifier" : " lacking an explicit initializer or caller guard"}.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: ["solidity-ast", "slither", "foundry"],
        witnesses: [...initFacts, ...staticFindings].map(toWitness),
      });
    }

    // 5. Unguarded state mutation (Solidity)
    const unguardedFacts = symFacts.filter((f) => f.kind === "unguarded_mutation");
    if (unguardedFacts.length && !privFacts.length && !mintFacts.length && !transferFacts.length && !initFacts.length) {
      const vars = (unguardedFacts[0].metadata?.variables as string[] | undefined) || [];
      const sensitiveVar = vars.some((v) => /owner|admin|role|govern|fee|oracle|vault|treasury|minter|paused|implementation|proxy|reward/i.test(v));
      const priority = Math.min(95, (sensitiveVar ? 82 : 48) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "access_control"),
        language: sym.language,
        file: sym.file,
        line: unguardedFacts[0].line,
        selector: sym.qualifiedName,
        category: "access_control",
        priority,
        disposition: sensitiveVar ? "ready_for_experiment" : "needs_deeper_analysis",
        statement: `Unauthorized caller ($account1) must not mutate state (${vars.join(", ")}) via ${sym.qualifiedName}.`,
        falsification: `Invoke ${sym.qualifiedName} from $account1 and verify state variables (${vars.join(", ")}) are unchanged or the transaction reverts.`,
        rationale: `${sym.file}:${unguardedFacts[0].line} (${sym.qualifiedName}) writes state (${vars.join(", ")}) without a detected auth modifier or sender check.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: ["solidity-ast", "slither", "foundry"],
        witnesses: [...unguardedFacts, ...staticFindings].map(toWitness),
      });
    }

    // 6. HTML reflection sinks (JS / Python / Java)
    const htmlSinks = symFacts.filter((f) => f.kind === "sink_html");
    if (htmlSinks.length) {
      const priority = Math.min(95, (hasAuthGuard ? 50 : 84) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "injection_html"),
        language: sym.language,
        file: sym.file,
        line: htmlSinks[0].line,
        selector: sym.qualifiedName,
        category: "injection_html",
        priority,
        disposition: hasAuthGuard ? "guarded_control" : "ready_for_experiment",
        statement: `Untrusted input passed into ${sym.qualifiedName} must be escaped rather than reflected as raw HTML markup.`,
        falsification: `Replay ${sym.qualifiedName} with control text and raw HTML payload; falsified if output escapes markup or rejects the payload.`,
        rationale: `${sym.file}:${htmlSinks[0].line} (${sym.qualifiedName}) constructs HTML output${hasAuthGuard ? " with a detected escaping/sanitization pattern" : " without a detected HTML sanitizer in scope"}.`,
        recommendedProbeKind: "html_reflection",
        recommendedAdapters: sym.language === "javascript" ? ["babel-parser", "fast-check"] : sym.language === "python" ? ["libcst", "semgrep"] : ["javaparser", "joern"],
        witnesses: [...htmlSinks, ...staticFindings].map(toWitness),
      });
    }

    // 7. Path traversal / path construction sinks
    const pathSinks = symFacts.filter((f) => f.kind === "sink_path");
    if (pathSinks.length) {
      const priority = Math.min(95, (hasAuthGuard ? 48 : 82) + staticBoost);
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "path_traversal"),
        language: sym.language,
        file: sym.file,
        line: pathSinks[0].line,
        selector: sym.qualifiedName,
        category: "path_traversal",
        priority,
        disposition: hasAuthGuard ? "guarded_control" : "ready_for_experiment",
        statement: `Traversal input (../) supplied to ${sym.qualifiedName} must not escape the intended base directory.`,
        falsification: `Replay ${sym.qualifiedName} with control filename and traversal payload; falsified if path normalization confines output inside base root or rejects traversal.`,
        rationale: `${sym.file}:${pathSinks[0].line} (${sym.qualifiedName}) builds or reads a filesystem path${hasAuthGuard ? " with containment checks present" : " without a detected base-directory containment check"}.`,
        recommendedProbeKind: "path_construction",
        recommendedAdapters: sym.language === "javascript" ? ["babel-parser", "fast-check"] : sym.language === "python" ? ["libcst", "semgrep"] : ["javaparser", "joern"],
        witnesses: [...pathSinks, ...staticFindings].map(toWitness),
      });
    }

    // 8. Command / eval / deserialization / SQL sinks
    const criticalSinks = symFacts.filter(
      (f) => f.kind === "sink_command" || f.kind === "sink_deserialization" || f.kind === "sink_sql",
    );
    if (criticalSinks.length) {
      const topSink = criticalSinks[0];
      const category: HypothesisCategory =
        topSink.kind === "sink_command" ? "command_or_eval"
        : topSink.kind === "sink_deserialization" ? "deserialization"
        : "sql_injection";
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, category),
        language: sym.language,
        file: sym.file,
        line: topSink.line,
        selector: sym.qualifiedName,
        category,
        priority: Math.min(98, 86 + staticBoost),
        disposition: "needs_deeper_analysis",
        statement: `Untrusted input reaching ${sym.qualifiedName} must not control ${topSink.kind.replace("sink_", "")} execution.`,
        falsification: `Trace dataflow from external inputs to ${sym.file}:${topSink.line}; falsified if input is constant, validated, or parameterized.`,
        rationale: `${sym.file}:${topSink.line} (${sym.qualifiedName}) reaches ${topSink.detail}.`,
        recommendedAdapters: ["joern", "semgrep", "z3"],
        witnesses: [...criticalSinks, ...staticFindings].map(toWitness),
      });
    }

    // 9. Static scanner lead with no higher-priority hypothesis already emitted
    if (staticFindings.length && !results.some((r) => r.file === sym.file && r.selector === sym.qualifiedName)) {
      const top = staticFindings[0];
      const highSev = top.severity === "high" || top.severity === "critical";
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, "static_triage"),
        language: sym.language,
        file: sym.file,
        line: top.line,
        selector: sym.qualifiedName,
        category: "static_triage",
        priority: highSev ? (hasAuthGuard ? 55 : 74) : (hasAuthGuard ? 30 : 45),
        disposition: hasAuthGuard ? "guarded_control" : "needs_deeper_analysis",
        statement: `Static scanner finding on ${sym.qualifiedName} (${String(top.metadata?.rule || "rule")}) must not allow unauthorized state transition or unsafe sink behavior.`,
        falsification: `Inspect or execute ${sym.qualifiedName} at ${sym.file}:${top.line}; falsified if caller guard, input validation, or precondition prevents exploitability.`,
        rationale: `${sym.file}:${top.line} (${sym.qualifiedName}) flagged by ${top.adapter}: ${top.detail}${hasAuthGuard ? " (auth/sanitization guard present in enclosing function)" : ""}.`,
        recommendedProbeKind: sym.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: [top.adapter, "tree-sitter", "z3"],
        witnesses: staticFindings.map(toWitness),
      });
    }
  }

  results.sort((a, b) => b.priority - a.priority || a.file.localeCompare(b.file) || a.line - b.line);
  return results;
}

/**
 * Deterministic lead evaluator for LOTUS's ANALYZE stage.
 * Produces a source-grounded assess_lead or defer_lead decision backed strictly
 * by ProgramFactsGraph + generated hypotheses (zero LLM calls).
 */
export function evaluateAnalysisLead(
  graph: ProgramFactsGraph,
  lead: LeadAnalysisInput,
): LeadAnalysisDecision {
  const allHypotheses = generateHypotheses(graph);
  const directMatches = allHypotheses.filter(
    (h) => h.file === lead.path && (h.selector === lead.selector || h.selector.endsWith("." + lead.selector) || lead.selector.endsWith("." + h.selector)),
  );
  const fileFacts = graph.byFile.get(lead.path)?.facts || [];
  const symbolFacts = fileFacts.filter(
    (f) => !f.symbol || f.symbol === lead.selector || f.symbol.endsWith("." + lead.selector) || lead.selector.endsWith("." + f.symbol),
  );

  if (directMatches.length > 0) {
    const top = directMatches[0];
    const shouldTest = top.disposition === "ready_for_experiment" || (top.disposition === "guarded_control" && top.priority >= 40);
    const witnessSummary = top.witnesses
      .slice(0, 3)
      .map((w) => `${w.file}:${w.line} [${w.factKind}] ${w.detail}`)
      .join("; ");
    return {
      action: shouldTest ? "assess_lead" : "defer_lead",
      leadId: lead.leadId,
      path: lead.path,
      query: lead.selector,
      hypothesis: top.statement.slice(0, 580),
      answer: `${top.rationale} Facts (${symbolFacts.length}): ${witnessSummary || lead.sourceEvidence}`.slice(0, 680),
      matchedHypotheses: directMatches,
    };
  }

  // Fallback: inspect symbol/file facts directly so every lead receives factual disposition
  const authGuards = symbolFacts.filter((f) => f.kind === "auth_guard" || f.kind === "constraint_guard");
  const stateWrites = symbolFacts.filter((f) => f.kind === "state_write" || f.kind === "unguarded_mutation");
  const sinks = symbolFacts.filter((f) => f.kind.startsWith("sink_") || f.kind === "value_transfer" || f.kind === "mint_or_burn");

  if (sinks.length > 0 || stateWrites.length > 0) {
    const primary = sinks[0] || stateWrites[0];
    return {
      action: "assess_lead",
      leadId: lead.leadId,
      path: lead.path,
      query: lead.selector,
      hypothesis: `Unauthorized or untrusted invocation of ${lead.selector} must not violate access or sink safety at ${primary.file}:${primary.line}.`,
      answer: `Deterministic AST/fact analysis of ${lead.sourceEvidence} identified ${primary.kind} (${primary.detail})${authGuards.length ? ` alongside ${authGuards.length} guard fact(s)` : " with no explicit guard fact"}.`.slice(0, 680),
      matchedHypotheses: [],
    };
  }

  return {
    action: "defer_lead",
    leadId: lead.leadId,
    path: lead.path,
    query: lead.selector,
    hypothesis: "No supported executable property",
    answer: `Deterministic program-facts analysis of ${lead.sourceEvidence} (${lead.selector}) found ${symbolFacts.length} fact(s), ${authGuards.length} guard(s), and no direct unguarded state mutation or executable sink; deferred for deeper symbolic/fuzzing adapters (Foundry/Mythril/Joern/Z3).`.slice(0, 680),
    matchedHypotheses: [],
  };
}
