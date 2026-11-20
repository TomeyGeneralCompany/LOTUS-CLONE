/**
 * Deterministic Function-Level Analysis Candidate Queue.
 *
 * Separates candidate generation (preserving every eligible unqueued function
 * across the entire acquired source inventory) from bounded candidate admission
 * (selecting a scored, evidence-ranked batch for the current ANALYZE pass while
 * retaining all remaining candidates in the persisted queue).
 */
import { createHash } from "node:crypto";
import type { StaticLeadHint } from "../controller-solidity-experiment-planner";
import type { ProgramFactsGraph } from "./program-facts";

export interface AnalysisCandidate {
  id: string;
  path: string;
  selector: string;
  sourceCommit: string;
  sourceSha256: string;
  staticLeadIds: string[];
  priority: number;
  selectionReasons: string[];
  status: "admitted" | "queued" | "blocked";
  sourceEvidence: string;
  sourceExcerpt: string;
  excerptStart: number;
  truncated: boolean;
  lineStart: number;
  lineEnd: number;
}

export interface AnalysisCandidateSourceItem {
  path: string;
  sourceCommit: string;
  sourceContent: string;
  unqueuedSelectors: readonly string[];
}

export interface AnalysisCandidateQueueOptions {
  items: readonly AnalysisCandidateSourceItem[];
  staticLeads?: readonly StaticLeadHint[];
  graph?: ProgramFactsGraph | null;
  maxAdmitted?: number;
  maxPerFile?: number;
}

export interface AnalysisCandidateQueueResult {
  /** Complete inventory of every eligible function candidate (deterministic order). */
  inventory: AnalysisCandidate[];
  /** Bounded subset admitted to the active ANALYZE window. */
  admitted: AnalysisCandidate[];
  /** Unprocessed candidates retained in the queue for subsequent passes. */
  queued: AnalysisCandidate[];
  /** Candidates blocked because acquired repository commit or declaration span was unavailable. */
  blocked: Array<{ path: string; selector: string; reason: string }>;
}

const FINANCIAL_ENTRYPOINT_RE =
  /^(?:deposit|withdraw|earlyWithdraw|topupDeposit|rolloverDeposit|mintVested|fund|claim|redeem|stake|unstake|borrow|repay|liquidate|swap|zap|rescue|skim|mint|burn|accrue|distribute|settle|collect|harvest|rebalance|flashLoan)$/i;

const ACCOUNTING_STATE_HINT_RE =
  /\b(?:balances?|totalSupply|totalAssets|totalDeposits|shares?|debt|principal|accrued|reserves?|liquidity|reward(?:s|PerToken)?|deposits?)\b/;

function computeLineNumber(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function stableStaticLeadId(lead: StaticLeadHint): string {
  return createHash("sha256")
    .update(JSON.stringify([lead.path, lead.line, lead.rule, lead.engine || ""]))
    .digest("hex")
    .slice(0, 16);
}

/**
 * Locate the target function span inside Solidity source without losing
 * multi-function files to first-selector-only truncation.
 */
function locateFunctionSpan(
  content: string,
  selector: string,
): { start: number; end: number; lineStart: number; lineEnd: number; excerpt: string; truncated: boolean } | null {
  const method = selector.split(".").pop() || "";
  const safeMethod = method.replace(/[^A-Za-z0-9_]/g, "");
  if (!safeMethod) return null;
  const re = new RegExp(`\\bfunction\\s+${safeMethod}\\s*\\(`);
  const match = re.exec(content);
  if (!match) return null;

  const start = Math.max(0, match.index - 160);
  const end = Math.min(content.length, match.index + 1100);
  const lineStart = computeLineNumber(content, match.index);
  const lineEnd = computeLineNumber(content, Math.min(content.length, match.index + 1100));
  return {
    start,
    end,
    lineStart,
    lineEnd,
    excerpt: content.slice(start, end),
    truncated: end < content.length,
  };
}

/**
 * Build the complete deterministic function-level candidate inventory and select
 * a bounded batch for admission without silently discarding overflow candidates.
 */
export function buildAnalysisCandidateQueue(
  options: AnalysisCandidateQueueOptions,
): AnalysisCandidateQueueResult {
  const staticLeads = options.staticLeads || [];
  const graph = options.graph || null;
  const maxAdmitted = Math.max(1, Math.min(options.maxAdmitted ?? 18, 128));
  const maxPerFile = Math.max(1, Math.min(options.maxPerFile ?? 4, maxAdmitted));

  const blocked: Array<{ path: string; selector: string; reason: string }> = [];
  const rawCandidates: AnalysisCandidate[] = [];
  const seenIds = new Set<string>();

  // Pre-index shared-state variables across functions if a graph is supplied
  const varWriters = new Map<string, Set<string>>();
  if (graph) {
    for (const edge of graph.edges) {
      if (String(edge.kind) === "writes_state" || String(edge.kind) === "reads_state") {
        const set = varWriters.get(edge.to) || new Set<string>();
        set.add(edge.from);
        varWriters.set(edge.to, set);
      }
    }
  }

  for (const item of options.items) {
    const sourceSha256 = createHash("sha256").update(item.sourceContent).digest("hex");
    const fileLeads = staticLeads.filter((l) => l.path === item.path);

    for (const selector of item.unqueuedSelectors) {
      if (!/^[a-f0-9]{40}$/.test(item.sourceCommit)) {
        blocked.push({
          path: item.path,
          selector,
          reason: "acquired_repository_commit_unavailable",
        });
        continue;
      }

      const span = locateFunctionSpan(item.sourceContent, selector);
      if (!span) {
        blocked.push({
          path: item.path,
          selector,
          reason: "function_declaration_not_located",
        });
        continue;
      }

      const id = createHash("sha256")
        .update(JSON.stringify([item.sourceCommit, sourceSha256, item.path, selector]))
        .digest("hex");
      if (seenIds.has(id)) continue;
      seenIds.add(id);

      const method = selector.split(".").pop() || "";
      let priority = 10;
      const selectionReasons: string[] = [];
      const staticLeadIds: string[] = [];

      // 1. Financial / accounting entrypoint signal
      if (FINANCIAL_ENTRYPOINT_RE.test(method)) {
        priority += 40;
        selectionReasons.push(`financial_entrypoint:${method}`);
      }

      // 2. Function-local accounting state references
      if (ACCOUNTING_STATE_HINT_RE.test(span.excerpt)) {
        priority += 15;
        selectionReasons.push("accounting_state_reference");
      }

      // 3. Function-localized static leads vs broader file leads
      const matchedFnLeads = fileLeads.filter(
        (l) =>
          (l.line >= span.lineStart && l.line <= span.lineEnd) ||
          (method.length >= 3 && l.message.includes(method)),
      );
      if (matchedFnLeads.length > 0) {
        const boost = Math.min(45, matchedFnLeads.length * 20);
        priority += boost;
        for (const l of matchedFnLeads) {
          staticLeadIds.push(stableStaticLeadId(l));
        }
        selectionReasons.push(`function_static_leads:${matchedFnLeads.length}`);
      } else if (fileLeads.length > 0) {
        priority += Math.min(12, fileLeads.length * 3);
        for (const l of fileLeads.slice(0, 4)) {
          staticLeadIds.push(stableStaticLeadId(l));
        }
        selectionReasons.push(`file_static_leads:${fileLeads.length}`);
      }

      // 4. Program-facts graph signals (when available)
      if (graph) {
        const fileBucket = graph.byFile.get(item.path);
        const symFacts = (fileBucket?.facts || []).filter(
          (f) => f.symbol === selector || (f.symbol && selector.endsWith("." + f.symbol)),
        );
        if (symFacts.some((f) => f.kind === "privileged_primitive")) {
          priority += 30;
          selectionReasons.push("fact:privileged_primitive");
        }
        if (symFacts.some((f) => f.kind === "unguarded_mutation")) {
          priority += 25;
          selectionReasons.push("fact:unguarded_mutation");
        }
        if (symFacts.some((f) => f.kind === "value_transfer" || f.kind === "mint_or_burn")) {
          priority += 20;
          selectionReasons.push("fact:value_or_supply_mutation");
        }
        if (symFacts.some((f) => f.kind === "state_write") && !symFacts.some((f) => f.kind === "auth_guard")) {
          priority += 10;
          selectionReasons.push("fact:state_write_without_auth_guard");
        }
        // Multi-function shared-state coupling boost
        const coupledVars = new Set<string>();
        for (const edge of graph.edges) {
          if (
            edge.from === selector &&
            (String(edge.kind) === "writes_state" || String(edge.kind) === "reads_state") &&
            (varWriters.get(edge.to)?.size || 0) >= 2
          ) {
            coupledVars.add(edge.to);
          }
        }
        if (coupledVars.size > 0) {
          priority += Math.min(20, coupledVars.size * 10);
          selectionReasons.push(`shared_state_coupling:${[...coupledVars].sort().slice(0, 3).join(",")}`);
        }
      }

      if (selectionReasons.length === 0) {
        selectionReasons.push("unqueued_state_changing_entrypoint");
      }

      const sourceEvidence = `${item.path}:${span.start}-${span.end}:${sourceSha256}`;
      rawCandidates.push({
        id,
        path: item.path,
        selector,
        sourceCommit: item.sourceCommit,
        sourceSha256,
        staticLeadIds: [...new Set(staticLeadIds)].sort(),
        priority,
        selectionReasons,
        status: "queued",
        sourceEvidence,
        sourceExcerpt: span.excerpt,
        excerptStart: span.start,
        truncated: span.truncated,
        lineStart: span.lineStart,
        lineEnd: span.lineEnd,
      });
    }
  }

  // Deterministic ordering: highest priority first, then path, then selector, then id
  rawCandidates.sort(
    (a, b) =>
      b.priority - a.priority ||
      a.path.localeCompare(b.path) ||
      a.selector.localeCompare(b.selector) ||
      a.id.localeCompare(b.id),
  );

  // Bounded admission with per-file diversity cap (second pass fills remaining slots
  // if fewer files exist than maxAdmitted so small repos never under-admit).
  const admitted: AnalysisCandidate[] = [];
  const admittedIds = new Set<string>();
  const perFileCount = new Map<string, number>();

  for (const cand of rawCandidates) {
    if (admitted.length >= maxAdmitted) break;
    const count = perFileCount.get(cand.path) || 0;
    if (count >= maxPerFile) continue;
    cand.status = "admitted";
    admitted.push(cand);
    admittedIds.add(cand.id);
    perFileCount.set(cand.path, count + 1);
  }

  if (admitted.length < maxAdmitted) {
    for (const cand of rawCandidates) {
      if (admitted.length >= maxAdmitted) break;
      if (admittedIds.has(cand.id)) continue;
      cand.status = "admitted";
      admitted.push(cand);
      admittedIds.add(cand.id);
    }
  }

  const queued = rawCandidates.filter((c) => c.status === "queued");
  return {
    inventory: rawCandidates,
    admitted,
    queued,
    blocked,
  };
}
