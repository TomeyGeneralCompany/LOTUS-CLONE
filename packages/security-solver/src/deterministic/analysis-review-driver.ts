/**
 * Deterministic Analysis & Review Driver.
 *
 * Replaces Ollama/Qwen across ANALYZE, REVIEW/REPORT, and evidence-only review
 * using the Program-Facts IR, Hypothesis Engine, and controller execution ledger.
 * Zero LLM calls are made when LOCAL_MODEL_ADAPTER=deterministic (the default in
 * LOTUS-CLONE when AUTOHACK_OLLAMA_URL is not explicitly configured).
 */
import { createHash } from "node:crypto";
import type { SourceSnapshot, StaticLeadHint } from "../controller-solidity-experiment-planner";
import { buildProgramFactsGraph, createHostFactsAdapters } from "./program-facts";
import { evaluateAnalysisLead, type LeadAnalysisInput } from "./hypothesis-engine";

export type LocalModelAdapter = "deterministic" | "ollama" | "qwen-agent";

export function resolveLocalModelAdapter(env: NodeJS.ProcessEnv = process.env): LocalModelAdapter {
  const explicit = env.LOCAL_MODEL_ADAPTER?.trim();
  if (explicit) {
    if (explicit === "deterministic" || explicit === "ollama" || explicit === "qwen-agent") {
      return explicit;
    }
    throw new Error("Unknown LOCAL_MODEL_ADAPTER");
  }
  if (env.LOTUS_DETERMINISTIC === "1" || env.LOTUS_DETERMINISTIC === "true") {
    return "deterministic";
  }
  if (env.AUTOHACK_OLLAMA_URL?.trim()) {
    return "ollama";
  }
  return "deterministic";
}

export function isDeterministicMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return resolveLocalModelAdapter(env) === "deterministic";
}

export interface DeterministicOutcomeCounts {
  observed: number;
  observation_only: number;
  not_observed: number;
  unsupported: number;
  incomplete: number;
  rejected: number;
  pending: number;
}

export interface DeterministicObservedCase {
  caseId: string;
  path: string;
  selector: string;
  kind: string;
  callerFile?: string;
  callerLine?: number;
  reachability?: "caller" | "direct_transaction";
}

export interface DeterministicAuditTurnInput {
  stage?: string;
  analyzeModelPending?: boolean;
  activeLead?: LeadAnalysisInput | null;
  pendingLeadIds?: readonly string[];
  sources: readonly SourceSnapshot[];
  staticLeads?: readonly StaticLeadHint[];
  constraints?: Partial<Record<"action" | "path" | "query" | "answer", string[]>>;
  requestSchema?: Record<string, any>;
  initialSourcePaths?: readonly string[];
  readPaths?: readonly string[];
  outcomes?: DeterministicOutcomeCounts;
  observedCases?: readonly DeterministicObservedCase[];
  recoveredFinalJson?: string | null;
}

export interface DeterministicAuditAction {
  action: string;
  path: string;
  query: string;
  answer: string;
  leadId?: string;
  hypothesis?: string;
  offset?: number;
  result?: Record<string, unknown>;
}

function buildDeterministicNegativeFinal(input: DeterministicAuditTurnInput): Record<string, unknown> {
  const o = input.outcomes || {
    observed: 0,
    observation_only: 0,
    not_observed: 0,
    unsupported: 0,
    incomplete: 0,
    rejected: 0,
    pending: 0,
  };
  const totalSelected =
    o.observed + o.observation_only + o.not_observed + o.unsupported + o.incomplete + o.rejected + o.pending;
  const readCount = input.readPaths?.length ?? input.sources.length;
  const indexedCount = Math.max(readCount, input.initialSourcePaths?.length ?? input.sources.length);
  const incompleteTotal = o.observation_only + o.incomplete + o.unsupported + o.pending;
  const reason =
    `${readCount}/${indexedCount} source files inspected; ${totalSelected} experiments selected: ` +
    `${o.not_observed} source-supported negative experiments, ${o.observation_only} observation-only, ` +
    `${o.incomplete} failed/incomplete fixtures, ${o.unsupported} unsupported, ${o.observed} observed behaviors. ` +
    (incompleteTotal > 0
      ? `Deterministic analysis recorded no verified positive behavior; no vulnerability absence claim is made for ${incompleteTotal} incomplete, observation-only, or unsupported items.`
      : `Deterministic analysis completed all ${totalSelected} selected experiments with zero observed security violations.`);
  return {
    findings: [],
    outcome: "no_testable_candidate",
    reason: reason.slice(0, 980),
  };
}

function buildDeterministicPositiveFinal(
  observedCases: readonly DeterministicObservedCase[],
): Record<string, unknown> {
  const findings = observedCases.slice(0, 8).map((obs) => {
    const isSolidity = obs.kind === "solidity_sequence" || obs.path.endsWith(".sol");
    const callerFile = obs.callerFile || obs.path;
    const callerLine = Math.max(1, obs.callerLine || 1);
    const reachability: "caller" | "direct_transaction" =
      obs.reachability || (isSolidity ? "direct_transaction" : "caller");
    const kindLabel =
      obs.kind === "html_reflection"
        ? "unescaped HTML reflection"
        : obs.kind === "path_construction"
          ? "unconfined path construction"
          : "local Solidity security invariant violation";
    return {
      caseId: obs.caseId,
      severity: "low" as const,
      confidence: 0.65,
      ratingReason:
        `Deterministic controller reproduction observed ${kindLabel} on ${obs.selector} (${obs.path}) with recorded differential evidence; external deployment context and impact require independent verification.`,
      title: `Deterministic replay observed ${kindLabel} in ${obs.selector}`.slice(0, 195),
      impact:
        `Verified local execution of ${obs.selector} in ${obs.path} violated the expected security assertion; actual production impact depends on deployment reachability and external controls.`,
      callerFile,
      callerLine,
      reachability,
      falsification:
        `Independently replay recorded case ${obs.caseId.slice(0, 12)} against ${obs.path} (${obs.selector}) and inspect caller/deployment guards at ${callerFile}:${callerLine}; reject if a source-backed mitigation blocks exploitation.`,
    };
  });
  return {
    findings,
    outcome: "inspected",
  };
}

export function driveDeterministicAuditTurn(
  input: DeterministicAuditTurnInput,
): DeterministicAuditAction {
  const allowedActions: string[] =
    input.constraints?.action ||
    (Array.isArray(input.requestSchema?.properties?.action?.enum)
      ? input.requestSchema.properties.action.enum
      : []);
  const can = (action: string) => allowedActions.length === 0 || allowedActions.includes(action);
  const wantsResultObject = Boolean(
    input.requestSchema?.properties?.result ||
      (Array.isArray(input.requestSchema?.required) && input.requestSchema.required.includes("result")),
  );

  // 1. ANALYZE stage: deterministically evaluate active pending lead using ProgramFactsGraph + HypothesisEngine
  if (input.stage === "ANALYZE" && input.analyzeModelPending) {
    if (input.activeLead && (can("assess_lead") || can("defer_lead"))) {
      const graph = buildProgramFactsGraph({
        sources: input.sources,
        staticLeads: input.staticLeads,
      });
      const decision = evaluateAnalysisLead(graph, input.activeLead);
      const chosenAction = can(decision.action)
        ? decision.action
        : can("assess_lead")
          ? "assess_lead"
          : "defer_lead";
      return {
        action: chosenAction,
        leadId: decision.leadId,
        path: decision.path,
        query: decision.query,
        hypothesis: decision.hypothesis,
        answer: decision.answer,
      };
    }
    if (can("finalize_analysis")) {
      return {
        action: "finalize_analysis",
        path: "",
        query: "",
        answer: "Deterministic program-facts analysis finished evaluating all pending leads.",
      };
    }
  }

  // 2. REVIEW / REPORT or final-only constrained turn
  const finalOnly = allowedActions.length === 1 && allowedActions[0] === "final";
  if (finalOnly || input.stage === "REVIEW" || input.stage === "REPORT") {
    let payload: Record<string, unknown> | null = null;
    if (input.recoveredFinalJson) {
      try {
        const parsed = JSON.parse(input.recoveredFinalJson);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          payload = parsed as Record<string, unknown>;
        }
      } catch {}
    }
    if (!payload) {
      const observed = (input.observedCases || []).filter((c) => /^[a-f0-9]{64}$/.test(c.caseId));
      payload =
        observed.length > 0
          ? buildDeterministicPositiveFinal(observed)
          : buildDeterministicNegativeFinal(input);
    }
    if (wantsResultObject) {
      return {
        action: "final",
        path: "",
        query: "",
        answer: "",
        result: payload,
      };
    }
    return {
      action: "final",
      path: "",
      query: "",
      answer: JSON.stringify(payload),
    };
  }

  // 3. Fallback source navigation: deterministically read next unread indexed file
  const readSet = new Set(input.readPaths || []);
  const unread = (input.initialSourcePaths || []).filter((p) => !readSet.has(p));
  if (unread.length > 0) {
    const nextPath = unread[0];
    if (can("read_file")) {
      return { action: "read_file", path: nextPath, query: "", answer: "", offset: 0 };
    }
  }

  // 4. Final fallback: emit deterministic final if allowed
  const fallbackPayload = buildDeterministicNegativeFinal(input);
  if (wantsResultObject) {
    return { action: "final", path: "", query: "", answer: "", result: fallbackPayload };
  }
  return { action: "final", path: "", query: "", answer: JSON.stringify(fallbackPayload) };
}

export interface DeterministicEvidenceReviewResult {
  verdict: "approve" | "reject";
  recommendation: "submit" | "submit_cautiously" | "dont_submit";
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence: number;
  ratingReason: string;
  bet100: boolean;
  rubric: {
    exploitability: number;
    impactSeverity: number;
    evidenceQuality: number;
    novelty: number;
    scopeAlignment: number;
  };
  issues: Array<{ category: string; severity: "fatal" | "warning" | "info"; description: string }>;
  reasoning: string;
}

function extractJsonField(prompt: string, key: string): unknown {
  const re = new RegExp(`"${key}"\\s*:\\s*(true|false|\\[[^\\]]*\\]|"[^"]*")`);
  const m = re.exec(prompt);
  if (!m) return undefined;
  try {
    return JSON.parse(m[1]);
  } catch {
    return undefined;
  }
}

/**
 * Deterministic replacement for postOllamaChat in evidence-only-review.ts.
 * Evaluates the controller-prepared immutable evidence packet directly against
 * technical replay, differential control/attack checks, and mitigation facts.
 */
export function evaluateDeterministicEvidenceReview(prompt: string): DeterministicEvidenceReviewResult {
  const verifiedLocalEntry = extractJsonField(prompt, "verifiedLocalEntryInjection") === true;
  const independentlyReplayed =
    extractJsonField(prompt, "independentlyReplayed") === true ||
    /"status"\s*:\s*"behavior_observed"/i.test(prompt) ||
    /"behavior_observed"\s*:\s*true/i.test(prompt);
  const notObserved =
    /"status"\s*:\s*"behavior_not_observed"/i.test(prompt) ||
    /"behavior_observed"\s*:\s*false/i.test(prompt);

  const escapingArr = extractJsonField(prompt, "sourceBackedEscaping");
  const hasSourceEscaping = Array.isArray(escapingArr) && escapingArr.length > 0;
  const textOnlyArr = extractJsonField(prompt, "sourceBackedTextOnlyResponse");
  const hasTextOnly = Array.isArray(textOnlyArr) && textOnlyArr.length > 0;

  const isSolidity = /"replayedProbeKind"\s*:\s*"solidity_sequence"|"kind"\s*:\s*"solidity_sequence"/i.test(prompt);
  const isPath = /"replayedProbeKind"\s*:\s*"path_construction"|"kind"\s*:\s*"path_construction"/i.test(prompt);
  const isHtml = /"replayedProbeKind"\s*:\s*"html_reflection"|"kind"\s*:\s*"html_reflection"/i.test(prompt);

  const digestMatch = /"sourceDigest"\s*:\s*"([a-f0-9]{16,64})"/i.exec(prompt);
  const digestNote = digestMatch ? ` (digest ${digestMatch[1].slice(0, 16)})` : "";

  const citationMatch = /([A-Za-z0-9_./-]+\.(?:sol|js|mjs|cjs|ts|py|java):\d+)/.exec(prompt);
  const citation = citationMatch ? citationMatch[1] : "recorded controller evidence";

  // Reject if a source-backed mitigation blocks the behavior or replay did not observe it
  if (hasSourceEscaping || hasTextOnly || (!independentlyReplayed && notObserved)) {
    const technicalReason = hasSourceEscaping
      ? `Source-backed escaping/sanitization present in controller facts at ${citation}; unescaped injection is mitigated.`
      : hasTextOnly
        ? `Source-backed text/plain response declaration present at ${citation}; raw HTML execution is mitigated.`
        : `Independent controller replay did not observe the claimed vulnerable behavior at ${citation}; technical evidence is insufficient.`;
    return {
      verdict: "reject",
      recommendation: "dont_submit",
      severity: "informational",
      confidence: 0.8,
      ratingReason: `Deterministic evidence review rejected the candidate${digestNote}: ${technicalReason}`,
      bet100: false,
      rubric: {
        exploitability: 0,
        impactSeverity: 0,
        evidenceQuality: 2,
        novelty: 0,
        scopeAlignment: 1,
      },
      issues: [
        {
          category: hasSourceEscaping || hasTextOnly ? "mitigation_present" : "unreproduced_behavior",
          severity: "fatal",
          description: technicalReason,
        },
      ],
      reasoning: `Deterministic controller evidence check${digestNote} evaluated immutable replay records and source-backed mitigations at ${citation}. ${technicalReason}`,
    };
  }

  // Approve technically verified local replay, conservatively keeping recommendation = dont_submit
  if (independentlyReplayed || verifiedLocalEntry) {
    const behaviorType = isSolidity
      ? "isolated EVM Solidity sequence violation"
      : isPath
        ? "unconfined path construction"
        : isHtml
          ? "unescaped HTML reflection"
          : "replayed local security behavior";
    return {
      verdict: "approve",
      recommendation: "dont_submit",
      severity: "low",
      confidence: isSolidity ? 0.78 : 0.72,
      ratingReason: `Deterministic evidence review verified the independently replayed ${behaviorType}${digestNote} cited at ${citation}; external deployment exploitability remains unverified so submission is held.`,
      bet100: false,
      rubric: {
        exploitability: isSolidity ? 2 : 1,
        impactSeverity: 1,
        evidenceQuality: 3,
        novelty: 0,
        scopeAlignment: 2,
      },
      issues: [
        {
          category: "evidence_limit",
          severity: "warning",
          description: `Local source-level ${behaviorType} is verified at ${citation}, but live deployment configuration, external reachability, and end-to-end exploit impact are not established.`,
        },
      ],
      reasoning: `Deterministic review verified immutable controller replay evidence${digestNote} at ${citation} with no source-backed escaping or text-only mitigation recorded. Local technical behavior is confirmed; external submission remains disabled pending live deployment impact proof.`,
    };
  }

  // Fallback when prompt lacks explicit replay markers
  const promptHash = createHash("sha256").update(prompt).digest("hex").slice(0, 12);
  return {
    verdict: "reject",
    recommendation: "dont_submit",
    severity: "informational",
    confidence: 0.65,
    ratingReason: `Deterministic evidence review could not confirm an independent positive replay record in evidence packet ${promptHash} (${citation}).`,
    bet100: false,
    rubric: {
      exploitability: 0,
      impactSeverity: 0,
      evidenceQuality: 1,
      novelty: 0,
      scopeAlignment: 1,
    },
    issues: [
      {
        category: "missing_replay_proof",
        severity: "fatal",
        description: `Evidence packet ${promptHash} does not contain a confirmed behavior_observed replay record at ${citation}.`,
      },
    ],
    reasoning: `Deterministic review requires an independently replayed behavior_observed record with verifiable source citations; packet ${promptHash} lacks confirmed positive execution evidence.`,
  };
}
