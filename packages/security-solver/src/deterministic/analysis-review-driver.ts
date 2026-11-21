/**
 * Deterministic Analysis & Review Driver.
 *
 * Replaces Ollama/Qwen across ANALYZE, REVIEW/REPORT, and evidence-only review
 * using the Program-Facts IR, Hypothesis Engine, closed-loop specialized
 * analytical escalation (Z3, Joern, Mythril, Foundry, isolated fast-check),
 * and typed controller-verified evidence records.
 * Zero LLM calls are made when LOCAL_MODEL_ADAPTER=deterministic (the default in
 * LOTUS-CLONE when AUTOHACK_OLLAMA_URL is not explicitly configured).
 */
import { createHash } from "node:crypto";
import {
  constructSolidityExperiments,
  type PreparedSecurityExperiment,
  type SourceSnapshot,
  type StaticLeadHint,
} from "../controller-solidity-experiment-planner";
import type { SolidityProbeDeclaration } from "../solidity-probe-inputs";
import type { SoliditySequence } from "../solidity-sequence";
import {
  controllerVerifiedLocalHtmlReview,
  type ControllerReviewGrounds,
} from "../controller-review-boundary";
import type { EntryReviewObservation } from "../entry-review-evidence";
import type { ReviewEvidence } from "../review-evidence-chain";
import {
  buildProgramFactsGraph,
  createHostFactsAdapters,
  type ProgramFact,
  type ProgramFactsGraph,
} from "./program-facts";
import type { LeadAnalysisDecision, LeadAnalysisInput } from "./hypothesis-engine";
import {
  runClosedLoopLeadAnalysis,
  runPreparedFinancialFoundryProperty,
  type ClosedLoopLeadResult,
  type EscalationCache,
  type SpecializedEscalationHooks,
} from "./specialized-escalation";

export type LocalModelAdapter = "deterministic";

/** The LOTUS-CLONE production runtime has one engine. A copied legacy .env
 * cannot silently reactivate an Ollama/Qwen endpoint or Qwen-Agent bridge.
 * Historical mock-transport tests must be migrated rather than enabling an
 * alternate model in the application.
 */
export function resolveLocalModelAdapter(env: NodeJS.ProcessEnv = process.env): LocalModelAdapter {
  const explicit=env.LOCAL_MODEL_ADAPTER?.trim();
  if(explicit && explicit!=="deterministic")
    throw new Error("LOTUS_MODEL_REMOVED: only the deterministic engine is supported");
  return "deterministic";
}

export function isDeterministicMode(_env: NodeJS.ProcessEnv = process.env): boolean {
  return true;
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
  sourceIndexedCount?: number;
  sourceReadCount?: number;
  candidateCoverage?: import("./analysis-progress-store").CandidateCoverage;
  outcomes?: DeterministicOutcomeCounts;
  observedCases?: readonly DeterministicObservedCase[];
  recoveredFinalJson?: string | null;
  /** Optional cache shared across turns of the same audit to avoid repeating escalations. */
  escalationCache?: EscalationCache;
  /** Optional specialized analyzer hooks (defaults to host Z3/Joern/Mythril/Foundry/bwrap fast-check). */
  escalationHooks?: SpecializedEscalationHooks;
  /** Enable closed-loop analytical escalation during ANALYZE (default: true unless LOTUS_DISABLE_ESCALATION=1). */
  enableSpecializedEscalation?: boolean;
  /** Maximum specialized adapters invoked per lead (default: 3). */
  maxEscalations?: number;
  /** Optional repository root for isolated bubblewrap probes. */
  repositoryDir?: string;
  /** Optional pre-built ProgramFactsGraph reused across leads within the same audit. */
  graph?: ProgramFactsGraph;
  /** Optional git commit hash for offline Solidity experiment construction. */
  repositoryCommit?: string;
  /** Optional Solidity probe declarations for the active lead's source file. */
  declarations?: readonly SolidityProbeDeclaration[];
  /** Optional set of already-queued experiment IDs or sequence fingerprints to avoid duplicates. */
  existingExperimentIds?: ReadonlySet<string>;
  /** Optional observer called with closed-loop escalation telemetry (kept off the wire action JSON). */
  onEscalation?: (result: ClosedLoopLeadResult) => void;
  /** Optional observer called with structured analysis + prepared experiment candidates. */
  onAnalysisResult?: (result: DeterministicAnalysisResult) => void;
}

export interface PreparedExperimentCandidate {
  id: string;
  path: string;
  selector: string;
  hypothesis: string;
  securityProperty: string;
  sequence: SoliditySequence;
  witnesses: PreparedSecurityExperiment["witnesses"];
  prerequisites: PreparedSecurityExperiment["prerequisites"];
}

export interface AnalyticalDisposition {
  action: "assess_lead" | "defer_lead";
  status: "supported" | "uncertain" | "contradicted";
  reason: string;
  smtRefuted: boolean;
}

export interface ConstructionFeasibility {
  attempted: boolean;
  feasible: boolean;
  candidateCount: number;
  unresolvedCategories: string[];
  unresolvedReasons: string[];
  skippedReason?: string;
}

export interface DeterministicAnalysisResult {
  decision: LeadAnalysisDecision;
  analyticalDisposition: AnalyticalDisposition;
  constructionFeasibility: ConstructionFeasibility;
  experimentCandidates: PreparedExperimentCandidate[];
  unresolvedReasons: string[];
  closedLoop: ClosedLoopLeadResult;
}

export interface DeterministicAuditAction {
  action: string;
  path: string;
  query: string;
  answer: string;
  leadId?: string;
  hypothesis?: string;
  sequence?: SoliditySequence;
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
  const readCount = input.sourceReadCount ?? input.readPaths?.length ?? input.sources.length;
  const indexedCount = input.sourceIndexedCount ?? Math.max(readCount, input.initialSourcePaths?.length ?? input.sources.length);
  const unresolvedCandidates=input.candidateCoverage?.unresolvedIds.length ?? 0;
  const incompleteTotal = o.observation_only + o.incomplete + o.unsupported + o.pending + unresolvedCandidates;
  const reason =
    `${readCount}/${indexedCount} source files inspected; ${totalSelected} experiments selected: ` +
    `${o.not_observed} source-supported negative experiments, ${o.observation_only} observation-only, ` +
    `${o.incomplete} failed/incomplete fixtures, ${o.unsupported} unsupported, ${o.observed} observed behaviors; ` +
    `${unresolvedCandidates} candidate properties still unresolved. ` +
    (incompleteTotal > 0
      ? `Selected-experiment pass only; investigation partial. ${incompleteTotal} incomplete, observation-only, unsupported or pending items require resolution.`
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

function runnerExperimentId(
  path: string,
  selector: string,
  hypothesis: string,
  sequence: SoliditySequence,
): string {
  const fingerprint = createHash("sha256")
    .update(JSON.stringify([hypothesis.slice(0, 600), sequence]))
    .digest("hex");
  return JSON.stringify([path, selector, "solidity_sequence", fingerprint]);
}

/**
 * Structured deterministic analysis for an active lead:
 *   1. Reuse pre-built host-enriched ProgramFactsGraph (or build once if omitted)
 *   2. Run closed-loop specialized analytical escalation & hypothesis evaluation
 *   3. For assessed Solidity leads with declarations, invoke the 3-stage
 *      offline experiment constructor and return PreparedExperimentCandidates
 *      alongside explicit unresolved reasons when prerequisites are missing.
 */
export function evaluateDeterministicAnalysisTurn(
  input: DeterministicAuditTurnInput,
): DeterministicAnalysisResult | null {
  if (!input.activeLead) return null;

  const graph =
    input.graph ??
    buildProgramFactsGraph(
      {
        sources: input.sources,
        staticLeads: input.staticLeads,
      },
      createHostFactsAdapters(),
    );

  const closedLoop = runClosedLoopLeadAnalysis({
    graph,
    lead: input.activeLead,
    sources: input.sources,
    cache: input.escalationCache,
    hooks: input.escalationHooks,
    enableSpecializedEscalation: input.enableSpecializedEscalation,
    maxEscalations: input.maxEscalations,
    repositoryDir: input.repositoryDir,
  });

  const decision = closedLoop.finalDecision;
  const activeFileFacts = graph.byFile.get(input.activeLead.path)?.facts || [];
  const smtRefuted =
    activeFileFacts.some(
      (f) =>
        f.kind === "smt_unsat_guard" &&
        (!f.symbol ||
          f.symbol === input.activeLead!.selector ||
          f.symbol.endsWith("." + input.activeLead!.selector) ||
          input.activeLead!.selector.endsWith("." + f.symbol)),
    ) || /proved unsatisfiable/i.test(decision.hypothesis);

  const analyticalDisposition: AnalyticalDisposition = {
    action: decision.action,
    status: smtRefuted
      ? "contradicted"
      : decision.action === "assess_lead"
        ? "supported"
        : "uncertain",
    reason: decision.answer,
    smtRefuted,
  };

  const experimentCandidates: PreparedExperimentCandidate[] = [];
  const unresolvedReasons: string[] = [];
  const constructionUnresolvedCategories: string[] = [];
  const constructionUnresolvedReasons: string[] = [];

  for (const hyp of decision.matchedHypotheses) {
    if (hyp.relational?.unresolvedPrerequisites?.length) {
      for (const prereq of hyp.relational.unresolvedPrerequisites) {
        if (!unresolvedReasons.includes(prereq)) {
          unresolvedReasons.push(prereq);
        }
      }
    }
  }

  // Evaluate construction feasibility independently of analytical deferral so a
  // deferred relational hypothesis never blocks an alternative constructible property
  // on the same function (except when Z3 SMT proved guard unreachability).
  let constructionAttempted = false;
  let skippedReason: string | undefined;
  if (smtRefuted) {
    skippedReason = "smt_unsat_guard";
  } else if (!input.activeLead.path.endsWith(".sol")) {
    skippedReason = "non_solidity_lead";
  } else if (!input.declarations || input.declarations.length === 0) {
    skippedReason = "missing_declarations";
  } else {
    constructionAttempted = true;
    const constructed = constructSolidityExperiments({
      repositoryCommit: input.repositoryCommit || "",
      targetPath: input.activeLead.path,
      targetSelector: input.activeLead.selector,
      sources: input.sources,
      declarations: input.declarations,
      skipLegacy: false,
      staticLeads: input.staticLeads,
    });
    if (constructed.ok) {
      for (const exp of constructed.experiments) {
        if(exp.securityProperty.startsWith("financial ")){
          const original=input.sources.find(source=>source.path===exp.path);
          if(original){
            const propertyProbe=runPreparedFinancialFoundryProperty(original,exp);
            closedLoop.steps.push(propertyProbe.step);
            if(propertyProbe.step.status==="executed"){
              closedLoop.escalatedAdapters.push("foundry");
              closedLoop.addedFacts.push(...propertyProbe.facts);
            }
            if(propertyProbe.step.status==="error")
              unresolvedReasons.push("foundry_property_replay_error:"+String(propertyProbe.step.detail||"unknown").slice(0,120));
          }
        }
        const hypothesis = exp.hypothesis.slice(0, 600);
        experimentCandidates.push({
          id: exp.id,
          path: exp.path,
          selector: exp.selector,
          hypothesis,
          securityProperty: exp.securityProperty,
          sequence: exp.sequence,
          witnesses: exp.witnesses,
          prerequisites: exp.prerequisites,
        });
      }
    } else {
      const cat = constructed.unresolvedCategory ? `(${constructed.unresolvedCategory})` : "";
      const detail = `${constructed.code}${cat}: ${constructed.detail}`;
      if (constructed.unresolvedCategory) {
        constructionUnresolvedCategories.push(constructed.unresolvedCategory);
      }
      constructionUnresolvedReasons.push(detail);
      if (!unresolvedReasons.includes(detail)) {
        unresolvedReasons.push(detail);
      }
    }
  }

  const constructionFeasibility: ConstructionFeasibility = {
    attempted: constructionAttempted,
    feasible: experimentCandidates.length > 0,
    candidateCount: experimentCandidates.length,
    unresolvedCategories: [...new Set(constructionUnresolvedCategories)],
    unresolvedReasons: constructionUnresolvedReasons,
    ...(skippedReason ? { skippedReason } : {}),
  };

  return {
    decision,
    analyticalDisposition,
    constructionFeasibility,
    experimentCandidates,
    unresolvedReasons,
    closedLoop,
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

  // 1. ANALYZE stage: closed-loop deterministic evaluation (ProgramFactsGraph ->
  //    initial hypothesis -> specialized analytical escalation -> fact merge ->
  //    reconsider -> source-grounded experiment construction -> discover_experiment).
  if (input.stage === "ANALYZE" && input.analyzeModelPending) {
    if (
      input.activeLead &&
      (can("discover_experiment") || can("assess_lead") || can("defer_lead"))
    ) {
      const analysis = evaluateDeterministicAnalysisTurn(input)!;
      input.onEscalation?.(analysis.closedLoop);
      input.onAnalysisResult?.(analysis);

      const decision = analysis.decision;
      if (can("discover_experiment") && analysis.experimentCandidates.length > 0) {
        const existing = input.existingExperimentIds;
        const freshCandidate = analysis.experimentCandidates.find((cand) => {
          if (!existing || existing.size === 0) return true;
          const runnerId = runnerExperimentId(
            cand.path,
            cand.selector,
            cand.hypothesis,
            cand.sequence,
          );
          const seqKey = JSON.stringify([
            cand.path,
            cand.selector,
            cand.hypothesis,
            cand.sequence,
          ]);
          return !existing.has(cand.id) && !existing.has(runnerId) && !existing.has(seqKey);
        });

        if (freshCandidate) {
          return {
            action: "discover_experiment",
            leadId: decision.leadId,
            path: freshCandidate.path,
            query: freshCandidate.selector,
            hypothesis: freshCandidate.hypothesis.slice(0, 600),
            answer: "solidity_sequence",
            sequence: freshCandidate.sequence,
          };
        }
      }

      const chosenAction = can(decision.action)
        ? decision.action
        : can("assess_lead")
          ? "assess_lead"
          : "defer_lead";
      const unresolvedSuffix =
        analysis.unresolvedReasons.length > 0 && chosenAction === "assess_lead"
          ? ` [Unresolved experiment prerequisites: ${analysis.unresolvedReasons.slice(0, 2).join("; ")}]`
          : "";
      return {
        action: chosenAction,
        leadId: decision.leadId,
        path: decision.path,
        query: decision.query,
        hypothesis: decision.hypothesis?.slice(0, 600),
        answer: `${decision.answer}${unresolvedSuffix}`.slice(0, 680),
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

export interface DeterministicReplayRecord {
  status?: string;
  kind?: string;
  behavior_observed?: boolean;
  observations?: Record<string, unknown> | null;
}

export interface DeterministicSecurityImpactEvidence {
  /** Must be explicitly true to confirm security impact beyond a raw local replay marker. */
  verified: boolean;
  /** Concrete impact class (e.g. "local_html_injection", "solidity_role_consumer_impact", "path_escape"). */
  category: string;
  /** Exact source file:line or verified replay observation establishing the security impact. */
  evidence: string;
  /** Optional proof that a privileged downstream consumer or security boundary was violated. */
  downstreamConsumerVerified?: boolean;
}

export interface DeterministicReviewEvidence {
  /** Controller-constructed immutable factual grounds (never parsed from prompt prose). */
  grounds: ControllerReviewGrounds;
  /** Independently replayed sandbox record from the controller. */
  replay?: DeterministicReplayRecord | null;
  /** Independently replayed controller entry handler record (for HTTP/HTML entry verification). */
  entryReplay?: EntryReviewObservation | null;
  /** Optional source-backed call/dataflow chain constructed by the controller. */
  chainEvidence?: ReviewEvidence | null;
  /** Optional target metadata. */
  target?: {
    caseId?: string;
    file?: string;
    selector?: string;
    kind?: string;
    reachability?: string;
    callerFile?: string;
    callerLine?: number;
  };
  /**
   * Typed security-impact proof separate from raw replay observation.
   * A positive replay marker alone NEVER establishes a security vulnerability.
   */
  securityImpact?: DeterministicSecurityImpactEvidence | null;
  /** Optional specialized analyzer facts (Z3 UNSAT refutation, Joern taint, Mythril, Foundry). */
  analyzerFacts?: readonly ProgramFact[];
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

function resolveTypedCitation(evidence: DeterministicReviewEvidence): string {
  if (evidence.target?.callerFile && evidence.target?.callerLine) {
    return `${evidence.target.callerFile}:${evidence.target.callerLine}`;
  }
  const firstLink = evidence.chainEvidence?.links?.[0];
  if (firstLink?.file && firstLink?.line) {
    return `${firstLink.file}:${firstLink.line}`;
  }
  if (evidence.grounds.sourceBackedEscaping[0]) {
    return evidence.grounds.sourceBackedEscaping[0];
  }
  if (evidence.grounds.sourceBackedTextOnlyResponse[0]) {
    return evidence.grounds.sourceBackedTextOnlyResponse[0];
  }
  if (evidence.target?.file) {
    return evidence.target.selector
      ? `${evidence.target.file} (${evidence.target.selector})`
      : evidence.target.file;
  }
  return "controller-verified evidence";
}

function rejectResult(params: {
  category: string;
  description: string;
  ratingReason: string;
  reasoning: string;
  confidence?: number;
  evidenceQuality?: number;
}): DeterministicEvidenceReviewResult {
  return {
    verdict: "reject",
    recommendation: "dont_submit",
    severity: "informational",
    confidence: params.confidence ?? 0.82,
    ratingReason: params.ratingReason,
    bet100: false,
    rubric: {
      exploitability: 0,
      impactSeverity: 0,
      evidenceQuality: params.evidenceQuality ?? 2,
      novelty: 0,
      scopeAlignment: 1,
    },
    issues: [
      {
        category: params.category,
        severity: "fatal",
        description: params.description,
      },
    ],
    reasoning: params.reasoning,
  };
}

/**
 * Deterministic evidence-only reviewer consuming LOTUS's typed, independently
 * verified controller records directly (ZERO regex scraping of prompt text).
 *
 * Security Invariants:
 *  1. Fail closed if typed `evidence` or `grounds` or valid `sourceDigest` is missing.
 *  2. Reject immediately if Z3 proved the guard UNSAT (`smt_unsat_guard`) or if
 *     source-backed escaping / text-only mitigations exist.
 *  3. Reject if independent replay did not observe the claimed behavior.
 *  4. A positive replay marker ALONE NEVER establishes a security vulnerability:
 *     approval requires BOTH independent replay AND typed verified security impact
 *     (`securityImpact.verified === true` or `controllerVerifiedLocalHtmlReview`).
 *  5. External submission remains strictly disabled (`recommendation: "dont_submit"`,
 *     `bet100: false`) unless external deployment impact is separately proven.
 */
export function evaluateDeterministicEvidenceReview(
  evidence: DeterministicReviewEvidence | null | undefined,
): DeterministicEvidenceReviewResult {
  // 1. Fail closed when typed controller evidence is absent (never scrape prompt prose)
  if (!evidence || !evidence.grounds) {
    return rejectResult({
      category: "missing_typed_evidence",
      description:
        "Deterministic review requires typed, independently verified controller evidence records (ControllerReviewGrounds); unverified or serialized prose cannot establish a vulnerability.",
      ratingReason:
        "Deterministic review rejected the candidate because no typed controller-verified evidence record was provided.",
      reasoning:
        "Fail-closed deterministic review does not parse free-form prompt text. Supply typed controller grounds, replay observations, and security-impact evidence.",
      confidence: 0.9,
      evidenceQuality: 0,
    });
  }

  const { grounds } = evidence;
  const digest = typeof grounds.sourceDigest === "string" ? grounds.sourceDigest.trim() : "";
  if (!/^[a-f0-9]{16,64}$/i.test(digest)) {
    return rejectResult({
      category: "missing_source_digest",
      description:
        "Controller evidence record lacks a valid cryptographic sourceDigest tying findings to committed source.",
      ratingReason:
        "Deterministic review rejected the candidate because source provenance (sourceDigest) is missing or invalid.",
      reasoning:
        "Every deterministic security decision must be anchored to a valid controller-computed sourceDigest.",
      confidence: 0.88,
      evidenceQuality: 0,
    });
  }

  const digestNote = ` (digest ${digest.slice(0, 16)})`;
  const citation = resolveTypedCitation(evidence);

  // 2. Z3 SMT UNSAT refutation
  const unsatFact = (evidence.analyzerFacts || []).find((f) => f.kind === "smt_unsat_guard");
  if (unsatFact) {
    const desc = `Z3 SMT analysis proved the guard path unreachable at ${unsatFact.file}:${unsatFact.line}: ${unsatFact.detail}`;
    return rejectResult({
      category: "unreachable_guard_unsat",
      description: desc,
      ratingReason: `Deterministic review rejected the candidate${digestNote}: ${desc}`,
      reasoning: `Typed analyzer evidence${digestNote} includes an smt_unsat_guard proof at ${unsatFact.file}:${unsatFact.line}, refuting reachability.`,
      confidence: 0.92,
      evidenceQuality: 3,
    });
  }

  // 3. Source-backed mitigations (typed ControllerReviewGrounds arrays, exact file:line citations)
  if (grounds.sourceBackedEscaping.length > 0) {
    const escSites = grounds.sourceBackedEscaping.join(", ");
    const desc = `Source-backed escaping/sanitization recorded by controller at ${escSites} mitigates unescaped injection.`;
    return rejectResult({
      category: "mitigation_present",
      description: desc,
      ratingReason: `Deterministic review rejected the candidate${digestNote}: ${desc}`,
      reasoning: `Controller-verified source grounds${digestNote} cite escaping/sanitization at ${escSites}, blocking the claimed injection.`,
      confidence: 0.86,
      evidenceQuality: 3,
    });
  }

  if (grounds.sourceBackedTextOnlyResponse.length > 0) {
    const plainSites = grounds.sourceBackedTextOnlyResponse.join(", ");
    const desc = `Source-backed text/plain response declaration recorded by controller at ${plainSites} mitigates raw HTML execution.`;
    return rejectResult({
      category: "mitigation_present",
      description: desc,
      ratingReason: `Deterministic review rejected the candidate${digestNote}: ${desc}`,
      reasoning: `Controller-verified source grounds${digestNote} cite explicit text/plain response output at ${plainSites}.`,
      confidence: 0.86,
      evidenceQuality: 3,
    });
  }

  // 4. Independent replay verification (typed replay object + grounds.independentlyReplayed)
  const replayProvided = evidence.replay !== undefined && evidence.replay !== null;
  const replayObserved = replayProvided
    ? evidence.replay!.status === "behavior_observed" && evidence.replay!.behavior_observed === true
    : grounds.independentlyReplayed;

  if (!grounds.independentlyReplayed || !replayObserved) {
    const statusLabel = evidence.replay?.status || (grounds.independentlyReplayed ? "observation_only" : "not_observed");
    const desc = grounds.independentlyReplayed
      ? `Independent controller replay completed at ${citation} with status "${statusLabel}", which did not establish a positive security behavior violation.`
      : `Independent controller replay did not observe the claimed behavior at ${citation} (status: "${statusLabel}").`;
    return rejectResult({
      category: "unreproduced_behavior",
      description: desc,
      ratingReason: `Deterministic review rejected the candidate${digestNote}: ${desc}`,
      reasoning: `Typed controller replay records${digestNote} at ${citation} show status="${statusLabel}" without a confirmed positive behavior violation.`,
      confidence: 0.82,
      evidenceQuality: 2,
    });
  }

  // 5. Strict Security-Impact Gate:
  //    A positive replay marker ALONE NEVER proves a security vulnerability!
  const verifiedHtmlReview = evidence.entryReplay
    ? controllerVerifiedLocalHtmlReview(grounds, evidence.entryReplay)
    : null;
  const explicitImpact =
    evidence.securityImpact &&
    evidence.securityImpact.verified === true &&
    evidence.securityImpact.category.trim().length > 0 &&
    evidence.securityImpact.evidence.trim().length > 0
      ? evidence.securityImpact
      : null;

  if (!explicitImpact && !verifiedHtmlReview) {
    const probeKind = grounds.replayedProbeKind || evidence.replay?.kind || evidence.target?.kind || "local_probe";
    const desc = grounds.sourceBackedNonadminRoleMutation
      ? `Independent controller replay at ${citation} confirmed the nonadministrator role mutation, but downstream privileged consumer impact is not established; positive replay alone does not establish a security vulnerability.`
      : `Independent controller replay at ${citation} (${probeKind}) recorded local behavior, but typed security impact is not established; a positive replay marker alone does not prove a security vulnerability.`;
    return rejectResult({
      category: "missing_security_impact",
      description: desc,
      ratingReason: `Deterministic review rejected the candidate${digestNote}: ${desc}`,
      reasoning: `Controller replay${digestNote} completed at ${citation} (${probeKind}), confirming local execution behavior. However, neither controller-verified entry-to-HTML injection nor typed security-impact evidence (such as downstream privileged consumer impact or security boundary breach) is established, so the candidate is rejected without denying the completed replay.`,
      confidence: 0.84,
      evidenceQuality: 2,
    });
  }

  // 6. Both independent replay AND typed verified security impact are present ->
  //    approve technically with recommendation strictly held at dont_submit.
  const probeKind = grounds.replayedProbeKind || evidence.replay?.kind || evidence.target?.kind || "local_probe";
  const isSolidity = probeKind === "solidity_sequence" || grounds.language === "solidity";
  const impactLabel = explicitImpact
    ? `${explicitImpact.category} (${explicitImpact.evidence})`
    : "controller-verified local entry-to-HTML markup injection";
  const confidence = explicitImpact?.downstreamConsumerVerified || isSolidity ? 0.78 : 0.72;

  return {
    verdict: "approve",
    recommendation: "dont_submit",
    severity: "low",
    confidence,
    ratingReason: `Deterministic evidence review verified both independent controller replay and typed security impact [${impactLabel}]${digestNote} at ${citation}; external deployment exploitability remains unverified so submission is held.`,
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
        description: `Local source-level security impact [${impactLabel}] is verified at ${citation}, but live deployment configuration, external reachability, and end-to-end production impact are not established.`,
      },
    ],
    reasoning: `Deterministic review consumed typed controller evidence${digestNote} at ${citation} with zero source-backed escaping or text-only mitigations. Both independent replay (${probeKind}) and typed security impact (${impactLabel}) are verified; external submission remains disabled pending live deployment impact proof.`,
  };
}
