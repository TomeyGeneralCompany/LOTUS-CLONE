/**
 * Deterministic Hypothesis Engine.
 *
 * Consumes normalized ProgramFactsGraph entries (from AST parsers, Semgrep,
 * Slither, and future Tree-sitter / Joern / Z3 / Mythril / Foundry adapters)
 * and synthesizes ranked, falsifiable, source-grounded security hypotheses
 * without invoking any LLM.
 */
import { createHash } from "node:crypto";
import {summarizeEntrypointEffects} from "./entrypoint-effects";
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
  | "accounting_invariant"
  | "relational_state"
  | "injection_html"
  | "path_traversal"
  | "command_or_eval"
  | "deserialization"
  | "sql_injection"
  | "static_triage";

export type RelationalPropertyKind =
  | "conservation"
  | "supply-accounting"
  | "share-accounting"
  | "interest-accrual"
  | "authorization-chain"
  | "state-coupling";

export interface RelationalHypothesis {
  id: string;
  file: string;
  language: FactLanguage;
  entrypoints: string[];
  stateDependencies: string[];
  sourceWitnesses: HypothesisWitness[];
  propertyKind: RelationalPropertyKind;
  expectedRelation: string;
  requiredObservations: string[];
  /** Prerequisites strictly required to observe or define this specific property (e.g. missing public getters). */
  propertyRequiredPrerequisites: string[];
  /** External protocol/token dependencies required to instantiate a local execution fixture. */
  fixturePrerequisites: string[];
  /** Unresolved calls that do not block the asserted property or its local fixture. */
  unrelatedUnresolvedCalls: string[];
  /** Combined property + fixture prerequisites (excludes unrelated unresolved calls). */
  unresolvedPrerequisites: string[];
}

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
  relational?: RelationalHypothesis;
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


const ROLE_STATE_RE = /(?:^|\.)(?:owner|admin|administrator|operator|manager|guardian|controller|authority|minter|pauser|governance|governor|keeper)$/i;
const SUPPLY_STATE_RE = /(?:^|\.)(?:totalSupply|supply|minted|burned|vestedSupply)$/i;
const SHARE_STATE_RE = /(?:^|\.)(?:shares?|totalShares|vaultShares|exchangeRate)$/i;
const INTEREST_STATE_RE = /(?:^|\.)(?:interest|accrued|accruedInterest|rate|index|rewardPerToken|rewards?|surplus|yield)$/i;
const CONSERVATION_STATE_RE = /(?:^|\.)(?:balances?|totalDeposits|totalAssets|totalStaked|totalDebt|totalDeposit|deposits?|reserves?|liquidity|principal|debt|staked|vested)$/i;
const CONFIG_OR_ADDRESS_STATE_RE =
  /(?:^|\.)(?:stablecoin|token|underlying|asset|cToken|aToken|yVault|fVault|vault|lendingPool|pool|comptroller|registry|factory|router|oracle|priceFeed|feeModel|interestModel|moneyMarket|mph|mphMinter|vesting|stakingPool|distributor|implementation|proxy|paused|initialized|isInitialized|decimals|symbol|name|recipient|treasury|beneficiary|strategy|gauge|market|rewardsToken|stakingToken|depositToken)$/i;
const INITIALIZER_FN_RE = /(?:^|\.)(?:initialize|init|__[A-Za-z0-9_]*init)$/i;
const CONFIG_SETTER_FN_RE = /(?:^|\.)(?:set[A-Z][A-Za-z0-9_]*|update[A-Z][A-Za-z0-9_]*|change[A-Z][A-Za-z0-9_]*)$/i;
const UTILITY_CALL_TARGET_RE =
  /^(?:SafeMath|Math|SignedSafeMath|Address|Strings|Arrays|Counters|ECDSA|MerkleProof|Clones|Create2|BitMaps|EnumerableSet|EnumerableMap|SafeCast|FixedPoint|PRBMath|DecMath|Console|console|console2|abi|type|super|this)(?:\.|$)/i;
const FIXTURE_CALL_TARGET_RE =
  /\.(?:transfer|transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove|safeIncreaseAllowance|safeDecreaseAllowance|mint|burn|deposit|withdraw|redeem|redeemUnderlying|borrow|repay|repayBorrow|balanceOf|claim|claimComp|getReward|exit|credit|debit|flashLoan|swap)\b|(?:^|:)(?:ERC20|IERC20|SafeERC20|ICERC20|ILendingPool|IComptroller|IVault|IHarvestVault|IYVault|IMoneyMarket|IBenqi|ICToken|AToken|CToken)\b/i;
const TOKEN_ONLY_FIXTURE_RE =
  /(?:^|:)(?:ERC20|IERC20|SafeERC20|token|stablecoin|underlying|asset)(?:\.(?:transfer|transferFrom|safeTransfer|safeTransferFrom|approve|safeApprove|safeIncreaseAllowance|safeDecreaseAllowance|balanceOf|allowance))?$/i;

function isAccountingStateVar(stateVar: string): boolean {
  if (CONFIG_OR_ADDRESS_STATE_RE.test(stateVar) || ROLE_STATE_RE.test(stateVar)) {
    return false;
  }
  return (
    INTEREST_STATE_RE.test(stateVar) ||
    SHARE_STATE_RE.test(stateVar) ||
    SUPPLY_STATE_RE.test(stateVar) ||
    CONSERVATION_STATE_RE.test(stateVar)
  );
}

function classifyRelationalProperty(stateVars: readonly string[]): RelationalPropertyKind {
  const accountingVars = stateVars.filter(isAccountingStateVar);
  if (accountingVars.some((v) => INTEREST_STATE_RE.test(v))) return "interest-accrual";
  if (accountingVars.some((v) => SHARE_STATE_RE.test(v))) return "share-accounting";
  if (accountingVars.some((v) => SUPPLY_STATE_RE.test(v))) return "supply-accounting";
  if (accountingVars.some((v) => CONSERVATION_STATE_RE.test(v))) return "conservation";
  if (stateVars.some((v) => ROLE_STATE_RE.test(v))) return "authorization-chain";
  return "state-coupling";
}

function isFinancialRelationalKind(kind: RelationalPropertyKind): boolean {
  return (
    kind === "conservation" ||
    kind === "supply-accounting" ||
    kind === "share-accounting" ||
    kind === "interest-accrual"
  );
}

function classifyUnresolvedCallForProperty(
  unresolvedItem: string,
  propertyKind: RelationalPropertyKind,
): "fixture" | "unrelated" {
  const target = unresolvedItem.replace(/^(?:unresolved_external_call|unresolved_call|ambiguous_call):/, "");
  if (UTILITY_CALL_TARGET_RE.test(target)) {
    return "unrelated";
  }
  if (propertyKind === "authorization-chain") {
    // Role-state takeover tests depend on authority state mutation, not unrelated downstream token/market calls.
    return "unrelated";
  }
  if (isFinancialRelationalKind(propertyKind) && FIXTURE_CALL_TARGET_RE.test(target)) {
    return "fixture";
  }
  return "unrelated";
}

function relationalId(file: string, entrypoints: readonly string[], stateDeps: readonly string[], kind: RelationalPropertyKind): string {
  return createHash("sha256")
    .update(JSON.stringify([file, [...entrypoints].sort(), [...stateDeps].sort(), kind]))
    .digest("hex")
    .slice(0, 32);
}

/**
 * Second-pass multi-function relational hypothesis generator.
 * Traverses ProgramFactsGraph edges (`writes_state`, `reads_state`, `precedes`,
 * `value_flow`, resolved `calls_resolved`, `external_call`, and `inherits`) to
 * synthesize cross-function accounting, authorization-chain, and state-coupling
 * hypotheses with complete multi-function source witnesses and explicit
 * unresolved prerequisites.
 */
export function generateRelationalHypotheses(graph: ProgramFactsGraph): RelationalHypothesis[] {
  const results: RelationalHypothesis[] = [];
  const seen = new Set<string>();

  const symbolByQualified = new Map<string, ProgramSymbol>();
  const stateVarSymbols = new Map<string, ProgramSymbol>();
  const entrypoints = new Set<string>();

  for (const sym of graph.symbols) {
    if (sym.kind === "function" || sym.kind === "method") {
      symbolByQualified.set(sym.qualifiedName, sym);
      const isSolEntry =
        sym.language === "solidity" &&
        sym.name !== "constructor" &&
        (sym.visibility === "public" || sym.visibility === "external") &&
        sym.mutability !== "view" &&
        sym.mutability !== "pure";
      if (isSolEntry) {
        entrypoints.add(sym.qualifiedName);
      }
    } else if (sym.kind === "state_var") {
      stateVarSymbols.set(sym.qualifiedName, sym);
    }
  }

  // Index unresolved/ambiguous calls per function so we never disguise guessed targets as resolved
  const unresolvedByFn = new Map<string, string[]>();
  const resolvedInternalCalls = new Map<string, Array<{ to: string; file: string; line: number }>>();
  const stateWriters = new Map<string, Array<{ fn: string; file: string; line: number; operator?: string }>>();
  const stateReaders = new Map<string, Array<{ fn: string; file: string; line: number }>>();
  const valueFlowFns = new Set<string>();

  for (const edge of graph.edges) {
    if (edge.kind === "writes_state") {
      const list = stateWriters.get(edge.to) || [];
      list.push({
        fn: edge.from,
        file: edge.file,
        line: edge.line,
        operator: typeof edge.metadata?.operator === "string" ? edge.metadata.operator : undefined,
      });
      stateWriters.set(edge.to, list);
    } else if (edge.kind === "reads_state") {
      const list = stateReaders.get(edge.to) || [];
      list.push({ fn: edge.from, file: edge.file, line: edge.line });
      stateReaders.set(edge.to, list);
    } else if (edge.kind === "value_flow") {
      valueFlowFns.add(edge.from);
    } else if (edge.kind === "calls_resolved") {
      if (edge.resolution === "resolved") {
        const list = resolvedInternalCalls.get(edge.from) || [];
        list.push({ to: edge.to, file: edge.file, line: edge.line });
        resolvedInternalCalls.set(edge.from, list);
      } else if (edge.resolution === "ambiguous" || edge.resolution === "unresolved") {
        const list = unresolvedByFn.get(edge.from) || [];
        list.push(`${edge.resolution}_call:${edge.to}`);
        unresolvedByFn.set(edge.from, list);
      }
    } else if (edge.kind === "external_call") {
      const isLowLevel = edge.metadata?.lowLevel === true;
      if (edge.resolution !== "resolved" && !isLowLevel) {
        const list = unresolvedByFn.get(edge.from) || [];
        list.push(`unresolved_external_call:${edge.to}`);
        unresolvedByFn.set(edge.from, list);
      }
    }
  }

  // Propagate internal helper state writes/reads to external entrypoints via resolved calls ONLY
  const effectiveWrites = new Map<string, Set<string>>();
  const effectiveReads = new Map<string, Set<string>>();
  for (const [stateVar, writers] of stateWriters) {
    for (const w of writers) {
      const s = effectiveWrites.get(w.fn) || new Set<string>();
      s.add(stateVar);
      effectiveWrites.set(w.fn, s);
    }
  }
  for (const [stateVar, readers] of stateReaders) {
    for (const r of readers) {
      const s = effectiveReads.get(r.fn) || new Set<string>();
      s.add(stateVar);
      effectiveReads.set(r.fn, s);
    }
  }
  // A single pass misses deposit -> _deposit -> _depositRecordData.
  // Traverse the complete resolved call graph, retaining original state witnesses.
  for (const entrypoint of entrypoints) {
    const summary=summarizeEntrypointEffects(graph,entrypoint);
    effectiveWrites.set(entrypoint,new Set(summary.stateWrites));
    effectiveReads.set(entrypoint,new Set(summary.stateReads));
    for(const sv of summary.stateWrites) {
      const list=stateWriters.get(sv)||[];
      if(!list.some(x=>x.fn===entrypoint)) {
        const sourceEdge=graph.edges.find(e=>e.kind==="writes_state"&&e.to===sv&&summary.reachableFunctions.includes(e.from));
        list.push({fn:entrypoint,file:sourceEdge?.file||"",line:sourceEdge?.line||1});
        stateWriters.set(sv,list);
      }
    }
    for(const sv of summary.stateReads) {
      const list=stateReaders.get(sv)||[];
      if(!list.some(x=>x.fn===entrypoint)){
        const sourceEdge=graph.edges.find(e=>e.kind==="reads_state"&&e.to===sv&&summary.reachableFunctions.includes(e.from));
        list.push({fn:entrypoint,file:sourceEdge?.file||"",line:sourceEdge?.line||1});
        stateReaders.set(sv,list);
      }
    }
    if(summary.valueTransfers.length)valueFlowFns.add(entrypoint);
    const unresolved=unresolvedByFn.get(entrypoint)||[];
    for(const edge of summary.unresolvedCalls){
      const desc=`${edge.resolution||"unresolved"}_call:${edge.to}`;
      if(!unresolved.includes(desc))unresolved.push(desc);
    }
    if(unresolved.length)unresolvedByFn.set(entrypoint,unresolved);
  }

  const buildWitnessForFn = (fn: string, factKind: ProgramFact["kind"], detail: string): HypothesisWitness => {
    const sym = symbolByQualified.get(fn);
    return {
      file: sym?.file || "",
      line: sym?.line || 1,
      symbol: fn,
      factKind,
      detail,
    };
  };

  // Pass A: Pairwise entrypoints coupled through shared state variables (especially accounting & role state)
  const pairStates = new Map<string, { a: string; b: string; file: string; vars: Set<string>; ordered: boolean }>();
  for (const edge of graph.edges) {
    if (edge.kind === "precedes" && entrypoints.has(edge.from) && entrypoints.has(edge.to)) {
      const vars = Array.isArray(edge.metadata?.stateVars) ? (edge.metadata!.stateVars as string[]) : [];
      if (!vars.length) continue;
      const key = `${edge.from}->${edge.to}`;
      const existing = pairStates.get(key) || {
        a: edge.from,
        b: edge.to,
        file: edge.file,
        vars: new Set<string>(),
        ordered: true,
      };
      for (const v of vars) existing.vars.add(v);
      pairStates.set(key, existing);
    }
  }

  // Also capture unordered co-writers of the same accounting/role state variable
  for (const [stateVar, writers] of stateWriters) {
    const entryWriters = [...new Set(writers.map((w) => w.fn).filter((fn) => entrypoints.has(fn)))].sort();
    if (entryWriters.length < 2) continue;
    for (let i = 0; i < entryWriters.length; i++) {
      for (let j = i + 1; j < entryWriters.length; j++) {
        const a = entryWriters[i];
        const b = entryWriters[j];
        if (pairStates.has(`${a}->${b}`) || pairStates.has(`${b}->${a}`)) {
          const existing = pairStates.get(`${a}->${b}`) || pairStates.get(`${b}->${a}`)!;
          existing.vars.add(stateVar);
          continue;
        }
        const symA = symbolByQualified.get(a);
        if (!symA) continue;
        const key = `${a}<->${b}`;
        const existing = pairStates.get(key) || {
          a,
          b,
          file: symA.file,
          vars: new Set<string>(),
          ordered: false,
        };
        existing.vars.add(stateVar);
        pairStates.set(key, existing);
      }
    }
  }

  for (const pair of pairStates.values()) {
    const rawStateDeps = [...pair.vars].sort();
    const accountingDeps = rawStateDeps.filter(isAccountingStateVar);
    const roleDeps = rawStateDeps.filter((v) => ROLE_STATE_RE.test(v));
    const nonConfigDeps = rawStateDeps.filter((v) => !CONFIG_OR_ADDRESS_STATE_RE.test(v));
    const propertyKind = classifyRelationalProperty(rawStateDeps);
    const isFinancial = isFinancialRelationalKind(propertyKind);

    // Do not elevate ordinary configuration/address references (e.g. initialize + withdraw
    // sharing `stablecoin`, `lendingPool`, or `vault`) into accounting invariants.
    if (isFinancial) {
      if (accountingDeps.length === 0) continue;
      if (INITIALIZER_FN_RE.test(pair.a) || INITIALIZER_FN_RE.test(pair.b)) continue;
      if (CONFIG_SETTER_FN_RE.test(pair.a) && CONFIG_SETTER_FN_RE.test(pair.b)) continue;
    } else if (propertyKind === "authorization-chain") {
      if (roleDeps.length === 0) continue;
    } else {
      // Pure config/address coupling without accounting or role state is not a relational
      // accounting invariant; skip even if one function happens to perform a token transfer.
      if (nonConfigDeps.length === 0) continue;
      if (INITIALIZER_FN_RE.test(pair.a) || INITIALIZER_FN_RE.test(pair.b)) continue;
      const hasValueFlow = valueFlowFns.has(pair.a) || valueFlowFns.has(pair.b);
      if (!hasValueFlow) continue;
    }

    const stateDeps = isFinancial
      ? accountingDeps
      : propertyKind === "authorization-chain"
        ? roleDeps
        : nonConfigDeps;

    const entryList = pair.ordered ? [pair.a, pair.b] : [pair.a, pair.b].sort();
    const id = relationalId(pair.file, entryList, stateDeps, propertyKind);
    if (seen.has(id)) continue;
    seen.add(id);

    const requiredObservations: string[] = [];
    const propertyRequiredPrerequisites: string[] = [];
    const fixturePrerequisites: string[] = [];
    const unrelatedUnresolvedCalls: string[] = [];

    for (const sv of stateDeps) {
      const svSym = stateVarSymbols.get(sv);
      if (svSym?.visibility === "public") {
        const getterSig = svSym.returnType === "mapping" ? `${svSym.name}(address)` : `${svSym.name}()`;
        requiredObservations.push(getterSig);
      } else {
        propertyRequiredPrerequisites.push(`missing_public_getter:${sv}`);
      }
    }

    for (const fn of entryList) {
      for (const u of unresolvedByFn.get(fn) || []) {
        const bucket = classifyUnresolvedCallForProperty(u, propertyKind);
        if (bucket === "fixture") {
          if (!fixturePrerequisites.includes(u)) fixturePrerequisites.push(u);
        } else {
          if (!unrelatedUnresolvedCalls.includes(u)) unrelatedUnresolvedCalls.push(u);
        }
      }
    }

    const unresolvedPrerequisites = [
      ...new Set([...propertyRequiredPrerequisites, ...fixturePrerequisites]),
    ].sort();

    const witnesses: HypothesisWitness[] = [
      buildWitnessForFn(pair.a, "state_write", `${pair.a} mutates shared state (${stateDeps.join(", ")})`),
      buildWitnessForFn(
        pair.b,
        effectiveWrites.get(pair.b)?.size ? "state_write" : "entry_point",
        `${pair.b} reads/mutates shared state (${stateDeps.join(", ")})`,
      ),
    ];

    const expectedRelation =
      propertyKind === "conservation"
        ? `Sequence ${entryList.join(" -> ")} must conserve tracked accounting state across [${stateDeps.join(", ")}] so post-state equals net inflow minus outflow.`
        : propertyKind === "supply-accounting"
          ? `Sequence ${entryList.join(" -> ")} must keep supply accounting [${stateDeps.join(", ")}] consistent with minted/burned balances.`
          : propertyKind === "share-accounting"
            ? `Sequence ${entryList.join(" -> ")} must keep share accounting [${stateDeps.join(", ")}] proportional to underlying assets.`
            : propertyKind === "interest-accrual"
              ? `Sequence ${entryList.join(" -> ")} must preserve monotonic, bounded interest/reward accounting across [${stateDeps.join(", ")}].`
              : propertyKind === "authorization-chain"
                ? `Unauthorized mutation via ${entryList[0]} must not satisfy privilege guard consumed by ${entryList[1]} on [${stateDeps.join(", ")}].`
                : `Ordered interaction ${entryList.join(" -> ")} must preserve state consistency across [${stateDeps.join(", ")}].`;

    results.push({
      id,
      file: pair.file,
      language: symbolByQualified.get(pair.a)?.language || "solidity",
      entrypoints: entryList,
      stateDependencies: stateDeps,
      sourceWitnesses: witnesses,
      propertyKind,
      expectedRelation,
      requiredObservations: [...new Set(requiredObservations)].sort(),
      propertyRequiredPrerequisites: [...new Set(propertyRequiredPrerequisites)].sort(),
      fixturePrerequisites: [...new Set(fixturePrerequisites)].sort(),
      unrelatedUnresolvedCalls: [...new Set(unrelatedUnresolvedCalls)].sort(),
      unresolvedPrerequisites,
    });
  }

  results.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.entrypoints.join(",").localeCompare(b.entrypoints.join(",")) ||
      a.id.localeCompare(b.id),
  );
  return results;
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
    const hasUnsatGuard = symFacts.some((f) => f.kind === "smt_unsat_guard");
    const hasSatWitness = symFacts.some((f) => f.kind === "smt_sat_witness");
    const staticFindings = symFacts.filter((f) => f.kind === "static_finding");
    const staticBoost = (staticFindings.length ? 8 : 0) + (hasSatWitness ? 6 : 0) - (hasUnsatGuard ? 35 : 0);

    // 0. Direct high-signal evidence from fast-check, Foundry, Mythril, or Joern CPG
    const directEvidenceFacts = symFacts.filter(
      (f) =>
        f.kind === "property_counterexample" ||
        f.kind === "foundry_invariant_violated" ||
        f.kind === "symbolic_finding" ||
        f.kind === "taint_flow",
    );
    if (directEvidenceFacts.length && !hasUnsatGuard) {
      const top = directEvidenceFacts[0];
      const category: HypothesisCategory =
        top.kind === "taint_flow"
          ? "command_or_eval"
          : top.kind === "property_counterexample"
            ? "injection_html"
            : "access_control";
      pushUnique({
        id: hypothesisId(sym.file, sym.qualifiedName, category),
        language: sym.language,
        file: sym.file,
        line: top.line || sym.line,
        selector: sym.qualifiedName,
        category,
        priority: 99,
        disposition: "ready_for_experiment",
        statement: `${sym.qualifiedName} has direct deterministic evidence from ${top.adapter}: ${top.detail}`,
        falsification: `Replay the witness/counterexample against ${sym.qualifiedName} in the isolated verifier and confirm impact.`,
        rationale: `Corroborated directly by ${[...new Set(directEvidenceFacts.map((f) => f.adapter))].join(", ")}.`,
        recommendedProbeKind:
          sym.language === "solidity"
            ? "solidity_sequence"
            : top.kind === "property_counterexample"
              ? "html_reflection"
              : undefined,
        recommendedAdapters: [...new Set(directEvidenceFacts.map((f) => f.adapter))],
        witnesses: directEvidenceFacts.map(toWitness),
      });
    }

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

  // File-level high-signal facts from Joern/Mythril/Foundry/fast-check not attached to a parsed symbol
  for (const fact of graph.facts) {
    if (
      fact.kind !== "taint_flow" &&
      fact.kind !== "symbolic_finding" &&
      fact.kind !== "property_counterexample" &&
      fact.kind !== "foundry_invariant_violated"
    ) {
      continue;
    }
    const selector = fact.symbol || `${fact.file}:${fact.line}`;
    const category: HypothesisCategory =
      fact.kind === "taint_flow"
        ? "command_or_eval"
        : fact.kind === "property_counterexample"
          ? "injection_html"
          : "access_control";
    pushUnique({
      id: hypothesisId(fact.file, selector, category),
      language: fact.language,
      file: fact.file,
      line: fact.line,
      selector,
      category,
      priority: 96,
      disposition: "ready_for_experiment",
      statement: `${selector} flagged by ${fact.adapter}: ${fact.detail}`,
      falsification: `Confirm reachability and impact of ${selector} in the isolated verifier.`,
      rationale: `Direct deterministic evidence emitted by ${fact.adapter}.`,
      recommendedProbeKind: fact.language === "solidity" ? "solidity_sequence" : undefined,
      recommendedAdapters: [fact.adapter],
      witnesses: [toWitness(fact)],
    });
  }

  // Pass 2: Multi-function relational hypotheses across graph edges (state reads/writes,
  // resolved calls, precedence, value flow, and inheritance).
  const relationalHypotheses = generateRelationalHypotheses(graph);
  for (const rel of relationalHypotheses) {
    const primarySelector = rel.entrypoints[rel.entrypoints.length - 1] || rel.entrypoints[0];
    const primaryWitness = rel.sourceWitnesses[rel.sourceWitnesses.length - 1] || rel.sourceWitnesses[0];
    const isFinancial =
      rel.propertyKind === "conservation" ||
      rel.propertyKind === "supply-accounting" ||
      rel.propertyKind === "share-accounting" ||
      rel.propertyKind === "interest-accrual";
    const category: HypothesisCategory = isFinancial ? "accounting_invariant" : "relational_state";
    const nonTokenFixturePrereqs = rel.fixturePrerequisites.filter((p) => !TOKEN_ONLY_FIXTURE_RE.test(p));
    const ready =
      rel.propertyRequiredPrerequisites.length === 0 &&
      nonTokenFixturePrereqs.length === 0 &&
      rel.requiredObservations.length > 0;
    for (const ep of rel.entrypoints) {
      const epWitness = rel.sourceWitnesses.find((w) => w.symbol === ep) || primaryWitness;
      pushUnique({
        id: createHash("sha256").update(`rel|${rel.id}|${ep}`).digest("hex").slice(0, 32),
        language: rel.language,
        file: rel.file,
        line: epWitness?.line || 1,
        selector: ep,
        category,
        priority: isFinancial ? (ready ? 91 : 76) : (ready ? 84 : 64),
        disposition: ready ? "ready_for_experiment" : "needs_deeper_analysis",
        statement: rel.expectedRelation,
        falsification: `Execute ordered sequence [${rel.entrypoints.join(" -> ")}] observing [${rel.requiredObservations.join(", ") || rel.stateDependencies.join(", ")}]; falsified if post-state satisfies the expected accounting/authorization relation.`,
        rationale: `Relational graph analysis linked [${rel.entrypoints.join(", ")}] via shared state [${rel.stateDependencies.join(", ")}] (${rel.propertyKind}${rel.unresolvedPrerequisites.length ? `; unresolved: ${rel.unresolvedPrerequisites.join(", ")}` : ""}).`,
        recommendedProbeKind: rel.language === "solidity" ? "solidity_sequence" : undefined,
        recommendedAdapters: isFinancial ? ["solidity-ast", "foundry", "z3"] : ["solidity-ast", "foundry", "mythril"],
        witnesses: rel.sourceWitnesses,
        relational: rel,
      });
    }
    void primarySelector;
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
  const effects=summarizeEntrypointEffects(graph,lead.selector);
  const fileFacts = graph.byFile.get(lead.path)?.facts || [];
  // Reachable facts keep their original locations. Guard resolution still
  // operates on the entrypoint itself; only investigative effect evidence grows.
  const reachableFacts=effects.facts;
  const symbolFacts = fileFacts.filter(
    (f) =>
      !f.symbol ||
      f.symbol === lead.selector ||
      f.symbol.endsWith("." + lead.selector) ||
      lead.selector.endsWith("." + f.symbol),
  );

  // 1. Z3 SMT UNSAT refutation takes precedence: if a guard on this lead is proved
  //    unsatisfiable (unreachable), immediately defer the lead rather than wasting verification.
  const unsatFacts = symbolFacts.filter((f) => f.kind === "smt_unsat_guard");
  if (unsatFacts.length > 0) {
    const primary = unsatFacts[0];
    return {
      action: "defer_lead",
      leadId: lead.leadId,
      path: lead.path,
      query: lead.selector,
      hypothesis: "Guard constraints proved unsatisfiable (unreachable) by Z3 SMT analysis",
      answer: `Deterministic Z3 SMT analysis refuted reachability for ${lead.selector} at ${primary.file}:${primary.line}: ${primary.detail}`.slice(0, 680),
      matchedHypotheses: [],
    };
  }

  const allHypotheses = generateHypotheses(graph);
  const directMatches = allHypotheses.filter(
    (h) =>
      h.file === lead.path &&
      (h.selector === lead.selector ||
        h.selector.endsWith("." + lead.selector) ||
        lead.selector.endsWith("." + h.selector)),
  );

  // 2. Specialized analyzer findings (Joern taint_flow, Mythril symbolic_finding,
  //    Foundry foundry_invariant_violated, isolated fast-check property_counterexample)
  //    promote a lead directly to assess_lead for isolated verification.
  const specializedFindings = symbolFacts.filter(
    (f) =>
      f.kind === "taint_flow" ||
      f.kind === "symbolic_finding" ||
      f.kind === "foundry_invariant_violated" ||
      f.kind === "property_counterexample",
  );
  if (specializedFindings.length > 0) {
    const primary = specializedFindings[0];
    const witnessSummary = specializedFindings
      .slice(0, 3)
      .map((f) => `${f.file}:${f.line} [${f.adapter}:${f.kind}] ${f.detail}`)
      .join("; ");
    return {
      action: "assess_lead",
      leadId: lead.leadId,
      path: lead.path,
      query: lead.selector,
      hypothesis: `Specialized ${primary.adapter} analysis identified ${primary.kind} in ${lead.selector} at ${primary.file}:${primary.line}; verify exploitability and security impact in isolated replay.`,
      answer: `Specialized escalation (${primary.adapter}) returned actionable evidence for ${lead.selector}: ${witnessSummary}`.slice(0, 680),
      matchedHypotheses: directMatches,
    };
  }

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
  const reachableWrites=reachableFacts.filter(f=>f.kind==="state_write"||f.kind==="unguarded_mutation");
  const reachableSinks=reachableFacts.filter(f=>f.kind.startsWith("sink_")||f.kind==="value_transfer"||f.kind==="mint_or_burn");
  const sinks = [...symbolFacts.filter((f) => f.kind.startsWith("sink_") || f.kind === "value_transfer" || f.kind === "mint_or_burn"),...reachableSinks];

  if (sinks.length > 0 || stateWrites.length > 0 || reachableWrites.length > 0) {
    const primary = sinks[0] || stateWrites[0] || reachableWrites[0];
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
