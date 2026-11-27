/**
 * Deterministic Function-Level Analysis Candidate Queue.
 *
 * Separates candidate generation (preserving every eligible unqueued function
 * across the entire acquired source inventory) from bounded candidate admission
 * (selecting a scored, evidence-ranked batch for the current ANALYZE pass while
 * retaining all remaining candidates in the persisted queue).
 */
import { createHash } from "node:crypto";
import { parse as parseSolidity } from "@solidity-parser/parser";
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
  /** Explicitly opt into admitting test/mock/echidna harness contracts (default: false). */
  includeTestContracts?: boolean;
  /** Synchronous bounded heartbeat for long CPU-only queue builds. */
  onProgress?: (progress:Readonly<{
    completedItems:number;totalItems:number;candidates:number;blocked:number;currentPath:string;
  }>)=>void;
}

export interface AnalysisCandidateQueueResult {
  /** Complete inventory of every eligible production function candidate (deterministic order). */
  inventory: AnalysisCandidate[];
  /** Bounded subset admitted to the active ANALYZE window. */
  admitted: AnalysisCandidate[];
  /** Unprocessed candidates retained in the queue for subsequent passes. */
  queued: AnalysisCandidate[];
  /** Candidates blocked (e.g., test/mock harness, missing commit, or declaration span unavailable). */
  blocked: Array<{ path: string; selector: string; reason: string }>;
}

const TEST_OR_MOCK_DIR_RE =
  /(?:^|\/)(?:mocks?|tests?|__tests__|fixtures?|echidna|fuzz|foundry-test|harness)(?:\/|$)/i;
const TEST_OR_MOCK_PREFIX_RE =
  /(?:^|\/)(?:Echidna|Mock|Test|Fuzz|Harness|Fake|Stub)[A-Z_][A-Za-z0-9_]*\.sol$/;
const TEST_OR_MOCK_LOWER_PREFIX_RE =
  /(?:^|\/)(?:echidna|mock|test|fuzz|harness)[_-][A-Za-z0-9_.-]*\.sol$/i;
const TEST_OR_MOCK_SUFFIX_RE =
  /(?:Mock|Mocks|Test|Tests|Echidna|Fuzz|Harness|Spec|Fake|Stub)\.sol$/;
const FOUNDRY_TEST_SUFFIX_RE = /\.t\.sol$/i;

/**
 * Consistent repository-wide test/mock/fuzz harness path classifier.
 * Keeps test harnesses available as supporting repository source without admitting
 * them as primary production vulnerability candidates.
 */
export function isTestOrMockContractPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return (
    TEST_OR_MOCK_DIR_RE.test(normalized) ||
    TEST_OR_MOCK_PREFIX_RE.test(normalized) ||
    TEST_OR_MOCK_LOWER_PREFIX_RE.test(normalized) ||
    TEST_OR_MOCK_SUFFIX_RE.test(normalized) ||
    FOUNDRY_TEST_SUFFIX_RE.test(normalized)
  );
}

const EXTERNAL_ADAPTER_PATH_RE =
  /(?:^|\/)(?:models\/)?(?:money[-_]?markets?|adapters?|connectors?|integrations?|wrappers?)(?:\/|$)/i;
const EXTERNAL_ADAPTER_FILE_RE = /(?:Market|Adapter|Connector|Wrapper)\.sol$/;

/**
 * Identifies thin external-protocol adapter/wrapper contracts (e.g., money market
 * integrations such as BenqiERC20Market.sol or HarvestMarket.sol) so core protocol
 * contracts receive higher initial admission priority.
 */
export function isExternalAdapterOrMarketPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return EXTERNAL_ADAPTER_PATH_RE.test(normalized) || EXTERNAL_ADAPTER_FILE_RE.test(normalized);
}

const CORE_PROTOCOL_NAME_RE =
  /(?:^|\/)(?:DInterest|MPHMinter|Minter|Vesting\d*|Vault|Pool|Treasury|Controller|Router|Staking|Exchange|LendingPool|ClearingHouse|Governor|Timelock|Escrow|Ledger|Factory|ZeroCouponBond|NFT)[A-Za-z0-9_]*\.sol$/i;

const FINANCIAL_ENTRYPOINT_RE =
  /^(?:deposit|withdraw|earlyWithdraw|topupDeposit|rolloverDeposit|mintVested|fund|claim|redeem|stake|unstake|borrow|repay|liquidate|swap|zap|rescue|skim|mint|burn|accrue|distribute|settle|collect|harvest|rebalance|flashLoan|withdrawInterest|payInterestToFunders|takeBackDepositedAmount)$/i;

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
type LocatedFunctionSpan = {
  span: { start:number; end:number; lineStart:number; lineEnd:number; excerpt:string; truncated:boolean };
} | { reason:string };

function canonicalAbiType(type:any,sourceAst:any,depth=0):string|null {
  if(!type||depth>16)return null;
  if(type.type==="ElementaryTypeName"){
    const name=String(type.name||"");
    if(name==="uint")return "uint256";
    if(name==="int")return "int256";
    return /^(?:address|bool|string|bytes(?:[1-9]|[12][0-9]|3[012])?|u?int(?:[0-9]{1,3})?)$/.test(name)?
      name:null;
  }
  if(type.type==="ArrayTypeName"){
    const base=canonicalAbiType(type.baseTypeName,sourceAst,depth+1);
    if(!base)return null;
    const length=type.length?.value===undefined?"":String(type.length.value);
    if(length&&!/^\d+$/.test(length))return null;
    return base+"["+length+"]";
  }
  if(type.type!=="UserDefinedTypeName")return null;
  const fullName=String(type.namePath||"");
  const name=fullName.split(".").pop()||"";
  const definitions:any[]=[];
  for(const top of sourceAst?.children||[]){
    if(top.type==="ContractDefinition"){
      for(const child of top.subNodes||[]){
        if(child.name===name&&["StructDefinition","EnumDefinition"].includes(child.type))
          definitions.push(child);
      }
    }else if(top.type==="TypeDefinition"&&top.name===name){
      definitions.push(top.definition);
    }else if(top.type==="ContractDefinition"&&top.name===name){
      definitions.push(top);
    }
  }
  if(definitions.length!==1)return null;
  const definition=definitions[0];
  if(definition.type==="EnumDefinition")return "uint8";
  if(definition.type==="ContractDefinition")return "address";
  if(definition.type==="StructDefinition"){
    const members=(definition.members||[]).map((member:any)=>
      canonicalAbiType(member.typeName,sourceAst,depth+1));
    return members.length&&members.every(Boolean)?"("+members.join(",")+")":null;
  }
  return canonicalAbiType(definition,sourceAst,depth+1);
}

function canonicalFunctionSignature(fn:any,sourceAst:any):string|null {
  const inputs=(fn.parameters||[]).map((parameter:any)=>
    canonicalAbiType(parameter.typeName,sourceAst));
  return fn.name&&inputs.every(Boolean)?
    String(fn.name)+"("+inputs.join(",")+")":null;
}

/**
 * Locate source declarations through the Solidity AST. Brace scanning can stop
 * inside comments or strings, and choosing the first same-name declaration is
 * unsafe for overloaded functions.
 */
function locateFunctionSpan(content:string,selector:string,sourceAst:any):LocatedFunctionSpan {
  const separator=selector.lastIndexOf(".");
  const contractName=separator>0?selector.slice(0,separator):"";
  const selectorMethod=selector.slice(separator+1);
  const exactSignature=/^([A-Za-z_]\w*\(.*\))$/.test(selectorMethod);
  const method=exactSignature?selectorMethod.slice(0,selectorMethod.indexOf("(")):selectorMethod;
  if(!/^[A-Za-z_]\w*$/.test(contractName)||!(/^[A-Za-z_]\w*$/.test(method)||exactSignature))
    return {reason:"function_selector_not_canonical"};
  const contracts=(sourceAst?.children||[]).filter((node:any)=>
    node.type==="ContractDefinition"&&node.name===contractName);
  if(contracts.length!==1)return {reason:"function_contract_not_unique"};
  const declarations=(contracts[0].subNodes||[]).filter((node:any)=>
    node.type==="FunctionDefinition"&&node.name===method&&!node.isConstructor&&
    !node.isFallback&&!node.isReceiveEther);
  if(declarations.length===0)return {reason:"function_declaration_not_located"};
  const selected=exactSignature?
    declarations.filter((node:any)=>canonicalFunctionSignature(node,sourceAst)===selectorMethod):
    declarations;
  if(exactSignature&&selected.length===0)
    return {reason:"exact_function_abi_signature_not_resolved"};
  if(selected.length>1||(!exactSignature&&selected.length>1))
    return {reason:"overloaded_function_requires_exact_abi_signature"};
  const declaration=selected[0],range=declaration.range,location=declaration.loc;
  if(!Array.isArray(range)||range.length!==2||!location?.start||!location?.end||
    !Number.isInteger(range[0])||!Number.isInteger(range[1]))
    return {reason:"function_source_range_missing"};
  const start=range[0],excerptStart=Math.max(0,start-160);
  // Keep the complete declaration available to source-grounded analysis. The
  // old fixed 1,100-character window silently cut off long accounting paths.
  const excerptEnd=Math.min(content.length,range[1]+1);
  return {span:{start:excerptStart,end:excerptEnd,
    lineStart:location.start.line,lineEnd:location.end.line,
    excerpt:content.slice(excerptStart,excerptEnd),truncated:excerptEnd<content.length}};
}

/**
 * Build the complete deterministic function-level candidate inventory and select
 * a bounded batch for admission without silently discarding overflow candidates.
 */
/** Frozen lead admission must include source-grounded staged methods too.
 * A method gaining an executable experiment must never disappear from the
 * original source-property inventory (Benqi.claimRewards regression).
 */
export function reconcileStagedLeadSelectors(
  initial:ReadonlyMap<string,ReadonlySet<string>>,
  staged:readonly {plan:{path:string;query:string;answer:string}}[],
  declarations:ReadonlyMap<string,readonly {selector:string;operation:string}[]>,
):Map<string,Set<string>> {
  const merged=new Map<string,Set<string>>(
    [...initial].map(([path,selectors])=>[path,new Set(selectors)]));
  for(const {plan} of staged){
    if(plan.answer!=="solidity_sequence"||isTestOrMockContractPath(plan.path))
      continue;
    const menu=declarations.get(plan.path)||[];
    if(!menu.some(d=>d.selector===plan.query&&d.operation==="send"))continue;
    const selectors=merged.get(plan.path)||new Set<string>();
    selectors.add(plan.query);
    merged.set(plan.path,selectors);
  }
  return merged;
}

export function buildAnalysisCandidateQueue(
  options: AnalysisCandidateQueueOptions,
): AnalysisCandidateQueueResult {
  const staticLeads = options.staticLeads || [];
  const graph = options.graph || null;
  const maxAdmitted = Math.max(1, Math.min(options.maxAdmitted ?? 18, 128));
  const maxPerFile = Math.max(1, Math.min(options.maxPerFile ?? 4, maxAdmitted));
  const includeTestContracts = options.includeTestContracts === true;

  const blocked: Array<{ path: string; selector: string; reason: string }> = [];
  const rawCandidates: AnalysisCandidate[] = [];
  const seenIds = new Set<string>();

  // Pre-index graph coupling, unresolved external call dominance, and core protocol centrality
  const varWriters = new Map<string, Set<string>>();
  const fnUnresolvedExtCount = new Map<string, number>();
  const fnOwnStateWriteCount = new Map<string, number>();
  const fileInboundReferrers = new Map<string, Set<string>>();
  const contractNameToFile = new Map<string, string>();

  if (graph) {
    for (const sym of graph.symbols) {
      if (sym.kind === "contract" && sym.name && sym.file) {
        contractNameToFile.set(sym.name, sym.file);
      }
    }
    for (const edge of graph.edges) {
      const kind = String(edge.kind);
      if (kind === "writes_state" || kind === "reads_state") {
        const set = varWriters.get(edge.to) || new Set<string>();
        set.add(edge.from);
        varWriters.set(edge.to, set);
        if (kind === "writes_state") {
          fnOwnStateWriteCount.set(edge.from, (fnOwnStateWriteCount.get(edge.from) || 0) + 1);
        }
      } else if (
        (kind === "external_call" && edge.resolution !== "resolved" && edge.metadata?.lowLevel !== true) ||
        (kind === "calls_resolved" && (edge.resolution === "unresolved" || edge.resolution === "ambiguous"))
      ) {
        fnUnresolvedExtCount.set(edge.from, (fnUnresolvedExtCount.get(edge.from) || 0) + 1);
      } else if (kind === "imports" || kind === "inherits") {
        const targetName = edge.to.split("/").pop()?.replace(/\.sol$/i, "") || edge.to;
        const targetFile =
          contractNameToFile.get(targetName) ||
          (graph.byFile.has(edge.to) ? edge.to : undefined);
        if (targetFile && targetFile !== edge.file) {
          const refs = fileInboundReferrers.get(targetFile) || new Set<string>();
          refs.add(edge.file);
          fileInboundReferrers.set(targetFile, refs);
        }
      }
    }
  }

  let completedItems=0;
  const reportItemProgress=(path:string)=>{
    completedItems++;
    if(completedItems%4===0||completedItems===options.items.length)
      options.onProgress?.({completedItems,totalItems:options.items.length,
        candidates:rawCandidates.length,blocked:blocked.length,currentPath:path});
  };
  for (const item of options.items) {
    const isTestOrMock = isTestOrMockContractPath(item.path);
    if (isTestOrMock && !includeTestContracts) {
      for (const selector of item.unqueuedSelectors) {
        blocked.push({
          path: item.path,
          selector,
          reason: "test_or_mock_contract",
        });
      }
      reportItemProgress(item.path);
      continue;
    }

    const sourceSha256 = createHash("sha256").update(item.sourceContent).digest("hex");
    const fileLeads = staticLeads.filter((l) => l.path === item.path);
    let sourceAst:any=null;
    try { sourceAst=parseSolidity(item.sourceContent,{range:true,loc:true}); }
    catch { /* Each selector is retained as an explicit parser blocker below. */ }
    const isExternalAdapter = isExternalAdapterOrMarketPath(item.path);
    const isCoreProtocolName = CORE_PROTOCOL_NAME_RE.test(item.path) && !isExternalAdapter;
    const inboundRefCount = fileInboundReferrers.get(item.path)?.size || 0;
    const financialEntryCount = item.unqueuedSelectors.filter((sel) =>
      FINANCIAL_ENTRYPOINT_RE.test(sel.split(".").pop() || ""),
    ).length;

    for (const selector of item.unqueuedSelectors) {
      if (!/^[a-f0-9]{40}$/.test(item.sourceCommit)) {
        blocked.push({
          path: item.path,
          selector,
          reason: "acquired_repository_commit_unavailable",
        });
        continue;
      }

      const located = sourceAst
        ? locateFunctionSpan(item.sourceContent, selector, sourceAst)
        : {reason:"solidity_source_parse_failed"};
      if ("reason" in located) {
        blocked.push({path:item.path,selector,reason:located.reason});
        continue;
      }
      const span=located.span;

      const id = createHash("sha256")
        .update(JSON.stringify([item.sourceCommit, sourceSha256, item.path, selector]))
        .digest("hex");
      if (seenIds.has(id)) continue;
      seenIds.add(id);

      const selectorMethod=selector.split(".").pop()||"";
      const method=selectorMethod.slice(0,selectorMethod.indexOf("(")<0?
        selectorMethod.length:selectorMethod.indexOf("("));
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

      // 3. Core protocol prioritization vs thin external market adapters
      if (isCoreProtocolName) {
        priority += 25;
        selectionReasons.push("core_protocol_contract");
      }
      if (inboundRefCount > 0 && !isExternalAdapter) {
        priority += Math.min(20, inboundRefCount * 8);
        selectionReasons.push(`core_protocol_inbound_refs:${inboundRefCount}`);
      }
      if (financialEntryCount >= 2 && !isExternalAdapter) {
        priority += 15;
        selectionReasons.push(`multi_entrypoint_accounting_contract:${financialEntryCount}`);
      }
      if (isExternalAdapter) {
        priority -= 25;
        selectionReasons.push("demoted_external_adapter_path");
      }

      // 4. Function-localized static leads vs broader file leads
      const matchedFnLeads = fileLeads.filter(
        (l) =>
          (l.line >= span.lineStart && l.line <= span.lineEnd) ||
          (method.length >= 3 && l.message.includes(method)),
      );
      if (matchedFnLeads.length > 0) {
        const boost = Math.min(isExternalAdapter ? 20 : 45, matchedFnLeads.length * (isExternalAdapter ? 10 : 20));
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

      // 5. Program-facts graph signals (when available)
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
        // Demote thin external-call-dominated wrappers with zero own state writes
        const unresolvedExt = fnUnresolvedExtCount.get(selector) || 0;
        const ownWrites = fnOwnStateWriteCount.get(selector) || 0;
        if (unresolvedExt >= 2 && ownWrites === 0) {
          priority -= 18;
          selectionReasons.push(`demoted_external_call_dominated:${unresolvedExt}`);
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
    reportItemProgress(item.path);
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
