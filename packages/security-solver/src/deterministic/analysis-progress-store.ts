/**
 * Durable, source-revision-bound deterministic analysis inventory.
 * A batch is a scheduling window, never the unit of audit completion.
 */
import {createHash} from "node:crypto";
import {readFile,writeFile,rename,mkdir} from "node:fs/promises";
import {dirname} from "node:path";
import type {AnalysisCandidate} from "./analysis-candidate-queue";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";
import {proposeInterfaceUnavailability,independentlyReviewInterfaceUnavailability} from
  "./source-unavailability-verifier";

export type CandidateLifecycle="queued"|"admitted"|"analyzing"|"dependencies_pending"|
  "experiment_pending"|"experiment_completed"|"source_unavailable"|"analysis_exhausted"|"blocked";
export type PropertyResolution="unexamined"|"analyzing"|"prerequisites_pending"|
  "test_constructed"|"test_completed"|"contradicted"|"unsupported"|"blocked";

export interface CandidatePropertyProgress {
  id:string; state:PropertyResolution; sourceWitnesses:string[];
  unresolvedPrerequisites:string[]; experimentIds:string[]; supersededBy?:string;
}
export interface ExperimentEvidence {
  experimentId:string; leadId:string; sourceCommit:string; sourceSha256:string;
  evidenceId:string; result:'observed'|'not_observed'; verifierDigest:string;
}
export interface SourceUnavailableEvidence {
  kind:"interface_without_acquired_implementation";
  leadId:string; sourceCommit:string; sourceSha256:string;
  sourceWitnesses:string[]; acquiredInventoryDigest:string;
  verifierDigest:string; independentReviewDigest:string;
  evidenceId:string; detail:string;
}
export interface LeadExperimentCertificate {
  version:1|2; manifestDigest:string; evidenceDigest:string;
  total:number; conclusive:number; sourceUnavailable:number; sourceUnavailableIds:string[];
  unavailabilityEvidenceDigest:string; unresolvedIds:string[];
  pendingReasons:Record<string,string[]>; evidenceCount:number;
}
export interface CandidateProgress {
  id:string; sourceCommit:string; sourceSha256:string;
  lifecycle:CandidateLifecycle; attempts:number;
  properties:CandidatePropertyProgress[];
  experimentIds:string[]; lastError?:string;
  experimentEvidence?:ExperimentEvidence[];
  inconclusiveAttempts?:Array<{experimentId:string;status:string;evidenceId:string;reason:string;replacedBy?:string}>;
  sourceUnavailable?:SourceUnavailableEvidence;
  repairAttempts?:Array<{strategy:string;sourceSha256:string;result:string}>;
  specialistAttempts?:Array<{adapter:string;status:string;reason:string;detail?:string}>;
}
export interface CandidateCoverage {
  total:number; queued:number; admitted:number; dependenciesPending:number;
  experimentsPending:number; experimentsCompleted:number; terminalExhausted:number;
  blocked:number; unresolvedIds:string[]; unresolvedPrerequisites:Record<string,string[]>;
}

export interface AnalysisProgressSnapshot {
  version:1|2|3|4; inventoryFingerprint:string;
  candidateIds:string[]; records:CandidateProgress[];
  processedBatches:number; completedExperimentIds:string[];
}
const fingerprint=(candidates:readonly AnalysisCandidate[])=>createHash("sha256")
  .update(JSON.stringify(candidates.map(c=>[c.id,c.sourceCommit,c.sourceSha256]).sort((a,b)=>String(a[0]).localeCompare(String(b[0])))))
  .digest("hex");

export class AnalysisProgressStore {
  readonly records=new Map<string,CandidateProgress>();
  readonly candidates:readonly AnalysisCandidate[];
  readonly inventoryFingerprint:string;
  processedBatches=0;
  readonly completedExperimentIds=new Set<string>();
  private constructor(readonly path:string,candidates:readonly AnalysisCandidate[]) {
    this.candidates=[...candidates];
    this.inventoryFingerprint=fingerprint(candidates);
    for(const c of candidates)this.records.set(c.id,{
      id:c.id,sourceCommit:c.sourceCommit,sourceSha256:c.sourceSha256,
      lifecycle:"queued",attempts:0,properties:[],experimentIds:[],
    });
  }
  static async open(path:string,candidates:readonly AnalysisCandidate[]):Promise<AnalysisProgressStore>{
    const store=new AnalysisProgressStore(path,candidates);
    let raw:string;
    try{raw=await readFile(path,"utf8");}
    catch(e){if((e as NodeJS.ErrnoException).code==="ENOENT")return store;throw e;}
    const parsed=JSON.parse(raw) as AnalysisProgressSnapshot;
    // V1 snapshots contain valid source identities but lack the V2 terminality contract.
    // Preserve their candidate lifecycles and upgrade the schema on the next save.
    if(![1,2,3,4].includes(parsed.version)||parsed.inventoryFingerprint!==store.inventoryFingerprint||
       JSON.stringify([...parsed.candidateIds].sort())!==JSON.stringify([...store.records.keys()].sort()))
      throw new Error("ANALYSIS_CHECKPOINT_SOURCE_MISMATCH: source inventory or revision changed");
    if(!Array.isArray(parsed.records)||parsed.records.length!==candidates.length||
       new Set(parsed.records.map(x=>x.id)).size!==candidates.length)
      throw new Error("ANALYSIS_CHECKPOINT_CORRUPT: candidate set");
    for(const r of parsed.records){
      const orig=store.records.get(r.id);
      if(!orig||orig.sourceCommit!==r.sourceCommit||orig.sourceSha256!==r.sourceSha256)
        throw new Error("ANALYSIS_CHECKPOINT_SOURCE_MISMATCH: "+r.id);
      if(!Array.isArray(r.properties)||!Array.isArray(r.experimentIds)||!Number.isSafeInteger(r.attempts))
        throw new Error("ANALYSIS_CHECKPOINT_CORRUPT: "+r.id);
      // A process crash must never strand an admitted but unassessed candidate.
      if(r.lifecycle==="admitted"||r.lifecycle==="analyzing")r.lifecycle="queued";
      // A legacy checkpoint may contain terminal dispositions and experiment IDs
      // but no source-bound verifier evidence. Re-admit that candidate for
      // deterministic source analysis instead of accepting its stale closure.
      // Keep genuine source-bound evidence intact for reproducible continuation.
      const legacyMissingEvidence=(r.experimentIds.length>0&&!r.experimentEvidence?.length)||
        r.properties.some(p=>p.experimentIds.length>0&&!p.sourceWitnesses.length);
      if((parsed.version<4 && legacyMissingEvidence) || (parsed.version<4 &&
        !store.isConclusive(r) && ["dependencies_pending","analysis_exhausted","blocked"].includes(r.lifecycle))){
        r.lifecycle="queued";
        r.properties=[];
        r.experimentIds=[];
        r.repairAttempts=[];
        r.inconclusiveAttempts=[];
        r.lastError="checkpoint_requires_source_bound_replay";
      } else {
        store.pruneSubsumedWitnesslessProperties(r);
        if(store.isConclusive(r)){
          r.lifecycle="experiment_completed";
        } else if(["experiment_completed","analysis_exhausted","blocked"].includes(r.lifecycle)){
          r.lifecycle="dependencies_pending";
        }
      }
      store.records.set(r.id,r);
    }
    store.processedBatches=parsed.processedBatches||0;
    // Historical completion IDs remain audit history, not proof of a source-
    // bound property; the certificate enforces the separate evidence contract.
    for(const id of parsed.completedExperimentIds||[])
      if(parsed.version>=4||[...store.records.values()].some(r=>
        r.experimentIds.includes(id)&&r.experimentEvidence?.some(e=>e.experimentId===id)))
        store.completedExperimentIds.add(id);
    return store;
  }
  get counts():CandidateCoverage {
    const records=[...this.records.values()];
    const count=(state:CandidateLifecycle)=>records.filter(r=>r.lifecycle===state).length;
    // Source-reading or an unsupported analytical disposition is not experiment proof.
    const unresolved=records.filter(r=>!this.isConclusive(r)&&!this.hasSourceUnavailableEvidence(r));
    return {
      total:records.length,queued:count("queued"),
      admitted:count("admitted")+count("analyzing"),
      dependenciesPending:count("dependencies_pending"),
      experimentsPending:count("experiment_pending"),
      experimentsCompleted:count("experiment_completed"),
      terminalExhausted:count("analysis_exhausted"),blocked:count("blocked"),
      unresolvedIds:unresolved.map(r=>r.id).sort(),
      unresolvedPrerequisites:Object.fromEntries(unresolved
        .filter(r=>r.properties.some(p=>p.unresolvedPrerequisites.length))
        .map(r=>[r.id,[...new Set(r.properties.flatMap(p=>p.unresolvedPrerequisites))]])),
    };
  }
  private hasValidWitnesses(record:CandidateProgress,witnesses:readonly string[]):boolean {
    return witnesses.length>0 &&
      witnesses.some(x=>x.includes(record.sourceSha256)) &&
      !witnesses.some(x=>!/\b[a-f0-9]{64}\b/.test(x));
  }
  private hasValidEvidence(record:CandidateProgress,experimentId:string):boolean {
    return (record.experimentEvidence||[]).some(e=>
      e.experimentId===experimentId&&e.leadId===record.id&&
      e.sourceCommit===record.sourceCommit&&e.sourceSha256===record.sourceSha256&&
      /^[a-f0-9]{64}$/.test(e.verifierDigest)&&e.evidenceId.length>0&&
      (e.result==="observed"||e.result==="not_observed"));
  }
  // Remove a legacy witnessless duplicate property ONLY when another property
  // on the same lead already carries valid source witnesses AND verified EVM
  // evidence for the exact same experiment ID(s). Never removes unresolved
  // prerequisites or properties with distinct/unverified experiments.
  private pruneSubsumedWitnesslessProperties(record:CandidateProgress):void {
    const witnessedVerifiedIds=new Set<string>();
    for(const p of record.properties){
      if(p.state==="test_completed"&&this.hasValidWitnesses(record,p.sourceWitnesses)&&
        p.experimentIds.length>0&&p.experimentIds.every(id=>this.hasValidEvidence(record,id))){
        for(const id of p.experimentIds)witnessedVerifiedIds.add(id);
      }
    }
    if(!witnessedVerifiedIds.size)return;
    record.properties=record.properties.filter(p=>!(
      p.sourceWitnesses.length===0&&
      p.unresolvedPrerequisites.length===0&&
      p.experimentIds.length>0&&
      p.experimentIds.every(id=>witnessedVerifiedIds.has(id))
    ));
  }
  private isConclusive(record:CandidateProgress):boolean {
    return record.properties.length>0 &&
      record.properties.every(p=>p.state==="test_completed"&&p.unresolvedPrerequisites.length===0&&
        p.sourceWitnesses.length>0&&
        p.experimentIds.length>0 &&
        p.experimentIds.every(id=>this.hasValidEvidence(record,id)));
  }
  private hasSourceUnavailableEvidence(record:CandidateProgress):boolean {
    const e=record.sourceUnavailable;
    return !!e&&e.kind==="interface_without_acquired_implementation"&&
      e.leadId===record.id&&e.sourceCommit===record.sourceCommit&&
      e.sourceSha256===record.sourceSha256&&
      this.hasValidWitnesses(record,e.sourceWitnesses)&&
      /^[a-f0-9]{64}$/.test(e.acquiredInventoryDigest)&&
      /^[a-f0-9]{64}$/.test(e.verifierDigest)&&
      /^[a-f0-9]{64}$/.test(e.independentReviewDigest)&&
      e.verifierDigest!==e.independentReviewDigest&&
      e.evidenceId.length>0&&e.detail.length>0&&
      !record.properties.some(p=>p.state==="test_completed");
  }
  recordSourceUnavailable(id:string,evidence:SourceUnavailableEvidence,
    acquiredSources:readonly SourceSnapshot[],expectedAcquiredPaths:readonly string[]):void {
    const record=this.records.get(id);
    const candidate=this.candidates.find(c=>c.id===id);
    if(!record||!candidate||record.lifecycle==="queued"||
      record.lifecycle==="admitted"||record.lifecycle==="analyzing")
      throw new Error("SOURCE_UNAVAILABLE_LEAD_NOT_ASSESSED: "+id);
    if(record.sourceUnavailable)throw new Error("SOURCE_UNAVAILABLE_ALREADY_RECORDED: "+id);
    if(this.isConclusive(record)||record.properties.some(p=>p.state==="test_completed"))
      throw new Error("SOURCE_UNAVAILABLE_HAS_EXECUTED_EXPERIMENT: "+id);
    // An arbitrary SHA-shaped review digest is NOT a verifier. Recompute
    // BOTH proof paths against the exact entire acquired program revision
    // before accepting a durable terminal entry into the 290-lead ledger.
    const proposal=proposeInterfaceUnavailability(candidate,
      acquiredSources,expectedAcquiredPaths);
    const reviewed=proposal&&independentlyReviewInterfaceUnavailability(
      proposal,acquiredSources,expectedAcquiredPaths);
    if(!reviewed||JSON.stringify(reviewed)!==JSON.stringify(evidence))
      throw new Error("SOURCE_UNAVAILABLE_REPLAY_VERIFICATION_FAILED: "+id);
    const next={...record,sourceUnavailable:reviewed};
    if(!this.hasSourceUnavailableEvidence(next))
      throw new Error("SOURCE_UNAVAILABLE_INDEPENDENT_EVIDENCE_REQUIRED: "+id);
    record.sourceUnavailable={...reviewed,sourceWitnesses:[...reviewed.sourceWitnesses]};
    record.lifecycle="source_unavailable";
  }
  get experimentCertificate():LeadExperimentCertificate {
    const entries=[...this.records.values()].sort((a,b)=>a.id.localeCompare(b.id));
    const unavailable=entries.filter(e=>this.hasSourceUnavailableEvidence(e));
    const unresolved=entries.filter(e=>!this.isConclusive(e)&&!this.hasSourceUnavailableEvidence(e));
    const evidence=entries.flatMap(e=>(e.experimentEvidence||[])
      .map(x=>[x.experimentId,x.leadId,x.sourceSha256,x.evidenceId,x.verifierDigest,x.result]))
      .sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
    return {
      version:2,
      manifestDigest:createHash("sha256").update(JSON.stringify(entries.map(e=>e.id))).digest("hex"),
      evidenceDigest:createHash("sha256").update(JSON.stringify(evidence)).digest("hex"),
      total:entries.length,conclusive:entries.filter(e=>this.isConclusive(e)).length,
      sourceUnavailable:unavailable.length,
      sourceUnavailableIds:unavailable.map(e=>e.id),
      unavailabilityEvidenceDigest:createHash("sha256").update(JSON.stringify(
        unavailable.map(e=>[e.id,e.sourceUnavailable?.evidenceId,
          e.sourceUnavailable?.verifierDigest,e.sourceUnavailable?.independentReviewDigest,
          e.sourceUnavailable?.acquiredInventoryDigest]))).digest("hex"),
      unresolvedIds:unresolved.map(e=>e.id),
      pendingReasons:Object.fromEntries(unresolved.map(e=>[e.id,
        e.properties.flatMap(p=>p.unresolvedPrerequisites).concat(
          e.properties.filter(p=>p.state!=="test_completed").map(p=>p.state))
          .concat(e.properties.length?[]:["no_executable_property"])
          .filter((x,i,a)=>a.indexOf(x)===i)])),
      evidenceCount:evidence.length,
    };
  }
  get terminallyComplete(){return this.experimentCertificate.unresolvedIds.length===0;}
  get remaining(){return this.counts.queued;}
  get assessed(){return this.records.size-this.remaining;}
  nextBatch(maxAdmitted:number,maxPerFile:number):AnalysisCandidate[]{
    const eligible=this.candidates.filter(c=>this.records.get(c.id)?.lifecycle==="queued");
    const admitted:AnalysisCandidate[]=[];
    const countByFile=new Map<string,number>();
    for(const c of eligible){
      if(admitted.length>=maxAdmitted)break;
      const count=countByFile.get(c.path)||0;
      if(count>=maxPerFile)continue;
      admitted.push(c);countByFile.set(c.path,count+1);
    }
    if(admitted.length<maxAdmitted)for(const c of eligible){
      if(admitted.length>=maxAdmitted)break;
      if(!admitted.some(x=>x.id===c.id))admitted.push(c);
    }
    for(const c of admitted){
      const r=this.records.get(c.id)!;
      r.lifecycle="admitted";r.attempts++;
    }
    return admitted;
  }
  recordAssessment(id:string,propertyIds:readonly string[],unresolved:readonly string[],experimentIds:readonly string[],
    specialistAttempts:ReadonlyArray<{adapter:string;status:string;reason:string;detail?:string}>=[],
    obligations:ReadonlyArray<{id:string;experimentIds:string[];sourceWitnesses:string[]}>=[]){
    const record=this.records.get(id);
    if(!record||!["admitted","analyzing","dependencies_pending"].includes(record.lifecycle))
      throw new Error("ANALYSIS_CANDIDATE_NOT_ACTIVE: "+id);
    // Multiple candidate properties must retain independent outcomes. A valid
    // authorization experiment cannot discharge a separate unresolved
    // accounting prerequisite for the same source function.
    const properties:CandidatePropertyProgress[]=[];
    const uniqueExperiments=[...new Set(experimentIds)];
    if(obligations.length){
      for(const obligation of obligations){
        const linked=obligation.experimentIds.filter(id=>uniqueExperiments.includes(id));
        if(!linked.length)throw new Error("PROPERTY_EXPERIMENT_ID_NOT_SCHEDULED: "+obligation.id);
        if(!obligation.sourceWitnesses.length)throw new Error("PROPERTY_SOURCE_WITNESS_REQUIRED: "+obligation.id);
        properties.push({id:obligation.id,state:"test_constructed",
          sourceWitnesses:[...new Set(obligation.sourceWitnesses)],
          unresolvedPrerequisites:[],experimentIds:linked});
      }
    } else for(const pid of [...new Set(propertyIds)]){
      if(uniqueExperiments.length)properties.push({id:pid,state:"test_constructed",
        sourceWitnesses:[],unresolvedPrerequisites:[],experimentIds:uniqueExperiments});
    }
    // The unmet-prerequisite identity belongs to the exact source-backed
    // blocker, not its incidental array position. Regenerating analysis in
    // another order must not silently assign the old property ID to a new
    // unrelated prerequisite or permit an incorrect supersession.
    for(const reason of [...new Set(unresolved)].sort()){
      const blockerId=createHash("sha256").update(JSON.stringify([
        record.sourceCommit,record.sourceSha256,reason])).digest("hex");
      properties.push({id:id+":unresolved:"+blockerId,state:"prerequisites_pending",
        sourceWitnesses:[],unresolvedPrerequisites:[reason],experimentIds:[]});
    }
    if(!properties.length)properties.push({id:id+":needs_property",state:"prerequisites_pending",
      sourceWitnesses:[],unresolvedPrerequisites:["source_grounded_falsifier_missing"],experimentIds:[]});
    // A repeated analysis of the identical immutable source must not erase
    // earlier independently verified properties, EVM transcripts or unrelated
    // outstanding obligations. New discovery is additive; source/identity
    // changes are rejected by the checkpoint inventory fingerprint.
    const prior=new Map(record.properties.map(p=>[p.id,p]));
    const merged=new Map<string,CandidatePropertyProgress>();
    for(const p of record.properties)merged.set(p.id,{...p,
      sourceWitnesses:[...p.sourceWitnesses],
      unresolvedPrerequisites:[...p.unresolvedPrerequisites],
      experimentIds:[...p.experimentIds]});
    for(const p of properties){
      const previous=prior.get(p.id);
      if(!previous){merged.set(p.id,p);continue;}
      const unresolved=[...new Set([
        ...previous.unresolvedPrerequisites,...p.unresolvedPrerequisites])];
      const experimentIds=[...new Set([...previous.experimentIds,...p.experimentIds])];
      const witnesses=[...new Set([...previous.sourceWitnesses,...p.sourceWitnesses])];
      const verified=experimentIds.length>0&&
        experimentIds.every(exp=>this.hasValidEvidence(record,exp))&&
        this.hasValidWitnesses(record,witnesses);
      merged.set(p.id,{...previous,
        unresolvedPrerequisites:unresolved,experimentIds,
        sourceWitnesses:witnesses,
        state:unresolved.length?"prerequisites_pending":
          verified?"test_completed":
          experimentIds.length?"test_constructed":"prerequisites_pending"});
    }
    record.properties=[...merged.values()];
    record.experimentIds=[...new Set([...record.experimentIds,...uniqueExperiments])];
    record.specialistAttempts=[...new Map([
      ...(record.specialistAttempts||[]),...specialistAttempts]
      .map(x=>[x.adapter+":"+x.status+":"+x.reason,{...x}])).values()];
    record.lifecycle=this.isConclusive(record)?"experiment_completed":
      record.properties.some(p=>p.state==="prerequisites_pending")?"dependencies_pending":
      record.experimentIds.length?"experiment_pending":"dependencies_pending";
  }
  markTerminalAssessment(id:string,reason?:string){
    const record=this.records.get(id);
    if(!record||record.lifecycle==="queued")throw new Error("ANALYSIS_CANDIDATE_NOT_PROCESSED: "+id);
    if(record.lifecycle==="admitted"||record.lifecycle==="analyzing")
      record.lifecycle="analysis_exhausted";
    if(reason)record.lastError=reason;
  }
  // A verifier completion is the only source of truth for experiment terminality.
  // Rejected, incomplete and unsupported sequences remain unresolved.
  markExperimentCompleted(id:string,evidence?:Omit<ExperimentEvidence,"leadId"|"sourceCommit"|"sourceSha256"|"experimentId">){
    if(![...this.records.values()].some(r=>r.experimentIds.includes(id)))
      throw new Error("ANALYSIS_EXPERIMENT_ID_UNMATCHED: "+id);
    this.completedExperimentIds.add(id);
    for(const r of this.records.values())if(r.experimentIds.includes(id)){
      if(evidence){
        if(!evidence.evidenceId||!(/^[a-f0-9]{64}$/).test(evidence.verifierDigest)||
          !["observed","not_observed"].includes(evidence.result))
          throw new Error("INVALID_EXPERIMENT_EVIDENCE: "+id);
        r.experimentEvidence||=[];
        if(!r.experimentEvidence.some(x=>x.experimentId===id))
          r.experimentEvidence.push({experimentId:id,leadId:r.id,
            sourceCommit:r.sourceCommit,sourceSha256:r.sourceSha256,...evidence});
      }
      for(const p of r.properties)if(p.experimentIds.includes(id)&&
        p.unresolvedPrerequisites.length===0&&this.hasValidEvidence(r,id))
        p.state="test_completed";
      const successfulProperties=new Set(r.properties.filter(p=>p.state==="test_completed"&&
        p.experimentIds.length>0).map(p=>p.id));
      r.properties=r.properties.filter(p=>!(p.supersededBy&&successfulProperties.has(p.supersededBy)));
      this.pruneSubsumedWitnesslessProperties(r);
      if(this.isConclusive(r))r.lifecycle="experiment_completed";
      else if(r.experimentIds.every(x=>this.completedExperimentIds.has(x)) &&
        !r.properties.some(p=>p.state==="prerequisites_pending"))
        r.lifecycle="experiment_completed";
    }
  }
  noteRepairAttempt(leadId:string,strategy:string,result:string):boolean {
    const record=this.records.get(leadId);
    if(!record)throw new Error("REPAIR_LEAD_NOT_FOUND: "+leadId);
    record.repairAttempts||=[];
    if(record.repairAttempts.some(a=>a.strategy===strategy&&
      a.sourceSha256===record.sourceSha256))return false;
    record.repairAttempts.push({strategy,sourceSha256:record.sourceSha256,
      result:result.slice(0,500)});
    return true;
  }
  addRepairExperiment(leadId:string,propertyId:string,experimentId:string,witnesses:string[],resolvedAbstractFixture=false){
    const record=this.records.get(leadId);
    // The lead's original source must be witnessed; the concrete imported
    // implementation necessarily has a different SHA and must retain its
    // own independent source-bound witness rather than inheriting the root hash.
    if(!record||!experimentId||!witnesses.length||
      !witnesses.some(x=>x.includes(record.sourceSha256))||
      witnesses.some(x=>!/\b[a-f0-9]{64}\b/.test(x)))
      throw new Error("REPAIR_EXPERIMENT_SOURCE_WITNESS_REQUIRED: "+leadId);
    // Re-link an already scheduled/executed experiment to a different proven
    // property of the same lead. Queue deduplication is not property closure.
    // One verifier transcript may discharge more than one lead/property only
    // when the exact source-identified experiment and witnesses match.
    const wasScheduled=record.experimentIds.includes(experimentId);
    if(!wasScheduled)record.experimentIds.push(experimentId);
    const existing=record.properties.find(p=>p.id===propertyId);
    if(existing){
      if(existing.experimentIds.includes(experimentId))return;
      const inconclusive=(record.inconclusiveAttempts||[]).filter(a=>
        existing.experimentIds.includes(a.experimentId)&&!a.replacedBy);
      if(existing.state!=="prerequisites_pending"||!inconclusive.length||
        !existing.unresolvedPrerequisites.some(x=>/^experiment_/.test(x)))
        throw new Error("REPAIR_PROPERTY_ID_CONFLICT: "+propertyId);
      // Retain every old attempt in durable history; only a new sourced
      // experiment may replace its active obligation. No outcome is presumed.
      for(const attempt of inconclusive)attempt.replacedBy=experimentId;
      existing.experimentIds=[experimentId];
      existing.sourceWitnesses=[...new Set(witnesses)];
      existing.unresolvedPrerequisites=existing.unresolvedPrerequisites
        .filter(x=>!/^experiment_/.test(x));
      existing.state=existing.unresolvedPrerequisites.length?
        "prerequisites_pending":"test_constructed";
      record.lifecycle=existing.unresolvedPrerequisites.length?
        "dependencies_pending":"experiment_pending";
      return;
    }
    // Only a missing-property/missing-observable refusal may be superseded
    // by an executable property with verified source witnesses. External calls,
    // ambiguous dependencies and unrelated prerequisites remain unresolved.
    for(const p of record.properties)if(p.state==="prerequisites_pending" &&
      p.unresolvedPrerequisites.length>0 &&
      p.unresolvedPrerequisites.every(reason=>
        /UNKNOWN_ASSERTION\((?:no_supported_property|missing_observable_state)\)/.test(reason)||
        reason==="source_grounded_falsifier_missing"||
        (resolvedAbstractFixture&&/UNKNOWN_ASSERTION\(missing_fixture\)/.test(reason)&&
          /abstract and cannot be instantiated directly/.test(reason))))
      p.supersededBy=propertyId;
    record.properties=record.properties.filter(p=>!p.id.endsWith(":needs_property"));
    const evidence=(record.experimentEvidence||[]).find(x=>x.experimentId===experimentId&&
      x.leadId===record.id&&x.sourceCommit===record.sourceCommit&&
      x.sourceSha256===record.sourceSha256&&
      /^[a-f0-9]{64}$/.test(x.verifierDigest)&&
      (x.result==="observed"||x.result==="not_observed"));
    record.properties.push({id:propertyId,state:evidence?"test_completed":"test_constructed",
      sourceWitnesses:witnesses,unresolvedPrerequisites:[],experimentIds:[experimentId]});
    const successful=new Set(record.properties.filter(p=>p.state==="test_completed").map(p=>p.id));
    record.properties=record.properties.filter(p=>!(p.supersededBy&&successful.has(p.supersededBy)));
    this.pruneSubsumedWitnesslessProperties(record);
    record.lifecycle=this.isConclusive(record)?"experiment_completed":
      record.properties.some(p=>p.state==="prerequisites_pending")?"dependencies_pending":"experiment_pending";
  }
  // Reconcile persisted relational-call blockers against a freshly computed
  // ProgramFactsGraph for the exact same acquired sourceSha256. Only stale
  // unresolved_call/unresolved_external_call/ambiguous_call blockers that are
  // no longer present in the fresh graph may be pruned, and only when the lead
  // retains at least one witnessed property.
  reconcileRelationalPrerequisites(leadId:string,currentRelationalUnresolved:ReadonlySet<string>):boolean {
    const record=this.records.get(leadId);
    if(!record)return false;
    const isRelationalCall=(reason:string)=>/^(?:unresolved_call|unresolved_external_call|ambiguous_call):/.test(reason);
    const hasRetainedWitnessedProperty=record.properties.some(p=>
      p.state!=="prerequisites_pending"&&this.hasValidWitnesses(record,p.sourceWitnesses)&&
      p.experimentIds.length>0);
    if(!hasRetainedWitnessedProperty)return false;
    let changed=false;
    const nextProperties:CandidatePropertyProgress[]=[];
    for(const p of record.properties){
      if(p.state==="prerequisites_pending"&&p.unresolvedPrerequisites.length>0&&
        p.unresolvedPrerequisites.every(isRelationalCall)){
        const stillRelevant=p.unresolvedPrerequisites.filter(r=>currentRelationalUnresolved.has(r));
        if(stillRelevant.length===0){
          changed=true;
          continue;
        }
        if(stillRelevant.length<p.unresolvedPrerequisites.length){
          changed=true;
          nextProperties.push({...p,unresolvedPrerequisites:stillRelevant});
          continue;
        }
      }
      nextProperties.push(p);
    }
    if(!changed||!nextProperties.length)return false;
    record.properties=nextProperties;
    this.pruneSubsumedWitnesslessProperties(record);
    record.lifecycle=this.isConclusive(record)?"experiment_completed":
      record.properties.some(p=>p.state==="prerequisites_pending")?"dependencies_pending":"experiment_pending";
    return true;
  }
  /** Old failed attempts remain durable. Only a verified replacement for
   * every affected lead can release an obsolete inconclusive queue outcome. */
  retirableInconclusiveExperiments(replacementId:string):string[] {
    const oldIds=new Set<string>();
    for(const record of this.records.values()){
      if(!this.hasValidEvidence(record,replacementId))continue;
      for(const attempt of record.inconclusiveAttempts||[])
        if(attempt.replacedBy===replacementId)oldIds.add(attempt.experimentId);
    }
    return [...oldIds].filter(oldId=>{
      const affected=[...this.records.values()].filter(r=>r.experimentIds.includes(oldId));
      return affected.length>0&&affected.every(r=>
        !r.properties.some(p=>p.experimentIds.includes(oldId))&&
        (r.inconclusiveAttempts||[]).some(a=>a.experimentId===oldId&&
          !!a.replacedBy&&this.hasValidEvidence(r,a.replacedBy!)));
    });
  }
  recordInconclusive(id:string,status:string,evidenceId:string,reason:string){
    if(!this.records.size)throw new Error("EMPTY_ANALYSIS_INVENTORY");
    let matched=false;
    for(const record of this.records.values()){
      if(!record.experimentIds.includes(id))continue;
      matched=true;
      record.inconclusiveAttempts||=[];
      record.inconclusiveAttempts.push({experimentId:id,status,evidenceId,reason:reason.slice(0,500)});
      for(const property of record.properties)if(property.experimentIds.includes(id)){
        property.state="prerequisites_pending";
        const blocker="experiment_"+status+":"+id+":"+reason.slice(0,120);
        if(!property.unresolvedPrerequisites.includes(blocker))property.unresolvedPrerequisites.push(blocker);
      }
      record.lifecycle="dependencies_pending";
    }
    if(!matched)throw new Error("INCONCLUSIVE_EXPERIMENT_UNMAPPED: "+id);
  }
  // A blocked property remains durable and eligible for a genuinely different
  // source-backed experiment. Identical failed scripts cannot be counted twice.
  nextRepairBatch(max:number):AnalysisCandidate[]{
    // Repair eligibility follows the actual evidence certificate, not a
    // particular legacy lifecycle label. Both analysis_exhausted and
    // experiment_pending can still have uncovered source-backed obligations.
    const eligible=this.candidates.filter(c=>{
      const record=this.records.get(c.id);
      return !!record && record.lifecycle!=="queued" &&
        record.lifecycle!=="admitted" && record.lifecycle!=="analyzing" &&
        !this.isConclusive(record)&&!this.hasSourceUnavailableEvidence(record);
    });
    return eligible.slice(0,max);
  }
  async save():Promise<void>{
    const state:AnalysisProgressSnapshot={version:4,inventoryFingerprint:this.inventoryFingerprint,
      candidateIds:[...this.records.keys()],records:[...this.records.values()],
      processedBatches:this.processedBatches,completedExperimentIds:[...this.completedExperimentIds]};
    await mkdir(dirname(this.path),{recursive:true});
    const temp=this.path+".tmp-"+process.pid;
    await writeFile(temp,JSON.stringify(state,null,2),{mode:0o600});
    await rename(temp,this.path);
  }
}
