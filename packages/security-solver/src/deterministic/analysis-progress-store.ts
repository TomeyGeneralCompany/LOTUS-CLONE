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
import type {FixtureSearchCheckpoint} from "./fixture-dependency-planner";

export type CandidateLifecycle="queued"|"admitted"|"analyzing"|"dependencies_pending"|
  "experiment_pending"|"experiment_completed"|"source_unavailable"|"analysis_exhausted"|"blocked"|
  "explicitly_unresolved";
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
  unavailabilityEvidenceDigest:string; unresolvedIds:string[]; explicitlyUnresolvedIds:string[];
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
  /** Unexplored fixture selection frontier, bound to the immutable acquired
   * inventory by its own digest and checksum. */
  fixtureSearchCheckpoint?:FixtureSearchCheckpoint;
}
export interface CandidateCoverage {
  total:number; queued:number; admitted:number; dependenciesPending:number;
  experimentsPending:number; experimentsCompleted:number; sourceUnavailable:number; terminalExhausted:number;
  blocked:number; unresolvedIds:string[]; explicitlyUnresolvedIds:string[];
  unresolvedReasons:Record<string,string[]>; unresolvedPrerequisites:Record<string,string[]>;
}

export interface AnalysisProgressSnapshot {
  version:1|2|3|4|5|6; inventoryFingerprint:string;
  /** Explicitly version the source-property interpreter, independently of the acquired program SHA. */
  analysisEngineRevision?:string;
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
  private constructor(readonly path:string,candidates:readonly AnalysisCandidate[],
    readonly analysisEngineRevision:string) {
    this.candidates=[...candidates];
    this.inventoryFingerprint=fingerprint(candidates);
    for(const c of candidates)this.records.set(c.id,{
      id:c.id,sourceCommit:c.sourceCommit,sourceSha256:c.sourceSha256,
      lifecycle:"queued",attempts:0,properties:[],experimentIds:[],
    });
  }
  static async open(path:string,candidates:readonly AnalysisCandidate[],
    analysisEngineRevision="source-property-engine-v5"):Promise<AnalysisProgressStore>{
    if(!analysisEngineRevision.trim())
      throw new Error("ANALYSIS_ENGINE_REVISION_REQUIRED");
    const store=new AnalysisProgressStore(path,candidates,analysisEngineRevision);
    let raw:string;
    try{raw=await readFile(path,"utf8");}
    catch(e){if((e as NodeJS.ErrnoException).code==="ENOENT")return store;throw e;}
    const parsed=JSON.parse(raw) as AnalysisProgressSnapshot;
    // V1 snapshots contain valid source identities but lack the V2 terminality contract.
    // Preserve their candidate lifecycles and upgrade the schema on the next save.
    if(![1,2,3,4,5,6].includes(parsed.version)||parsed.inventoryFingerprint!==store.inventoryFingerprint||
       JSON.stringify([...parsed.candidateIds].sort())!==JSON.stringify([...store.records.keys()].sort()))
      throw new Error("ANALYSIS_CHECKPOINT_SOURCE_MISMATCH: source inventory or revision changed");
    if(!Array.isArray(parsed.records)||parsed.records.length!==candidates.length||
       new Set(parsed.records.map(x=>x.id)).size!==candidates.length)
      throw new Error("ANALYSIS_CHECKPOINT_CORRUPT: candidate set");
    const engineChanged=parsed.analysisEngineRevision!==analysisEngineRevision;
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
        } else if(store.hasSourceUnavailableEvidence(r)){
          r.lifecycle="source_unavailable";
        } else if(engineChanged){
          // A new source-property interpreter must reassess every unresolved
          // immutable lead; a resumed cached assessment is not a new analysis.
          // Keep EVM transcripts, inconclusive attempts, source witnesses and
          // unresolved obligations as durable audit history until independently
          // verified source evidence supersedes them.
          r.lifecycle="queued";
          r.lastError="reassessment_required_for_engine_revision:"+analysisEngineRevision;
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
    const certificate=this.experimentCertificate;
    const count=(state:CandidateLifecycle)=>records.filter(r=>r.lifecycle===state).length;
    // Source-unavailable is a separately verified disposition, not an EVM
    // result. Count it as accounted for while preserving its own ledger so a
    // report can distinguish it from an experiment-backed lead.
    const unresolved=records.filter(r=>!this.isConclusive(r)&&
      !this.hasSourceUnavailableEvidence(r));
    return {
      total:records.length,queued:count("queued"),
      admitted:count("admitted")+count("analyzing"),
      dependenciesPending:count("dependencies_pending"),
      experimentsPending:count("experiment_pending"),
      experimentsCompleted:count("experiment_completed"),
      sourceUnavailable:records.filter(r=>this.hasSourceUnavailableEvidence(r)).length,
      terminalExhausted:count("analysis_exhausted"),blocked:count("blocked"),
      unresolvedIds:unresolved.map(r=>r.id).sort(),
      explicitlyUnresolvedIds:certificate.explicitlyUnresolvedIds,
      unresolvedReasons:certificate.pendingReasons,
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
  /**
   * Close only the remaining assessed leads as explicit unresolved outcomes
   * after the caller has exhausted its source-grounded repair pass. This is a
   * durable disposition, separate from a lead that is still pending work.
   */
  markExplicitlyUnresolved():string[]{
    const unresolved=[...this.records.values()].filter(record=>
      !this.isConclusive(record)&&!this.hasSourceUnavailableEvidence(record));
    for(const record of unresolved){
      if(["queued","admitted","analyzing"].includes(record.lifecycle))
        throw new Error("UNRESOLVED_LEAD_STILL_PENDING: "+record.id+":"+record.lifecycle);
      if(record.experimentIds.some(id=>!this.completedExperimentIds.has(id))||
        record.properties.some(property=>["unexamined","analyzing","test_constructed"]
          .includes(property.state)))continue;
      const reasons=[
        ...record.properties.flatMap(property=>property.unresolvedPrerequisites),
        ...record.properties.filter(property=>property.state!=="test_completed")
          .map(property=>"property_state:"+property.state),
        ...(record.specialistAttempts||[]).map(attempt=>
          "specialist:"+attempt.adapter+":"+attempt.status+":"+attempt.reason),
        ...(record.repairAttempts||[]).filter(attempt=>
          !["no_constructed_experiment","no_distinct_sourced_experiment"].includes(attempt.result))
          .map(attempt=>
          "repair:"+attempt.strategy+":"+attempt.result),
        ...(record.lastError?["controller_error:"+record.lastError]:[]),
      ];
      // A lifecycle label or lack of a property is not a concrete blocker.
      // Leave such a lead pending so the gate requires further analysis.
      if(reasons.length===0)continue;
      record.lifecycle="explicitly_unresolved";
    }
    return unresolved.filter(record=>record.lifecycle==="explicitly_unresolved")
      .map(record=>record.id).sort();
  }
  get experimentCertificate():LeadExperimentCertificate {
    const entries=[...this.records.values()].sort((a,b)=>a.id.localeCompare(b.id));
    const unavailable=entries.filter(e=>this.hasSourceUnavailableEvidence(e));
    // Keep source-unavailable dispositions distinct from experiments while
    // allowing the independently verified disposition to account for a lead.
    const unresolved=entries.filter(e=>!this.isConclusive(e)&&
      !this.hasSourceUnavailableEvidence(e));
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
      explicitlyUnresolvedIds:unresolved.filter(e=>e.lifecycle==="explicitly_unresolved")
        .map(e=>e.id),
      pendingReasons:Object.fromEntries(unresolved.map(e=>{
        const reasons=[
          ...e.properties.flatMap(p=>p.unresolvedPrerequisites),
          ...e.properties.filter(p=>p.state!=="test_completed").map(p=>"property_state:"+p.state),
          ...(e.specialistAttempts||[]).map(p=>"specialist:"+p.adapter+":"+p.status+":"+p.reason),
          ...(e.repairAttempts||[]).filter(p=>
            !["no_constructed_experiment","no_distinct_sourced_experiment"].includes(p.result))
            .map(p=>"repair:"+p.strategy+":"+p.result),
          ...(e.lastError?["controller_error:"+e.lastError]:[]),
          ...(!e.properties.length?["lifecycle:"+e.lifecycle+":no_source_grounded_property_recorded"]:[]),
        ];
        if(!reasons.length)reasons.push(
          "lifecycle:"+e.lifecycle+":source_property_not_conclusively_verified");
        return [e.id,[...new Set(reasons)]] as const;
      })),
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
  setFixtureSearchCheckpoint(leadId:string,checkpoint:FixtureSearchCheckpoint|undefined):void {
    const record=this.records.get(leadId);
    if(!record)throw new Error("FIXTURE_SEARCH_LEAD_NOT_FOUND: "+leadId);
    if(checkpoint)record.fixtureSearchCheckpoint=structuredClone(checkpoint);
    else delete record.fixtureSearchCheckpoint;
  }
  addRepairExperiment(leadId:string,propertyId:string,experimentId:string,witnesses:string[],
    resolvedAbstractFixture=false,maySupersedePriorBlockers=true){
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
    for(const p of record.properties)if(maySupersedePriorBlockers &&
      p.state==="prerequisites_pending" &&
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
        record.lifecycle!=="explicitly_unresolved"&&
        !this.isConclusive(record)&&!this.hasSourceUnavailableEvidence(record);
    });
    return eligible.slice(0,max);
  }
  async save():Promise<void>{
    const state:AnalysisProgressSnapshot={version:6,analysisEngineRevision:this.analysisEngineRevision,
      inventoryFingerprint:this.inventoryFingerprint,
      candidateIds:[...this.records.keys()],records:[...this.records.values()],
      processedBatches:this.processedBatches,completedExperimentIds:[...this.completedExperimentIds]};
    await mkdir(dirname(this.path),{recursive:true});
    const temp=this.path+".tmp-"+process.pid;
    await writeFile(temp,JSON.stringify(state,null,2),{mode:0o600});
    await rename(temp,this.path);
  }
}
