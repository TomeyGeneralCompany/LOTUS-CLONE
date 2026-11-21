/**
 * Durable, source-revision-bound deterministic analysis inventory.
 * A batch is a scheduling window, never the unit of audit completion.
 */
import {createHash} from "node:crypto";
import {readFile,writeFile,rename,mkdir} from "node:fs/promises";
import {dirname} from "node:path";
import type {AnalysisCandidate} from "./analysis-candidate-queue";

export type CandidateLifecycle="queued"|"admitted"|"analyzing"|"dependencies_pending"|
  "experiment_pending"|"experiment_completed"|"analysis_exhausted"|"blocked";
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
export interface LeadExperimentCertificate {
  version:1; manifestDigest:string; evidenceDigest:string;
  total:number; conclusive:number; unresolvedIds:string[];
  pendingReasons:Record<string,string[]>; evidenceCount:number;
}
export interface CandidateProgress {
  id:string; sourceCommit:string; sourceSha256:string;
  lifecycle:CandidateLifecycle; attempts:number;
  properties:CandidatePropertyProgress[];
  experimentIds:string[]; lastError?:string;
  experimentEvidence?:ExperimentEvidence[];
  inconclusiveAttempts?:Array<{experimentId:string;status:string;evidenceId:string;reason:string}>;
  repairAttempts?:Array<{strategy:string;sourceSha256:string;result:string}>;
  specialistAttempts?:Array<{adapter:string;status:string;reason:string;detail?:string}>;
}
export interface CandidateCoverage {
  total:number; queued:number; admitted:number; dependenciesPending:number;
  experimentsPending:number; experimentsCompleted:number; terminalExhausted:number;
  blocked:number; unresolvedIds:string[]; unresolvedPrerequisites:Record<string,string[]>;
}

export interface AnalysisProgressSnapshot {
  version:1|2|3; inventoryFingerprint:string;
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
    if(![1,2,3].includes(parsed.version)||parsed.inventoryFingerprint!==store.inventoryFingerprint||
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
      // Older checkpoints contain completed IDs but no verifier evidence. Their
      // records remain actionable until a source-identical replay is recorded.
      if(r.lifecycle==="experiment_completed"&&!store.isConclusive(r))
        r.lifecycle="dependencies_pending";
      store.records.set(r.id,r);
    }
    store.processedBatches=parsed.processedBatches||0;
    for(const id of parsed.completedExperimentIds||[])store.completedExperimentIds.add(id);
    return store;
  }
  get counts():CandidateCoverage {
    const records=[...this.records.values()];
    const count=(state:CandidateLifecycle)=>records.filter(r=>r.lifecycle===state).length;
    // Source-reading or an unsupported analytical disposition is not experiment proof.
    const unresolved=records.filter(r=>!this.isConclusive(r));
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
  private isConclusive(record:CandidateProgress):boolean {
    return record.properties.length>0 &&
      record.properties.every(p=>p.state==="test_completed"&&p.sourceWitnesses.length>0&&
        p.experimentIds.length>0 &&
        p.experimentIds.every(id=>(record.experimentEvidence||[]).some(e=>
          e.experimentId===id&&e.leadId===record.id&&
          e.sourceCommit===record.sourceCommit&&e.sourceSha256===record.sourceSha256&&
          /^[a-f0-9]{64}$/.test(e.verifierDigest)&&e.evidenceId.length>0&&
          (e.result==="observed"||e.result==="not_observed"))));
  }
  get experimentCertificate():LeadExperimentCertificate {
    const entries=[...this.records.values()].sort((a,b)=>a.id.localeCompare(b.id));
    const unresolved=entries.filter(e=>!this.isConclusive(e));
    const evidence=entries.flatMap(e=>(e.experimentEvidence||[])
      .map(x=>[x.experimentId,x.leadId,x.sourceSha256,x.evidenceId,x.verifierDigest,x.result]))
      .sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
    return {
      version:1,
      manifestDigest:createHash("sha256").update(JSON.stringify(entries.map(e=>e.id))).digest("hex"),
      evidenceDigest:createHash("sha256").update(JSON.stringify(evidence)).digest("hex"),
      total:entries.length,conclusive:entries.length-unresolved.length,
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
    for(const [index,reason] of [...new Set(unresolved)].entries())
      properties.push({id:id+":unresolved:"+index,state:"prerequisites_pending",
        sourceWitnesses:[],unresolvedPrerequisites:[reason],experimentIds:[]});
    if(!properties.length)properties.push({id:id+":needs_property",state:"prerequisites_pending",
      sourceWitnesses:[],unresolvedPrerequisites:["source_grounded_falsifier_missing"],experimentIds:[]});
    record.properties=properties;
    record.experimentIds=[...new Set([...record.experimentIds,...uniqueExperiments])];
    record.specialistAttempts=specialistAttempts.map(x=>({...x}));
    record.lifecycle=(unresolved.length||!uniqueExperiments.length)?"dependencies_pending":
      "experiment_pending";
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
        (r.experimentEvidence||[]).some(e=>e.experimentId===id))
        p.state="test_completed";
      const successfulProperties=new Set(r.properties.filter(p=>p.state==="test_completed"&&
        p.experimentIds.length>0).map(p=>p.id));
      r.properties=r.properties.filter(p=>!(p.supersededBy&&successfulProperties.has(p.supersededBy)));
      if(r.experimentIds.every(x=>this.completedExperimentIds.has(x)) &&
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
  addRepairExperiment(leadId:string,propertyId:string,experimentId:string,witnesses:string[]){
    const record=this.records.get(leadId);
    if(!record||!experimentId||!witnesses.length||
      witnesses.some(x=>!x.includes(record.sourceSha256)))
      throw new Error("REPAIR_EXPERIMENT_SOURCE_WITNESS_REQUIRED: "+leadId);
    if(record.experimentIds.includes(experimentId))return;
    record.experimentIds.push(experimentId);
    // Only a missing-property/missing-observable refusal may be superseded
    // by an executable property with verified source witnesses. External calls,
    // ambiguous dependencies and unrelated prerequisites remain unresolved.
    for(const p of record.properties)if(p.state==="prerequisites_pending" &&
      p.unresolvedPrerequisites.length>0 &&
      p.unresolvedPrerequisites.every(reason=>
        /UNKNOWN_ASSERTION\((?:no_supported_property|missing_observable_state)\)/.test(reason)||
        reason==="source_grounded_falsifier_missing"))
      p.supersededBy=propertyId;
    record.properties=record.properties.filter(p=>!p.id.endsWith(":needs_property"));
    record.properties.push({id:propertyId,state:"test_constructed",
      sourceWitnesses:witnesses,unresolvedPrerequisites:[],experimentIds:[experimentId]});
    record.lifecycle="experiment_pending";
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
    const eligible=this.candidates.filter(c=>{
      const record=this.records.get(c.id);
      return record?.lifecycle==="dependencies_pending"&&
        !record.properties.every(p=>p.state==="test_completed");
    });
    return eligible.slice(0,max);
  }
  async save():Promise<void>{
    const state:AnalysisProgressSnapshot={version:3,inventoryFingerprint:this.inventoryFingerprint,
      candidateIds:[...this.records.keys()],records:[...this.records.values()],
      processedBatches:this.processedBatches,completedExperimentIds:[...this.completedExperimentIds]};
    await mkdir(dirname(this.path),{recursive:true});
    const temp=this.path+".tmp-"+process.pid;
    await writeFile(temp,JSON.stringify(state,null,2),{mode:0o600});
    await rename(temp,this.path);
  }
}
