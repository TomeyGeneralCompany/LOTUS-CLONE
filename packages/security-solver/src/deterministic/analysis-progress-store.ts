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
  unresolvedPrerequisites:string[]; experimentIds:string[];
}
export interface CandidateProgress {
  id:string; sourceCommit:string; sourceSha256:string;
  lifecycle:CandidateLifecycle; attempts:number;
  properties:CandidatePropertyProgress[];
  experimentIds:string[]; lastError?:string;
  specialistAttempts?:Array<{adapter:string;status:string;reason:string;detail?:string}>;
}
export interface CandidateCoverage {
  total:number; queued:number; admitted:number; dependenciesPending:number;
  experimentsPending:number; experimentsCompleted:number; terminalExhausted:number;
  blocked:number; unresolvedIds:string[]; unresolvedPrerequisites:Record<string,string[]>;
}

export interface AnalysisProgressSnapshot {
  version:1|2; inventoryFingerprint:string;
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
    if(![1,2].includes(parsed.version)||parsed.inventoryFingerprint!==store.inventoryFingerprint||
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
      store.records.set(r.id,r);
    }
    store.processedBatches=parsed.processedBatches||0;
    for(const id of parsed.completedExperimentIds||[])store.completedExperimentIds.add(id);
    return store;
  }
  get counts():CandidateCoverage {
    const records=[...this.records.values()];
    const count=(state:CandidateLifecycle)=>records.filter(r=>r.lifecycle===state).length;
    const unresolved=records.filter(r=>["queued","admitted","analyzing","dependencies_pending","experiment_pending"].includes(r.lifecycle));
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
  get terminallyComplete(){return this.counts.unresolvedIds.length===0;}
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
    specialistAttempts:ReadonlyArray<{adapter:string;status:string;reason:string;detail?:string}>=[]){
    const record=this.records.get(id);
    if(!record||!["admitted","analyzing","dependencies_pending"].includes(record.lifecycle))
      throw new Error("ANALYSIS_CANDIDATE_NOT_ACTIVE: "+id);
    record.properties=[...new Set(propertyIds)].map(pid=>({
      id:pid,state:experimentIds.length?"test_constructed":unresolved.length?"prerequisites_pending":"unsupported",
      sourceWitnesses:[],unresolvedPrerequisites:[...unresolved],experimentIds:[...experimentIds],
    }));
    record.experimentIds=[...new Set([...record.experimentIds,...experimentIds])];
    record.specialistAttempts=specialistAttempts.map(x=>({...x}));
    record.lifecycle=experimentIds.length?"experiment_pending":unresolved.length?"dependencies_pending":"analysis_exhausted";
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
  markExperimentCompleted(id:string){
    if(![...this.records.values()].some(r=>r.experimentIds.includes(id)))
      throw new Error("ANALYSIS_EXPERIMENT_ID_UNMATCHED: "+id);
    this.completedExperimentIds.add(id);
    for(const r of this.records.values())if(r.experimentIds.includes(id)){
      for(const p of r.properties)if(p.experimentIds.includes(id))p.state="test_completed";
      if(r.experimentIds.every(x=>this.completedExperimentIds.has(x)))r.lifecycle="experiment_completed";
    }
  }
  async save():Promise<void>{
    const state:AnalysisProgressSnapshot={version:2,inventoryFingerprint:this.inventoryFingerprint,
      candidateIds:[...this.records.keys()],records:[...this.records.values()],
      processedBatches:this.processedBatches,completedExperimentIds:[...this.completedExperimentIds]};
    await mkdir(dirname(this.path),{recursive:true});
    const temp=this.path+".tmp-"+process.pid;
    await writeFile(temp,JSON.stringify(state,null,2),{mode:0o600});
    await rename(temp,this.path);
  }
}
