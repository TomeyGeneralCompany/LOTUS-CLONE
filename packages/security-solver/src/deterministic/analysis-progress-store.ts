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
}
export interface AnalysisProgressSnapshot {
  version:1; inventoryFingerprint:string;
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
    if(parsed.version!==1||parsed.inventoryFingerprint!==store.inventoryFingerprint||
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
      store.records.set(r.id,r);
    }
    store.processedBatches=parsed.processedBatches||0;
    for(const id of parsed.completedExperimentIds||[])store.completedExperimentIds.add(id);
    return store;
  }
  get remaining(){return [...this.records.values()].filter(x=>x.lifecycle==="queued").length;}
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
  recordAssessment(id:string,propertyIds:readonly string[],unresolved:readonly string[],experimentIds:readonly string[]){
    const record=this.records.get(id);
    if(!record||!["admitted","analyzing","dependencies_pending"].includes(record.lifecycle))
      throw new Error("ANALYSIS_CANDIDATE_NOT_ACTIVE: "+id);
    record.properties=[...new Set(propertyIds)].map(pid=>({
      id:pid,state:experimentIds.length?"test_constructed":unresolved.length?"prerequisites_pending":"unsupported",
      sourceWitnesses:[],unresolvedPrerequisites:[...unresolved],experimentIds:[...experimentIds],
    }));
    record.experimentIds=[...new Set([...record.experimentIds,...experimentIds])];
    record.lifecycle=experimentIds.length?"experiment_pending":unresolved.length?"dependencies_pending":"analysis_exhausted";
  }
  markTerminalAssessment(id:string,reason?:string){
    const record=this.records.get(id);
    if(!record||record.lifecycle==="queued")throw new Error("ANALYSIS_CANDIDATE_NOT_PROCESSED: "+id);
    if(record.lifecycle==="admitted"||record.lifecycle==="analyzing")
      record.lifecycle="analysis_exhausted";
    if(reason)record.lastError=reason;
  }
  markExperimentCompleted(id:string){
    this.completedExperimentIds.add(id);
    for(const r of this.records.values())if(r.experimentIds.includes(id)){
      for(const p of r.properties)if(p.experimentIds.includes(id))p.state="test_completed";
      if(r.experimentIds.every(x=>this.completedExperimentIds.has(x)))r.lifecycle="experiment_completed";
    }
  }
  async save():Promise<void>{
    const state:AnalysisProgressSnapshot={version:1,inventoryFingerprint:this.inventoryFingerprint,
      candidateIds:[...this.records.keys()],records:[...this.records.values()],
      processedBatches:this.processedBatches,completedExperimentIds:[...this.completedExperimentIds]};
    await mkdir(dirname(this.path),{recursive:true});
    const temp=this.path+".tmp-"+process.pid;
    await writeFile(temp,JSON.stringify(state,null,2),{mode:0o600});
    await rename(temp,this.path);
  }
}
