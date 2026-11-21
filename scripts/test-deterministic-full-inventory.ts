/**
 * Round 3: full-inventory stage-lock/scheduler/checkpoint integration regression.
 * Exercises the real AnalysisProgressStore and ControllerStageLock together.
 * Does not claim to substitute for the self-hosted 88mph investigation.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
import {AnalysisProgressStore} from '../packages/security-solver/src/deterministic/analysis-progress-store';
import type {AnalysisCandidate} from '../packages/security-solver/src/deterministic/analysis-candidate-queue';

const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const path='source-1/contracts/Finance.sol';
const content='contract Finance { function deposit(uint n) external {} }';
const revision='a'.repeat(40);
const sourceSha=hash(content);
const candidates:AnalysisCandidate[]=Array.from({length:244},(_,i)=>({
  id:hash('candidate:'+i),path,selector:'Finance.method'+i,
  sourceCommit:revision,sourceSha256:sourceSha,
  staticLeadIds:[],priority:244-i,selectionReasons:[],
  status:'queued',sourceEvidence:path+':1',sourceExcerpt:content,
  excerptStart:0,truncated:false,lineStart:1,lineEnd:1,
}));

async function stage():Promise<ControllerStageLock>{
  const lock=new ControllerStageLock();
  lock.completeIndex([{path,characters:content.length,sha256:sourceSha}]);
  lock.recordRead({path,start:0,end:content.length,totalCharacters:content.length,text:content});
  await lock.completeReading(async()=>content);
  lock.noteSourcePreclassified(path,'indexed-options-built');
  lock.registerAnalysisInventory(candidates.map(c=>c.id));
  return lock;
}
async function run(){
  const dir=await mkdtemp(join(tmpdir(),'lotus-round3-'));
  const file=join(dir,'analysis.json');
  try{
    let store=await AnalysisProgressStore.open(file,candidates);
    let lock=await stage();
    assert.throws(()=>lock.completeAnalysis(),/ANALYSIS_INVENTORY_INCOMPLETE/);
    const experiments=Array.from({length:64},(_,i)=>hash('experiment:'+i));
    const mapped=new Map(candidates.slice(0,64).map((c,i)=>[c.id,experiments[i]]));
    const seen=new Set<string>();
    let batches=0;
    while(store.remaining){
      const batch=store.nextBatch(18,18);
      assert.ok(batch.length>0&&batch.length<=18,'bounded batch must make progress');
      for(const item of batch){
        assert.equal(seen.has(item.id),false,'candidate never admitted twice');
        seen.add(item.id);
        lock.registerAnalysisLead({
          id:item.id,path:item.path,selector:item.selector,
          sourceCommit:item.sourceCommit,sourceSha256:item.sourceSha256,
        });
        lock.recordLeadAssessment(item.id,{
          kind:'assessed',
          sourceEvidence:[item.sourceEvidence],
          hypothesis:'Source-reviewed security property '+item.selector,
          disposition:'defer',
          reason:'Fixture establishes complete inventory accounting, not target exploitability',
        },'controller');
        store.recordAssessment(item.id,[hash('property:'+item.id)],[],mapped.has(item.id)?[mapped.get(item.id)!]:[]);
      }
      lock.completeAnalysisBatch();
      store.processedBatches++;
      await store.save();
      batches++;
      if(batches===5){
        assert.equal(lock.currentStage,'ANALYZE');
        assert.throws(()=>lock.completeAnalysis(),/ANALYSIS_INVENTORY_INCOMPLETE/);
        store=await AnalysisProgressStore.open(file,candidates);
        lock=await stage();
        for(const item of candidates){
          if(store.records.get(item.id)?.lifecycle!=='queued'){
            lock.restoreResolvedAnalysisCandidate(item.id);
          }
        }
        assert.equal(lock.analysisInventoryProgress.resolved,90);
      }
    }
    assert.equal(batches,14,'244 candidates at 18 per batch require 14 batches');
    assert.equal(seen.size,244);
    assert.equal(store.remaining,0);
    assert.equal(lock.analysisInventoryProgress.remaining,0);
    // The 64 distinct experiment identities are all retained; no tier-4 loss.
    for(const id of experiments)lock.discover(id);
    lock.completeAnalysis();
    assert.equal(lock.currentStage,'EXPERIMENT');
    for(const id of experiments){
      lock.requireCandidate(id);
      lock.finishExperiment(id,'not_observed');
      store.markExperimentCompleted(id);
    }
    await store.save();
    assert.equal(store.completedExperimentIds.size,64);
    assert.equal(store.counts.experimentsCompleted,64);
    assert.equal(store.counts.unresolvedIds.length,0);
    assert.equal(lock.completedCount,64);
    lock.completeExperiments();
    for(const id of experiments)lock.review(id);
    lock.completeReviews();
    lock.completeReport(true);
    assert.equal(lock.currentStage,'COMPLETE');
    const resumed=await AnalysisProgressStore.open(file,candidates);
    assert.equal(resumed.completedExperimentIds.size,64);
    assert.equal(resumed.remaining,0);
    // A second inventory must never turn unresolved dependencies, queued
    // candidates or selected-but-unexecuted experiments into terminal claims.
    const pendingCandidates=candidates.slice(0,6).map((c,i)=>({...c,id:hash('coverage-state:'+i)}));
    const pendingFile=join(dir,'pending.json');
    let pending=await AnalysisProgressStore.open(pendingFile,pendingCandidates);
    const one=pending.nextBatch(5,5);
    assert.equal(one.length,5);
    pending.recordAssessment(one[0].id,['negative'],[],[hash('done-negative')]);
    pending.recordAssessment(one[1].id,['positive'],[],[hash('done-positive')]);
    pending.recordAssessment(one[2].id,['unsupported'],[],[]);
    pending.recordAssessment(one[3].id,['money-market'],['unresolved_money_market'],[]);
    pending.recordAssessment(one[4].id,['withdraw'],[],[hash('unexecuted')]);
    pending.markExperimentCompleted(hash('done-negative'));
    pending.markExperimentCompleted(hash('done-positive'));
    await pending.save();
    assert.equal(pending.counts.queued,1);
    assert.equal(pending.counts.dependenciesPending,1);
    assert.equal(pending.counts.experimentsPending,1);
    assert.equal(pending.terminallyComplete,false);
    pending=await AnalysisProgressStore.open(pendingFile,pendingCandidates);
    assert.equal(pending.terminallyComplete,false,'checkpoint must preserve all three pending states');
    assert.equal(pending.counts.unresolvedIds.length,3);
    assert.throws(()=>pending.markExperimentCompleted(hash('unmatched')),
      /ANALYSIS_EXPERIMENT_ID_UNMATCHED/);
    const changed=candidates.map(c=>({...c}));
    changed[0].sourceSha256=hash('changed source');
    await assert.rejects(AnalysisProgressStore.open(file,changed),/SOURCE_MISMATCH/);
    console.log('Round 3 full inventory and checkpoint lifecycle PASSED: 244/244, 64/64, restart, source mismatch');
  }finally{
    await rm(dir,{recursive:true,force:true});
  }
}
void run().catch(error=>{console.error(error);process.exitCode=1;});
