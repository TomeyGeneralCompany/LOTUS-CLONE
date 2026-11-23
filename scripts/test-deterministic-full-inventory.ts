/**
 * Round 3: full-inventory stage-lock/scheduler/checkpoint integration regression.
 * Exercises the real AnalysisProgressStore and ControllerStageLock together.
 * Does not claim to substitute for the self-hosted 88mph investigation.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
import {AnalysisProgressStore} from '../packages/security-solver/src/deterministic/analysis-progress-store';
import {reconcileStagedLeadSelectors} from '../packages/security-solver/src/deterministic/analysis-candidate-queue';
import {resolveSourceFixtureDependencies,resolveAcquiredConcreteImplementations,resolveAcquiredInterfaceCallers,verifyAcquiredReceiverMethods,enumerateAcquiredInheritedAbi} from '../packages/security-solver/src/deterministic/fixture-dependency-planner';
import type {AnalysisCandidate} from '../packages/security-solver/src/deterministic/analysis-candidate-queue';
import {constructSolidityExperiments,sourcePreparationGraph} from '../packages/security-solver/src/controller-solidity-experiment-planner';
import {buildProgramFactsGraph} from '../packages/security-solver/src/deterministic/program-facts';
import {generateRelationalHypotheses} from '../packages/security-solver/src/deterministic/hypothesis-engine';

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

async function stage(inventory:readonly AnalysisCandidate[]=candidates):Promise<ControllerStageLock>{
  const lock=new ControllerStageLock();
  lock.completeIndex([{path,characters:content.length,sha256:sourceSha}]);
  lock.recordRead({path,start:0,end:content.length,totalCharacters:content.length,text:content});
  await lock.completeReading(async()=>content);
  lock.noteSourcePreclassified(path,'indexed-options-built');
  lock.registerAnalysisInventory(inventory.map(c=>c.id));
  return lock;
}
async function run(){
  const dir=await mkdtemp(join(tmpdir(),'lotus-round3-'));
  const file=join(dir,'analysis.json');
  try{
    // A property blocker must have an invariant source-bound identity even
    // when a fresh analysis enumerates the same independent failures in the
    // opposite order. Otherwise later repairs can supplant the wrong property.
    const firstLead=[candidates[0]];
    const blockers=['UNKNOWN_ASSERTION(no_supported_property):unobserved delta',
      'UNKNOWN_ASSERTION(missing_fixture):unbound external token'];
    const obligationsFrom=(values:string[],fileName:string)=>AnalysisProgressStore
      .open(join(dir,fileName),firstLead).then(store=>{
        assert.equal(store.nextBatch(1,1).length,1);
        store.recordAssessment(firstLead[0].id,[],values,[]);
        return store.records.get(firstLead[0].id)!.properties.map(p=>p.id).sort();
      });
    assert.deepEqual(await obligationsFrom(blockers,'stable-blockers-a.json'),
      await obligationsFrom([...blockers].reverse(),'stable-blockers-b.json'),
      'Property identity must follow source revision and blocker, not insertion order');
    // Regression from the first PR-branch 88mph cloud trial. An ordinary
    // staged source experiment must NEVER remove the originally queued
    // BenqiERC20Market.claimRewards lead from the frozen source inventory.
    const benqiPath='source-1/contracts/moneymarkets/benqi/BenqiERC20Market.sol';
    const originalManifest=new Map<string,ReadonlySet<string>>([
      [benqiPath,new Set(['BenqiERC20Market.deposit',
        'BenqiERC20Market.claimRewards'])]]);
    const scheduled=[{plan:{path:benqiPath,
      query:'BenqiERC20Market.claimRewards',answer:'solidity_sequence'}}];
    const menu=new Map([[benqiPath,[
      {selector:'BenqiERC20Market.deposit',operation:'send'},
      {selector:'BenqiERC20Market.claimRewards',operation:'send'}]]]);
    const reconciled=reconcileStagedLeadSelectors(originalManifest,scheduled,menu);
    assert.deepEqual([...reconciled.get(benqiPath)!].sort(),
      ['BenqiERC20Market.claimRewards','BenqiERC20Market.deposit'].sort());
    assert.equal(originalManifest.get(benqiPath)!.size,2,
      'The original lead identity must never be mutated by experiment selection');
    assert.deepEqual([...reconcileStagedLeadSelectors(new Map([[benqiPath,
      new Set(['BenqiERC20Market.deposit'])]]),scheduled,menu).get(benqiPath)!].sort(),
      ['BenqiERC20Market.deposit','BenqiERC20Market.claimRewards'].sort(),
      'A staged selector must be ADDED when previously absent from analyzed inventory');
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
    const repairedId=hash('source-repair-experiment');
    assert.throws(()=>lock.registerRepairedExperiment(repairedId,candidates[0].id,
      sourceSha,[]),/EXPERIMENT_REPAIR_SOURCE_WITNESS_REQUIRED/,
      'An unwitnessed runtime repair may not enter the experiment queue');
    assert.throws(()=>lock.registerRepairedExperiment(repairedId,hash('unknown-lead'),
      sourceSha,[candidates[0].sourceEvidence+':'+sourceSha]),
      /EXPERIMENT_REPAIR_SOURCE_WITNESS_REQUIRED/,
      'Repairs may not introduce a lead outside the immutable inventory');
    lock.registerRepairedExperiment(repairedId,candidates[0].id,sourceSha,
      [candidates[0].sourceEvidence+':'+sourceSha]);
    assert.throws(()=>lock.registerRepairedExperiment(repairedId,candidates[0].id,
      sourceSha,[candidates[0].sourceEvidence+':'+sourceSha]),
      /EXPERIMENT_REPAIR_SOURCE_WITNESS_REQUIRED/,
      'Identical repair experiments cannot be scheduled twice');
    assert.equal(lock.candidateCount,65,'A valid repair is appended, not substituted');
    lock.requireCandidate(repairedId);
    lock.finishExperiment(repairedId,'incomplete');
    for(const id of experiments){
      lock.requireCandidate(id);
      lock.finishExperiment(id,'not_observed');
      store.markExperimentCompleted(id);
    }
    await store.save();
    assert.equal(store.completedExperimentIds.size,64);
    assert.equal(store.counts.experimentsCompleted,64);
    assert.equal(store.counts.unresolvedIds.length,244,
      'The other 180 never-experimented leads and 64 unproven results remain unresolved');
    assert.equal(lock.completedCount,65);
    assert.throws(()=>lock.completeExperiments(store.experimentCertificate),
      /EXPERIMENT_LEAD_COVERAGE_INCOMPLETE/);
    assert.equal(lock.currentStage,'EXPERIMENT');
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
    pending.recordAssessment(one[3].id,['money-market'],['unresolved_money_market'],[hash('completed-other')]);
    pending.recordAssessment(one[4].id,['withdraw'],[],[hash('unexecuted')]);
    pending.markExperimentCompleted(hash('done-negative'));
    pending.markExperimentCompleted(hash('done-positive'));
    pending.markExperimentCompleted(hash('completed-other'));
    assert.equal(pending.records.get(one[3].id)?.lifecycle,'dependencies_pending',
      'A completed role test must not resolve an unrelated missing financial prerequisite');
    await pending.save();
    assert.equal(pending.counts.queued,1);
    assert.equal(pending.counts.dependenciesPending,2, 'Unexecutable properties are pending, not terminally exhausted');
    assert.equal(pending.counts.experimentsPending,1);
    assert.equal(pending.terminallyComplete,false);
    pending=await AnalysisProgressStore.open(pendingFile,pendingCandidates);
    assert.equal(pending.terminallyComplete,false,'checkpoint must preserve all three pending states');
    assert.equal(pending.counts.unresolvedIds.length,6,
      'No unsupported, selected-only, or evidence-free completed candidate counts as proof');
    assert.throws(()=>pending.markExperimentCompleted(hash('unmatched')),
      /ANALYSIS_EXPERIMENT_ID_UNMATCHED/);
    // A replacement must have different source-backed experiment identity;
    // neither retry scheduling nor an unverified outcome can erase a failure.
    const replacementLead={...candidates[0],id:hash('inconclusive-repair-lead')};
    const replacementStore=await AnalysisProgressStore.open(
      join(dir,'inconclusive-repair.json'),[replacementLead]);
    replacementStore.nextBatch(1,1);
    const failedId=hash('attempt-failed'),repairedId2=hash('attempt-repaired');
    const propertyId=hash('replacement-property');
    const proofWitness=replacementLead.path+':'+replacementLead.sourceSha256+':0:10';
    replacementStore.recordAssessment(replacementLead.id,[propertyId],[],[failedId],[],
      [{id:propertyId,experimentIds:[failedId],sourceWitnesses:[proofWitness]}]);
    replacementStore.recordInconclusive(failedId,'incomplete',hash('failed-run'),'setup failed');
    assert.equal(replacementStore.retirableInconclusiveExperiments(repairedId2).length,0);
    replacementStore.addRepairExperiment(replacementLead.id,propertyId,repairedId2,
      [proofWitness]);
    const history=replacementStore.records.get(replacementLead.id)!;
    assert.deepEqual(history.properties[0].experimentIds,[repairedId2]);
    assert.equal(history.inconclusiveAttempts?.[0].replacedBy,repairedId2);
    assert.equal(replacementStore.terminallyComplete,false);
    assert.deepEqual(replacementStore.retirableInconclusiveExperiments(repairedId2),[],
      'Replacement admission alone is never sufficient to retire failure');
    replacementStore.markExperimentCompleted(repairedId2,{
      result:'not_observed',evidenceId:hash('verified-evidence'),
      verifierDigest:hash('verified-receipt')});
    assert.deepEqual(replacementStore.retirableInconclusiveExperiments(repairedId2),[failedId]);
    assert.equal(replacementStore.terminallyComplete,true);
    assert.equal(history.inconclusiveAttempts?.length,1,'Failed receipt must persist');

    const replacementLock=await stage([replacementLead]);
    replacementLock.registerAnalysisLead({id:replacementLead.id,
      path:replacementLead.path,selector:replacementLead.selector,
      sourceCommit:replacementLead.sourceCommit,sourceSha256:replacementLead.sourceSha256});
    replacementLock.recordLeadAssessment(replacementLead.id,{kind:'assessed',
      sourceEvidence:[proofWitness],hypothesis:'source-backed retry',
      disposition:'test',reason:'same property with a different executable falsifier'},'controller');
    replacementLock.completeAnalysisBatch();
    replacementLock.discover(failedId);
    replacementLock.completeAnalysis();
    replacementLock.finishExperiment(failedId,'incomplete');
    replacementLock.registerRepairedExperiment(repairedId2,replacementLead.id,
      replacementLead.sourceSha256,[proofWitness]);
    assert.throws(()=>replacementLock.retireVerifiedInconclusive(failedId,repairedId2),
      /INCONCLUSIVE_RETIREMENT_REQUIRES_VERIFIED_REPLACEMENT/);
    replacementLock.finishExperiment(repairedId2,'not_observed');
    replacementLock.retireVerifiedInconclusive(failedId,repairedId2);
    assert.equal(replacementLock.candidateCount,1);
    assert.equal(replacementLock.outcomeCounts.incomplete,0);
    replacementLock.completeExperiments(replacementStore.experimentCertificate);
    // Source-typed, recursive fixture chain: Vault -> Adapter -> Token.
    const vaultSource='pragma solidity ^0.8.0; contract Vault { IAdapter public adapter; function initialize(address _adapter) external { adapter = IAdapter(_adapter); } }';
    const adapterSource='pragma solidity ^0.8.0; contract Adapter is IAdapter { constructor(Token token) {} }';
    const tokenSource='pragma solidity ^0.8.0; contract Token { }';
    const fixtureSources=[
      {path:'source-1/contracts/Vault.sol',sha256:hash(vaultSource),content:vaultSource},
      {path:'source-1/contracts/Adapter.sol',sha256:hash(adapterSource),content:adapterSource},
      {path:'source-1/contracts/Token.sol',sha256:hash(tokenSource),content:tokenSource},
    ];
    const fixture=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',fixtureSources);
    assert.equal(fixture.status,'resolved',JSON.stringify(fixture));
    if(fixture.status==='resolved'){
      assert.equal(fixture.deployments.length,2);
      assert.deepEqual(fixture.deployments.map(x=>x.contract),['Token','Adapter']);
      assert.equal(fixture.substitutions._adapter,'$deployment:dependency2');
      assert.equal(fixture.bindings[0].receiver,'adapter');
      assert.ok(fixture.witnesses.some(x=>x.sourceSha256===fixtureSources[0].sha256));
    }
    // The planner's prerequisite graph cannot be empty when an acquired
    // Solidity sequence actually deploys dependencies and initializes them.
    // Constructor dependencies MUST already exist at deployment time.
    const prepSequence={constructorArgs:[],steps:[{operation:'call',function:'owner()',
      args:[],expect:'0x0000000000000000000000000000000000000000'}],
      preparation:{deployments:[
        {id:'token',file:fixtureSources[2].path,contract:'Token',constructorArgs:[]},
        {id:'adapter',file:fixtureSources[1].path,contract:'Adapter',
          constructorArgs:['$deployment:token']}],
        operations:[{id:'configure',deploymentId:'adapter',function:'ping()',
          args:[],sender:0}],checks:[{id:'readback',deploymentId:'adapter',
          function:'ping()',args:[],sender:0,expect:'0'}]}} as any;
    const prepSources=new Map(fixtureSources.map(x=>[x.path,x]));
    const prepGraph=sourcePreparationGraph(prepSequence,prepSources);
    assert.equal(prepGraph.ok,true,'A real preparation DAG needs acquired source witnesses');
    if(prepGraph.ok){
      assert.deepEqual(prepGraph.nodes.map(x=>x.id),[
        'deploy:token','deploy:adapter','operation:configure','check:readback']);
      assert.ok(prepGraph.nodes.every(x=>x.sourceEvidence.length>0&&
        x.sourceEvidence.every(w=>w.sourceSha256.length===64)));
      assert.ok(prepGraph.nodes.find(x=>x.id==='deploy:adapter')!
        .dependsOn.includes('deploy:token'));
    }
    const badPrep=JSON.parse(JSON.stringify(prepSequence));
    badPrep.preparation.deployments.reverse();
    const rejected=sourcePreparationGraph(badPrep,prepSources);
    assert.equal(rejected.ok,false,
      'A constructor cannot reference a deployment scheduled later');
    // Initializer-only dependencies can be discovered after the consumer was
    // registered. Execution must deploy the producer before the consumer.
    const initializedAdapter='pragma solidity ^0.8.0; contract Adapter is IAdapter { Token public token; function initialize(address _token) external { token = Token(_token); } }';
    const initialized=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      fixtureSources[0],{...fixtureSources[1],content:initializedAdapter,
        sha256:hash(initializedAdapter)},fixtureSources[2]]);
    assert.equal(initialized.status,'resolved',
      'A source-bound initializer dependency must produce a complete fixture');
    if(initialized.status==='resolved'){
      assert.deepEqual(initialized.deployments.map(x=>x.contract).sort(),['Adapter','Token'],
        'Both source-proven contracts must deploy before initializer operations');
      assert.equal(new Set(initialized.deployments.map(x=>x.id)).size,
        initialized.deployments.length,
        'Initializer-recursive deployments must retain unique stable IDs');
      assert.notEqual(initialized.deployments[0].id,initialized.deployments[1].id,
        'Consumer and initializer-discovered producer cannot share a deployment ID');
      assert.equal(initialized.initializerOperations.length,1);
      assert.equal(initialized.initializerOperations[0].args[0],
        '$deployment:'+initialized.deployments.find(x=>x.contract==='Token')!.id);
    }
    // Acquired initializer operation must invoke the actual declared ABI selector.
    // Solidity contracts may expose init(...) rather than initialize(...).
    const shortInitAdapter='pragma solidity ^0.8.0; contract Adapter is IAdapter { Token public token; function init(address _token) external { token = Token(_token); } }';
    const shortInit=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      fixtureSources[0],{...fixtureSources[1],content:shortInitAdapter,sha256:hash(shortInitAdapter)},fixtureSources[2]]);
    assert.equal(shortInit.status,'resolved',
      'A source-declared init entrypoint with a fully bound dependency must be executable');
    if(shortInit.status==='resolved'){
      assert.equal(shortInit.initializerOperations.length,1);
      assert.equal(shortInit.initializerOperations[0].function,'init(address)',
        'Never fabricate initialize(address) when the acquired source declares init(address)');
      assert.equal(shortInit.initializerOperations[0].args[0],
        '$deployment:'+shortInit.deployments.find(d=>d.contract==='Token')!.id);
    }
    // An acquired dependency whose initializer cannot be completely bound
    // must not be reported as an executable fixture.
    const unboundAdapter='pragma solidity ^0.8.0; contract Adapter is IAdapter { constructor(Token token) {} function initialize(uint256[33] memory configuration) external {} }';
    const unbound=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      fixtureSources[0],{...fixtureSources[1],content:unboundAdapter,sha256:hash(unboundAdapter)},fixtureSources[2]]);
    assert.equal(unbound.status,'unresolved',
      'An oversized initializer array must invalidate the bounded fixture graph');
    if(unbound.status==='unresolved')
      assert.ok(unbound.missingDependencies.some(x=>x.includes('unsupported_initializer_parameter')||
        x.includes('incomplete_initializer_arguments')));
    // Struct fields are compiler ABI tuples. A successful typed fixture still
    // requires a real local EVM deployment and successful initializer receipt.
    const tupleContract=`pragma solidity ^0.8.0;
contract TupleDependency {
  struct Options { uint256 threshold; bool enabled; }
  Options public options;
  constructor(Options memory first) { options=first; }
}`;
    const tupleConsumer=`pragma solidity ^0.8.0;
contract TupleConsumer {
  TupleDependency public dependency;
  function initialize(address chosen) external {
    dependency=TupleDependency(chosen);
  }
}`;
    const tupleSources=[
      {path:'source-1/contracts/TupleDependency.sol',content:tupleContract,sha256:hash(tupleContract)},
      {path:'source-1/contracts/TupleConsumer.sol',content:tupleConsumer,sha256:hash(tupleConsumer)}
    ];
    const tupleResolved=resolveSourceFixtureDependencies(tupleSources[1],'TupleConsumer',tupleSources);
    assert.equal(tupleResolved.status,'resolved','Acquired struct constructor ABI must be constructible');
    if(tupleResolved.status==='resolved')
      assert.deepEqual(tupleResolved.deployments[0].constructorArgs,[['0',false]],
        'Struct ABI must encode bool as false, not as truthy string');
    // Primitive casts are initializer values, never deployable contract edges.
    // Regression: the controller previously requested a uint256 implementation.
    const primitiveInitSource=`pragma solidity ^0.8.0;
contract PrimitiveInit {
  uint256 public accrued;
  function initialize(uint256 amount) external {
    accrued = uint256(amount);
  }
}`;
    const primitiveInitSnapshot={path:'source-1/contracts/PrimitiveInit.sol',
      content:primitiveInitSource,sha256:hash(primitiveInitSource)};
    const primitiveInitResolved=resolveSourceFixtureDependencies(
      primitiveInitSnapshot,'PrimitiveInit',[primitiveInitSnapshot]);
    assert.equal(primitiveInitResolved.status,'resolved',
      'A uint256 initializer cast must be treated as a value, not a contract dependency');
    if(primitiveInitResolved.status==='resolved'){
      assert.deepEqual(primitiveInitResolved.deployments,[],
        'Primitive state bindings must never create deployment nodes');
      assert.deepEqual(primitiveInitResolved.bindings,[],
        'Primitive state bindings must never create contract bindings');
    }
    // Use explicit source-grounded require() constraints rather than a generic
    // zero constructor value for acquired transitive dependencies.
    const boundedInterface='pragma solidity ^0.8.0; interface IBounded { function ping() external; }';
    const boundedSource=`pragma solidity ^0.8.0; import "./IBounded.sol";
contract Bounded is IBounded {
  constructor(uint256 minimum) { require(minimum > 100); }
  function ping() external override {}
}`;
    const boundedConsumer=`pragma solidity ^0.8.0; import "./IBounded.sol";
contract BoundedConsumer {
  IBounded public dependency;
  function initialize(address chosen) external { dependency=IBounded(chosen); }
  function callDependency() external { dependency.ping(); }
}`;
    const boundedSources=[
      {path:'source-1/contracts/IBounded.sol',content:boundedInterface,sha256:hash(boundedInterface)},
      {path:'source-1/contracts/Bounded.sol',content:boundedSource,sha256:hash(boundedSource)},
      {path:'source-1/contracts/BoundedConsumer.sol',content:boundedConsumer,sha256:hash(boundedConsumer)}
    ];
    const boundedFixture=resolveSourceFixtureDependencies(boundedSources[2],
      'BoundedConsumer',boundedSources);
    assert.equal(boundedFixture.status,'resolved',
      'A supported source literal bound must not prevent fixture construction');
    if(boundedFixture.status==='resolved'){
      assert.deepEqual(boundedFixture.deployments.find(d=>d.contract==='Bounded')?.constructorArgs,
        ['101'],'Derive a satisfying value from require(minimum > 100)');
    }
    // A user-defined AST type is not automatically a deployable contract.
    // Local struct/enum constructors are typed values, never contract fixtures.
    const localValues=`pragma solidity ^0.8.0;
contract ValueBindings {
  struct Choice { uint256 amount; }
  enum Mode { Idle, Active }
  Choice public choice;
  Mode public mode;
  function initialize(uint256 amount, uint256 selected) external {
    choice = Choice(amount);
    mode = Mode(selected);
  }
}`;
    const valueSnapshot={path:'source-1/contracts/ValueBindings.sol',
      content:localValues,sha256:hash(localValues)};
    const valueFixture=resolveSourceFixtureDependencies(valueSnapshot,'ValueBindings',
      [valueSnapshot]);
    assert.equal(valueFixture.status,'resolved',
      'Struct/enum initializer casts must not be treated as deployable contracts');
    if(valueFixture.status==='resolved'){
      assert.deepEqual(valueFixture.deployments,[]);
      assert.deepEqual(valueFixture.bindings,[]);
      assert.deepEqual(valueFixture.substitutions,{});
    }
    // Solidity literal bounds can refer to source-declared immutable compile
    // constants, including exponentiation and time units.
    const constantBoundedIface='pragma solidity ^0.8.0; interface IConstrained { function ready() external; }';
    const constantBoundedImpl=`pragma solidity ^0.8.0;
import "./IConstrained.sol";
contract ConstantBounded is IConstrained {
  uint256 internal constant MINIMUM = 10 ** 9;
  constructor(uint256 amount) { require(amount > MINIMUM); }
  function ready() external override {}
}`;
    const constantBoundedCaller=`pragma solidity ^0.8.0;
import "./IConstrained.sol";
contract ConstantBoundedCaller {
  IConstrained public implementation;
  function initialize(address chosen) external { implementation = IConstrained(chosen); }
  function callReady() external { implementation.ready(); }
}`;
    const constSources=[
      {path:'source-1/contracts/IConstrained.sol',content:constantBoundedIface,sha256:hash(constantBoundedIface)},
      {path:'source-1/contracts/ConstantBounded.sol',content:constantBoundedImpl,sha256:hash(constantBoundedImpl)},
      {path:'source-1/contracts/ConstantBoundedCaller.sol',content:constantBoundedCaller,sha256:hash(constantBoundedCaller)}
    ];
    const sourceConstrained=resolveSourceFixtureDependencies(constSources[2],
      'ConstantBoundedCaller',constSources);
    assert.equal(sourceConstrained.status,'resolved',
      'Source-defined MINIMUM must produce a bounded constructor fixture');
    if(sourceConstrained.status==='resolved'){
      assert.deepEqual(sourceConstrained.deployments.find(x=>x.contract==='ConstantBounded')?.constructorArgs,
        ['1000000001'],'10**9 constant precondition must be evaluated precisely');
    }
    // Imported namespaced structs and enums have UDT AST nodes but are
    // compiler ABI VALUES, never concrete receiver deployments.
    const importedTypesSource=`pragma solidity ^0.8.0;
library SharedTypes {
  struct Choice { uint256 value; bool active; }
  enum Status { Pending, Active }
}`;
    const importedValueConsumer=`pragma solidity ^0.8.0;
import "./SharedTypes.sol";
contract ImportedValues {
  SharedTypes.Choice public choice;
  SharedTypes.Status public status;
  function initialize(SharedTypes.Choice memory selected,SharedTypes.Status mode) external {
    choice = selected;
    status = mode;
  }
}`;
    const importedValueSources=[
      {path:'source-1/contracts/SharedTypes.sol',
        content:importedTypesSource,sha256:hash(importedTypesSource)},
      {path:'source-1/contracts/ImportedValues.sol',
        content:importedValueConsumer,sha256:hash(importedValueConsumer)}
    ];
    const importedValues=resolveSourceFixtureDependencies(importedValueSources[1],
      'ImportedValues',importedValueSources);
    assert.equal(importedValues.status,'resolved',
      'Acquired imported struct/enum variables must not generate contract fixture requirements');
    if(importedValues.status==='resolved'){
      assert.deepEqual(importedValues.deployments,[]);
      assert.deepEqual(importedValues.bindings,[]);
    }
    // Solidity's public mapping-of-struct getter returns elementary ABI
    // fields separately; source-verified interface compatibility must not
    // confuse (bool,uint256) tuple input with two getter outputs.
    const structGetterInterface=`pragma solidity ^0.8.0;
interface IStructGetter {
 function read(address account) external view returns(bool,uint256);
}`;
    const structGetterImpl=`pragma solidity ^0.8.0;
contract SourceStructGetter {
 struct Data {bool ready;uint256 amount;}
 mapping(address=>Data) public read;
}`;
    const structGetterSources=[
      {path:'source-1/contracts/IStructGetter.sol',content:structGetterInterface,
        sha256:hash(structGetterInterface)},
      {path:'source-1/contracts/SourceStructGetter.sol',content:structGetterImpl,
        sha256:hash(structGetterImpl)}
    ];
    assert.deepEqual(verifyAcquiredReceiverMethods('IStructGetter',['read'],
      structGetterSources[1].path,'SourceStructGetter',structGetterSources),
      {ok:true,missing:[]},
      'Compiler-generated public struct mapping getter must expose two typed ABI returns');
    const wrongOrder=structGetterInterface.replace('returns(bool,uint256)','returns(uint256,bool)');
    const wrongOrderSources=[{...structGetterSources[0],content:wrongOrder,
      sha256:hash(wrongOrder)},structGetterSources[1]];
    assert.equal(verifyAcquiredReceiverMethods('IStructGetter',['read'],
      wrongOrderSources[1].path,'SourceStructGetter',wrongOrderSources).ok,false,
      'Field order and ABI return types must be authenticated, not name-matched');
    // A transitive constructor imports an enum from an acquired library.
    // Its ABI value must be uint8 zero, never a synthetic contract reference.
    const importedEnumTypes='pragma solidity ^0.8.0; library ChoiceTypes { enum Tier { Basic, Premium } }';
    const importedEnumImpl=`pragma solidity ^0.8.0;
import "./ChoiceTypes.sol";
import "./IEnumService.sol";
contract ImportedEnumService is IEnumService {
  ChoiceTypes.Tier public tier;
  constructor(ChoiceTypes.Tier selected) { tier = selected; }
  function ping() external override {}
}`;
    const importedEnumIface='pragma solidity ^0.8.0; interface IEnumService { function ping() external; }';
    const importedEnumCaller=`pragma solidity ^0.8.0;
import "./IEnumService.sol";
contract ImportedEnumConsumer {
  IEnumService public service;
  function initialize(address chosen) external { service = IEnumService(chosen); }
  function run() external { service.ping(); }
}`;
    const enumImportSources=[
      {path:'source-1/contracts/ChoiceTypes.sol',content:importedEnumTypes,sha256:hash(importedEnumTypes)},
      {path:'source-1/contracts/IEnumService.sol',content:importedEnumIface,sha256:hash(importedEnumIface)},
      {path:'source-1/contracts/ImportedEnumService.sol',content:importedEnumImpl,sha256:hash(importedEnumImpl)},
      {path:'source-1/contracts/ImportedEnumConsumer.sol',content:importedEnumCaller,sha256:hash(importedEnumCaller)}
    ];
    const importedEnumFixture=resolveSourceFixtureDependencies(enumImportSources[3],
      'ImportedEnumConsumer',enumImportSources);
    assert.equal(importedEnumFixture.status,'resolved',JSON.stringify(importedEnumFixture));
    if(importedEnumFixture.status==='resolved'){
      assert.deepEqual(importedEnumFixture.deployments.map(x=>x.contract),['ImportedEnumService']);
      assert.deepEqual(importedEnumFixture.deployments[0].constructorArgs,['0']);
    }
    // An imported enum initializer must use the compiler ABI uint8 and a
    // typed zero value, not a fictitious initialize(address) call.
    const enumInitContract=`pragma solidity ^0.8.0;
import "./ChoiceTypes.sol";
import "./IEnumService.sol";
contract ImportedEnumInitializable is IEnumService {
 ChoiceTypes.Tier public tier;
 function initialize(ChoiceTypes.Tier selected) external {tier=selected;}
 function ping() external override {}
}`;
    const importedEnumInitSources=[
      enumImportSources[0],enumImportSources[1],
      {path:'source-1/contracts/ImportedEnumInitializable.sol',
       content:enumInitContract,sha256:hash(enumInitContract)},
      enumImportSources[3]];
    const enumInitializerPlan=resolveSourceFixtureDependencies(
      importedEnumInitSources[3],'ImportedEnumConsumer',importedEnumInitSources);
    assert.equal(enumInitializerPlan.status,'resolved',JSON.stringify(enumInitializerPlan));
    if(enumInitializerPlan.status==='resolved'){
      assert.deepEqual(enumInitializerPlan.deployments.map(x=>x.contract),['ImportedEnumInitializable']);
      assert.equal(enumInitializerPlan.initializerOperations.length,1);
      assert.equal(enumInitializerPlan.initializerOperations[0].function,
        'initialize(uint8)');
      assert.deepEqual(enumInitializerPlan.initializerOperations[0].args,['0']);
    }
    // A Solidity user-defined type may be a struct or enum, not an address.
    // Exact imported ABI identities are required for concrete receivers.
    const shapeTypes=`pragma solidity ^0.8.0;
library Shapes { struct Config { uint256 amount; bool enabled; } enum Mode { Off, On } }`;
    const shapeIface=`pragma solidity ^0.8.0;
import "./Shapes.sol";
interface IShape { function quote(Shapes.Config calldata cfg) external returns(uint256); }`;
    const shapeGood=`pragma solidity ^0.8.0;
import "./IShape.sol";
contract ShapeGood is IShape {
  function quote(Shapes.Config calldata cfg) external override returns(uint256) {
    return cfg.amount;
  }
}`;
    const shapeBad=`pragma solidity ^0.8.0;
import "./IShape.sol";
contract ShapeBad {
  function quote(address cfg) external returns(uint256) { return 1; }
}`;
    const shapeSnapshots=[
      {path:'source-1/contracts/Shapes.sol',content:shapeTypes,sha256:hash(shapeTypes)},
      {path:'source-1/contracts/IShape.sol',content:shapeIface,sha256:hash(shapeIface)},
      {path:'source-1/contracts/ShapeGood.sol',content:shapeGood,sha256:hash(shapeGood)},
      {path:'source-1/contracts/ShapeBad.sol',content:shapeBad,sha256:hash(shapeBad)}
    ];
    assert.deepEqual(verifyAcquiredReceiverMethods('IShape',['quote'],
      shapeSnapshots[2].path,'ShapeGood',shapeSnapshots),{ok:true,missing:[]},
      'Imported source struct must encode the correct ABI tuple');
    assert.equal(verifyAcquiredReceiverMethods('IShape',['quote'],
      shapeSnapshots[3].path,'ShapeBad',shapeSnapshots).ok,false,
      'Address arguments must not impersonate ABI structs');
    // Solidity enum is a value with a numeric ABI, not a contract reference.
    // Transitive dependency constructors must receive the source enum zero.
    const enumInterface='pragma solidity ^0.8.0; interface IEnumService { function ping() external; }';
    const enumService=`pragma solidity ^0.8.0;
import "./IEnumService.sol";
contract EnumService is IEnumService {
 enum Tier { Basic, Premium }
 Tier public tier;
 constructor(Tier initialTier) { tier = initialTier; }
 function ping() external override {}
}`;
    const enumConsumer=`pragma solidity ^0.8.0;
import "./IEnumService.sol";
contract EnumConsumer {
 IEnumService public service;
 function initialize(address chosen) external { service = IEnumService(chosen); }
 function callService() external { service.ping(); }
}`;
    const enumSources=[
      {path:'source-1/contracts/IEnumService.sol',content:enumInterface,sha256:hash(enumInterface)},
      {path:'source-1/contracts/EnumService.sol',content:enumService,sha256:hash(enumService)},
      {path:'source-1/contracts/EnumConsumer.sol',content:enumConsumer,sha256:hash(enumConsumer)}
    ];
    const enumFixture=resolveSourceFixtureDependencies(enumSources[2],'EnumConsumer',enumSources);
    assert.equal(enumFixture.status,'resolved',
      'Enum constructor state is a source value, not a dependency deployment');
    if(enumFixture.status==='resolved'){
      assert.deepEqual(enumFixture.deployments.map(d=>d.contract),['EnumService']);
      assert.deepEqual(enumFixture.deployments[0].constructorArgs,['0']);
    }
    const ambiguousSource='pragma solidity ^0.8.0; contract AdapterTwo is IAdapter {}';
    const ambiguous=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      ...fixtureSources,{path:'source-1/contracts/AdapterTwo.sol',content:ambiguousSource,sha256:hash(ambiguousSource)}]);
    assert.equal(ambiguous.status,'unresolved');
    if(ambiguous.status==='unresolved')
      assert.ok(ambiguous.missingDependencies.some(x=>x.includes('ambiguous_implementation')));
    // A source-declared interface method and an acquired concrete method ABI
    // can disambiguate competing implementations without guessing by name.
    const ifaceText='pragma solidity ^0.8.0; interface IAdapter { function quote(uint256 amount) external returns (uint256); }';
    const consumerText='pragma solidity ^0.8.0; import "./IAdapter.sol"; contract Consumer { IAdapter public adapter; function initialize(address chosen) external { adapter = IAdapter(chosen); } function read(uint256 amount) external { adapter.quote(amount); } }';
    const correctText='pragma solidity ^0.8.0; import "./IAdapter.sol"; contract CorrectAdapter is IAdapter { function quote(uint256 amount) external override returns (uint256) { return amount; } }';
    const incompatibleText='pragma solidity ^0.8.0; import "./IAdapter.sol"; contract WrongAdapter is IAdapter { function quote(uint256 amount) external override returns (bool) { return true; } }';
    const typedSources=[
      {path:'source-1/contracts/IAdapter.sol',content:ifaceText,sha256:hash(ifaceText)},
      {path:'source-1/contracts/Consumer.sol',content:consumerText,sha256:hash(consumerText)},
      {path:'source-1/contracts/CorrectAdapter.sol',content:correctText,sha256:hash(correctText)},
      {path:'source-1/contracts/WrongAdapter.sol',content:incompatibleText,sha256:hash(incompatibleText)}];
    assert.deepEqual(verifyAcquiredReceiverMethods('IAdapter',['quote'],
      typedSources[2].path,'CorrectAdapter',typedSources),{ok:true,missing:[]});
    assert.equal(verifyAcquiredReceiverMethods('IAdapter',['quote'],
      typedSources[3].path,'WrongAdapter',typedSources).ok,false,
      'Matching method names cannot substitute for a matching return ABI');
    const soleIncompatible=resolveSourceFixtureDependencies(
      typedSources[1],'Consumer',[typedSources[0],typedSources[1],typedSources[3]]);
    assert.equal(soleIncompatible.status,'unresolved',
      'A single ABI-incompatible implementation must not be accepted by default');
    if(soleIncompatible.status==='unresolved')
      assert.ok(soleIncompatible.missingDependencies.some(x=>
        x.includes('no_acquired_abi_compatible_implementation')),
        'Reject the incompatible receiver by ABI rather than declaring fixture success');
    const selectedFixture=resolveSourceFixtureDependencies(typedSources[1],'Consumer',typedSources);
    assert.equal(selectedFixture.status,'resolved',
      'An acquired caller ABI must uniquely select the compatible concrete implementation');
    if(selectedFixture.status==='resolved'){
      assert.deepEqual(selectedFixture.deployments.map(x=>x.contract),['CorrectAdapter']);
      assert.equal(selectedFixture.bindings[0].receiver,'adapter');
    }
    // A source-linked standard dependency is not an absent implementation;
    // compiler-backed OpenZeppelin and compiler-generated getters are valid.
    const abiInterface=`pragma solidity ^0.8.0;
interface ISourceReceiver {
  function balances(address account) external view returns(uint256);
  function coin() external view returns(address);
  function batch(uint256[] calldata values) external returns(uint256[] memory);
  function owner() external view returns(address);
}`;
    const abiReceiver=`pragma solidity ^0.8.0;
import {ISourceReceiver} from "./ISourceReceiver.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
contract ReceiverWithAbi is OwnableUpgradeable {
  mapping(address=>uint256) public balances;
  ISourceReceiver public coin;
  function batch(uint256[] calldata values) external returns(uint256[] memory) {
    return values;
  }
}`;
    const abiSrc=[
      {path:'source-1/contracts/ISourceReceiver.sol',content:abiInterface,sha256:hash(abiInterface)},
      {path:'source-1/contracts/ReceiverWithAbi.sol',content:abiReceiver,sha256:hash(abiReceiver)}
    ];
    assert.deepEqual(verifyAcquiredReceiverMethods('ISourceReceiver',
      ['balances','coin','batch','owner'],abiSrc[1].path,'ReceiverWithAbi',abiSrc),
      {ok:true,missing:[]},
      'Canonical OZ inheritance, mapping getter, address-valued UDT getter and array ABI are executable candidates');
    const noOZ=abiReceiver.replace('@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol',
      './UnknownOwner.sol');
    assert.equal(verifyAcquiredReceiverMethods('ISourceReceiver',['owner'],
      abiSrc[1].path,'ReceiverWithAbi',
      [abiSrc[0],{...abiSrc[1],content:noOZ,sha256:hash(noOZ)}]).ok,false,
      'An unacquired, noncanonical owner class cannot be credited with inherited methods');
    const bothCompatible='pragma solidity ^0.8.0; import "./IAdapter.sol"; contract AlsoCorrect is IAdapter { function quote(uint256 amount) external override returns (uint256) { return amount; } }';
    const unresolvedChoice=resolveSourceFixtureDependencies(typedSources[1],'Consumer',[
      ...typedSources,{path:'source-1/contracts/AlsoCorrect.sol',
        content:bothCompatible,sha256:hash(bothCompatible)}]);
    assert.equal(unresolvedChoice.status,'unresolved',
      'Two ABI-compatible implementations remain ambiguous without stronger binding evidence');
    if(unresolvedChoice.status==='unresolved')
      assert.ok(unresolvedChoice.missingDependencies.some(x=>x.includes('ambiguous_implementation')));
    // Cyclic initializer references are not cyclic constructors. Deploy both
    // bytecodes first, then send the two source-backed initializer calls.
    const initA='pragma solidity ^0.8.0; contract InitA { InitB public peer; function initialize(address b) external { peer = InitB(b); } }';
    const initB='pragma solidity ^0.8.0; contract InitB { InitA public peer; function initialize(address a) external { peer = InitA(a); } }';
    const initConsumer='pragma solidity ^0.8.0; contract InitConsumer { InitA public a; InitB public b; function initialize(address first,address second) external { a=InitA(first); b=InitB(second); } }';
    const initCycleSources=[
      {path:'source-1/contracts/InitA.sol',content:initA,sha256:hash(initA)},
      {path:'source-1/contracts/InitB.sol',content:initB,sha256:hash(initB)},
      {path:'source-1/contracts/InitConsumer.sol',content:initConsumer,sha256:hash(initConsumer)}
    ];
    const initCycle=resolveSourceFixtureDependencies(initCycleSources[2],
      'InitConsumer',initCycleSources);
    assert.equal(initCycle.status,'resolved',
      'Mutually referencing initializer args cannot create a fake deployment cycle');
    if(initCycle.status==='resolved'){
      assert.deepEqual(initCycle.deployments.map(d=>d.contract).sort(),['InitA','InitB'],
        'Both actual acquired contracts are prepared before initializer calls');
      assert.equal(initCycle.initializerOperations.length,2);
      for(const operation of initCycle.initializerOperations)
        assert.ok(operation.args[0].startsWith('$deployment:'),
          'Initializer references must resolve to real deployed addresses');
    }
    const extendedIface=`pragma solidity ^0.8.0;
interface IPlug { function ping() external returns(uint256); }`;
    const extendedPlug=`pragma solidity ^0.8.0;
import "./IPlug.sol";
contract Plug is IPlug {
  function ping() external override returns(uint256){return 1;}
  function initialize(string memory label,bytes memory data,uint256[] memory entries) external {}
}`;
    const extendedConsumer=`pragma solidity ^0.8.0;
import "./IPlug.sol";
contract PlugConsumer {
  IPlug public plug;
  function initialize(IPlug implementation) external { plug=implementation; }
  function read() external {plug.ping();}
}`;
    const extendedSources=[
      {path:'source-1/contracts/IPlug.sol',content:extendedIface,sha256:hash(extendedIface)},
      {path:'source-1/contracts/Plug.sol',content:extendedPlug,sha256:hash(extendedPlug)},
      {path:'source-1/contracts/PlugConsumer.sol',content:extendedConsumer,sha256:hash(extendedConsumer)},
    ];
    const extended=resolveSourceFixtureDependencies(extendedSources[2],
      'PlugConsumer',extendedSources);
    assert.equal(extended.status,'resolved',
      'Direct interface-typed initializer bindings must resolve to source-proven implementations');
    if(extended.status==='resolved'){
      assert.deepEqual(extended.deployments.map(d=>d.contract),['Plug']);
      assert.equal(extended.initializerOperations[0].function,
        'initialize(string,bytes,uint256[])',
        'String, bytes and array fixture parameters must retain exact ABI');
      assert.deepEqual(extended.initializerOperations[0].args,['','0x',[]]);
      assert.equal(extended.bindings[0].receiver,'plug');
    }
    // Verified deep transitive constructor chains are no longer discarded at
    // the historical eight-contract ceiling; bounds remain configurable and
    // must fail closed before EVM execution when explicitly exceeded.
    const deepChainText='pragma solidity ^0.8.0; contract Leaf {} '+
      Array.from({length:10},(_,i)=>'contract Node'+(i+1)+
        ' { constructor('+(i===0?'Leaf':'Node'+i)+' dependency) {} }').join(' ')+
      ' contract DeepConsumer { Node10 public node; '+
      'function initialize(address chosen) external { node = Node10(chosen); } }';
    const deepChainSource={path:'source-1/contracts/DeepConsumer.sol',
      content:deepChainText,sha256:hash(deepChainText)};
    const deepGraph=resolveSourceFixtureDependencies(deepChainSource,
      'DeepConsumer',[deepChainSource]);
    assert.equal(deepGraph.status,'resolved',
      'Eleven acquired transitive contracts must fit within the bounded graph');
    if(deepGraph.status==='resolved'){
      assert.equal(deepGraph.deployments.length,11);
      assert.deepEqual(deepGraph.deployments.map(x=>x.contract),
        ['Leaf',...Array.from({length:10},(_,i)=>'Node'+(i+1))]);
    }
    const artificiallySmall=resolveSourceFixtureDependencies(deepChainSource,
      'DeepConsumer',[deepChainSource],{maxDepth:10,maxNodes:8});
    assert.equal(artificiallySmall.status,'unresolved');
    if(artificiallySmall.status==='unresolved')assert.ok(
      artificiallySmall.missingDependencies.some(x=>x.includes('max_dependency_nodes')));
    const invalidBudget=resolveSourceFixtureDependencies(deepChainSource,
      'DeepConsumer',[deepChainSource],{maxNodes:100});
    assert.equal(invalidBudget.status,'unresolved');
    if(invalidBudget.status==='unresolved')assert.ok(
      invalidBudget.missingDependencies.includes('invalid_fixture_resource_budget'));
    const cycA='pragma solidity ^0.8.0; contract CycA { constructor(CycB dependency) {} }';
    const cycB='pragma solidity ^0.8.0; contract CycB { constructor(CycA dependency) {} }';
    const cycleSources=[
      {path:'source-1/contracts/CycA.sol',content:cycA,sha256:hash(cycA)},
      {path:'source-1/contracts/CycB.sol',content:cycB,sha256:hash(cycB)}];
    const cycle=resolveSourceFixtureDependencies(cycleSources[0],'CycA',cycleSources);
    assert.equal(cycle.status,'unresolved');
    if(cycle.status==='unresolved')
      assert.ok(cycle.missingDependencies.some(x=>x.includes('dependency_cycle')));
    // All 241 distinct leads must have at least one evidence-backed obligation.
    // 240/241 is forbidden even if every registered experiment has finished.
    const all241=candidates.slice(0,241);
    const proofFile=join(dir,'proof241.json');
    const proofStore=await AnalysisProgressStore.open(proofFile,all241);
    const proofLock=await stage(all241);
    let position=0;
    while(proofStore.remaining){
      const batch=proofStore.nextBatch(18,18);
      for(const lead of batch){
        const exp=hash('real-experiment-for-'+lead.id);
        proofLock.registerAnalysisLead({id:lead.id,path:lead.path,selector:lead.selector,
          sourceCommit:lead.sourceCommit,sourceSha256:lead.sourceSha256});
        proofLock.recordLeadAssessment(lead.id,{kind:'assessed',
          sourceEvidence:[lead.sourceEvidence],hypothesis:'Independent source-verified obligation',
          disposition:'test',reason:'Distinct lead must have an executable falsifier'},'controller');
        proofStore.recordAssessment(lead.id,[hash('obligation-for-'+lead.id)],[],[exp],[],[
          {id:hash('obligation-for-'+lead.id),experimentIds:[exp],
            sourceWitnesses:[lead.path+':'+lead.sourceSha256+':0:'+content.length]}
        ]);
        proofLock.discover(exp);
        position++;
      }
      proofLock.completeAnalysisBatch();
    }
    assert.equal(position,241);
    proofLock.completeAnalysis();
    let completed=0;
    for(const lead of all241){
      const id=hash('real-experiment-for-'+lead.id);
      proofLock.requireCandidate(id);
      proofLock.finishExperiment(id,'not_observed');
      proofStore.markExperimentCompleted(id,{result:'not_observed',
        evidenceId:hash('case:'+id),verifierDigest:hash('isolated-EVM-result:'+id)});
      completed++;
      if(completed===240){
        assert.equal(proofStore.experimentCertificate.conclusive,240);
        assert.throws(()=>proofLock.completeExperiments(proofStore.experimentCertificate),
          /EXPERIMENTS_INCOMPLETE|EXPERIMENT_LEAD_COVERAGE_INCOMPLETE/);
        assert.equal(proofLock.currentStage,'EXPERIMENT');
      }
    }
    assert.equal(proofStore.experimentCertificate.total,241);
    assert.equal(proofStore.experimentCertificate.conclusive,241);
    assert.equal(proofStore.experimentCertificate.evidenceCount,241);
    await proofStore.save();
    const resumedProof=await AnalysisProgressStore.open(proofFile,all241);
    assert.equal(resumedProof.experimentCertificate.conclusive,241);
    proofLock.completeExperiments(resumedProof.experimentCertificate);
    for(const lead of all241)proofLock.review(hash('real-experiment-for-'+lead.id));
    proofLock.completeReviews();
    proofLock.completeReport(true);
    assert.equal(proofLock.currentStage,'COMPLETE');
    // Regression for the real laptop: v3 persisted lead dispositions but no
    // source-bound verifier evidence for the old 67 selected experiments.
    // Migration must actually queue the leads for new source-grounded work,
    // never silently certify them or strand them as already assessed.
    const legacyFile=join(dir,'laptop-v3.json');
    const legacyData=JSON.parse(await readFile(proofFile,'utf8')) as any;
    legacyData.version=3;
    const missing=legacyData.records[0];
    missing.experimentEvidence=[];
    missing.properties[0].sourceWitnesses=[];
    missing.lifecycle='experiment_completed';
    const deferred=legacyData.records[1];
    deferred.experimentEvidence=[];
    deferred.properties=[{id:'old-unresolved',state:'prerequisites_pending',
      sourceWitnesses:[],unresolvedPrerequisites:['missing_fixture'],experimentIds:[]}];
    deferred.experimentIds=[];
    deferred.lifecycle='dependencies_pending';
    await writeFile(legacyFile,JSON.stringify(legacyData));
    const migrated=await AnalysisProgressStore.open(legacyFile,all241);
    assert.equal(migrated.records.get(missing.id)?.lifecycle,'queued');
    assert.equal(migrated.records.get(deferred.id)?.lifecycle,'queued');
    assert.equal(migrated.remaining,2,'The two legacy unsupported states must be reanalyzed');
    assert.equal(migrated.experimentCertificate.conclusive,239,
      'Other 239 real source-evidence-backed cases must survive migration');
    await migrated.save();
    const stableMigration=await AnalysisProgressStore.open(legacyFile,all241);
    assert.equal(stableMigration.remaining,2,'Version-four resume must not re-migrate');
    assert.equal(stableMigration.experimentCertificate.conclusive,239);
    // Repair selection follows evidence completeness, not legacy lifecycle.
    // The old scheduler ignored analysis_exhausted, hiding 50 laptop leads.
    const repairTypes=candidates.slice(0,4).map((c,i)=>({...c,id:hash('repair-state:'+i)}));
    const repairStore=await AnalysisProgressStore.open(join(dir,'repair-selection.json'),repairTypes);
    for(const lead of repairStore.nextBatch(4,4))
      repairStore.recordAssessment(lead.id,[],[],[]);
    repairStore.records.get(repairTypes[0].id)!.lifecycle="analysis_exhausted";
    repairStore.records.get(repairTypes[1].id)!.lifecycle="dependencies_pending";
    repairStore.records.get(repairTypes[2].id)!.lifecycle="experiment_pending";
    repairStore.records.get(repairTypes[3].id)!.lifecycle="blocked";
    assert.deepEqual(
      new Set(repairStore.nextRepairBatch(4).map(x=>x.id)),
      new Set(repairTypes.map(x=>x.id)),
      'All four unresolved lifecycles need construction repair or explicit blockers');
    const abstractLead=repairStore.records.get(repairTypes[0].id)!;
    abstractLead.lifecycle="dependencies_pending";
    abstractLead.properties=[{id:'abstract-deployment',state:'prerequisites_pending',
      sourceWitnesses:[],experimentIds:[],
      unresolvedPrerequisites:['UNKNOWN_ASSERTION(missing_fixture): Contract IWallet is abstract and cannot be instantiated directly']}];
    const concreteEvidenceId=hash('concrete-implementation-run');
    const concreteExperimentId=hash('concrete-wallet-experiment');
    repairStore.addRepairExperiment(repairTypes[0].id,concreteEvidenceId,concreteExperimentId,
      [path+':'+sourceSha, 'source-1/contracts/Wallet.sol:'+hash('actual wallet')],true);
    repairStore.markExperimentCompleted(concreteExperimentId,{result:'not_observed',
      evidenceId:hash('real-experiment-case'),verifierDigest:hash('real-verifier-output')});
    assert.equal(repairStore.records.get(repairTypes[0].id)!.lifecycle,'experiment_completed');
    assert.equal(repairStore.records.get(repairTypes[0].id)!.properties.length,1,
      'A proven implementation may supersede only its abstract deployment blocker');
    const anotherProperty=hash('independent-property-same-experiment');
    // Same source-revision and same verifier trace may support another
    // separately witnessed obligation; its property must not be orphaned by
    // the experiment scheduler's ID deduplication.
    repairStore.addRepairExperiment(repairTypes[0].id,anotherProperty,concreteExperimentId,
      [path+':'+sourceSha, 'source-1/contracts/Wallet.sol:'+hash('actual wallet')],true);
    assert.equal(repairStore.records.get(repairTypes[0].id)!.properties.length,2);
    assert.equal(repairStore.records.get(repairTypes[0].id)!.properties[1].state,'test_completed');
    assert.equal(repairStore.experimentCertificate.conclusive,1,
      'Verifier-backed duplicate can satisfy two distinct source-witnessed properties');
    const futureProperty=hash('new-property-pending-verifier');
    repairStore.addRepairExperiment(repairTypes[0].id,futureProperty,hash('new-not-yet-run'),
      [path+':'+sourceSha],false);
    assert.equal(repairStore.experimentCertificate.conclusive,0,
      'A linked second property without verifier transcript must reopen the lead');
    // Abstract interfaces must resolve only to acquired concrete implementations
    // with an explicit import and direct inheritance of the target interface.
    // Unrelated names and guessed network contracts cannot supply test evidence.
    const abstractSource='pragma solidity ^0.8.0; interface IWallet { function withdraw(uint256 value) external; }';
    const implSource='pragma solidity ^0.8.0; import "./IWallet.sol"; contract Wallet is IWallet { function withdraw(uint256 value) external override {} }';
    const unrelatedSource='pragma solidity ^0.8.0; contract Other is IWallet { function withdraw(uint256 value) external {} }';
    const targetInterface={path:'source-1/contracts/IWallet.sol',content:abstractSource,sha256:hash(abstractSource)};
    const targetImpl={path:'source-1/contracts/Wallet.sol',content:implSource,sha256:hash(implSource)};
    const unrelatedImpl={path:'source-1/contracts/Other.sol',content:unrelatedSource,sha256:hash(unrelatedSource)};
    const available=resolveAcquiredConcreteImplementations(targetInterface,'IWallet','withdraw',
      [targetInterface,targetImpl,unrelatedImpl]);
    assert.equal(available.length,1,'An unrelated source with no verified import edge must not be substituted');
    assert.equal(available[0].selector,'Wallet.withdraw');
    assert.equal(available[0].sourceSha256,targetImpl.sha256);
    assert.equal(resolveAcquiredConcreteImplementations(targetInterface,'IWallet','borrow',
      [targetInterface,targetImpl]).length,0,'Do not invent an unimplemented method');
    // The acquired compiler ABI must preserve the selected operation's view
    // mutability and return types. A name/input match alone is insufficient.
    const viewIface='pragma solidity ^0.8.0; interface IView { function read(uint256 amount) external view returns(uint256); }';
    const viewGood='pragma solidity ^0.8.0; import "./IView.sol"; contract ConcreteView is IView { function read(uint256 amount) external pure override returns(uint256) { return amount; } }';
    const viewBad='pragma solidity ^0.8.0; import "./IView.sol"; contract WrongView is IView { function read(uint256 amount) external pure returns(bool) { return true; } }';
    const viewSource={path:'source-1/contracts/IView.sol',content:viewIface,sha256:hash(viewIface)};
    const viewCorrect={path:'source-1/contracts/ConcreteView.sol',content:viewGood,sha256:hash(viewGood)};
    const viewWrong={path:'source-1/contracts/WrongView.sol',content:viewBad,sha256:hash(viewBad)};
    const concreteView=resolveAcquiredConcreteImplementations(viewSource,'IView','read',
      [viewSource,viewCorrect,viewWrong]);
    assert.deepEqual(concreteView.map(x=>x.selector),['ConcreteView.read']);
    assert.equal(concreteView[0].operation,'call',
      'A pure inherited interface method must use a read-only EVM step');
    // Source-backed inherited two-step ownership claim needs the BASE
    // prerequisite transfer/owner/pendingOwner ABI, not just claimOwnership.
    const claimBaseText=`pragma solidity ^0.8.0;
contract ClaimBase {
  address private _owner;
  address private _pendingOwner;
  function __Ownable_init() internal { _owner = msg.sender; }
  function owner() external view returns(address) { return _owner; }
  function pendingOwner() external view returns(address) { return _pendingOwner; }
  modifier onlyOwner() { require(msg.sender == _owner); _; }
  function transferOwnership(address next,bool direct,bool renounce) public onlyOwner {
    if(direct) { require(next != address(0) || renounce);
      _owner = next; _pendingOwner = address(0);
    } else { _pendingOwner = next; }
  }
  function claimOwnership() public {
    address __pendingOwner = _pendingOwner;
    require(msg.sender == __pendingOwner);
    _owner = __pendingOwner;
    _pendingOwner = address(0);
  }
}`;
    const claimChildText=`pragma solidity ^0.8.0;
import "./ClaimBase.sol";
contract ClaimChild is ClaimBase {
  modifier initializer() { _; }
  function initialize() external initializer { __Ownable_init(); }
}`;
    const claimSources=[
      {path:'source-1/contracts/ClaimBase.sol',content:claimBaseText,sha256:hash(claimBaseText)},
      {path:'source-1/contracts/ClaimChild.sol',content:claimChildText,sha256:hash(claimChildText)}
    ];
    const claimImpl=resolveAcquiredConcreteImplementations(
      claimSources[0],'ClaimBase','claimOwnership',claimSources);
    assert.ok(claimImpl.some(x=>x.contract==='ClaimChild'),
      'Actual concrete inherited claimant must be discoverable');
    const claimAbi=enumerateAcquiredInheritedAbi(claimSources[0],
      'ClaimBase','ClaimChild',claimSources);
    assert.ok(claimAbi.some(x=>x.selector==='ClaimChild.transferOwnership'&&
      JSON.stringify(x.inputs)===JSON.stringify(['address','bool','bool'])));
    assert.ok(claimAbi.some(x=>x.selector==='ClaimChild.pendingOwner'&&x.operation==='call'));
    const claimBuilt=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:claimSources[1].path,
      targetSelector:'ClaimChild.claimOwnership',sources:claimSources,
      declarations:claimAbi as any,skipLegacy:true});
    assert.equal(claimBuilt.ok,true,
      'Claimable concrete implementation must admit the source-verified role transition');
    if(claimBuilt.ok)assert.ok(claimBuilt.experiments.some(x=>
      x.securityProperty.includes('two-step ownership claim authorization')&&
      x.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='claimOwnership()'&&step.sender===2)));
    // Transitive A <- B <- C must resolve a real inherited implementation
    // without admitting an unrelated same-named contract or an abstract leaf.
    const middleText='pragma solidity ^0.8.0; import "./IWallet.sol"; abstract contract WalletBase is IWallet { function withdraw(uint256 value) external virtual override {} }';
    const leafText='pragma solidity ^0.8.0; import "./WalletBase.sol"; contract FinalWallet is WalletBase {}';
    const falseLeafText='pragma solidity ^0.8.0; contract UnlinkedWallet is WalletBase {}';
    const middleSnap={path:'source-1/contracts/WalletBase.sol',content:middleText,sha256:hash(middleText)};
    const leafSnap={path:'source-1/contracts/FinalWallet.sol',content:leafText,sha256:hash(leafText)};
    const falseLeafSnap={path:'source-1/contracts/UnlinkedWallet.sol',content:falseLeafText,sha256:hash(falseLeafText)};
    const deepImplementations=resolveAcquiredConcreteImplementations(
      targetInterface,'IWallet','withdraw',[targetInterface,middleSnap,leafSnap,falseLeafSnap]);
    assert.deepEqual(deepImplementations.map(x=>x.selector),['FinalWallet.withdraw'],
      'Only a complete authenticated two-hop inheritance chain is executable');
    assert.equal(deepImplementations[0].sourceSha256,leafSnap.sha256);
    assert.ok(deepImplementations[0].witness.startsWith(middleSnap.path+':'+middleSnap.sha256),
      'Inherited executable method must retain the implementing source witness');
    // An acquired intermediate import may re-export the base type. Resolve
    // that closure without admitting a disconnected same-name declaration.
    const bridgeText='pragma solidity ^0.8.0; import "./WalletBase.sol";';
    const bridgedLeafText='pragma solidity ^0.8.0; import "./Bridge.sol"; contract BridgedWallet is WalletBase {}';
    const bridgeSnap={path:'source-1/contracts/Bridge.sol',content:bridgeText,sha256:hash(bridgeText)};
    const bridgedSnap={path:'source-1/contracts/BridgedWallet.sol',content:bridgedLeafText,sha256:hash(bridgedLeafText)};
    const bridged=resolveAcquiredConcreteImplementations(targetInterface,'IWallet','withdraw',
      [targetInterface,middleSnap,bridgeSnap,bridgedSnap]);
    assert.deepEqual(bridged.map(x=>x.selector),['BridgedWallet.withdraw'],
      'Cycle-safe transitive import closure must preserve inherited method proof');
    assert.ok(bridged[0].witness.startsWith(middleSnap.path+':'+middleSnap.sha256));
    // Source-authenticated caller graph for interface-only leads: the caller
    // directly imports this interface, holds a typed state binding and calls
    // its method from an executable public operation. A mock without the import
    // is not a production implementation.
    const icTokenSource=`pragma solidity ^0.8.20;
interface ICToken { function mint(uint256 amount) external returns(uint256); }`;
    const realCallerSource=`pragma solidity ^0.8.20;
import {ICToken} from "./ICToken.sol";
contract Market {
  ICToken public cToken;
  constructor(address token) { cToken = ICToken(token); }
  function deposit(uint256 amount) external { require(cToken.mint(amount)==0); }
}`;
    const fakeCallerSource=`pragma solidity ^0.8.20;
contract UnlinkedMarket {
  function deposit(uint256 amount) external { fake.mint(amount); }
}`;
    const icSnap={path:'source-1/contracts/ICToken.sol',content:icTokenSource,
      sha256:hash(icTokenSource)};
    const callerSnap={path:'source-1/contracts/Market.sol',content:realCallerSource,
      sha256:hash(realCallerSource)};
    const fakeSnap={path:'source-1/contracts/UnlinkedMarket.sol',content:fakeCallerSource,
      sha256:hash(fakeCallerSource)};
    const witnessedCallers=resolveAcquiredInterfaceCallers(icSnap,'ICToken','mint',
      [icSnap,callerSnap,fakeSnap]);
    assert.equal(witnessedCallers.length,1,
      'Only acquired and verified imports may form an interface caller obligation');
    assert.equal(witnessedCallers[0].selector,'Market.deposit');
    assert.equal(witnessedCallers[0].receiver,'cToken');
    assert.equal(witnessedCallers[0].sourceSha256,callerSnap.sha256);
    const intermediateText='pragma solidity ^0.8.20; import "./ICToken.sol";';
    const transitiveText=`pragma solidity ^0.8.20;
import "./Intermediate.sol";
contract TransitiveMarket {
  ICToken public cToken;
  function deposit(uint256 amount) external { require(cToken.mint(amount)==0); }
}`;
    const intermediateSnap={path:'source-1/contracts/Intermediate.sol',
      content:intermediateText,sha256:hash(intermediateText)};
    const transitiveSnap={path:'source-1/contracts/TransitiveMarket.sol',
      content:transitiveText,sha256:hash(transitiveText)};
    const transitiveCallers=resolveAcquiredInterfaceCallers(icSnap,'ICToken','mint',
      [icSnap,intermediateSnap,transitiveSnap,fakeSnap]);
    assert.deepEqual(transitiveCallers.map(x=>x.selector),['TransitiveMarket.deposit'],
      'An acquired transitive import must preserve a real interface call witness');
    assert.equal(transitiveCallers[0].sourceSha256,transitiveSnap.sha256);
    // An acquired concrete consumer may inherit the typed interface receiver
    // from a parent instead of declaring the state variable in its own file.
    const stateBaseText=`pragma solidity ^0.8.20;
import "./ICToken.sol";
contract StateBase { ICToken public cToken; }`;
    const stateChildText=`pragma solidity ^0.8.20;
import "./StateBase.sol";
contract StateChild is StateBase {
  function deposit(uint256 amount) external { require(cToken.mint(amount)==0); }
}`;
    const stateBaseSnap={path:'source-1/contracts/StateBase.sol',
      content:stateBaseText,sha256:hash(stateBaseText)};
    const stateChildSnap={path:'source-1/contracts/StateChild.sol',
      content:stateChildText,sha256:hash(stateChildText)};
    const inheritedCallers=resolveAcquiredInterfaceCallers(icSnap,'ICToken','mint',
      [icSnap,stateBaseSnap,stateChildSnap,fakeSnap]);
    assert.deepEqual(inheritedCallers.map(x=>x.selector),['StateChild.deposit'],
      'An acquired inherited source state receiver is a valid concrete caller');
    assert.equal(inheritedCallers[0].receiver,'cToken');
    assert.equal(resolveAcquiredInterfaceCallers(icSnap,'ICToken','burn',
      [icSnap,callerSnap]).length,0,'No invented interface method');
    // A source-acquired concrete child must remain discoverable even when
    // its unrelated standard parent comes from an installed OpenZeppelin
    // package. This does not certify that child as deployable; the EVM must.
    const acquiredBaseText=`pragma solidity ^0.8.0;
abstract contract AcquiredBase {
  function mint(uint256 amount) public virtual { require(amount>0); }
}`;
    const acquiredChildText=`pragma solidity ^0.8.0;
import "./AcquiredBase.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
contract AcquiredChild is AcquiredBase, OwnableUpgradeable {
  function checkpoint() public {}
}`;
    const acquiredBase={path:'source-1/contracts/AcquiredBase.sol',
      content:acquiredBaseText,sha256:hash(acquiredBaseText)};
    const acquiredChild={path:'source-1/contracts/AcquiredChild.sol',
      content:acquiredChildText,sha256:hash(acquiredChildText)};
    const acquiredImpl=resolveAcquiredConcreteImplementations(
      acquiredBase,'AcquiredBase','mint',[acquiredBase,acquiredChild]);
    assert.equal(acquiredImpl.length,1,
      'An actual acquired child may inherit a separately installed canonical OpenZeppelin base');
    assert.equal(acquiredImpl[0].selector,'AcquiredChild.mint');
    assert.ok(acquiredImpl[0].witness.includes(acquiredBase.sha256),
      'The implementation method witness must remain the acquired project source');
    const unprovenChildText=acquiredChildText.replace(
      '@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol',
      './UnacquiredOwner.sol');
    const unprovenChild={...acquiredChild,content:unprovenChildText,
      sha256:hash(unprovenChildText)};
    assert.equal(resolveAcquiredConcreteImplementations(
      acquiredBase,'AcquiredBase','mint',[acquiredBase,unprovenChild]).length,0,
      'An arbitrary missing parent must never be assumed to exist');
    // A named import alias must resolve to the actual acquired base AST.
    // Another same-named base in a transitive import must not create a false
    // ambiguous inheritance rejection or a synthetic source witness.
    const aliasedBaseText=`pragma solidity ^0.8.0;
abstract contract BaseLedger {
  function debit(uint256 amount) external virtual;
}`;
    const aliasedChildText=`pragma solidity ^0.8.0;
import {BaseLedger as LedgerRoot} from "./BaseLedger.sol";
contract LedgerChild is LedgerRoot {
  function debit(uint256 amount) external override {}
}`;
    const aliasedBase={path:'source-1/contracts/BaseLedger.sol',
      content:aliasedBaseText,sha256:hash(aliasedBaseText)};
    const aliasedChild={path:'source-1/contracts/LedgerChild.sol',
      content:aliasedChildText,sha256:hash(aliasedChildText)};
    const aliasedImpl=resolveAcquiredConcreteImplementations(
      aliasedBase,'BaseLedger','debit',[aliasedBase,aliasedChild]);
    assert.equal(aliasedImpl.length,1,
      'An explicitly aliased base must resolve to the acquired parent contract');
    assert.equal(aliasedImpl[0].selector,'LedgerChild.debit');
    const unrelatedBaseText=`pragma solidity ^0.8.0;
contract BaseLedger { function debit(uint256 amount) external {} }`;
    const unrelatedBase={path:'source-1/contracts/OtherBase.sol',
      content:unrelatedBaseText,sha256:hash(unrelatedBaseText)};
    assert.equal(resolveAcquiredConcreteImplementations(
      aliasedBase,'BaseLedger','debit',
      [aliasedBase,aliasedChild,unrelatedBase]).length,1,
      'Unrelated same-name symbols cannot displace an explicit import alias');
    // One target can have multiple independently source-proven opposing
    // transitions. Neither the companion order nor names justify dropping one.
    // A burn test without a valid minted token is a meaningless dual-revert.
    // Source-proved mint/setup must be part of the same experiment.
    const nftText=`pragma solidity ^0.8.4;
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC721URIStorageUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
contract GuardedNFT is ERC721URIStorageUpgradeable, OwnableUpgradeable {
  function initialize(string calldata name, string calldata symbol) external initializer {
    __Ownable_init(); __ERC721_init(name,symbol);
  }
  function mint(address recipient,uint256 tokenId) external onlyOwner {
    _safeMint(recipient,tokenId);
  }
  function burn(uint256 tokenId) external onlyOwner { _burn(tokenId); }
}`;
    const nftSource={path:'source-1/contracts/GuardedNFT.sol',
      content:nftText,sha256:hash(nftText)};
    const nftDeclarations=[
      {selector:'GuardedNFT.mint',operation:'send',inputs:['address','uint256']},
      {selector:'GuardedNFT.burn',operation:'send',inputs:['uint256']},
      // Inherited owner() and balanceOf(address) are intentionally omitted:
      // production source menus need not enumerate compiler-inherited ABI.
    ];
    const nftBurn=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:nftSource.path,
      targetSelector:'GuardedNFT.burn',sources:[nftSource],
      declarations:nftDeclarations as any,skipLegacy:true
    });
    assert.equal(nftBurn.ok,true,
      'Guarded ERC721 burn must include authorized mint prerequisites and witnessed ownership');
    if(nftBurn.ok){
      const candidate=nftBurn.experiments.find(x=>
        x.securityProperty.includes('owner-gated burn'));
      assert.ok(candidate,'NFT burn must not silently degrade into a generic test');
      const operations=candidate.sequence.steps.filter(x=>x.operation==='send') as any[];
      assert.deepEqual(operations.map(x=>x.function),[
        'initialize(string,string)','mint(address,uint256)','burn(uint256)','burn(uint256)']);
      assert.equal(operations[2].expectRevert,true,
        'Unauthorized burn must be checked only after successful source-declared mint');
      assert.notEqual(operations[3].expectRevert,true,
        'Authorized comparison must succeed rather than accepting a dual revert');
    }
    // Removing the canonical acquired OpenZeppelin import must NOT permit
    // an inferred getter ABI merely because the base class has a familiar name.
    const unlinkedNftText=nftText.replace(
      'import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";',
      ''); 
    const unlinkedNftSource={...nftSource,content:unlinkedNftText,
      sha256:hash(unlinkedNftText)};
    const unlinkedNftBurn=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:unlinkedNftSource.path,
      targetSelector:'GuardedNFT.burn',sources:[unlinkedNftSource],
      declarations:nftDeclarations as any,skipLegacy:true
    });
    assert.ok(!unlinkedNftBurn.ok||!unlinkedNftBurn.experiments.some(x=>
      x.securityProperty.includes('owner-gated burn')),
      'An unacquired ownership import cannot be treated as verified inherited ABI');
    // A source-proven scalar transition may be expressed by assignment rather
    // than +=. That is still a falsifiable getter-backed property.
    // A private accounting scalar may still have a strictly equivalent,
    // source-declared view readback. Getter identity must be exact.
    const privateScalarText=`pragma solidity ^0.8.0;
contract PrivateScalar {
  uint256 private accumulated;
  function total() external view returns(uint256) { return accumulated; }
  function add(uint256 amount) external { accumulated += amount; }
}`;
    const privateScalarSnap={path:'source-1/contracts/PrivateScalar.sol',
      content:privateScalarText,sha256:hash(privateScalarText)};
    const privateScalarBuild=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:privateScalarSnap.path,
      targetSelector:'PrivateScalar.add',sources:[privateScalarSnap],
      declarations:[
        {selector:'PrivateScalar.add',operation:'send',inputs:['uint256']},
        {selector:'PrivateScalar.total',operation:'call',inputs:[]}
      ] as any,skipLegacy:true});
    assert.equal(privateScalarBuild.ok,true,
      'Source-exact private-state readbacks must permit observable arithmetic properties');
    if(privateScalarBuild.ok)assert.ok(privateScalarBuild.experiments.some(exp=>
      exp.sequence.sourceProperty?.state==='accumulated'&&
      exp.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='total()'&&step.expect==='1000')),
      'Private-state obligation must use the source-equivalent total() view');
    const missingReadback=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:privateScalarSnap.path,
      targetSelector:'PrivateScalar.add',sources:[privateScalarSnap],
      declarations:[{selector:'PrivateScalar.add',operation:'send',inputs:['uint256']}] as any,
      skipLegacy:true,skipFinancialInvariants:true});
    assert.ok(!missingReadback.ok||!missingReadback.experiments.some(exp=>
      exp.sequence.sourceProperty?.state==='accumulated'),
      'No acquired callable readback means no fabricated private-state assertion');
    const directScalarText=`pragma solidity ^0.8.0;
contract DirectScalar {
  uint256 public total;
  function addValue(uint256 amount) external { total = total + amount; }
}`;
    const directScalarSource={path:'source-1/contracts/DirectScalar.sol',
      content:directScalarText,sha256:hash(directScalarText)};
    const directScalar=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:directScalarSource.path,
      targetSelector:'DirectScalar.addValue',sources:[directScalarSource],
      declarations:[{selector:'DirectScalar.addValue',operation:'send',inputs:['uint256'],
        outputs:[],stateMutability:'nonpayable'}] as any,skipLegacy:true
    });
    assert.equal(directScalar.ok,true,
      'Exact same-lvalue scalar assignment must construct a source-bound experiment');
    if(directScalar.ok)assert.ok(directScalar.experiments.some(x=>
      x.sequence.sourceProperty?.kind==='scalar_delta'),
      'Scalar assignment property must retain executable source-property metadata');
    // A different RHS storage identity must never become a scalar invariant.
    const unrelatedScalarText=directScalarText.replace(
      'uint256 public total;', 'uint256 public total; uint256 public other;').replace(
      'total = total + amount;', 'total = other + amount;');
    const unrelatedScalarSource={...directScalarSource,
      content:unrelatedScalarText,sha256:hash(unrelatedScalarText)};
    const unrelatedScalar=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:unrelatedScalarSource.path,
      targetSelector:'DirectScalar.addValue',sources:[unrelatedScalarSource],
      declarations:[{selector:'DirectScalar.addValue',operation:'send',inputs:['uint256'],
        outputs:[],stateMutability:'nonpayable'}] as any,skipLegacy:true
    });
    assert.ok(!unrelatedScalar.ok||!unrelatedScalar.experiments.some(x=>
      x.sequence.sourceProperty?.kind==='scalar_delta'),
      'Unrelated RHS storage cannot prove an exact scalar delta');
    // State relationships must be derived from exact mapping keys, not from
    // lexical similarity or a generic "balance" variable name.
    const directMapSourceText=`pragma solidity ^0.8.0;
contract DirectMap {
  mapping(address => uint256) public ledger;
  function credit(uint256 amount) external { ledger[msg.sender] += amount; }
  function creditFor(address recipient,uint256 amount) external {
    ledger[recipient] = ledger[recipient] + amount;
  }
  function creditOther(address recipient,uint256 amount) external {
    ledger[msg.sender] += amount;
  }
}`;
    const directMapSnapshot={path:'source-1/contracts/DirectMap.sol',
      content:directMapSourceText,sha256:hash(directMapSourceText)};
    const mapDecls=[{selector:'DirectMap.credit',operation:'send' as const,inputs:['uint256']},
      {selector:'DirectMap.creditFor',operation:'send' as const,inputs:['address','uint256']},
      {selector:'DirectMap.creditOther',operation:'send' as const,inputs:['address','uint256']}];
    const compileMap=(name:string)=>constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:directMapSnapshot.path,
      targetSelector:'DirectMap.'+name,sources:[directMapSnapshot],
      declarations:mapDecls as any,skipLegacy:true});
    const mapCredit=compileMap('credit');
    assert.equal(mapCredit.ok,true,'Source-grounded msg.sender mapping credit must be constructible');
    if(mapCredit.ok)assert.ok(mapCredit.experiments.some(e=>
      e.securityProperty.includes('mapping conservation')&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='ledger(address)'&&step.args[0]==='$account0')));
    const mapRecipient=compileMap('creditFor');
    assert.equal(mapRecipient.ok,true,'Source-grounded named-recipient credit must be constructible');
    if(mapRecipient.ok)assert.ok(mapRecipient.experiments.some(e=>
      e.securityProperty.includes('mapping conservation')&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='ledger(address)'&&step.args[0]==='$account2')));
    const mapWrong=compileMap('creditOther');
    assert.ok(!mapWrong.ok||!mapWrong.experiments.some(e=>
      e.securityProperty.includes('mapping conservation')&&
      e.securityProperty.endsWith(':recipient')),
      'Crediting msg.sender must not prove a credit to recipient');

    const directStateText=`pragma solidity ^0.8.0;
contract DirectState {
  uint256 public amount;
  bool public enabled;
  address public recipient;
  function change(uint256 next) external { amount = next; }
  function enable(bool value) external { enabled = value; }
  function choose(address chosen) external { recipient = chosen; }
  function conditional(uint256 next) external { if (next > 3) amount = next; }
}`;
    const directStateSnap={path:'source-1/contracts/DirectState.sol',
      content:directStateText,sha256:hash(directStateText)};
    const directStateMenu=[
      {selector:'DirectState.change',operation:'send',inputs:['uint256']},
      {selector:'DirectState.enable',operation:'send',inputs:['bool']},
      {selector:'DirectState.choose',operation:'send',inputs:['address']},
      {selector:'DirectState.conditional',operation:'send',inputs:['uint256']}
    ];
    for(const [name,getter,expected] of [
      ['change','amount()','7'],
      ['enable','enabled()',true],
      ['choose','recipient()','$account2']
    ] as const){
      const built=constructSolidityExperiments({repositoryCommit:'b'.repeat(40),
        targetPath:directStateSnap.path,targetSelector:'DirectState.'+name,
        sources:[directStateSnap],declarations:directStateMenu as any,skipLegacy:true});
      assert.equal(built.ok,true,'Direct state assignment must be source-testable: '+name);
      if(built.ok)assert.ok(built.experiments.some(exp=>
        exp.securityProperty.startsWith('source-defined direct state assignment')&&
        exp.sequence.steps.some(step=>step.operation==='call'&&
          step.function===getter&&step.expect===expected)));
    }
    const branchState=constructSolidityExperiments({repositoryCommit:'b'.repeat(40),
      targetPath:directStateSnap.path,targetSelector:'DirectState.conditional',
      sources:[directStateSnap],declarations:directStateMenu as any,skipLegacy:true});
    assert.ok(!branchState.ok||!branchState.experiments.some(exp=>
      exp.securityProperty.startsWith('source-defined direct state assignment')),
      'Conditional writes must not be mistaken for unconditional source assignments');
    // Acquired public mapping-of-struct getter: source-proven onlyOwner,
    // unauthorized revert, authorized transaction and BOTH struct fields.
    const overrideText=`pragma solidity ^0.8.4;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
contract OverrideRates is Ownable {
  struct Override { bool enabled; uint256 amount; }
  mapping(address=>Override) public poolRates;
  mapping(address=>mapping(uint64=>Override)) public depositRates;
  uint256 public cap;
  constructor(uint256 initialCap) { cap = initialCap; }
  function overridePool(address pool,uint256 fee) external onlyOwner {
    require(fee <= cap);
    poolRates[pool] = Override({enabled:true,amount:fee});
  }
  function overrideDeposit(address pool,uint64 id,uint256 fee) external onlyOwner {
    require(fee <= cap);
    depositRates[pool][id] = Override({enabled:true,amount:fee});
  }
}`;
    const overrideSource={path:'source-1/contracts/OverrideRates.sol',
      content:overrideText,sha256:hash(overrideText)};
    const overrideMenu=[
      {selector:'OverrideRates.overridePool',operation:'send',inputs:['address','uint256']},
      {selector:'OverrideRates.overrideDeposit',operation:'send',inputs:['address','uint64','uint256']}
    ];
    for(const [fn,getter,keyLength] of [
      ['overridePool','poolRates(address)',1],
      ['overrideDeposit','depositRates(address,uint64)',2]
    ] as const){
      const result=constructSolidityExperiments({
        repositoryCommit:'b'.repeat(40),targetPath:overrideSource.path,
        targetSelector:'OverrideRates.'+fn,sources:[overrideSource],
        declarations:overrideMenu as any,skipLegacy:true});
      assert.equal(result.ok,true,'Authenticated struct mapping is executable: '+fn);
      if(result.ok)assert.ok(result.experiments.some(exp=>{
        const sends=exp.sequence.steps.filter(x=>x.operation==='send');
        return exp.securityProperty.includes('owner-gated source struct override')&&
          sends.some(x=>x.operation==='send'&&x.sender===1&&x.expectRevert===true)&&
          sends.some(x=>x.operation==='send'&&x.sender===0&&!x.expectRevert)&&
          exp.sequence.steps.some(x=>x.operation==='call'&&x.function===getter&&
            x.args.length===keyLength&&Array.isArray(x.expect)&&
            x.expect[0]===true&&x.expect[1]==='7');
      }),'Both source-declared fields must be independently verified');
    }
    const unknownOwner=overrideText.replace(
      'import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";','');
    const unlinkedOwner={...overrideSource,content:unknownOwner,sha256:hash(unknownOwner)};
    const notOwned=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:unlinkedOwner.path,
      targetSelector:'OverrideRates.overridePool',sources:[unlinkedOwner],
      declarations:overrideMenu as any,skipLegacy:true});
    assert.ok(!notOwned.ok||!notOwned.experiments.some(x=>
      x.securityProperty.includes('owner-gated source struct override')),
      'An unacquired owner implementation is not an authorization witness');
    // Real ERC20Wrapper-like approval is a private mapping mutation via an
    // authenticated internal helper, with public getter readback. No parent
    // ERC1155 contract is required for the approval's local state assertion.
    const nestedAllowance=`pragma solidity ^0.8.0;
contract PrivateAllowance {
 mapping(address=>mapping(address=>uint256)) private _allowances;
 function allowance(address owner,address spender) external view returns(uint256) {
   return _allowances[owner][spender];
 }
 function approve(address spender,uint256 amount) external returns(bool) {
   _approve(msg.sender,spender,amount);
   return true;
 }
 function _approve(address owner,address spender,uint256 amount) internal {
   require(owner != address(0));
   require(spender != address(0));
   _allowances[owner][spender] = amount;
 }
}`;
    const nestedAllowanceSnap={path:'source-1/contracts/PrivateAllowance.sol',
      content:nestedAllowance,sha256:hash(nestedAllowance)};
    const nestedAllowanceMenu=[
      {selector:'PrivateAllowance.approve',operation:'send',inputs:['address','uint256']},
      {selector:'PrivateAllowance.allowance',operation:'call',inputs:['address','address']}
    ];
    const allowancePlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:nestedAllowanceSnap.path,
      targetSelector:'PrivateAllowance.approve',sources:[nestedAllowanceSnap],
      declarations:nestedAllowanceMenu as any,skipLegacy:true});
    assert.equal(allowancePlan.ok,true,
      'Exact private mapping helper and public getter must produce an executable property');
    if(allowancePlan.ok)assert.ok(allowancePlan.experiments.some(exp=>
      exp.securityProperty.includes('internal setter and public mapping getter')&&
      exp.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='allowance(address,address)'&&step.expect==='7')),
      'Private mapping mutation must be falsified by an actual getter result');
    const wrongAllowance=nestedAllowance.replace(
      '_allowances[owner][spender] = amount;',
      '_allowances[spender][owner] = amount;');
    const wrongAllowanceSnap={...nestedAllowanceSnap,content:wrongAllowance,
      sha256:hash(wrongAllowance)};
    const wrongAllowancePlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:wrongAllowanceSnap.path,
      targetSelector:'PrivateAllowance.approve',sources:[wrongAllowanceSnap],
      declarations:nestedAllowanceMenu as any,skipLegacy:true});
    assert.ok(!wrongAllowancePlan.ok||!wrongAllowancePlan.experiments.some(exp=>
      exp.securityProperty.includes('internal setter and public mapping getter')),
      'Swapped helper keys cannot establish the claimed exact owner/spender relation');
    const sourcePureText=`pragma solidity ^0.8.0;
contract PureArithmetic {
  function calc(uint256 value) external pure returns(uint256) { return (value * 3) + 2; }
  function larger(uint256 value) external pure returns(bool) { return value > 4; }
  function unsafe(uint256 value) external pure returns(uint256) { return remote(value); }
  function remote(uint256 value) internal pure returns(uint256) { return value; }
}`;
    const pureSnapshot={path:'source-1/contracts/PureArithmetic.sol',
      content:sourcePureText,sha256:hash(sourcePureText)};
    const pureMenu=['calc','larger','unsafe'].map(selector=>({
      selector:'PureArithmetic.'+selector,operation:'call' as const,inputs:['uint256']}));
    const pureConstruct=(method:string)=>constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:pureSnapshot.path,
      targetSelector:'PureArithmetic.'+method,sources:[pureSnapshot],
      declarations:pureMenu as any,skipLegacy:true});
    const pureSuccess=pureConstruct('calc');
    assert.equal(pureSuccess.ok,true,'Exact pure expression must construct an executable oracle');
    if(pureSuccess.ok){
      assert.ok(pureSuccess.experiments.every(exp=>
        exp.prerequisites.some(p=>p.id==='target:deploy'&&p.kind==='deploy'&&
          p.sourceEvidence.some(w=>w.sourceSha256===pureSnapshot.sha256))),
        'Every experiment must attest its actual source-identified target deployment');
    }
    if(pureSuccess.ok)assert.ok(pureSuccess.experiments.some(exp=>
      exp.securityProperty.startsWith('source-exact pure return')&&
      exp.sequence.steps.some(step=>step.operation==='call'&&step.expect==='23')));
    const pureBoolean=pureConstruct('larger');
    assert.equal(pureBoolean.ok,true,'Typed boolean comparison must construct an executable oracle');
    if(pureBoolean.ok)assert.ok(pureBoolean.experiments.some(exp=>
      exp.securityProperty.startsWith('source-exact pure return')&&
      exp.sequence.steps.some(step=>step.operation==='call'&&step.expect===true)));
    const pureUnknown=pureConstruct('unsafe');
    assert.ok(!pureUnknown.ok||!pureUnknown.experiments.some(exp=>
      exp.securityProperty.startsWith('source-exact pure return')),
      'Unexpanded source helper calls are not a trustworthy independent return oracle');
    const ledgerText=`pragma solidity ^0.8.0;
contract Ledger {
  uint256 public total;
  mapping(address => uint256) public balances;
  function credit(uint256 amount) external { total += amount; balances[msg.sender] += amount; }
  function reward(uint256 amount) external { total += amount; balances[msg.sender] += amount; }
  function debit(uint256 amount) external { total -= amount; balances[msg.sender] -= amount; }
}`;
    const ledgerSource={path:'source-1/contracts/Ledger.sol',
      content:ledgerText,sha256:hash(ledgerText)};
    const ledgerDeclarations=['credit','reward','debit'].map(name=>({
      selector:'Ledger.'+name,operation:'send' as const,inputs:['uint256'],
      outputs:[],stateMutability:'nonpayable' as const}));
    ledgerDeclarations.push({selector:'Ledger.total',operation:'call',
      inputs:[],outputs:['uint256'],stateMutability:'view'} as any);
    ledgerDeclarations.push({selector:'Ledger.balances',operation:'call',
      inputs:['address'],outputs:['uint256'],stateMutability:'view'} as any);
    // Regression: accounting writes in internal helpers must be observable
    // through the same source-call closure used to detect the opposing pair.
    // Previously the property extractor discovered the pair, then rejected
    // the very same state getters because it searched only wrapper bodies.
    const helperLedgerText=`pragma solidity ^0.8.0;
contract HelperLedger {
  uint256 public total;
  mapping(address => uint256) public balances;
  function credit(uint256 amount) external { _credit(amount); }
  function debit(uint256 amount) external { _debit(amount); }
  function _credit(uint256 amount) private {
    total += amount; balances[msg.sender] += amount;
  }
  function _debit(uint256 amount) private {
    total -= amount; balances[msg.sender] -= amount;
  }
}`;
    const helperLedgerSource={path:'source-1/contracts/HelperLedger.sol',
      content:helperLedgerText,sha256:hash(helperLedgerText)};
    const helperLedgerDeclarations=['credit','debit'].map(name=>({
      selector:'HelperLedger.'+name,operation:'send' as const,
      inputs:['uint256'],outputs:[],stateMutability:'nonpayable' as const
    }));
    const helperExperiment=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:helperLedgerSource.path,
      targetSelector:'HelperLedger.debit',sources:[helperLedgerSource],
      declarations:helperLedgerDeclarations as any,skipLegacy:true
    });
    assert.equal(helperExperiment.ok,true,
      'Source-reachable internal accounting helpers must retain their observable getter properties');
    if(helperExperiment.ok)assert.ok(helperExperiment.experiments.some(x=>
      x.securityProperty.startsWith('financial ')),
      'The constructed property must be financial, not merely a generic call');
    // A source-backed pair may use explicit assignments or SafeMath.add/sub
    // instead of Solidity +=/-=. Unrelated RHS balances may not qualify.
    const mathLedgerText=`pragma solidity ^0.8.0;
library ProvenMath {
  function add(uint256 a,uint256 b) internal pure returns(uint256) { return a+b; }
  function sub(uint256 a,uint256 b) internal pure returns(uint256) { return a-b; }
}
contract MathLedger {
  using ProvenMath for uint256;
  uint256 public total;
  mapping(address=>uint256) public balances;
  function credit(uint256 amount) external {
    total = total.add(amount);
    balances[msg.sender] = balances[msg.sender].add(amount);
  }
  function debit(uint256 amount) external {
    total = total.sub(amount);
    balances[msg.sender] = balances[msg.sender].sub(amount);
  }
}`;
    const mathLedgerSource={path:'source-1/contracts/MathLedger.sol',
      content:mathLedgerText,sha256:hash(mathLedgerText)};
    const mathLedgerDecls=['credit','debit'].map(name=>({
      selector:'MathLedger.'+name,operation:'send' as const,
      inputs:['uint256'],outputs:[],stateMutability:'nonpayable' as const
    }));
    const mathBuilt=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:mathLedgerSource.path,
      targetSelector:'MathLedger.debit',sources:[mathLedgerSource],
      declarations:mathLedgerDecls as any,skipLegacy:true
    });
    assert.equal(mathBuilt.ok,true,
      'Acquired Same-lvalue SafeMath.add/sub accounting pairs must be constructible');
    if(mathBuilt.ok)assert.ok(mathBuilt.experiments.some(e=>
      e.securityProperty.startsWith('financial ')),
      'Must construct an actual financial conservation experiment');
    const falsePairText=mathLedgerText.replace(
      'total = total.sub(amount);','total = balances[msg.sender].sub(amount);');
    const falsePairSource={...mathLedgerSource,content:falsePairText,
      sha256:hash(falsePairText)};
    const falseBuilt=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:falsePairSource.path,
      targetSelector:'MathLedger.debit',sources:[falsePairSource],
      declarations:mathLedgerDecls as any,skipLegacy:true
    });
    assert.equal(falseBuilt.ok,true,
      'A broken total ledger must remain an executable falsification candidate');
    if(falseBuilt.ok)assert.ok(falseBuilt.experiments.some(e=>
      e.securityProperty.startsWith('financial ')&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='total()'&&step.expect==='600')),
      'The invariant must test total conservation even if only the balance ledger has an opposing write');
    // Inherited methods use their ORIGINAL file's AST offsets; applying
    // those offsets to the child file falsely erases source-backed effects.
    const parentLedgerText=`pragma solidity ^0.8.0;
contract ParentLedger {
  uint256 public total;
  mapping(address=>uint256) public balances;
  function _credit(uint256 amount) internal {
    total += amount;
    balances[msg.sender] += amount;
  }
  function debit(uint256 amount) external {
    total -= amount;
    balances[msg.sender] -= amount;
  }
}`;
    const childLedgerText=`pragma solidity ^0.8.0;
import "./ParentLedger.sol";
contract ChildLedger is ParentLedger {
  function credit(uint256 amount) external { _credit(amount); }
}`;
    const parentLedger={path:'source-1/contracts/ParentLedger.sol',
      content:parentLedgerText,sha256:hash(parentLedgerText)};
    const childLedger={path:'source-1/contracts/ChildLedger.sol',
      content:childLedgerText,sha256:hash(childLedgerText)};
    const inheritedLedgerBuilt=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:childLedger.path,
      targetSelector:'ChildLedger.credit',sources:[childLedger,parentLedger],
      declarations:[
        {selector:'ChildLedger.credit',operation:'send',inputs:['uint256']},
        {selector:'ChildLedger.debit',operation:'send',inputs:['uint256']}
      ] as any,skipLegacy:true
    });
    assert.equal(inheritedLedgerBuilt.ok,true,
      'Source-file-backed inherited accounting methods must create an executable experiment');
    if(inheritedLedgerBuilt.ok)assert.ok(inheritedLedgerBuilt.experiments.some(e=>
      e.securityProperty.startsWith('financial ')&&
      e.witnesses.some(w=>w.path===parentLedger.path&&w.sourceSha256===parentLedger.sha256)),
      'Inherited function evidence must cite the original parent source and SHA');
    const ledgerExperiment=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:ledgerSource.path,
      targetSelector:'Ledger.debit',sources:[ledgerSource],
      declarations:ledgerDeclarations as any,skipLegacy:true});
    assert.equal(ledgerExperiment.ok,true,
      'Distinct source-proven accounting companions must each be executable');
    if(ledgerExperiment.ok)
      assert.equal(ledgerExperiment.experiments.length,2,
        'Credit and reward are independent opposing transitions for debit');
    // Regression 1: receive() external payable has AST name===null; never emit "null()"
    // or pass an EOA into an isContract()-checked initializer parameter.
    const benqiLikeText=`pragma solidity ^0.8.0;
interface IComp { function claimReward(uint8 rewardType, address holder) external; }
contract EthReceiveMarket {
  IComp public comptroller;
  address payable public rewards;
  function initialize(address _comptroller, address payable _rewards) external {
    require(_comptroller.code.length > 0);
    comptroller = IComp(_comptroller);
    rewards = _rewards;
  }
  function claimRewards() external {
    comptroller.claimReward(0, address(this));
    rewards.transfer(address(this).balance);
  }
  receive() external payable {}
}`;
    const benqiLike={path:'source-1/contracts/EthReceiveMarket.sol',
      content:benqiLikeText,sha256:hash(benqiLikeText)};
    const benqiBuilt=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:benqiLike.path,
      targetSelector:'EthReceiveMarket.claimRewards',sources:[benqiLike],
      declarations:[
        {selector:'EthReceiveMarket.initialize',operation:'send',inputs:['address','address']},
        {selector:'EthReceiveMarket.claimRewards',operation:'send',inputs:[]},
      ] as any,skipLegacy:true
    });
    if(benqiBuilt.ok){
      for(const exp of benqiBuilt.experiments){
        assert.ok(!exp.sequence.steps.some(s=>'function' in s && String(s.function).includes('null(')),
          'Unnamed receive() must never produce an invalid null() ABI selector');
      }
    }

    // Regression 2: v4 checkpoint reconciliation must prune a legacy witnessless
    // duplicate property ONLY when a source-witnessed property with verified EVM
    // evidence already covers the exact same experimentId(s).
    const witnesslessFile=join(dir,'v4-witnessless.json');
    const singleLead=candidates.slice(0,1);
    const wlStore=await AnalysisProgressStore.open(witnesslessFile,singleLead);
    const wlExpId=hash('verified-init-exp');
    const wlBatch=wlStore.nextBatch(1,1);
    wlStore.recordAssessment(wlBatch[0].id,[hash('legacy-hyp')],[],[wlExpId]);
    wlStore.markExperimentCompleted(wlExpId,{result:'not_observed',
      evidenceId:hash('ev:'+wlExpId),verifierDigest:hash('digest:'+wlExpId)});
    // Without source witnesses, the lead MUST remain inconclusive.
    assert.equal(wlStore.experimentCertificate.conclusive,0,
      'A witnessless test_completed property alone must never certify a lead');
    // Adding a verified source-witnessed property for the exact same experimentId
    // supersedes the legacy witnessless duplicate and certifies the lead.
    wlStore.addRepairExperiment(wlBatch[0].id,hash('witnessed-prop'),wlExpId,
      [singleLead[0].path+':'+singleLead[0].sourceSha256+':0:10',
       'source-1/contracts/Base.sol:'+hash('base-source')+':0:10']);
    assert.equal(wlStore.experimentCertificate.conclusive,1,
      'Verified source-witnessed property for exact same experimentId must supersede witnessless duplicate');
    assert.equal(wlStore.records.get(wlBatch[0].id)!.lifecycle,'experiment_completed');
    // Also verify open() heals an already-persisted v4 checkpoint carrying both properties.
    await wlStore.save();
    const rawWl=JSON.parse(await readFile(witnesslessFile,'utf8')) as any;
    rawWl.records[0].properties.unshift({id:hash('stale-legacy-dup'),state:'test_completed',
      sourceWitnesses:[],unresolvedPrerequisites:[],experimentIds:[wlExpId]});
    rawWl.records[0].lifecycle='dependencies_pending';
    await writeFile(witnesslessFile,JSON.stringify(rawWl,null,2),'utf8');
    const healedWl=await AnalysisProgressStore.open(witnesslessFile,singleLead);
    assert.equal(healedWl.experimentCertificate.conclusive,1,
      'Opening a v4 checkpoint with a subsumed witnessless duplicate must heal cleanly');
    assert.equal(healedWl.records.get(wlBatch[0].id)!.lifecycle,'experiment_completed');

    // Regression 3: non-numeric `address public rewards` must NOT be misclassified
    // as a numeric interest-accrual accounting counter attaching ERC20 calls to setRewards.
    const rewardsMarketText=`pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address a) external view returns (uint256); function transfer(address to, uint256 amt) external returns (bool); }
contract RewardsMarket {
  address public owner;
  address public rewards;
  IERC20 public token;
  modifier onlyOwner() { require(msg.sender == owner); _; }
  function setRewards(address newRewards) external onlyOwner { rewards = newRewards; }
  function claimRewards() external { token.transfer(rewards, token.balanceOf(address(this))); }
}`;
    const rewardsGraph=buildProgramFactsGraph({sources:[{path:'source-1/contracts/RewardsMarket.sol',content:rewardsMarketText}]});
    const rewardsRels=generateRelationalHypotheses(rewardsGraph);
    assert.ok(!rewardsRels.some(r=>r.entrypoints.includes('RewardsMarket.setRewards')&&
      r.unresolvedPrerequisites.some(u=>u.includes('IERC20')||u.includes('balanceOf')||u.includes('transfer'))),
      'address public rewards must not attach claimRewards ERC20 calls to setRewards');
    // Reconciling stale relational blockers against fresh graph preserves genuine blockers.
    const relFile=join(dir,'v4-relational.json');
    const relStore=await AnalysisProgressStore.open(relFile,singleLead);
    relStore.nextBatch(1,1);
    relStore.recordAssessment(singleLead[0].id,[],[
      'unresolved_call:ERC20.balanceOf','unresolved_external_call:ERC20.safeTransfer'
    ],[wlExpId],[],[{id:hash('set-rewards-prop'),experimentIds:[wlExpId],
      sourceWitnesses:[singleLead[0].path+':'+singleLead[0].sourceSha256+':0:10']}]);
    relStore.markExperimentCompleted(wlExpId,{result:'not_observed',
      evidenceId:hash('ev2:'+wlExpId),verifierDigest:hash('digest2:'+wlExpId)});
    assert.equal(relStore.experimentCertificate.conclusive,0);
    assert.equal(relStore.reconcileRelationalPrerequisites(singleLead[0].id,
      new Set(['unresolved_call:ERC20.balanceOf'])),true);
    assert.equal(relStore.experimentCertificate.conclusive,0,
      'Still-present relational unresolved calls must remain blocking');
    assert.equal(relStore.reconcileRelationalPrerequisites(singleLead[0].id,new Set()),true);
    assert.equal(relStore.experimentCertificate.conclusive,1,
      'Once fresh graph confirms zero relational blockers, verified lead becomes conclusive');

    // Regression 4: resolveAcquiredConcreteImplementations must support ArrayTypeName
    // parameters (ERC1155 mintBatch) and UserDefinedTypeName public getters (MoneyMarket.stablecoin).
    const arrayBaseText=`pragma solidity ^0.8.0;
interface IToken {}
abstract contract BatchMarketBase {
  function stablecoin() external view virtual returns (IToken);
  function mint(address to, uint256 id, uint256 amt) external virtual;
  function mintBatch(address to, uint256[] memory ids, uint256[] memory amts) external virtual;
}`;
    const arrayChildText=`pragma solidity ^0.8.0;
import "./BatchMarketBase.sol";
contract ConcreteBatchMarket is BatchMarketBase {
  IToken public override stablecoin;
  function mint(address to, uint256 id, uint256 amt) external override {}
  function mintBatch(address to, uint256[] memory ids, uint256[] memory amts) external override {}
}`;
    const arrayBase={path:'source-1/contracts/BatchMarketBase.sol',
      content:arrayBaseText,sha256:hash(arrayBaseText)};
    const arrayChild={path:'source-1/contracts/ConcreteBatchMarket.sol',
      content:arrayChildText,sha256:hash(arrayChildText)};
    const arrayImpls=resolveAcquiredConcreteImplementations(
      arrayBase,'BatchMarketBase','mint',[arrayBase,arrayChild]);
    assert.deepEqual(arrayImpls.map(x=>x.selector),['ConcreteBatchMarket.mint'],
      'Concrete subclasses with array-typed methods and contract-typed public getters must resolve');
    const batchImpls=resolveAcquiredConcreteImplementations(
      arrayBase,'BatchMarketBase','mintBatch',[arrayBase,arrayChild]);
    assert.deepEqual(batchImpls.map(x=>x.selector),['ConcreteBatchMarket.mintBatch']);
    assert.deepEqual(batchImpls[0].inputs,['address','uint256[]','uint256[]']);

    // Regression 5: BoringOwnable two-step claimOwnership authorization experiment.
    const boringOwnableText=`pragma solidity ^0.8.0;
contract TwoStepOwnable {
  address public owner;
  address public pendingOwner;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner); _; }
  function transferOwnership(address newOwner, bool direct, bool renounce) public onlyOwner {
    if (direct) {
      require(newOwner != address(0) || renounce);
      owner = newOwner;
      pendingOwner = address(0);
    } else {
      pendingOwner = newOwner;
    }
  }
  function claimOwnership() public {
    address _pendingOwner = pendingOwner;
    require(msg.sender == _pendingOwner);
    owner = _pendingOwner;
    pendingOwner = address(0);
  }
}`;
    const boringSnap={path:'source-1/contracts/TwoStepOwnable.sol',
      content:boringOwnableText,sha256:hash(boringOwnableText)};
    const boringClaim=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:boringSnap.path,
      targetSelector:'TwoStepOwnable.claimOwnership',sources:[boringSnap],
      declarations:[
        {selector:'TwoStepOwnable.owner',operation:'call',inputs:[]},
        {selector:'TwoStepOwnable.pendingOwner',operation:'call',inputs:[]},
        {selector:'TwoStepOwnable.transferOwnership',operation:'send',inputs:['address','bool','bool']},
        {selector:'TwoStepOwnable.claimOwnership',operation:'send',inputs:[]},
      ] as any,skipLegacy:true
    });
    assert.equal(boringClaim.ok,true,
      'Two-step BoringOwnable.claimOwnership must construct a source-proven ownership claim guard');
    if(boringClaim.ok){
      const claimExp=boringClaim.experiments.find(e=>e.securityProperty.includes('two-step ownership claim'));
      assert.ok(claimExp,'Must produce two-step ownership claim property');
      const sends=claimExp.sequence.steps.filter(s=>s.operation==='send') as any[];
      assert.deepEqual(sends.map(s=>s.function),[
        'transferOwnership(address,bool,bool)','claimOwnership()','claimOwnership()']);
      assert.equal(sends[1].sender,1);
      assert.equal(sends[1].expectRevert,true);
      assert.equal(sends[2].sender,2);
    }

    const changed=candidates.map(c=>({...c}));
    changed[0].sourceSha256=hash('changed source');
    await assert.rejects(AnalysisProgressStore.open(file,changed),/SOURCE_MISMATCH/);
    console.log('Round 3 full inventory and checkpoint lifecycle PASSED: 244/244, 64/64, restart, source mismatch');
  }finally{
    await rm(dir,{recursive:true,force:true});
  }
}
void run().catch(error=>{console.error(error);process.exitCode=1;});
