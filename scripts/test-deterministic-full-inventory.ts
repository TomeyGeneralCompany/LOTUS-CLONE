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
import {resolveSourceFixtureDependencies,resolveAcquiredConcreteImplementations,resolveAcquiredInterfaceCallers} from '../packages/security-solver/src/deterministic/fixture-dependency-planner';
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
    assert.equal(lock.completedCount,64);
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
    assert.equal(fixture.status,'resolved');
    if(fixture.status==='resolved'){
      assert.equal(fixture.deployments.length,2);
      assert.deepEqual(fixture.deployments.map(x=>x.contract),['Token','Adapter']);
      assert.equal(fixture.substitutions._adapter,'$deployment:dependency2');
      assert.equal(fixture.bindings[0].receiver,'adapter');
      assert.ok(fixture.witnesses.some(x=>x.sourceSha256===fixtureSources[0].sha256));
    }
    // Initializer-only dependencies can be discovered after the consumer was
    // registered. Execution must deploy the producer before the consumer.
    const initializedAdapter='pragma solidity ^0.8.0; contract Adapter is IAdapter { Token public token; function initialize(address _token) external { token = Token(_token); } }';
    const initialized=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      fixtureSources[0],{...fixtureSources[1],content:initializedAdapter,
        sha256:hash(initializedAdapter)},fixtureSources[2]]);
    assert.equal(initialized.status,'resolved',
      'A source-bound initializer dependency must produce a complete fixture');
    if(initialized.status==='resolved'){
      assert.deepEqual(initialized.deployments.map(x=>x.contract),['Token','Adapter'],
        'Producer deployment must precede initializer consumer deployment');
      assert.equal(initialized.initializerOperations.length,1);
      assert.equal(initialized.initializerOperations[0].args[0],
        '$deployment:'+initialized.deployments[0].id);
    }
    // An acquired dependency whose initializer cannot be completely bound
    // must not be reported as an executable fixture.
    const unboundAdapter='pragma solidity ^0.8.0; contract Adapter is IAdapter { constructor(Token token) {} function initialize(string memory configuration) external {} }';
    const unbound=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      fixtureSources[0],{...fixtureSources[1],content:unboundAdapter,sha256:hash(unboundAdapter)},fixtureSources[2]]);
    assert.equal(unbound.status,'unresolved',
      'Missing initializer arguments must invalidate the acquired deployment graph');
    if(unbound.status==='unresolved')
      assert.ok(unbound.missingDependencies.some(x=>x.includes('unsupported_initializer_parameter')||
        x.includes('incomplete_initializer_arguments')));
    const ambiguousSource='pragma solidity ^0.8.0; contract AdapterTwo is IAdapter {}';
    const ambiguous=resolveSourceFixtureDependencies(fixtureSources[0],'Vault',[
      ...fixtureSources,{path:'source-1/contracts/AdapterTwo.sol',content:ambiguousSource,sha256:hash(ambiguousSource)}]);
    assert.equal(ambiguous.status,'unresolved');
    if(ambiguous.status==='unresolved')
      assert.ok(ambiguous.missingDependencies.some(x=>x.includes('ambiguous_implementation')));
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
    assert.equal(resolveAcquiredInterfaceCallers(icSnap,'ICToken','burn',
      [icSnap,callerSnap]).length,0,'No invented interface method');
    const changed=candidates.map(c=>({...c}));
    changed[0].sourceSha256=hash('changed source');
    await assert.rejects(AnalysisProgressStore.open(file,changed),/SOURCE_MISMATCH/);
    console.log('Round 3 full inventory and checkpoint lifecycle PASSED: 244/244, 64/64, restart, source mismatch');
  }finally{
    await rm(dir,{recursive:true,force:true});
  }
}
void run().catch(error=>{console.error(error);process.exitCode=1;});
