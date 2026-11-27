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
import {createRequire} from 'node:module';
import {ControllerStageLock} from '../packages/security-solver/src/controller-stage-lock';
import {AnalysisProgressStore} from '../packages/security-solver/src/deterministic/analysis-progress-store';
import {sourceRepairRoutes} from '../packages/security-solver/src/deterministic/typed-repair-routes';
import {repairAttemptIdentity} from '../packages/security-solver/src/deterministic/repair-attempt-identity';
import {unfittedVerifierTranscript} from '../packages/security-solver/src/deterministic/verifier-transcript';
import {proposeInterfaceUnavailability,independentlyReviewInterfaceUnavailability} from '../packages/security-solver/src/deterministic/source-unavailability-verifier';
import {reconcileStagedLeadSelectors} from '../packages/security-solver/src/deterministic/analysis-candidate-queue';
import {resolveSourceFixtureDependencies,enumerateSourceFixtureDependencies,enumerateSourceFixtureDependenciesDetailed,resolveAcquiredConcreteImplementations,resolveAcquiredInterfaceCallers,verifyAcquiredReceiverMethods,enumerateAcquiredInheritedAbi} from '../packages/security-solver/src/deterministic/fixture-dependency-planner';
import {extractAccountingObservations} from '../packages/security-solver/src/deterministic/accounting-observations';
import type {AnalysisCandidate} from '../packages/security-solver/src/deterministic/analysis-candidate-queue';
import {constructSolidityExperiments,sourcePreparationGraph,pickFlexibleArg} from '../packages/security-solver/src/controller-solidity-experiment-planner';
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
    // Acquired deterministic clone source and real template are required:
    // same salt must fail after one successful CREATE2 initialization.
    const simpleFactoryText=`pragma solidity ^0.8.4;
import {NFTWithSVG} from "./tokens/NFTWithSVG.sol";
contract Factory {
  function predictAddress(address template,bytes32 salt) external view returns(address) {
    return template.predictDeterministicAddress(salt);
  }
  function createNFT(address template,bytes32 salt,string calldata name,string calldata symbol) external returns(NFTWithSVG) {
    NFTWithSVG clone = NFTWithSVG(template.cloneDeterministic(salt));
    clone.initialize(name,symbol);
    clone.transferOwnership(msg.sender);
    return clone;
  }
}`;
    const simpleNftText=`pragma solidity ^0.8.4;
contract NFTWithSVG {
  function initialize(string memory name,string memory symbol) external {}
}`;
    const factorySnapshot={path:'source-1/contracts/Factory.sol',content:simpleFactoryText,
      sha256:hash(simpleFactoryText)};
    const nftSnapshot={path:'source-1/contracts/tokens/NFTWithSVG.sol',content:simpleNftText,
      sha256:hash(simpleNftText)};
    const factoryMenu=[
      {selector:'Factory.createNFT',operation:'send' as const,
        inputs:['address','bytes32','string','string']},
      {selector:'Factory.predictAddress',operation:'call' as const,
        inputs:['address','bytes32']}
    ];
    const factoryReplay=constructSolidityExperiments({
      repositoryCommit:revision,targetPath:factorySnapshot.path,
      targetSelector:'Factory.createNFT',sources:[factorySnapshot,nftSnapshot],
      declarations:factoryMenu});
    assert.equal(factoryReplay.ok,true,
      'Acquired CREATE2 factory and template must generate executable replay alternatives');
    if(factoryReplay.ok){
      const deterministic=factoryReplay.experiments.filter(e=>
        e.securityProperty.includes('CREATE2 deterministic clone replay'));
      assert.equal(deterministic.length,2);
      assert.ok(deterministic.every(e=>e.sequence.preparation?.deployments[0]?.contract==='NFTWithSVG'));
      assert.ok(deterministic.every(e=>e.sequence.steps.some(step=>
        step.operation==='send'&&step.expectRevert===true)));
      assert.equal(new Set(deterministic.map(e=>e.id)).size,2);
    }
    // A second, unrelated source family exercises real array ABI inputs,
    // bounded uint8 construction, and exact source-forwarded msg.sender.
    // This must be admitted by the same factory engine, not a createNFT name.
    const multitokenFactoryText=`pragma solidity ^0.8.4;
import {FundingMultitoken} from "./tokens/FundingMultitoken.sol";
contract Factory {
  function predictAddress(address template,bytes32 salt) external view returns(address) {
    return template.predictDeterministicAddress(salt);
  }
  function createFundingMultitoken(address template,bytes32 salt,
    address[] calldata dividendTokens,uint8 decimals) external returns(FundingMultitoken) {
    FundingMultitoken clone = FundingMultitoken(template.cloneDeterministic(salt));
    clone.initialize(msg.sender,dividendTokens,decimals);
    return clone;
  }
}`;
    const multitokenText=`pragma solidity ^0.8.4;
contract FundingMultitoken {
  function initialize(address owner,address[] memory tokens,uint8 decimals) external {}
}`;
    const multitokenFactory={path:'source-1/contracts/Factory.sol',
      content:multitokenFactoryText,sha256:hash(multitokenFactoryText)};
    const multitokenTemplate={path:'source-1/contracts/tokens/FundingMultitoken.sol',
      content:multitokenText,sha256:hash(multitokenText)};
    const multitokenReplay=constructSolidityExperiments({
      repositoryCommit:revision,targetPath:multitokenFactory.path,
      targetSelector:'Factory.createFundingMultitoken',
      sources:[multitokenFactory,multitokenTemplate],
      declarations:[
        {selector:'Factory.createFundingMultitoken',operation:'send',
          inputs:['address','bytes32','address[]','uint8']},
        {selector:'Factory.predictAddress',operation:'call',
          inputs:['address','bytes32']}
      ],
    });
    assert.equal(multitokenReplay.ok,true,
      'Array ABI, uint8 bounds and source-forwarded msg.sender admit genuine factory replay');
    if(multitokenReplay.ok){
      const variants=multitokenReplay.experiments.filter(e=>
        e.securityProperty.includes('CREATE2 deterministic clone replay'));
      assert.equal(variants.length,2);
      for(const candidate of variants){
        const firstCreate=candidate.sequence.steps.find(step=>
          step.operation==='send'&&step.function.startsWith('createFundingMultitoken('));
        assert.ok(firstCreate&&firstCreate.operation==='send');
        if(firstCreate&&firstCreate.operation==='send'){
          assert.deepEqual(firstCreate.args[2],[]);
          assert.equal(firstCreate.args[3],'18');
        }
        assert.ok(candidate.sequence.steps.some(step=>
          step.operation==='send'&&step.expectRevert===true));
      }
    }
    const unacquiredTemplate=constructSolidityExperiments({
      repositoryCommit:revision,targetPath:factorySnapshot.path,
      targetSelector:'Factory.createNFT',sources:[factorySnapshot],
      declarations:factoryMenu});
    assert.ok(!unacquiredTemplate.ok||
      !unacquiredTemplate.experiments.some(e=>e.securityProperty.includes(
        'CREATE2 deterministic clone replay')),
      'A missing template must never be replaced with invented deployable bytecode');

    // Initialization replay is a concrete source-state security property,
    // not an ownership-getter heuristic. Prove first setup, exact getters,
    // mined second-call revert, then unchanged getters in the real EVM.
    const initializingSourceText=`pragma solidity ^0.8.4;
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract InitialState is Initializable {
  uint8 public decimals;
  string public name;
  function initialize(uint8 value,string memory title) external initializer {
    decimals = value;
    name = title;
  }
}`;
    const initializingSource={path:'source-1/contracts/InitialState.sol',
      content:initializingSourceText,sha256:hash(initializingSourceText)};
    const initializationMenu=[
      {selector:'InitialState.initialize',operation:'send' as const,inputs:['uint8','string']},
      {selector:'InitialState.decimals',operation:'call' as const,inputs:[]},
      {selector:'InitialState.name',operation:'call' as const,inputs:[]}
    ];
    const initializePlan=constructSolidityExperiments({
      repositoryCommit:revision,targetPath:initializingSource.path,
      targetSelector:'InitialState.initialize',sources:[initializingSource],
      declarations:initializationMenu});
    assert.equal(initializePlan.ok,true,
      'Imported initializable with direct public state writes must yield a verifier experiment');
    if(initializePlan.ok){
      const replay=initializePlan.experiments.find(e=>
        e.securityProperty.includes('initializer replay protection'));
      assert.ok(replay,'Expect source-backed initializer replay property');
      assert.equal(replay!.sequence.steps[0].operation,'send');
      assert.ok(replay!.sequence.steps.some(step=>step.operation==='send'&&step.expectRevert),
        'Second initializer must be a falsifiable failed transaction');
      assert.ok(replay!.sequence.steps.filter(step=>step.operation==='call').length>=2,
        'Original typed state must be verified after setup and replay');
    }
    const unguardedText=initializingSourceText.replace('external initializer','external');
    const unguardedSource={...initializingSource,
      content:unguardedText,sha256:hash(unguardedText)};
    const noReplay=constructSolidityExperiments({
      repositoryCommit:revision,targetPath:unguardedSource.path,
      targetSelector:'InitialState.initialize',sources:[unguardedSource],
      declarations:initializationMenu});
    assert.ok(!noReplay.ok || !noReplay.experiments.some(e=>
      e.securityProperty.includes('initializer replay protection')),
      'An unguarded initializer cannot be mis-certified as replay protected');
    // An acquired interface may have multiple real ABI-compatible concrete
    // implementers. Enumerate distinct DAGs instead of refusing every one
    // or choosing the first arbitrarily. Never create an absent implementer.
    const intf='pragma solidity ^0.8.4; interface IQuote { function quote() external view returns(uint256); }';
    const implA='pragma solidity ^0.8.4; import "./IQuote.sol"; contract QuoteA is IQuote { function quote() external pure override returns(uint256) { return 1; } }';
    const implB='pragma solidity ^0.8.4; import "./IQuote.sol"; contract QuoteB is IQuote { function quote() external pure override returns(uint256) { return 2; } }';
    const consumer='pragma solidity ^0.8.4; import "./IQuote.sol"; contract QuoteConsumer { IQuote public quoteSource; constructor(IQuote _quoteSource) { quoteSource = _quoteSource; } function run() external view returns(uint256) {return quoteSource.quote();}}';
    const typedSrc=(name:string,solidity:string)=>({path:'source-1/contracts/'+name+'.sol',
      content:solidity,sha256:hash(solidity)});
    const quoteSource=typedSrc('IQuote',intf),firstSource=typedSrc('QuoteA',implA),
      secondSource=typedSrc('QuoteB',implB),consumerSource=typedSrc('QuoteConsumer',consumer);
    const acquire=[quoteSource,firstSource,secondSource,consumerSource];
    const cachedAbiResult=verifyAcquiredReceiverMethods('IQuote',['quote'],
      firstSource.path,'QuoteA',acquire,quoteSource.path);
    assert.equal(cachedAbiResult.ok,true,
      'Acquired interface ABI must verify the selected concrete implementation');
    cachedAbiResult.missing.push('caller-mutated-result');
    assert.deepEqual(verifyAcquiredReceiverMethods('IQuote',['quote'],
      firstSource.path,'QuoteA',acquire,quoteSource.path),{ok:true,missing:[]},
      'Mutating a returned ABI result must not poison the cached verification');
    const quoteAmbiguity=resolveSourceFixtureDependencies(consumerSource,'QuoteConsumer',acquire);
    assert.equal(quoteAmbiguity.status,'unresolved',
      'Ambiguous sources must not be assigned arbitrary single deployment');
    assert.ok(quoteAmbiguity.status==='unresolved'&&quoteAmbiguity.missingDependencies
      .some(x=>x.includes('ambiguous_implementation')));
    const resolvedChoices=enumerateSourceFixtureDependencies(
      consumerSource,'QuoteConsumer',acquire);
    assert.equal(resolvedChoices.length,2,
      'Both acquired concrete source and ABI alternatives remain executable');
    assert.deepEqual(new Set(resolvedChoices.flatMap(plan=>
      plan.deployments.map(deployment=>deployment.contract))),
      new Set(['QuoteA','QuoteB']));
    const truncatedChoices=enumerateSourceFixtureDependenciesDetailed(
      consumerSource,'QuoteConsumer',acquire,{maxAlternatives:1});
    assert.equal(truncatedChoices.alternatives.length,1);
    assert.equal(truncatedChoices.complete,false,
      'A bounded search that leaves a valid acquired alternative pending must be marked incomplete');
    assert.ok(truncatedChoices.pendingSelections>0);
    const fullChoices=enumerateSourceFixtureDependenciesDetailed(
      consumerSource,'QuoteConsumer',acquire);
    assert.equal(fullChoices.complete,true,
      'An exhausted source-backed search must explicitly report complete coverage');
    assert.equal(fullChoices.alternatives.length,2);
    resolvedChoices[0].deployments[0].contract='caller-mutated-result';
    const immutableCachedChoices=enumerateSourceFixtureDependencies(
      consumerSource,'QuoteConsumer',acquire);
    assert.ok(immutableCachedChoices.some(plan=>plan.deployments.some(deployment=>
      deployment.contract==='QuoteA')),
      'Mutating a returned fixture graph must not poison cached source alternatives');

    // Receiver methods in separate source owners are separate fixture
    // obligations even when both import the same interface. A deposit-only
    // consumer must not inherit a withdraw requirement from an unrelated
    // consumer elsewhere in the acquired inventory.
    const routeInterface=typedSrc('IRoute',
      'pragma solidity ^0.8.4; interface IRoute { function deposit() external; function withdraw() external; }');
    const depositRoute=typedSrc('DepositRoute',
      'pragma solidity ^0.8.4; contract DepositRoute { function deposit() external {} }');
    const withdrawRoute=typedSrc('WithdrawRoute',
      'pragma solidity ^0.8.4; contract WithdrawRoute { function withdraw() external {} }');
    const depositConsumer=typedSrc('DepositConsumer',
      'pragma solidity ^0.8.4; import "./IRoute.sol"; contract DepositConsumer { IRoute public route; function initialize(IRoute _route) external { route = _route; } function run() external { route.deposit(); } }');
    const withdrawConsumer=typedSrc('WithdrawConsumer',
      'pragma solidity ^0.8.4; import "./IRoute.sol"; contract WithdrawConsumer { IRoute public route; function initialize(IRoute _route) external { route = _route; } function run() external { route.withdraw(); } }');
    const separatedConsumers=[routeInterface,depositRoute,withdrawRoute,
      depositConsumer,withdrawConsumer];
    const depositGraph=resolveSourceFixtureDependencies(depositConsumer,
      'DepositConsumer',separatedConsumers);
    assert.equal(depositGraph.status,'resolved',
      'An unrelated consumer method must not contaminate this source owner\'s fixture ABI: '+
      JSON.stringify(depositGraph));
    if(depositGraph.status==='resolved')assert.ok(depositGraph.deployments.some(
      deployment=>deployment.contract==='DepositRoute'));
    // Public getters for structs can expose nested tuple members. Preserve
    // nested ABI boundaries instead of splitting every comma as a top-level
    // output or rejecting source-identified state as unobservable.
    const nestedGetter=typedSrc('NestedGetter',
      'pragma solidity ^0.8.4; contract NestedGetter { struct Identity { uint256 id; address account; } struct Position { uint256 shares; Identity identity; uint256 debt; } Position public position; }');
    const nestedGetterAbi=enumerateAcquiredInheritedAbi(nestedGetter,
      'NestedGetter','NestedGetter',[nestedGetter]);
    assert.ok(nestedGetterAbi.some(entry=>
      entry.selector==='NestedGetter.position'&&
      JSON.stringify(entry.outputs)===JSON.stringify([
        'uint256','(uint256,address)','uint256'
      ])),
      'Nested public struct getter must retain its exact nested ABI tuple output');
    // Solidity omits mapping-valued struct members from an autogenerated
    // public getter but still exposes the remaining fields. This is the shape
    // used by ERC1155DividendToken.DividendTokenData. Compare the source
    // resolver with solc's ABI so getter behavior is compiler-verified.
    const dividendGetterText=`pragma solidity ^0.8.4;
contract DividendGetter {
  struct DividendTokenData {
    address dividendToken;
    mapping(uint256 => uint256) magnifiedDividendPerShare;
    mapping(address => int256) magnifiedDividendCorrections;
    mapping(address => uint256) withdrawnDividends;
  }
  mapping(uint256 => DividendTokenData) public dividendTokenDataList;
}`;
    const dividendGetter=typedSrc('DividendGetter',dividendGetterText);
    const sourceGetterAbi=enumerateAcquiredInheritedAbi(dividendGetter,
      'DividendGetter','DividendGetter',[dividendGetter]).find(entry=>
        entry.selector==='DividendGetter.dividendTokenDataList');
    assert.ok(sourceGetterAbi,'Public mapping-to-struct getter must be source-resolved');
    const runtimeRequire=createRequire(join(process.cwd(),
      'scripts/reproduction-runtime/probe.cjs'));
    let solc:any=null;
    try{solc=runtimeRequire('solc');}
    catch(error){
      if((error as NodeJS.ErrnoException).code!=='MODULE_NOT_FOUND')throw error;
    }
    if(solc){
      const compiledGetter=JSON.parse(solc.compile(JSON.stringify({
        language:'Solidity',sources:{[dividendGetter.path]:{content:dividendGetterText}},
        settings:{outputSelection:{'*':{'*':['abi']}}},
      })));
      const compilerGetter=compiledGetter.contracts[dividendGetter.path].DividendGetter.abi
        .find((entry:any)=>entry.type==='function'&&entry.name==='dividendTokenDataList');
      assert.ok(compilerGetter,'Solc must expose the mapping getter');
      const canonicalCompilerOutput=(output:any):string=>output.type.startsWith('tuple')?
        '('+(output.components||[]).map(canonicalCompilerOutput).join(',')+')'+
          output.type.slice('tuple'.length):output.type;
      assert.deepEqual(sourceGetterAbi.outputs,
        compilerGetter.outputs.map(canonicalCompilerOutput),
        'Mapping-valued struct fields must be omitted exactly as the pinned Solidity compiler does');
    }
    // SafeERC20 extension calls are not token ABI requirements. Resolve the
    // acquired library body to the underlying IERC20 selector before matching
    // a concrete receiver; otherwise xMPH's token fixture is rejected for
    // lacking a fictitious `safeTransferFrom` method.
    const erc20Interface=typedSrc('IERC20',
      'pragma solidity ^0.8.4; interface IERC20 { function transferFrom(address,address,uint256) external returns(bool); }');
    const safeTokenLibrary=typedSrc('SafeERC20',
      'pragma solidity ^0.8.4; import "./IERC20.sol"; library SafeERC20 { function safeTransferFrom(IERC20 token,address from,address to,uint256 amount) internal { require(token.transferFrom(from,to,amount)); } }');
    const concreteToken=typedSrc('TokenFixture',
      'pragma solidity ^0.8.4; import "./IERC20.sol"; contract TokenFixture is IERC20 { function transferFrom(address,address,uint256) external pure override returns(bool) { return true; } }');
    const tokenConsumer=typedSrc('TokenConsumer',
      'pragma solidity ^0.8.4; import "./IERC20.sol"; import "./SafeERC20.sol"; contract TokenConsumer { using SafeERC20 for IERC20; IERC20 public token; function initialize(IERC20 _token) external { token = _token; } function deposit() external { token.safeTransferFrom(msg.sender,address(this),1); } }');
    const tokenFixtureGraph=resolveSourceFixtureDependencies(tokenConsumer,
      'TokenConsumer',[erc20Interface,safeTokenLibrary,concreteToken,tokenConsumer]);
    assert.equal(tokenFixtureGraph.status,'resolved',
      'SafeERC20.safeTransferFrom must resolve to acquired IERC20.transferFrom: '+
      JSON.stringify(tokenFixtureGraph));
    if(tokenFixtureGraph.status==='resolved')assert.ok(tokenFixtureGraph.deployments.some(
      deployment=>deployment.contract==='TokenFixture'));
    assert.deepEqual(enumerateSourceFixtureDependencies(consumerSource,
      'QuoteConsumer',[quoteSource,consumerSource]),[],
      'No acquired implementation must never become an invented fixture');
    const missingFixtureCoverage=enumerateSourceFixtureDependenciesDetailed(
      consumerSource,'QuoteConsumer',[quoteSource,consumerSource]);
    assert.equal(missingFixtureCoverage.complete,false,
      'Missing acquired fixture branches must remain explicit blockers');
    assert.ok(missingFixtureCoverage.unresolvedSelections.some(item=>
      item.missingDependencies.some(reason=>reason.includes('no_acquired_abi_compatible_implementation'))));
    assert.throws(()=>enumerateSourceFixtureDependencies(consumerSource,
      'QuoteConsumer',acquire,{maxAlternatives:4097}),/INVALID_FIXTURE_ALTERNATIVE_LIMIT/);
    assert.throws(()=>enumerateSourceFixtureDependencies(consumerSource,
      'QuoteConsumer',acquire,{maxSearchNodes:0}),/INVALID_FIXTURE_SEARCH_LIMIT/);

    // Real EVM transcripts may exceed the local model exchange budget. The
    // fitted model-visible summary cannot replace the canonical verifier bytes.
    const fullEvmTranscript=JSON.stringify({status:'behavior_not_observed',
      source_sha256:sourceSha,observations:{steps:Array.from({length:600},
        (_,i)=>({operation:'call',value:'0'.repeat(120),index:i}))}});
    const fitted=JSON.stringify({status:'behavior_not_observed',
      truncated:true,excerpt:fullEvmTranscript.slice(0,280)});
    assert.equal(unfittedVerifierTranscript(fullEvmTranscript,fitted),fullEvmTranscript,
      'Use the actual executed, source-identifying transcript');
    assert.equal(unfittedVerifierTranscript(undefined,fitted),fitted,
      'Without executed raw bytes no verifier evidence can be synthesized');
    assert.equal(unfittedVerifierTranscript('not-json',fitted),fitted);
    const changedStatus=JSON.stringify({status:'behavior_observed',truncated:true});
    assert.equal(unfittedVerifierTranscript(fullEvmTranscript,changedStatus),changedStatus,
      'Divergent display status must not silently inherit a full verifier result');
    // ABI width and signedness constrain all source-derived fixture literals,
    // including the exact uint8 _decimals failure observed on the Dell.
    assert.equal(pickFlexibleArg('uint8','_decimals'),'18');
    assert.equal(pickFlexibleArg('uint8','_amount'),'255');
    assert.equal(pickFlexibleArg('int8','_amount'),'127');
    assert.equal(pickFlexibleArg('uint16','_duration'),'65535');
    assert.equal(pickFlexibleArg('uint64','_duration'),'86400');
    assert.equal(pickFlexibleArg('uint8','_amount',{amount:'1000'}),'255');
    assert.equal(pickFlexibleArg('uint7','_amount'),null);
    // Partial executable properties retain real evidence without pretending
    // that their separately blocked source property was also verified.
    const partialLead=candidates[1];
    const partialStore=await AnalysisProgressStore.open(
      join(dir,'partial-source-properties.json'),[partialLead]);
    partialStore.nextBatch(1,1);
    partialStore.recordAssessment(partialLead.id,[],
      ['source_grounded_falsifier_missing'],[]);
    const partialWitness=partialLead.path+':'+partialLead.sourceSha256+':method';
    partialStore.addRepairExperiment(partialLead.id,'partial-property',
      'partial-experiment',[partialWitness],false,false);
    partialStore.markExperimentCompleted('partial-experiment',{
      evidenceId:'synthetic-checkpoint-regression-transcript',
      result:'not_observed',verifierDigest:hash('synthetic-evidence-digest')});
    assert.equal(partialStore.experimentCertificate.conclusive,0,
      'Partial proof cannot supersede another unmet property');
    assert.deepEqual(partialStore.experimentCertificate.unresolvedIds,[partialLead.id]);

    // A changed property engine must reopen unresolved checkpoints, never
    // reuse the old blocked assessment as proof that it was reevaluated.
    // Preserve the old source-bound property and attempt history for audit.
    const revisionFile=join(dir,'engine-revision-reassessment.json');
    const revisionCandidate=candidates[0];
    const priorEngine=await AnalysisProgressStore.open(revisionFile,
      [revisionCandidate],'property-engine-old');
    priorEngine.nextBatch(1,1);
    priorEngine.recordAssessment(revisionCandidate.id,[],
      ['source_grounded_falsifier_missing'],[]);
    await priorEngine.save();
    const rescanned=await AnalysisProgressStore.open(revisionFile,
      [revisionCandidate],'property-engine-current');
    assert.equal(rescanned.remaining,1,
      'Engine revision must requeue the actual unresolved source lead');
    assert.equal(rescanned.records.get(revisionCandidate.id)?.properties[0]
      ?.unresolvedPrerequisites[0],'source_grounded_falsifier_missing',
      'Reassessment must preserve the prior unmet prerequisite as evidence history');
    await rescanned.save();
    const sameEngine=await AnalysisProgressStore.open(revisionFile,
      [revisionCandidate],'property-engine-current');
    assert.equal(sameEngine.remaining,1,
      'Restarting the same revision cannot discard unfinished analysis');
    sameEngine.nextBatch(1,1);
    sameEngine.recordAssessment(revisionCandidate.id,[],
      ['source_grounded_falsifier_missing'],[]);
    await sameEngine.save();
    const completedAssessment=await AnalysisProgressStore.open(revisionFile,
      [revisionCandidate],'property-engine-current');
    assert.equal(completedAssessment.remaining,0,
      'An unchanged engine must resume an already analyzed source lead');
    const nextEngine=await AnalysisProgressStore.open(revisionFile,
      [revisionCandidate],'property-engine-next');
    assert.equal(nextEngine.remaining,1,
      'A later engine revision must reassess unresolved leads again');

    // A nondeployable interface is NOT automatically source-unavailable.
    // The entire acquired inventory must prove the absence of any executable
    // implementer and any typed callsite, with a second independent check.
    const orphanText='pragma solidity ^0.8.20; interface IOrphan { function act(uint256 amount) external; }';
    const orphanSource={path:'source-1/contracts/IOrphan.sol',content:orphanText,
      sha256:hash(orphanText)};
    const orphanLead:AnalysisCandidate={...candidates[0],id:hash('orphan-lead'),
      path:orphanSource.path,selector:'IOrphan.act',
      sourceSha256:orphanSource.sha256,sourceExcerpt:orphanText};
    const orphanSources=[orphanSource];
    const orphanProposal=proposeInterfaceUnavailability(orphanLead,
      orphanSources,[orphanSource.path]);
    assert.ok(orphanProposal,'Unacquired interface implementation requires typed source review');
    const reviewedOrphan=independentlyReviewInterfaceUnavailability(
      orphanProposal!,orphanSources,[orphanSource.path]);
    assert.ok(reviewedOrphan,'An independent acquired-source review must verify the missing implementation');
    assert.equal(reviewedOrphan?.kind,'interface_without_acquired_implementation');
    assert.equal(proposeInterfaceUnavailability(orphanLead,orphanSources,
      [orphanSource.path,'source-1/contracts/Uninspected.sol']),null,
      'An incomplete expected source inventory is not evidence of unavailability');
    assert.equal(proposeInterfaceUnavailability(orphanLead,
      [{...orphanSource,content:orphanText+'  '}],[orphanSource.path]),null,
      'Source SHA mismatches cannot produce reviewed terminal evidence');
    const implementingText=`pragma solidity ^0.8.20;
import "./IOrphan.sol";
contract Implementer is IOrphan {
  function act(uint256 amount) external override {}
}`;
    const implementingSource={path:'source-1/contracts/Implementer.sol',
      content:implementingText,sha256:hash(implementingText)};
    assert.equal(proposeInterfaceUnavailability(orphanLead,
      [...orphanSources,implementingSource],
      [orphanSource.path,implementingSource.path]),null,
      'Acquired deployable implementation forbids source-unavailable closure');
    const orphanConsumerText=`pragma solidity ^0.8.20;
import "./IOrphan.sol";
contract Consumer {
  IOrphan public target;
  function relay(uint256 amount) external { target.act(amount); }
}`;
    const orphanConsumerSource={path:'source-1/contracts/Consumer.sol',content:orphanConsumerText,
      sha256:hash(orphanConsumerText)};
    assert.equal(proposeInterfaceUnavailability(orphanLead,
      [...orphanSources,orphanConsumerSource],[orphanSource.path,orphanConsumerSource.path]),null,
      'An acquired actual typed caller must remain eligible for recovery');
    const orphanStore=await AnalysisProgressStore.open(
      join(dir,'orphan-source-unavailable.json'),[orphanLead]);
    orphanStore.nextBatch(1,1);
    orphanStore.recordAssessment(orphanLead.id,[],
      ['UNKNOWN_ASSERTION(missing_fixture):interface lacks runtime'],[]);
    assert.throws(()=>orphanStore.recordSourceUnavailable(orphanLead.id,{
      ...reviewedOrphan!,sourceWitnesses:['invented:bad-source']},
      orphanSources,[orphanSource.path]),
      /SOURCE_UNAVAILABLE_REPLAY_VERIFICATION_FAILED/,
      'Unverified witness strings cannot close an interface lead');
    orphanStore.recordSourceUnavailable(orphanLead.id,reviewedOrphan!,
      orphanSources,[orphanSource.path]);
    assert.equal(orphanStore.experimentCertificate.conclusive,0,
      'A source-unavailable lead is NEVER counted as experimentally verified');
    assert.equal(orphanStore.experimentCertificate.sourceUnavailable,1);
    assert.deepEqual(orphanStore.experimentCertificate.sourceUnavailableIds,[orphanLead.id]);
    assert.deepEqual(orphanStore.experimentCertificate.unresolvedIds,[],
      'Independently reviewed source-unavailable evidence is a separate terminal lead disposition');
    assert.equal(orphanStore.terminallyComplete,true,
      'The lead is fully accounted for by a verified unavailable-source disposition');
    assert.equal(orphanStore.nextRepairBatch(2).length,0,
      'Reviewed terminal state should not waste the deterministic repair budget');
    await orphanStore.save();
    const resumedOrphan=await AnalysisProgressStore.open(
      join(dir,'orphan-source-unavailable.json'),[orphanLead]);
    assert.equal(resumedOrphan.experimentCertificate.sourceUnavailable,1,
      'Typed unavailable source evidence survives checkpoint/resume');
    const orphanGate=await stage([orphanLead]);
    orphanGate.restoreResolvedAnalysisCandidate(orphanLead.id);
    orphanGate.completeAnalysis();
    orphanGate.completeExperiments(resumedOrphan.experimentCertificate);
    assert.equal(orphanGate.currentStage,'REVIEW',
      'An independently reviewed source-unavailable disposition is auditable at REVIEW without claiming an experiment');
    const explicitlyUnresolved={...orphanLead,id:hash('explicitly-unresolved-lead')};
    const dispositionGate=await stage([orphanLead,explicitlyUnresolved]);
    dispositionGate.restoreResolvedAnalysisCandidate(orphanLead.id);
    dispositionGate.restoreResolvedAnalysisCandidate(explicitlyUnresolved.id);
    dispositionGate.completeAnalysis();
    const partialCertificate={...resumedOrphan.experimentCertificate,
      manifestDigest:hash(JSON.stringify([orphanLead.id,explicitlyUnresolved.id].sort())),
      total:2,unresolvedIds:[explicitlyUnresolved.id],
      pendingReasons:{[explicitlyUnresolved.id]:['no_source_supported_security_property']}};
    assert.throws(()=>dispositionGate.completeExperiments(partialCertificate),
      /EXPERIMENT_LEAD_COVERAGE_INCOMPLETE/,
      'An explicit unresolved reason must remain visible while blocking REVIEW and REPORT');
    assert.equal(dispositionGate.currentStage,'EXPERIMENT');
    const reasonlessGate=await stage([orphanLead,explicitlyUnresolved]);
    reasonlessGate.restoreResolvedAnalysisCandidate(orphanLead.id);
    reasonlessGate.restoreResolvedAnalysisCandidate(explicitlyUnresolved.id);
    reasonlessGate.completeAnalysis();
    assert.throws(()=>reasonlessGate.completeExperiments({...partialCertificate,
      pendingReasons:{}}),/EXPERIMENT_LEAD_COVERAGE_INCOMPLETE/,
      'The stage gate must reject an unresolved disposition without its blocker reason');
    // Repair attempts have a real fixed-point identity. An audit history
    // append alone cannot trigger another identical retry, whereas a genuine
    // independently failed EVM execution must open a new recovery generation.
    const retrySource=[candidates[3]];
    const retryStore=await AnalysisProgressStore.open(
      join(dir,'repair-fingerprint.json'),retrySource);
    retryStore.nextBatch(1,1);
    const retryId=hash('source-recovery-attempt');
    retryStore.recordAssessment(retrySource[0].id,['property:stored'],
      [],[retryId],[],[{
        id:'property:stored',experimentIds:[retryId],
        sourceWitnesses:[retrySource[0].path+':'+retrySource[0].sourceSha256]
      }]);
    const retryProgress=retryStore.records.get(retrySource[0].id)!;
    const firstRetryKey=repairAttemptIdentity(retryProgress);
    retryStore.noteRepairAttempt(retrySource[0].id,
      'source-property-controller:'+firstRetryKey,'no_new_experiment');
    assert.equal(repairAttemptIdentity(retryProgress),firstRetryKey,
      'A no-op attempt must not rearm an identical deterministic repair');
    retryStore.recordInconclusive(retryId,'incomplete',
      hash('actual-incomplete-receipt'),'source-observed contract revert');
    const secondRetryKey=repairAttemptIdentity(retryProgress);
    assert.notEqual(secondRetryKey,firstRetryKey,
      'Independent runtime failure must unlock a different sourced retry generation');
    await retryStore.save();
    const reopenedRetry=await AnalysisProgressStore.open(
      join(dir,'repair-fingerprint.json'),retrySource);
    assert.equal(repairAttemptIdentity(reopenedRetry.records.get(retrySource[0].id)!),
      secondRetryKey,'Checkpoint recovery must preserve repair generation identity');
    // A valid completed property does not close a different unmet obligation.
    // The dispatcher must choose authenticated alternative routes even when
    // direct construction succeeded for a different security property.
    assert.deepEqual(sourceRepairRoutes(null,[],true),{
      categories:[],concrete:false,callers:false,hasUnresolved:false});
    assert.deepEqual(sourceRepairRoutes(null,[
      'UNKNOWN_ASSERTION(missing_fixture):unbound constructor',
      'UNKNOWN_ASSERTION(no_supported_property):missing price invariant',
      'missing_public_getter:Accounting.accrued'
    ],true),{
      categories:['missing_fixture','missing_observable_state','no_supported_property'],
      concrete:true,callers:true,hasUnresolved:true
    },'Partially completed lead must explore unresolved fixture and property routes');
    assert.deepEqual(sourceRepairRoutes(null,[
      'unresolved_external_call:Oracle.poke'
    ],true),{
      categories:['unresolved_dependency'],concrete:true,callers:true,
      hasUnresolved:true
    },'External call blockers remain separate obligations; no invented results');
    assert.deepEqual(sourceRepairRoutes(null,['unrelated_readonly_comment'],true),{
      categories:[],concrete:false,callers:false,hasUnresolved:true
    },'Unrecognized text must not manufacture a new authorized recovery route');
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
    // A repeated ANALYZE pass on the same acquired source is additive. It
    // cannot discard existing independently verified EVM evidence, erase a
    // different unmet property, or falsely certify an incomplete lead.
    const replayLead=[candidates[1]];
    const replayStore=await AnalysisProgressStore.open(
      join(dir,'property-reanalysis.json'),replayLead);
    replayStore.nextBatch(1,1);
    const verifiedId=hash('already-executed-property');
    const verifiedProperty='source-proven-conservation';
    const firstBlocker='UNKNOWN_ASSERTION(missing_fixture):token not acquired';
    replayStore.recordAssessment(replayLead[0].id,[verifiedProperty],
      [firstBlocker],[verifiedId],[],[{
        id:verifiedProperty,experimentIds:[verifiedId],
        sourceWitnesses:[replayLead[0].path+':'+replayLead[0].sourceSha256]
      }]);
    replayStore.markExperimentCompleted(verifiedId,{
      evidenceId:hash('real-evm-receipt-verified'),
      verifierDigest:hash('independent-verifier-replay'),
      result:'not_observed'
    });
    assert.equal(replayStore.experimentCertificate.conclusive,0);
    replayStore.recordAssessment(replayLead[0].id,[],
      ['UNKNOWN_ASSERTION(no_supported_property):missing second property'],[]);
    const replayProperties=replayStore.records.get(replayLead[0].id)!.properties;
    assert.ok(replayProperties.some(p=>p.id===verifiedProperty&&
      p.state==='test_completed'&&p.experimentIds.includes(verifiedId)),
      'Source-identical reanalysis must retain genuinely verified prior property');
    assert.ok(replayProperties.some(p=>p.unresolvedPrerequisites.includes(firstBlocker)));
    assert.ok(replayProperties.some(p=>p.unresolvedPrerequisites.some(reason=>
      reason.includes('missing second property'))));
    assert.equal(replayStore.experimentCertificate.conclusive,0,
      'Retaining evidence may never hide newly discovered independent blockers');
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
      /EXPERIMENT_LEAD_COVERAGE_INCOMPLETE|EXPERIMENT_INCONCLUSIVE_DISPOSITIONS/);
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
    pending.recordAssessment(one[2].id,[],['no_source_supported_security_property'],[]);
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
    const pendingCertificate=pending.experimentCertificate;
    assert.ok(pendingCertificate.pendingReasons[one[2].id].includes('no_source_supported_security_property'),
      'A lead without a supported source-derived property must retain its exact unresolved reason');
    assert.ok(pendingCertificate.pendingReasons[one[3].id].includes('unresolved_money_market'),
      'A missing financial dependency must retain its source-specific blocker');
    assert.ok(pendingCertificate.pendingReasons[one[4].id].includes('property_state:test_constructed'),
      'A constructed but unexecuted experiment must remain explicitly pending');
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
    const vaultSource='pragma solidity ^0.8.0; contract Vault { IAdapter public adapter; constructor(IAdapter _adapter) { adapter = _adapter; } function initialize(address _adapter) external { adapter = IAdapter(_adapter); } }';
    const adapterSource='pragma solidity ^0.8.0; contract Adapter is IAdapter { constructor(Token token) {} function configure() external {} function ping() external view returns(uint256) { return 0; } }';
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
        operations:[{id:'configure',deploymentId:'adapter',function:'configure()',
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
    // A well-formed Solidity sequence can still carry a deployment placeholder
    // as an argument. It must resolve to an acquired prior deployment.
    const missingConstructorRef=JSON.parse(JSON.stringify(prepSequence));
    missingConstructorRef.constructorArgs=['$deployment:not-acquired'];
    const rejectedTarget=sourcePreparationGraph(missingConstructorRef,prepSources);
    assert.equal(rejectedTarget.ok,false,
      'Target constructor placeholders cannot reference absent source deployments');
    const missingStepRef=JSON.parse(JSON.stringify(prepSequence));
    missingStepRef.steps[0].args=['$deployment:unknown-source'];
    assert.equal(sourcePreparationGraph(missingStepRef,prepSources).ok,false,
      'A readback must not resolve a deployment that was never constructed');
    const badCheckExpect=JSON.parse(JSON.stringify(prepSequence));
    badCheckExpect.preparation.checks[0].expect='$deployment:missing-receiver';
    assert.equal(sourcePreparationGraph(badCheckExpect,prepSources).ok,false,
      'Preparation readbacks cannot claim an unconstructed deployment');
    const badFactoryRef=JSON.parse(JSON.stringify(prepSequence));
    badFactoryRef.factoryClone={deploymentId:'token',function:'clone(address)',
      args:['$deployment:missing-factory-argument'],sender:0};
    assert.equal(sourcePreparationGraph(badFactoryRef,prepSources).ok,false,
      'Source factory clone arguments cannot bind absent contracts');
    const goodTargetRef=JSON.parse(JSON.stringify(prepSequence));
    goodTargetRef.constructorArgs=['$deployment:token'];
    const validatedTarget=sourcePreparationGraph(goodTargetRef,prepSources,
      fixtureSources[0],{name:'Vault',loc:{start:{line:1},end:{line:1}},subNodes:[
        {type:'FunctionDefinition',isConstructor:true,parameters:[
          {typeName:{type:'UserDefinedTypeName',namePath:'IAdapter'}}]}]});
    assert.equal(validatedTarget.ok,true,'Source-backed target dependency must be admissible');
    if(validatedTarget.ok){
      assert.ok(validatedTarget.nodes.some(n=>n.id==='target:deploy'&&
        n.dependsOn.includes('deploy:token')),
        'Target deploy must explicitly depend on acquired constructor fixture');
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
    const invalidWidthInterface='pragma solidity ^0.8.20; interface IInvalidWidth { function ping() external; }';
    const invalidWidthDependency=`pragma solidity ^0.8.20; import "./IInvalidWidth.sol";
contract InvalidWidthDependency is IInvalidWidth {
  constructor(uint7 amount) {}
  function ping() external override {}
}`;
    const invalidWidthConsumer=`pragma solidity ^0.8.20; import "./IInvalidWidth.sol";
contract InvalidWidthConsumer {
  IInvalidWidth public dependency;
  function initialize(address chosen) external { dependency=IInvalidWidth(chosen); }
  function callDependency() external { dependency.ping(); }
}`;
    const invalidWidthSources=[
      {path:'source-1/contracts/IInvalidWidth.sol',content:invalidWidthInterface,sha256:hash(invalidWidthInterface)},
      {path:'source-1/contracts/InvalidWidthDependency.sol',content:invalidWidthDependency,sha256:hash(invalidWidthDependency)},
      {path:'source-1/contracts/InvalidWidthConsumer.sol',content:invalidWidthConsumer,sha256:hash(invalidWidthConsumer)}
    ];
    const invalidWidthFixture=resolveSourceFixtureDependencies(invalidWidthSources[2],
      'InvalidWidthConsumer',invalidWidthSources);
    assert.equal(invalidWidthFixture.status,'unresolved',
      'Fixture construction must not fabricate a value for an integer width Solidity does not define');
    if(invalidWidthFixture.status==='unresolved')
      assert.ok(invalidWidthFixture.missingDependencies.some(reason=>
        reason.includes('unsupported_constructor_type')),
        'Invalid ABI widths need a concrete fixture blocker');
    const enumObservationSource=`pragma solidity ^0.8.20;
contract EnumObservation {
  enum Phase { Open, Closed }
  mapping(Phase => uint256) private balances;
  function balanceOf(Phase phase) external view returns (uint256) {
    return balances[phase];
  }
}`;
    const enumObservationSnapshot={path:'source-1/contracts/EnumObservation.sol',
      content:enumObservationSource,sha256:hash(enumObservationSource)};
    const enumObservations=extractAccountingObservations(enumObservationSnapshot,
      'EnumObservation',[{selector:'EnumObservation.balanceOf',operation:'call',inputs:['uint8']}] as any);
    assert.ok(enumObservations.some(o=>o.kind==='mapping'&&o.getter==='balanceOf(uint8)'&&
      o.keyType==='uint8'&&o.stateVariable==='balances'),
      'Accounting observations must resolve enum mapping keys to compiler ABI uint8');
    const fabricatedEnumReadSource=enumObservationSource.replace(
      'return balances[phase];','return 0; // balances[phase]');
    const fabricatedEnumReadSnapshot={path:'source-1/contracts/EnumObservation.sol',
      content:fabricatedEnumReadSource,sha256:hash(fabricatedEnumReadSource)};
    assert.equal(extractAccountingObservations(fabricatedEnumReadSnapshot,'EnumObservation',
      [{selector:'EnumObservation.balanceOf',operation:'call',inputs:['uint8']}] as any)
      .some(o=>o.kind==='mapping'),false,
      'A matching state name in comments or an unrelated return value is not a mapping observation');
    const importedAccountType=`pragma solidity ^0.8.20; type AccountKey is uint48;`;
    const importedObservationSource=`pragma solidity ^0.8.20;
import {AccountKey as UserKey} from "./AccountKey.sol";
contract ImportedObservation {
  mapping(UserKey => uint256) private balances;
  function balanceOf(UserKey key) external view returns (uint256) { return balances[key]; }
}`;
    const importedTypeSnapshot={path:'source-1/contracts/AccountKey.sol',
      content:importedAccountType,sha256:hash(importedAccountType)};
    const importedObservationSnapshot={path:'source-1/contracts/ImportedObservation.sol',
      content:importedObservationSource,sha256:hash(importedObservationSource)};
    const importedObservations=extractAccountingObservations(importedObservationSnapshot,
      'ImportedObservation',[{selector:'ImportedObservation.balanceOf',operation:'call',inputs:['uint48']}] as any,
      [importedTypeSnapshot,importedObservationSnapshot]);
    assert.ok(importedObservations.some(o=>o.kind==='mapping'&&o.getter==='balanceOf(uint48)'&&
      o.keyType==='uint48'&&o.stateVariable==='balances'),
      'Accounting readbacks must resolve imported aliased UDVT mapping keys from acquired source');
    const qualifiedObservationSource=`pragma solidity ^0.8.20;
import "./AccountKey.sol" as Types;
contract QualifiedObservation {
  mapping(Types.AccountKey => uint256) private balances;
  function balanceOf(Types.AccountKey key) external view returns (uint256) { return balances[key]; }
}`;
    const qualifiedObservationSnapshot={path:'source-1/contracts/QualifiedObservation.sol',
      content:qualifiedObservationSource,sha256:hash(qualifiedObservationSource)};
    const qualifiedObservations=extractAccountingObservations(qualifiedObservationSnapshot,
      'QualifiedObservation',[{selector:'QualifiedObservation.balanceOf',operation:'call',inputs:['uint48']}] as any,
      [importedTypeSnapshot,qualifiedObservationSnapshot]);
    assert.ok(qualifiedObservations.some(o=>o.kind==='mapping'&&o.getter==='balanceOf(uint48)'&&
      o.keyType==='uint48'&&o.stateVariable==='balances'),
      'Accounting readbacks must resolve namespace-qualified imported value types');
    const inheritedObservationBase=`pragma solidity ^0.8.20;
import {AccountKey as LocalKey} from "./AccountKey.sol";
contract ObservationBase {
  mapping(LocalKey => uint256) private balances;
  function balanceOf(LocalKey key) external view returns (uint256) { return balances[key]; }
}`;
    const inheritedObservationChild=`pragma solidity ^0.8.20;
import {ObservationBase as LedgerBase} from "./ObservationBase.sol";
contract InheritedObservation is LedgerBase {}`;
    const inheritedBaseSnapshot={path:'source-1/contracts/ObservationBase.sol',
      content:inheritedObservationBase,sha256:hash(inheritedObservationBase)};
    const inheritedChildSnapshot={path:'source-1/contracts/InheritedObservation.sol',
      content:inheritedObservationChild,sha256:hash(inheritedObservationChild)};
    const inheritedObservations=extractAccountingObservations(inheritedChildSnapshot,
      'InheritedObservation',[{selector:'InheritedObservation.balanceOf',operation:'call',inputs:['uint48']}] as any,
      [importedTypeSnapshot,inheritedBaseSnapshot,inheritedChildSnapshot]);
    assert.ok(inheritedObservations.some(o=>o.kind==='mapping'&&o.getter==='balanceOf(uint48)'&&
      o.keyType==='uint48'&&o.stateVariable==='balances'&&
      o.sourceWitness.includes('ObservationBase.sol')&&o.sourceWitness.includes(hash(inheritedObservationBase))),
      'Accounting observations must follow acquired aliased inheritance and retain the base function and state source identities');
    const importedStructSource=`pragma solidity ^0.8.20;
struct Position { uint256 amount; bool active; }`;
    const importedStructOwner=`pragma solidity ^0.8.20;
import {Position as AcquiredPosition} from "./Position.sol";
contract ImportedStructObservation {
  AcquiredPosition[] private positions;
  function position(uint256 index) external view returns (AcquiredPosition memory) { return positions[index]; }
}`;
    const importedStructSnapshot={path:'source-1/contracts/Position.sol',
      content:importedStructSource,sha256:hash(importedStructSource)};
    const importedStructOwnerSnapshot={path:'source-1/contracts/ImportedStructObservation.sol',
      content:importedStructOwner,sha256:hash(importedStructOwner)};
    const importedStructObservations=extractAccountingObservations(importedStructOwnerSnapshot,
      'ImportedStructObservation',[{selector:'ImportedStructObservation.position',operation:'call',inputs:['uint256']}] as any,
      [importedStructSnapshot,importedStructOwnerSnapshot]);
    assert.ok(importedStructObservations.some(o=>o.kind==='struct_field'&&o.fieldName==='amount'&&
      o.fieldType==='uint256'&&o.getter==='position(uint256)'),
      'Accounting observations must resolve fields of imported aliased structs from acquired source');
    const renamedTokenInterface=`pragma solidity ^0.8.20;
interface ITokenBalance { function balanceOf(address account) external view returns (uint256); }`;
    const renamedTokenConsumer=`pragma solidity ^0.8.20;
import {ITokenBalance as AcquiredToken} from "./ITokenBalance.sol";
contract TokenBalanceObservation {
  AcquiredToken public token;
  function tokenBalance(address account) external view returns (uint256) { return token.balanceOf(account); }
}`;
    const renamedTokenInterfaceSnapshot={path:'source-1/contracts/ITokenBalance.sol',
      content:renamedTokenInterface,sha256:hash(renamedTokenInterface)};
    const renamedTokenConsumerSnapshot={path:'source-1/contracts/TokenBalanceObservation.sol',
      content:renamedTokenConsumer,sha256:hash(renamedTokenConsumer)};
    const renamedTokenObservations=extractAccountingObservations(renamedTokenConsumerSnapshot,
      'TokenBalanceObservation',[{selector:'TokenBalanceObservation.tokenBalance',operation:'call',inputs:['address']}] as any,
      [renamedTokenInterfaceSnapshot,renamedTokenConsumerSnapshot]);
    assert.ok(renamedTokenObservations.some(o=>o.kind==='external_balance'&&
      o.getter==='tokenBalance(address)'&&o.stateVariable==='token'),
      'An aliased acquired ERC20 interface is a valid external balance readback only when its source declares balanceOf(address) view returning uint');
    const structObservationSource=`pragma solidity ^0.8.20;
contract StructObservation {
  struct Position { uint256 amount; bool active; }
  Position[] private positions;
  function position(uint256 index) external view returns (Position memory) { return positions[index]; }
}`;
    const structObservationSnapshot={path:'source-1/contracts/StructObservation.sol',
      content:structObservationSource,sha256:hash(structObservationSource)};
    const structObservations=extractAccountingObservations(structObservationSnapshot,
      'StructObservation',[{selector:'StructObservation.position',operation:'call',inputs:['uint256']}] as any);
    assert.ok(structObservations.some(o=>o.kind==='struct_field'&&o.getter==='position(uint256)'&&
      o.fieldName==='amount'&&o.fieldType==='uint256'),
      'Struct tuple ABI resolution must preserve source struct field observations');
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
    // A global Solidity custom value type can live in a source unit with no
    // ContractDefinition. The importer must resolve its precise ABI primitive.
    const globalValueType='pragma solidity ^0.8.20; type Price is uint128;';
    const rateIface=`pragma solidity ^0.8.20;
import "./GlobalPrice.sol";
interface IRate { function amount() external view returns(Price); }`;
    const rateImpl=`pragma solidity ^0.8.20;
import "./GlobalPrice.sol";
import "./IRate.sol";
contract Rate is IRate { Price public override amount; }`;
    const wrongRateImpl=`pragma solidity ^0.8.20;
import "./IRate.sol";
contract WrongRate { address public amount; }`;
    const rateSources=[
      {path:'source-1/contracts/GlobalPrice.sol',content:globalValueType,sha256:hash(globalValueType)},
      {path:'source-1/contracts/IRate.sol',content:rateIface,sha256:hash(rateIface)},
      {path:'source-1/contracts/Rate.sol',content:rateImpl,sha256:hash(rateImpl)},
      {path:'source-1/contracts/WrongRate.sol',content:wrongRateImpl,sha256:hash(wrongRateImpl)}
    ];
    // Emit a bounded compiler-parser diagnosis only when this real ABI
    // regression fails, so missing type namespaces are distinguishable from
    // missing public storage getter declarations.
    const rateVerification=verifyAcquiredReceiverMethods('IRate',['amount'],
      rateSources[2].path,'Rate',rateSources);
    if(!rateVerification.ok){
      const parser=(await import('@solidity-parser/parser')).parse;
      const outlines=rateSources.map(source=>{
        try{
          const tree=parser(source.content,{tolerant:true}) as any;
          return {path:source.path,children:(tree.children||[]).map((n:any)=>({
            type:n.type,name:n.name,
            variables:(n.subNodes||[]).filter((v:any)=>v.type==='StateVariableDeclaration')
              .flatMap((v:any)=>v.variables||[]).map((v:any)=>({
                name:v.name,visibility:v.visibility,type:v.typeName?.type,
                typePath:v.typeName?.namePath,override:v.override})),
          }))};
        }catch(error){return {path:source.path,parseFailure:String(error)};}
      });
      console.error('GLOBAL_VALUE_TYPE_DIAGNOSTICS',JSON.stringify(outlines).slice(0,2500));
    }
    assert.deepEqual(rateVerification,{ok:true,missing:[]},
      'Compiler-equivalent global custom value type must retain its exact uint128 ABI');
    assert.equal(verifyAcquiredReceiverMethods('IRate',['amount'],
      rateSources[3].path,'WrongRate',rateSources).ok,false,
      'An address getter cannot impersonate a global uint128 value-type return');
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
    // Inherited interface methods need not be locally redeclared.
    // Diamond inheritance is legal when each acquired path agrees on ABI.
    const baseInterface='pragma solidity ^0.8.20; interface IBaseView { function quote(uint256 value) external view returns(uint256); }';
    const leftInterface='pragma solidity ^0.8.20; import "./IBaseView.sol"; interface ILeftView is IBaseView {}';
    const rightInterface='pragma solidity ^0.8.20; import "./IBaseView.sol"; interface IRightView is IBaseView {}';
    const diamondInterface='pragma solidity ^0.8.20; import "./ILeftView.sol"; import "./IRightView.sol"; interface IDiamondView is ILeftView, IRightView {}';
    const diamondImpl='pragma solidity ^0.8.20; import "./IDiamondView.sol"; contract DiamondQuote is IDiamondView { function quote(uint256 value) external pure override returns(uint256) { return value; } }';
    const inheritedSources=[
      {path:'source-1/contracts/IBaseView.sol',content:baseInterface,sha256:hash(baseInterface)},
      {path:'source-1/contracts/ILeftView.sol',content:leftInterface,sha256:hash(leftInterface)},
      {path:'source-1/contracts/IRightView.sol',content:rightInterface,sha256:hash(rightInterface)},
      {path:'source-1/contracts/IDiamondView.sol',content:diamondInterface,sha256:hash(diamondInterface)},
      {path:'source-1/contracts/DiamondQuote.sol',content:diamondImpl,sha256:hash(diamondImpl)}
    ];
    const inheritedImpl=resolveAcquiredConcreteImplementations(inheritedSources[3],
      'IDiamondView','quote',inheritedSources);
    assert.deepEqual(inheritedImpl.map(x=>x.selector),['DiamondQuote.quote'],
      'Exact acquired method inherited via diamond interfaces is a valid ABI candidate');
    assert.equal(inheritedImpl[0].operation,'call',
      'Recovered inherited pure implementation is read-only');
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
    // Lexical lookalikes and local shadowing are NOT source-verified
    // interface call edges even if the receiver.method string is present.
    const commentCallerText=`pragma solidity ^0.8.20;
import "./ICToken.sol";
contract CommentCaller {
  ICToken public cToken;
  function deposit(uint256 amount) external {
    // cToken.mint(amount) is intentionally not executed
    revert("cToken.mint(amount)");
  }
}`;
    const commentCaller={path:'source-1/contracts/CommentCaller.sol',
      content:commentCallerText,sha256:hash(commentCallerText)};
    assert.deepEqual(resolveAcquiredInterfaceCallers(icSnap,'ICToken','mint',
      [icSnap,commentCaller]),[],
      'Comments and string literals cannot establish source callsite evidence');
    const shadowCallerText=`pragma solidity ^0.8.20;
import "./ICToken.sol";
contract ShadowCaller {
  ICToken public cToken;
  function deposit(ICToken cToken,uint256 amount) external {
    cToken.mint(amount);
  }
}`;
    const shadowCaller={path:'source-1/contracts/ShadowCaller.sol',
      content:shadowCallerText,sha256:hash(shadowCallerText)};
    assert.deepEqual(resolveAcquiredInterfaceCallers(icSnap,'ICToken','mint',
      [icSnap,shadowCaller]),[],
      'A shadowing parameter cannot prove a call through persistent source-state receiver');
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
    // The selected interface may inherit its actual ABI without a local
    // declaration. Accept only the acquired unique parent and callsite.
    const inheritedTokenBase='pragma solidity ^0.8.20; interface IBaseToken { function mint(uint256 amount) external returns(uint256); }';
    const inheritedTokenChild='pragma solidity ^0.8.20; import "./IBaseToken.sol"; interface IChildToken is IBaseToken {}';
    const inheritedTokenCaller=`pragma solidity ^0.8.20;
import "./IChildToken.sol";
contract ChildTokenConsumer {
 IChildToken public token;
 function use(uint256 amount) external { require(token.mint(amount)==0); }
}`;
    const inheritedTokenSnapshots=[
      {path:'source-1/contracts/IBaseToken.sol',content:inheritedTokenBase,
        sha256:hash(inheritedTokenBase)},
      {path:'source-1/contracts/IChildToken.sol',content:inheritedTokenChild,
        sha256:hash(inheritedTokenChild)},
      {path:'source-1/contracts/ChildTokenConsumer.sol',content:inheritedTokenCaller,
        sha256:hash(inheritedTokenCaller)}
    ];
    assert.deepEqual(resolveAcquiredInterfaceCallers(inheritedTokenSnapshots[1],
      'IChildToken','mint',inheritedTokenSnapshots).map(x=>x.selector),
      ['ChildTokenConsumer.use'],
      'Inherited ABI method and actual parsed caller must reconstruct a valid route');
    assert.deepEqual(resolveAcquiredInterfaceCallers(inheritedTokenSnapshots[1],
      'IChildToken','mint',inheritedTokenSnapshots.slice(1)),[],
      'An unacquired parent cannot invent an inherited ABI method');
    const aliasedTokenChild='pragma solidity ^0.8.20; import {IBaseToken as TokenBase} from "./IBaseToken.sol"; interface IChildToken is TokenBase {}';
    const aliasedTokenSnapshot={...inheritedTokenSnapshots[1],
      content:aliasedTokenChild,sha256:hash(aliasedTokenChild)};
    const aliasedRoutes=resolveAcquiredInterfaceCallers(aliasedTokenSnapshot,'IChildToken','mint',
      [inheritedTokenSnapshots[0],aliasedTokenSnapshot,inheritedTokenSnapshots[2]]);
    assert.deepEqual(aliasedRoutes.map(x=>x.selector),['ChildTokenConsumer.use'],
      'Actual acquired Solidity import aliases must resolve inherited interface methods');
    const unboundSecondParent='pragma solidity ^0.8.20; import "./IBaseToken.sol"; interface IChildToken is IBaseToken, IMissingBase {}';
    const missingSecond={...inheritedTokenSnapshots[1],
      content:unboundSecondParent,sha256:hash(unboundSecondParent)};
    assert.deepEqual(resolveAcquiredInterfaceCallers(missingSecond,'IChildToken','mint',
      [inheritedTokenSnapshots[0],missingSecond,inheritedTokenSnapshots[2]]),[],
      'One valid inherited method must not conceal another unresolved base');

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
    // The source argument is passed to a uniquely identified private
    // helper, which performs an unconditional exact state assignment. This
    // is testable even if the state getter bears a different name.
    const internalScalarText=`pragma solidity ^0.8.0;
contract InternalScalar {
  uint256 private held;
  function amount() external view returns(uint256) { return held; }
  function update(uint256 value) external { _set(value); }
  function _set(uint256 next) internal { held = next; }
  function updateUnrelated(uint256 value) external { _other(value); }
  function _other(uint256 next) internal { elsewhere = next; }
  uint256 private elsewhere;
}`;
    const internalScalarSnap={path:'source-1/contracts/InternalScalar.sol',
      content:internalScalarText,sha256:hash(internalScalarText)};
    const internalScalarMenu=[
      {selector:'InternalScalar.amount',operation:'call',inputs:[]},
      {selector:'InternalScalar.update',operation:'send',inputs:['uint256']},
      {selector:'InternalScalar.updateUnrelated',operation:'send',inputs:['uint256']}
    ];
    const internalScalarPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:internalScalarSnap.path,
      targetSelector:'InternalScalar.update',sources:[internalScalarSnap],
      declarations:internalScalarMenu as any,skipLegacy:true});
    assert.equal(internalScalarPlan.ok,true,
      'Source-exact helper delegation must construct a state obligation');
    if(internalScalarPlan.ok)assert.ok(internalScalarPlan.experiments.some(e=>
      e.securityProperty.startsWith('source internal state assignment')&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='amount()'&&step.expect==='7')&&
      e.witnesses.some(w=>w.symbol.includes('_set'))));
    const unrelatedScalar=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:internalScalarSnap.path,
      targetSelector:'InternalScalar.updateUnrelated',sources:[internalScalarSnap],
      declarations:internalScalarMenu as any,skipLegacy:true});
    assert.ok(!unrelatedScalar.ok||!unrelatedScalar.experiments.some(e=>
      e.securityProperty.startsWith('source internal state assignment')&&
      e.securityProperty.endsWith(':held')),
      'Internal helper mutating unrelated storage cannot prove held state');
    const privatePairSource=`pragma solidity ^0.8.0;
contract PrivatePair {
  uint256 private stored;
  function remaining() external view returns(uint256) { return stored; }
  function increase(uint256 amount) external { stored += amount; }
  function decrease(uint256 amount) external { stored -= amount; }
  function decreaseUnrelated(uint256 amount) external { other -= amount; }
  uint256 private other;
}`;
    const privatePairSnap={path:'source-1/contracts/PrivatePair.sol',
      content:privatePairSource,sha256:hash(privatePairSource)};
    const pairMenu=[
      {selector:'PrivatePair.remaining',operation:'call',inputs:[]},
      {selector:'PrivatePair.increase',operation:'send',inputs:['uint256']},
      {selector:'PrivatePair.decrease',operation:'send',inputs:['uint256']},
      {selector:'PrivatePair.decreaseUnrelated',operation:'send',inputs:['uint256']}
    ];
    for(const method of ['increase','decrease']){
      const pair=constructSolidityExperiments({
        repositoryCommit:'b'.repeat(40),targetPath:privatePairSnap.path,
        targetSelector:'PrivatePair.'+method,sources:[privatePairSnap],
        declarations:pairMenu as any,skipLegacy:true});
      assert.equal(pair.ok,true,'Paired scalar transition source must be executable: '+method);
      if(pair.ok)assert.ok(pair.experiments.some(e=>
        e.securityProperty.startsWith('source-paired scalar conservation')&&
        e.sequence.steps.some(step=>step.operation==='call'&&
          step.function==='remaining()'&&step.expect==='0')&&
        e.sequence.steps.filter(step=>step.operation==='send').length===2),
        'Opposite writes to a single private state must produce source-proven paired evidence');
    }
    const mismatchedPair=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:privatePairSnap.path,
      targetSelector:'PrivatePair.decreaseUnrelated',sources:[privatePairSnap],
      declarations:pairMenu as any,skipLegacy:true});
    assert.ok(!mismatchedPair.ok||!mismatchedPair.experiments.some(e=>
      e.securityProperty.startsWith('source-paired scalar conservation')&&
      e.securityProperty.endsWith(':stored')),
      'Two different storage variables cannot be conflated into conservation');
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
    const unrelatedScalarBaseline=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:unrelatedScalarSource.path,
      targetSelector:'DirectScalar.addValue',sources:[unrelatedScalarSource],
      declarations:[{selector:'DirectScalar.addValue',operation:'send',inputs:['uint256'],
        outputs:[],stateMutability:'nonpayable'}] as any,skipLegacy:true
    });
    assert.ok(!unrelatedScalarBaseline.ok||!unrelatedScalarBaseline.experiments.some(x=>
      x.sequence.sourceProperty?.kind==='scalar_delta'),
      'Unrelated RHS storage cannot prove an exact scalar delta');
    // State relationships must be derived from exact mapping keys, not from
    // lexical similarity or a generic "balance" variable name.
    const fundedMappingText=`pragma solidity ^0.8.20;
contract FundedMapping {
  mapping(address=>uint256) public credit;
  uint256 public totalCredit;
  address public operator;
  constructor(){operator=msg.sender;}
  function fund(address recipient,uint256 amount) external {
    credit[recipient]+=amount;totalCredit+=amount;
  }
  function settle(address recipient,uint256 amount) external {
    require(msg.sender==operator,"operator");
    require(amount>0&&amount<=totalCredit,"balance");
    credit[recipient]+=amount;totalCredit-=amount;
  }
}`;
    const fundedSource={path:'source-1/contracts/FundedMapping.sol',
      content:fundedMappingText,sha256:hash(fundedMappingText)};
    const fundedMenu=[
      {selector:'FundedMapping.fund',operation:'send',inputs:['address','uint256']},
      {selector:'FundedMapping.settle',operation:'send',inputs:['address','uint256']},
      {selector:'FundedMapping.operator',operation:'call',inputs:[]}
    ];
    const fundedPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:fundedSource.path,
      targetSelector:'FundedMapping.settle',sources:[fundedSource],
      declarations:fundedMenu as any,skipLegacy:true});
    assert.equal(fundedPlan.ok,true,
      'Acquired balance precondition must trigger source-derived funding preparation');
    if(fundedPlan.ok)assert.ok(fundedPlan.experiments.some(e=>
      e.securityProperty.startsWith('source-funded mapping balance')&&
      e.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='fund(address,uint256)'&&step.requiredSetup===true)&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='totalCredit()'&&step.expect==='4')&&
      e.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='credit(address)'&&step.expect==='6')),
      'Bounded settlement must have actual acquired funding and independent numeric postconditions');
    const unfundedText=fundedMappingText.replace(
      'credit[recipient]+=amount;totalCredit+=amount;',
      'require(amount<0);');
    const unfundedSource={...fundedSource,content:unfundedText,
      sha256:hash(unfundedText)};
    const refusedFunding=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:unfundedSource.path,
      targetSelector:'FundedMapping.settle',sources:[unfundedSource],
      declarations:fundedMenu as any,skipLegacy:true});
    assert.ok(!refusedFunding.ok||!refusedFunding.experiments.some(e=>
      e.securityProperty.startsWith('source-funded mapping balance')),
      'Without a real source-backed funding edge the controller must not invent one');
    const indexedLedgerText=[
      'pragma solidity ^0.8.20;',
      'contract IndexedLedger {',
      '  mapping(uint256 => uint256) public balances;',
      '  uint256 public totalDeposits;',
      '  function deposit(uint256 accountId,uint256 amount) external {',
      '    require(accountId > 0); balances[accountId] += amount; totalDeposits += amount;',
      '  }',
      '  function withdraw(uint256 accountId,uint256 amount) external {',
      '    require(accountId > 0); balances[accountId] -= amount; totalDeposits -= amount;',
      '  }',
      '}',
    ].join('\n');
    const indexedLedger={path:'source-1/contracts/IndexedLedger.sol',
      content:indexedLedgerText,sha256:hash(indexedLedgerText)};
    const indexedLedgerPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:indexedLedger.path,
      targetSelector:'IndexedLedger.withdraw',sources:[indexedLedger],
      declarations:[
        {selector:'IndexedLedger.deposit',operation:'send',inputs:['uint256','uint256']},
        {selector:'IndexedLedger.withdraw',operation:'send',inputs:['uint256','uint256']},
        {selector:'IndexedLedger.totalDeposits',operation:'call',inputs:[]}
      ] as any,skipLegacy:true});
    assert.equal(indexedLedgerPlan.ok,true,
      'A public uint-key mapping and its source-proven aggregate ledger must be executable');
    if(indexedLedgerPlan.ok){
      const mapped=indexedLedgerPlan.experiments.find(e=>
        e.securityProperty.startsWith('financial conservation invariant'));
      assert.ok(mapped,'Indexed ledger should produce its source-proven conservation experiment');
      assert.ok(mapped!.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='balances(uint256)'&&JSON.stringify(step.args)===JSON.stringify(['1'])),
        'Autogenerated uint-key mapping getters must use the proven nonzero key');
      assert.ok(mapped!.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='deposit(uint256,uint256)'&&
        JSON.stringify(step.args)===JSON.stringify(['1','1000'])),
        'Deposit must use the same source-proven mapping key and amount');
      assert.ok(mapped!.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='withdraw(uint256,uint256)'&&
        JSON.stringify(step.args)===JSON.stringify(['1','400'])),
        'Withdrawal must use the same source-proven mapping key and amount');
    }
    const enumLedgerText=`pragma solidity ^0.8.20;
contract EnumLedger {
  enum AccountId { Unknown, Treasury }
  mapping(AccountId => uint256) public balances;
  uint256 public total;
  function deposit(AccountId accountId,uint256 amount) external {
    require(accountId != AccountId.Unknown);
    balances[accountId] += amount; total += amount;
  }
  function withdraw(AccountId accountId,uint256 amount) external {
    require(accountId != AccountId.Unknown);
    balances[accountId] -= amount; total -= amount;
  }
}`;
    const enumLedger={path:'source-1/contracts/EnumLedger.sol',
      content:enumLedgerText,sha256:hash(enumLedgerText)};
    const enumLedgerPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:enumLedger.path,
      targetSelector:'EnumLedger.withdraw',sources:[enumLedger],
      declarations:[
        {selector:'EnumLedger.deposit',operation:'send',inputs:['uint8','uint256']},
        {selector:'EnumLedger.withdraw',operation:'send',inputs:['uint8','uint256']},
        {selector:'EnumLedger.total',operation:'call',inputs:[]}
      ] as any,skipLegacy:true});
    assert.equal(enumLedgerPlan.ok,true,
      'Enum-key public mapping accounting must resolve to its canonical uint8 getter ABI');
    if(enumLedgerPlan.ok){
      const enumExperiment=enumLedgerPlan.experiments.find(e=>
        e.securityProperty.startsWith('financial conservation invariant'));
      assert.ok(enumExperiment,'Enum-key ledger should produce a financial experiment');
      assert.ok(enumExperiment!.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='balances(uint8)'&&JSON.stringify(step.args)===JSON.stringify(['1'])),
        'Enum fixture key must remain within the acquired enum ordinal range');
    }
    const valueTypeLedgerText=`pragma solidity ^0.8.20;
type AccountId is uint16;
contract ValueTypeLedger {
  mapping(AccountId => uint256) public balances;
  uint256 public total;
  function deposit(AccountId accountId,uint256 amount) external {
    balances[accountId] += amount; total += amount;
  }
  function withdraw(AccountId accountId,uint256 amount) external {
    balances[accountId] -= amount; total -= amount;
  }
}`;
    const valueTypeLedger={path:'source-1/contracts/ValueTypeLedger.sol',
      content:valueTypeLedgerText,sha256:hash(valueTypeLedgerText)};
    const valueTypePlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:valueTypeLedger.path,
      targetSelector:'ValueTypeLedger.withdraw',sources:[valueTypeLedger],
      declarations:[
        {selector:'ValueTypeLedger.deposit',operation:'send',inputs:['uint16','uint256']},
        {selector:'ValueTypeLedger.withdraw',operation:'send',inputs:['uint16','uint256']},
        {selector:'ValueTypeLedger.total',operation:'call',inputs:[]}
      ] as any,skipLegacy:true});
    assert.equal(valueTypePlan.ok,true,
      'UDVT-key public mapping accounting must resolve using the acquired underlying integer width');
    if(valueTypePlan.ok){
      const valueTypeExperiment=valueTypePlan.experiments.find(e=>
        e.securityProperty.startsWith('financial conservation invariant'));
      assert.ok(valueTypeExperiment,'UDVT-key ledger should produce a financial experiment');
      assert.ok(valueTypeExperiment!.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='balances(uint16)'&&JSON.stringify(step.args)===JSON.stringify(['7'])),
        'UDVT fixture key must match the canonical underlying ABI type');
    }
    const mixedCallerLedgerText=`pragma solidity ^0.8.20;
contract MixedCallerLedger {
  mapping(address => uint256) public balances;
  uint256 public total;
  function deposit(uint256 amount) external {
    balances[msg.sender] += amount;
    total += amount;
  }
  function withdraw(address account,uint256 amount) external {
    balances[account] -= amount;
    total -= amount;
  }
}`;
    const mixedCallerLedger={path:'source-1/contracts/MixedCallerLedger.sol',
      content:mixedCallerLedgerText,sha256:hash(mixedCallerLedgerText)};
    const mixedCallerPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:mixedCallerLedger.path,
      targetSelector:'MixedCallerLedger.withdraw',sources:[mixedCallerLedger],
      declarations:[
        {selector:'MixedCallerLedger.deposit',operation:'send',inputs:['uint256']},
        {selector:'MixedCallerLedger.withdraw',operation:'send',inputs:['address','uint256']},
        {selector:'MixedCallerLedger.total',operation:'call',inputs:[]},
        {selector:'MixedCallerLedger.balances',operation:'call',inputs:['address']}
      ] as any,skipLegacy:true});
    assert.equal(mixedCallerPlan.ok,true,
      'A caller-keyed deposit may pair with an explicit-address withdrawal for the same actor');
    if(mixedCallerPlan.ok){
      const mixed=mixedCallerPlan.experiments.find(e=>
        e.securityProperty.startsWith('financial conservation invariant'));
      assert.ok(mixed,'Mixed caller-keyed operations need a financial conservation experiment');
      assert.ok(mixed!.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='balances(address)'&&JSON.stringify(step.args)===JSON.stringify(['$account0'])),
        'The getter must observe the shared caller address');
      assert.ok(mixed!.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='deposit(uint256)'&&JSON.stringify(step.args)===JSON.stringify(['1000'])),
        'Implicit caller-keyed deposit must receive only its amount argument');
      assert.ok(mixed!.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='withdraw(address,uint256)'&&
        JSON.stringify(step.args)===JSON.stringify(['$account0','400'])),
        'Explicit-key withdrawal must target the same actor as the deposit');
    }
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

    // An owner authorization conclusion must follow the actual source
    // require(msg.sender == acquired owner storage) and the exact state write.
    // The selected method name is deliberately unrelated to access control.
    const guardedGenericText=`pragma solidity ^0.8.20;
contract GenericGuard {
 address public administrator;
 uint256 public value;
 constructor(){administrator=msg.sender;}
 function execute(uint256 next) external {
   require(msg.sender==administrator, "administrator");
   value=next;
 }
 function inverted(uint256 next) external {
   require(msg.sender!=administrator, "different");
   value=next;
 }
}`;
    const guardedGeneric={path:'source-1/contracts/GenericGuard.sol',
      content:guardedGenericText,sha256:hash(guardedGenericText)};
    const guardedMenu=[
      {selector:'GenericGuard.execute',operation:'send',inputs:['uint256']},
      {selector:'GenericGuard.inverted',operation:'send',inputs:['uint256']}
    ];
    const genericAuthorized=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:guardedGeneric.path,
      targetSelector:'GenericGuard.execute',sources:[guardedGeneric],
      declarations:guardedMenu as any,skipLegacy:true});
    assert.equal(genericAuthorized.ok,true,
      'A genuine source-verified owner-equality guard must produce an executable property');
    if(genericAuthorized.ok){
      const guarded=genericAuthorized.experiments.find(exp=>
        exp.securityProperty.startsWith('source-proof generic owner guard'));
      assert.ok(guarded,'A source-verified owner equality guard must produce an executable property');
      if(guarded){
        const steps=guarded.sequence.steps;
        const unauthorized=steps.find(step=>step.operation==='send'&&step.sender===1);
        const authorized=steps.find(step=>step.operation==='send'&&step.sender===0);
        const valueReadbacks=steps.filter(step=>step.operation==='call'&&step.function==='value()');
        assert.ok(unauthorized?.operation==='send'&&unauthorized.expectRevert,
          'The non-owner transaction must be required to revert');
        assert.ok(authorized?.operation==='send','The authorized transaction must execute');
        assert.equal(valueReadbacks[0]?.operation==='call'?valueReadbacks[0].expect:null,'0',
          'The initial state must be observed');
        assert.equal(valueReadbacks[1]?.operation==='call'?valueReadbacks[1].expect:null,'0',
          'The unauthorized attempt must leave the state unchanged');
        assert.deepEqual(valueReadbacks[2]?.operation==='call'?valueReadbacks[2].expect:null,
          authorized?.operation==='send'?authorized.args[0]:null,
          'Authorized readback must equal the exact value sent');
      }
    }
    const falseGuard=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:guardedGeneric.path,
      targetSelector:'GenericGuard.inverted',sources:[guardedGeneric],
      declarations:guardedMenu as any,skipLegacy:true});
    assert.ok(!falseGuard.ok||!falseGuard.experiments.some(exp=>
      exp.securityProperty.startsWith('source-proof generic owner guard')),
      'The logically opposite source guard must not be misclassified as owner authorization');
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
    for(const [name,getter] of [
      ['change','amount()'],
      ['enable','enabled()'],
      ['choose','recipient()']
    ] as const){
      const built=constructSolidityExperiments({repositoryCommit:'b'.repeat(40),
        targetPath:directStateSnap.path,targetSelector:'DirectState.'+name,
        sources:[directStateSnap],declarations:directStateMenu as any,skipLegacy:true});
      assert.equal(built.ok,true,'Direct state assignment must be source-testable: '+name);
      if(built.ok){
        const exp=built.experiments.find(candidate=>
          candidate.securityProperty.startsWith('source-defined direct state assignment'));
        assert.ok(exp,'Direct assignment property must be constructed: '+name);
        if(exp){
          const steps=exp.sequence.steps;
          const observation=steps.find(step=>step.operation==='observe'&&step.function===getter);
          const write=steps.find(step=>step.operation==='send'&&step.sender===0);
          const readback=steps.find(step=>step.operation==='call'&&step.function===getter);
          assert.ok(observation?.operation==='observe',
            'Direct assignment must record its pre-state: '+name);
          assert.ok(write?.operation==='send','Direct assignment must execute its source-backed write: '+name);
          assert.deepEqual(readback?.operation==='call'?readback.expect:null,
            write?.operation==='send'?write.args[0]:null,
            'Observed state after the write must equal the exact source-backed argument: '+name);
        }
      }
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
 uint8 public decimals;
 mapping(address=>mapping(address=>uint256)) private _allowances;
 function initialize(uint8 decimals_) external { decimals=decimals_; }
 function allowance(address owner,address spender) external view returns(uint256) {
   return _allowances[owner][spender];
 }
 function approve(address spender,uint256 amount) external returns(bool) {
   _approve(msg.sender,spender,amount);
   return true;
 }
 function increaseAllowance(address spender,uint256 addedValue) external returns(bool) {
   _approve(msg.sender,spender,_allowances[msg.sender][spender] + addedValue);
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
      {selector:'PrivateAllowance.initialize',operation:'send',inputs:['uint8']},
      {selector:'PrivateAllowance.decimals',operation:'call',inputs:[]},
      {selector:'PrivateAllowance.approve',operation:'send',inputs:['address','uint256']},
      {selector:'PrivateAllowance.increaseAllowance',operation:'send',inputs:['address','uint256']},
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
      exp.sequence.steps.some(step=>step.operation==='send'&&
        step.function==='initialize(uint8)'&&step.args[0]==='18')&&
      exp.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='allowance(address,address)'&&step.expect==='7')),
      'Private mapping mutation must be falsified by an actual getter result');
    // A getter whose parameter positions do not match the storage key
    // order cannot justify the assumed owner/spender mapping identity.
    const increasePlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:nestedAllowanceSnap.path,
      targetSelector:'PrivateAllowance.increaseAllowance',sources:[nestedAllowanceSnap],
      declarations:nestedAllowanceMenu as any,skipLegacy:true});
    assert.equal(increasePlan.ok,true,
      'Source read-modify-write via internal helper must produce a falsifiable property');
    if(increasePlan.ok)assert.ok(increasePlan.experiments.some(exp=>
      exp.securityProperty.includes('internal setter and public mapping getter')&&
      exp.sequence.steps.some(step=>step.operation==='call'&&
        step.function==='allowance(address,address)'&&step.expect==='7')));
    const wrongIncrement=nestedAllowance.replace(
      '_allowances[msg.sender][spender] + addedValue',
      '_allowances[spender][msg.sender] + addedValue');
    const wrongIncrementSnap={...nestedAllowanceSnap,content:wrongIncrement,
      sha256:hash(wrongIncrement)};
    const wrongIncrementPlan=constructSolidityExperiments({
      repositoryCommit:'b'.repeat(40),targetPath:wrongIncrementSnap.path,
      targetSelector:'PrivateAllowance.increaseAllowance',sources:[wrongIncrementSnap],
      declarations:nestedAllowanceMenu as any,skipLegacy:true});
    assert.ok(!wrongIncrementPlan.ok||!wrongIncrementPlan.experiments.some(exp=>
      exp.securityProperty.includes('internal setter and public mapping getter')),
      'A read from reversed mapping keys must not prove same-key conservation');
    const wrongAllowance=nestedAllowance.replace(
      'return _allowances[owner][spender];',
      'return _allowances[spender][owner];');
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
      assert.equal(ledgerExperiment.experiments.filter(e=>
        e.securityProperty.startsWith('financial ')).length,2,
        'Credit and reward must each produce a separate verified financial pair, even when additional source-grounded properties are constructed');
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
