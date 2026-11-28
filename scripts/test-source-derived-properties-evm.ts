/**
 * Independent local EVM oracle for source-derived accounting properties.
 * Exercises acquired source construction, compiler ABI, mined receipts,
 * readbacks and a genuine counterexample against a mutated implementation.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {constructSolidityExperiments} from '../packages/security-solver/src/controller-solidity-experiment-planner';
const require=createRequire(import.meta.url);
const solc=require('./reproduction-runtime/node_modules/solc') as any;
const ganache=require('./reproduction-runtime/node_modules/ganache') as any;
const {runSequence,validateSequence}=require('./reproduction-runtime/solidity-sequence.cjs') as {
  runSequence:(artifact:any,sequence:any,transport:any)=>Promise<any>,
  validateSequence:(sequence:any)=>unknown,
};
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
function compile(file:string,source:string,contract:string):any {
  const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
    sources:{[file]:{content:source}},
    settings:{evmVersion:'shanghai',
      outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
  assert.deepEqual((compiled.errors||[]).filter((e:any)=>e.severity==='error'),[],
    'Every independent EVM fixture must compile');
  return compiled.contracts[file][contract];
}
async function execute(artifact:any,sequence:any):Promise<any> {
  validateSequence(sequence);
  const transport=ganache.provider({logging:{quiet:true},
    wallet:{deterministic:true,totalAccounts:3},
    chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},
    miner:{blockGasLimit:12000000,timestampIncrement:1}});
  try {return await runSequence(artifact,sequence,transport);}
  finally {await transport.disconnect();}
}
const pairSource=[
  'pragma solidity ^0.8.20;',
  'contract PairLedger {',
  ' uint256 private stored;',
  ' function remaining() external view returns(uint256){return stored;}',
  ' function increase(uint256 amount) external {stored+=amount;}',
  ' function decrease(uint256 amount) external {stored-=amount;}',
  '}',
].join('\n');
const pairFile='source-1/contracts/PairLedger.sol';
const pairMenu=[
  {selector:'PairLedger.remaining',operation:'call' as const,inputs:[]},
  {selector:'PairLedger.increase',operation:'send' as const,inputs:['uint256']},
  {selector:'PairLedger.decrease',operation:'send' as const,inputs:['uint256']},
];
const source={path:pairFile,content:pairSource,sha256:sha(pairSource)};
const pair=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:pairFile,
  targetSelector:'PairLedger.increase',sources:[source],
  declarations:pairMenu,skipLegacy:true});
assert.equal(pair.ok,true,JSON.stringify(pair));
if(!pair.ok)throw new Error('Pair source property missing');
const property=pair.experiments.find(e=>
  e.securityProperty.startsWith('source-paired scalar conservation'));
assert.ok(property,'Paired scalar conservation requires an acquired falsifier');
assert.ok(property.prerequisites.some(p=>
  p.id==='target:deploy'&&p.sourceEvidence.some(w=>w.sourceSha256===source.sha256)));
const observed=await execute(compile(pairFile,pairSource,'PairLedger'),property.sequence);
assert.ok(observed.steps.every((step:any)=>step.passed!==false),
  'Original EVM receipts and readbacks disagree: '+JSON.stringify(observed));
assert.equal(observed.steps.filter((step:any)=>step.operation==='send').length,2);
assert.deepEqual(await execute(compile(pairFile,pairSource,'PairLedger'),property.sequence),observed,
  'Fresh isolated EVM replay must be deterministic');
const changed=pairSource.replace(
  'function decrease(uint256 amount) external {stored-=amount;}',
  'function decrease(uint256 amount) external {require(amount>0);}');
const divergent=await execute(compile(pairFile,changed,'PairLedger'),property.sequence);
assert.ok(divergent.steps.some((step:any)=>step.operation==='call'&&step.passed===false),
  'A changed real EVM transition must falsify the original oracle');
const changedSource={path:pairFile,content:changed,sha256:sha(changed)};
const rejected=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:pairFile,
  targetSelector:'PairLedger.increase',sources:[changedSource],
  declarations:pairMenu,skipLegacy:true});
assert.ok(!rejected.ok||!rejected.experiments.some(e=>
  e.securityProperty.startsWith('source-paired scalar conservation')),
  'The source planner must refuse an unsupported paired conservation claim');
const mappingSource=[
  'pragma solidity ^0.8.20;',
  'contract MappingLedger {',
  ' mapping(address=>uint256) public credit;',
  ' function add(address recipient,uint256 amount) external {credit[recipient]+=amount;}',
  '}',
].join('\n');
const mappingFile='source-1/contracts/MappingLedger.sol';
const mapped=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:mappingFile,
  targetSelector:'MappingLedger.add',
  sources:[{path:mappingFile,content:mappingSource,sha256:sha(mappingSource)}],
  declarations:[{selector:'MappingLedger.add',operation:'send',inputs:['address','uint256']}],
  skipLegacy:true});
assert.equal(mapped.ok,true,JSON.stringify(mapped));
if(!mapped.ok)throw new Error('Mapping source property missing');
const mappingProperty=mapped.experiments.find(e=>
  e.securityProperty.startsWith('source-backed mapping conservation'));
assert.ok(mappingProperty);
const mappingObserved=await execute(
  compile(mappingFile,mappingSource,'MappingLedger'),mappingProperty.sequence);
assert.ok(mappingObserved.steps.every((step:any)=>step.passed!==false));
assert.ok(mappingObserved.steps.some((step:any)=>
  step.operation==='call'&&step.function==='credit(address)'&&step.actual==='1'));
const internalSource=[
  'pragma solidity ^0.8.20;',
  'contract InternalAllowance {',
  ' mapping(address=>mapping(address=>uint256)) private _allowances;',
  ' function allowance(address owner,address spender) external view returns(uint256) {',
  '   return _allowances[owner][spender];',
  ' }',
  ' function increaseAllowance(address spender,uint256 amount) external returns(bool) {',
  '   _approve(msg.sender,spender,_allowances[msg.sender][spender]+amount);',
  '   return true;',
  ' }',
  ' function _approve(address owner,address spender,uint256 amount) internal {',
  '   _allowances[owner][spender] = amount;',
  ' }',
  '}',
].join('\n');
const internalFile='source-1/contracts/InternalAllowance.sol';
const internalPlan=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:internalFile,
  targetSelector:'InternalAllowance.increaseAllowance',
  sources:[{path:internalFile,content:internalSource,sha256:sha(internalSource)}],
  declarations:[
    {selector:'InternalAllowance.increaseAllowance',operation:'send',inputs:['address','uint256']},
    {selector:'InternalAllowance.allowance',operation:'call',inputs:['address','address']}
  ],skipLegacy:true});
assert.equal(internalPlan.ok,true,JSON.stringify(internalPlan));
if(!internalPlan.ok)throw new Error('Source helper property missing');
const internalProperty=internalPlan.experiments.find(e=>
  e.securityProperty.startsWith('source-backed internal setter'));
assert.ok(internalProperty,'Exact helper state writes must yield source property');
const internalActual=await execute(
  compile(internalFile,internalSource,'InternalAllowance'),internalProperty.sequence);
assert.ok(internalActual.steps.every((step:any)=>step.passed!==false),
  'Actual private nested-mapping helper readback failed: '+JSON.stringify(internalActual));
assert.ok(internalActual.steps.some((step:any)=>step.operation==='call'&&
  step.function==='allowance(address,address)'&&step.actual==='7'));
const delegatedScalarSource=[
  'pragma solidity ^0.8.20;',
  'contract DelegatedScalar {',
  ' uint256 private held;',
  ' function amount() external view returns(uint256) { return held; }',
  ' function update(uint256 value) external { _set(value); }',
  ' function _set(uint256 next) internal { held = next; }',
  '}'
].join('\n');
const delegatedFile='source-1/contracts/DelegatedScalar.sol';
const delegated=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:delegatedFile,
  targetSelector:'DelegatedScalar.update',
  sources:[{path:delegatedFile,content:delegatedScalarSource,
    sha256:sha(delegatedScalarSource)}],
  declarations:[
    {selector:'DelegatedScalar.update',operation:'send',inputs:['uint256']},
    {selector:'DelegatedScalar.amount',operation:'call',inputs:[]}
  ],skipLegacy:true
});
assert.equal(delegated.ok,true,JSON.stringify(delegated));
if(!delegated.ok)throw new Error('Delegated scalar state property missing');
const delegatedProperty=delegated.experiments.find(e=>
  e.securityProperty.startsWith('source internal state assignment'));
assert.ok(delegatedProperty,'Acquired internal setter must produce executable source property');
const delegatedEvm=await execute(
  compile(delegatedFile,delegatedScalarSource,'DelegatedScalar'),
  delegatedProperty.sequence);
assert.ok(delegatedEvm.steps.every((step:any)=>step.passed!==false),
  'Acquired interprocedural source witness failed in actual EVM: '+JSON.stringify(delegatedEvm));
assert.ok(delegatedEvm.steps.some((step:any)=>step.operation==='call'&&
  step.function==='amount()'&&step.actual==='7'));
const typedScalarSource=[
  'pragma solidity ^0.8.20;',
  'contract TypedScalar {',
  ' uint256 public totalDeposits;',
  ' function deposit(uint256 amount) external { totalDeposits+=amount; }',
  ' function deposit(uint64 maturityTimestamp,uint256 wad,bool enabled) external {',
  '   require(maturityTimestamp>block.timestamp);',
  '   if (enabled) { totalDeposits+=wad; }',
  ' }',
  '}',
].join('\n');
const typedScalarFile='source-1/contracts/TypedScalar.sol';
const typedScalar=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:typedScalarFile,
  targetSelector:'TypedScalar.deposit',
  sources:[{path:typedScalarFile,content:typedScalarSource,
    sha256:sha(typedScalarSource)}],
  declarations:[
    {selector:'TypedScalar.deposit',operation:'send',inputs:['uint64','uint256','bool']},
    {selector:'TypedScalar.totalDeposits',operation:'call',inputs:[]},
  ],skipLegacy:true,
});
assert.equal(typedScalar.ok,true,JSON.stringify(typedScalar));
if(!typedScalar.ok)throw new Error('Typed scalar delta property missing');
const typedScalarProperty=typedScalar.experiments.find(e=>
  e.sequence.sourceProperty?.kind==='scalar_delta'&&
  e.sequence.sourceProperty.method==='deposit(uint64,uint256,bool)');
assert.ok(typedScalarProperty,'Source should bind the non-final uint amount parameter');
assert.deepEqual(typedScalarProperty.sequence.steps.find((step:any)=>
  step.operation==='send')&&
  (typedScalarProperty.sequence.steps.find((step:any)=>step.operation==='send') as any).args,
  ['2000000000','1000',true]);
const typedScalarEvm=await execute(
  compile(typedScalarFile,typedScalarSource,'TypedScalar'),
  typedScalarProperty.sequence);
assert.ok(typedScalarEvm.steps.every((step:any)=>step.passed!==false),
  'Source-derived future timestamp and typed arguments must execute: '+JSON.stringify(typedScalarEvm));
assert.ok(typedScalarEvm.steps.some((step:any)=>step.operation==='call'&&
  step.function==='totalDeposits()'&&step.actual==='1000'));
const feeFormulaSource=[
  'pragma solidity ^0.8.20;',
  'contract FeeLedger {',
  ' uint256 public principal;',
  ' uint256 public fees;',
  ' function deposit(uint256 amount) external {',
  '   principal += amount;',
  '   fees += amount * 100 / 10000;',
  ' }',
  '}',
].join('\n');
const feeFormulaFile='source-1/contracts/FeeLedger.sol';
const feeFormulaPlan=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:feeFormulaFile,
  targetSelector:'FeeLedger.deposit',
  sources:[{path:feeFormulaFile,content:feeFormulaSource,
    sha256:sha(feeFormulaSource)}],
  declarations:[
    {selector:'FeeLedger.deposit',operation:'send',inputs:['uint256']},
    {selector:'FeeLedger.principal',operation:'call',inputs:[]},
    {selector:'FeeLedger.fees',operation:'call',inputs:[]},
  ],skipLegacy:true,
});
assert.equal(feeFormulaPlan.ok,true,JSON.stringify(feeFormulaPlan));
if(!feeFormulaPlan.ok)throw new Error('Formula-backed fee transition missing');
const feeFormulaProperty=feeFormulaPlan.experiments.find(e=>
  e.sequence.sourceProperty?.kind==='scalar_delta'&&
  e.sequence.sourceProperty.state==='fees');
assert.ok(feeFormulaProperty,'Fee ledger formula must be independently executable');
const feeFormulaEvm=await execute(
  compile(feeFormulaFile,feeFormulaSource,'FeeLedger'),feeFormulaProperty.sequence);
assert.ok(feeFormulaEvm.steps.every((step:any)=>step.passed!==false),
  'Source-derived fee formula must match the mined EVM transition: '+JSON.stringify(feeFormulaEvm));
assert.ok(feeFormulaEvm.steps.some((step:any)=>step.operation==='call'&&
  step.function==='fees()'&&step.actual==='100'));
const reverseSafeMathSource=`pragma solidity ^0.8.20;
library AcquiredSafeMath {
  function add(uint256 a,uint256 b) internal pure returns(uint256) { return a+b; }
  function sub(uint256 a,uint256 b) internal pure returns(uint256) { return a-b; }
}
contract ReverseSafeMathLedger {
  using AcquiredSafeMath for uint256;
  uint256 public total;
  function deposit(uint256 amount) external { total = amount.add(total); }
  function withdraw(uint256 amount) external { total = total.sub(amount); }
}`;
const reverseSafeMathFile='source-1/contracts/ReverseSafeMathLedger.sol';
const reverseSafeMathPlan=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:reverseSafeMathFile,
  targetSelector:'ReverseSafeMathLedger.withdraw',
  sources:[{path:reverseSafeMathFile,content:reverseSafeMathSource,
    sha256:sha(reverseSafeMathSource)}],
  declarations:[
    {selector:'ReverseSafeMathLedger.deposit',operation:'send',inputs:['uint256']},
    {selector:'ReverseSafeMathLedger.withdraw',operation:'send',inputs:['uint256']},
    {selector:'ReverseSafeMathLedger.total',operation:'call',inputs:[]},
  ],skipLegacy:true,
});
assert.equal(reverseSafeMathPlan.ok,true,JSON.stringify(reverseSafeMathPlan));
if(!reverseSafeMathPlan.ok)throw new Error('Commutative SafeMath conservation property missing');
const reverseSafeMathProperty=reverseSafeMathPlan.experiments.find(e=>
  e.securityProperty==='financial conservation invariant (deposit->withdraw)');
assert.ok(reverseSafeMathProperty,'Reverse SafeMath arithmetic must produce a source-derived financial invariant');
const reverseSafeMathEvm=await execute(
  compile(reverseSafeMathFile,reverseSafeMathSource,'ReverseSafeMathLedger'),
  reverseSafeMathProperty.sequence);
assert.ok(reverseSafeMathEvm.steps.every((step:any)=>step.passed!==false),
  'Reverse SafeMath financial sequence must match independently mined EVM state: '+
  JSON.stringify(reverseSafeMathEvm));
assert.ok(reverseSafeMathEvm.steps.some((step:any)=>step.operation==='call'&&
  step.function==='total()'&&step.actual==='600'));
const privateScalarSource=[
  'pragma solidity ^0.8.20;',
  'contract PrivateScalar {',
  ' uint256 private held;',
  ' function observedAmount() external view returns(uint256) { return held; }',
  ' function accrue(uint256 value) external { held+=value; }',
  '}',
].join('\n');
const privateScalarFile='source-1/contracts/PrivateScalar.sol';
const privateScalar=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:privateScalarFile,
  targetSelector:'PrivateScalar.accrue',
  sources:[{path:privateScalarFile,content:privateScalarSource,
    sha256:sha(privateScalarSource)}],
  declarations:[
    {selector:'PrivateScalar.accrue',operation:'send',inputs:['uint256']},
    {selector:'PrivateScalar.observedAmount',operation:'call',inputs:[]},
  ],skipLegacy:true,
});
assert.equal(privateScalar.ok,true,JSON.stringify(privateScalar));
if(!privateScalar.ok)throw new Error('Private scalar getter property missing');
const privateScalarProperty=privateScalar.experiments.find(e=>
  e.sequence.sourceProperty?.kind==='scalar_delta');
assert.ok(privateScalarProperty,'Private source state needs a legitimate getter witness');
const privateScalarEvm=await execute(
  compile(privateScalarFile,privateScalarSource,'PrivateScalar'),
  privateScalarProperty.sequence);
assert.ok(privateScalarEvm.steps.every((step:any)=>step.passed!==false),
  'Source-declared private-state getter must observe the EVM transition: '+JSON.stringify(privateScalarEvm));
assert.ok(privateScalarEvm.steps.some((step:any)=>step.operation==='call'&&
  step.function==='observedAmount()'&&step.actual==='1000'));
const guardedSource=[
  'pragma solidity ^0.8.20;',
  'contract GuardedState {',
  ' address public trusted;',
  ' uint256 public stored;',
  ' constructor(){trusted=msg.sender;}',
  ' function update(uint256 next) external {',
  '   require(msg.sender==trusted,"owner");',
  '   stored=next;',
  ' }',
  '}',
].join('\n');
const guardedFile='source-1/contracts/GuardedState.sol';
const guardedMenu=[{selector:'GuardedState.update',operation:'send' as const,inputs:['uint256']}];
const guardedBuilt=constructSolidityExperiments({
  repositoryCommit:'d'.repeat(40),targetPath:guardedFile,
  targetSelector:'GuardedState.update',
  sources:[{path:guardedFile,content:guardedSource,sha256:sha(guardedSource)}],
  declarations:guardedMenu,skipLegacy:true});
assert.equal(guardedBuilt.ok,true,JSON.stringify(guardedBuilt));
if(!guardedBuilt.ok)throw new Error('Guarded source property missing');
const guardedProperty=guardedBuilt.experiments.find(e=>
  e.securityProperty.startsWith('source-proof generic owner guard'));
assert.ok(guardedProperty,'Generic authenticated storage property missing');
const guardedObserved=await execute(
  compile(guardedFile,guardedSource,'GuardedState'),guardedProperty.sequence);
assert.ok(guardedObserved.steps.every((step:any)=>step.passed!==false),
  'Source guardian proof failed actual EVM replay: '+JSON.stringify(guardedObserved));
assert.equal(guardedObserved.steps.find((step:any)=>step.operation==='send')?.reverted,true);
const invertedGuard=guardedSource.replace(
  'msg.sender==trusted','msg.sender!=trusted');
const nonownerAllowed=await execute(
  compile(guardedFile,invertedGuard,'GuardedState'),guardedProperty.sequence);
assert.ok(nonownerAllowed.steps.some((step:any)=>
  step.operation==='send'&&step.sender===1&&step.passed===false),
  'Reversing the real owner condition must produce an independently observed counterexample');
console.log('SOURCE_DERIVED_FINANCIAL_EVM_ORACLES_PASSED');
