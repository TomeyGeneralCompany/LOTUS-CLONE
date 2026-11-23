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
console.log('SOURCE_DERIVED_FINANCIAL_EVM_ORACLES_PASSED');
