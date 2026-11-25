'use strict';
// Owned synthetic contracts exercise the exact runtime executor without external services.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const solc=require('./reproduction-runtime/node_modules/solc');
const ganache=require('./reproduction-runtime/node_modules/ganache');
const solc_084=require('./reproduction-runtime/node_modules/solc_0_8_4');
const solc_076=require('./reproduction-runtime/node_modules/solc_0_7');
const {validateSequence,runSequence}=require('./reproduction-runtime/solidity-sequence.cjs');
const {compileSoliditySourceGroups}=require('./reproduction-runtime/solidity-compiler.cjs');
const source=`pragma solidity ^0.8.20;
contract Fixture {
 uint256 public value; address public owner;
 constructor(uint256 initial,address admin) payable {value=initial;owner=admin;}
 event ValueChanged(address indexed actor,uint256 oldValue,uint256 newValue);
 function set(uint256 x) external {require(msg.sender==owner,"owner");uint256 old=value;value=x;emit ValueChanged(msg.sender,old,x);}
 function set(uint256 x,bool plus) external {value=plus?x+1:x;}
 function deposit() external payable {value+=msg.value;}
 function balance() external view returns(uint256) {return address(this).balance;}
 function pair() external view returns(uint256,bool) {return (value,true);}
 function triple() external pure returns(uint256[][][] memory result) {
   result=new uint256[][][](1);result[0]=new uint256[][](1);
   result[0][0]=new uint256[](2);result[0][0][0]=1;result[0][0][1]=2;
 }
}`;
const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Fixture.sol':{content:source}},
 settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
assert.equal((compiled.errors||[]).filter(x=>x.severity==='error').length,0);
const artifact=compiled.contracts['Fixture.sol'].Fixture;
const sequence={constructorArgs:['9007199254740993','$account0'],constructorValueWei:'10',steps:[
 {operation:'call',function:'value()',args:[],expect:'9007199254740993'},
 {operation:'call',function:'owner()',args:[],expect:'$account0'},
 {operation:'send',function:'set(uint256)',args:['3'],sender:1,expectRevert:true},
 {operation:'call',function:'value()',args:[],expect:'9007199254740993'},
 {operation:'send',function:'set(uint256)',args:['7'],
  expectEvents:[{signature:'ValueChanged(address,uint256,uint256)',
   args:['$account0','9007199254740993','7']}]},
 {operation:'send',function:'deposit()',args:[],sender:2,valueWei:'5'},
 {operation:'call',function:'value()',args:[],expect:'12'},
 {operation:'call',function:'balance()',args:[],expect:'15'},
 {operation:'send',function:'set(uint256,bool)',args:['20',true]},
 {operation:'call',function:'pair()',args:[],expect:['21',true]},
 {operation:'call',function:'triple()',args:[],expect:[[['1','2']]]},
]};
async function execute(s) {
 const transport=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
  chain:{hardfork:'shanghai',chainId:1337,time:new Date('2020-01-01T00:00:00Z')},miner:{blockGasLimit:12000000,timestampIncrement:1}});
 try {return await runSequence(artifact,s,transport,{},{
   abiSha256:createHash('sha256').update(JSON.stringify(artifact.abi)).digest('hex'),
   preparationAbiSha256:{}
 });} finally {await transport.disconnect();}
}
(async()=>{
 validateSequence(sequence);
 const first=await execute(sequence);
 assert.ok(first.steps.every(x=>x.passed),JSON.stringify(first));
 assert.equal(first.diagnostics.abiSha256,
   createHash('sha256').update(JSON.stringify(artifact.abi)).digest('hex'),
   'Compiled ABI provenance must survive independent EVM result capture');
 assert.equal(first.steps[2].reverted,true);
 assert.equal(first.steps[4].eventsPassed,true,
   'Source-declared event arguments must be checked against the mined receipt');
 assert.equal(first.steps[4].receipt.status,1);
 assert.ok(first.steps[4].receipt.transactionHash);
 assert.ok(first.steps[4].receipt.logs.some(log=>log.topics.length>0&&log.data.startsWith('0x')),
   'The complete raw receipt log must be preserved');
 assert.deepEqual(await execute(sequence),first,'Fresh deployment replay must be deterministic');
 const wrongEvent=structuredClone(sequence);
 wrongEvent.steps[4].expectEvents[0].args[2]='8';
 const wrongEventResult=await execute(wrongEvent);
 assert.equal(wrongEventResult.steps[4].eventsPassed,false);
 assert.equal(wrongEventResult.steps[4].passed,false,
   'An event mismatch must fail assertion without discarding receipt evidence');
 assert.equal(wrongEventResult.steps[4].receipt.status,1);
 const inventedEvent=structuredClone(sequence);
 inventedEvent.steps[4].expectEvents[0].signature='Invented(address,uint256,uint256)';
 await assert.rejects(execute(inventedEvent),/not declared in the compiled acquired-source ABI/);
 const mismatch=structuredClone(sequence);mismatch.steps.at(-1).expect=['22',true];
 assert.equal((await execute(mismatch)).steps.at(-1).passed,false);
 const unexpected=structuredClone(sequence);unexpected.steps[2].expectRevert=false;
 const unexpectedResult=await execute(unexpected);
 assert.equal(unexpectedResult.steps[2].reverted,true);
 assert.equal(unexpectedResult.steps[2].passed,false);
 assert.match(unexpectedResult.steps[2].gasUsed,/^[0-9]+$/);
 assert.equal(unexpectedResult.steps[3].passed,true,
   'Read after an unexpected mined revert must remain observable');
 // Actual acquired preparation contracts can pin a different compiler than
 // the target. Compile, deploy and execute both compiler artifacts without
 // changing either source pragma or substituting a mock implementation.
 const mixedSources={
  'Target084.sol':{content:'pragma solidity 0.8.4; contract Target084 {'+
   ' uint256 public value; function set() external { value=7; } }'},
  'Dependency076.sol':{content:'pragma solidity 0.7.6; contract Dependency076 {'+
   ' uint256 public value; constructor(uint256 initial){value=initial;} }'}
 };
 const mixed=compileSoliditySourceGroups(mixedSources,source=>{
   if(/\b0\.7\.6\b/.test(source))return {solc:solc_076,evmVersion:'berlin'};
   if(/\b0\.8\.4\b/.test(source))return {solc:solc_084,evmVersion:'berlin'};
   throw new Error('Unpinned mixed-version fixture source');
 },undefined,true,()=>({error:'No imports expected in the version-isolation regression'}));
 assert.equal(mixed.compilerGroupCount,2,
  'Each distinct exact compiler version must receive a separate source group');
 assert.equal((mixed.compiled.errors||[]).filter(x=>x.severity==='error').length,0);
 const mixedTarget=mixed.compiled.contracts['Target084.sol'].Target084;
 const mixedDependency=mixed.compiled.contracts['Dependency076.sol'].Dependency076;
 assert.ok(mixedTarget.evm.bytecode.object&&mixedDependency.evm.bytecode.object,
  'Both compiler-produced deployment artifacts must be present');
 const mixedTransport=ganache.provider({logging:{quiet:true},
  wallet:{deterministic:true,totalAccounts:3},chain:{hardfork:'berlin',chainId:1337,
   time:new Date('2020-01-01T00:00:00Z')},miner:{blockGasLimit:12000000}});
 try{
  const mixedSequence={constructorArgs:[],preparation:{deployments:[
   {id:'legacy_dependency',file:'Dependency076.sol',contract:'Dependency076',constructorArgs:['4']}
  ],operations:[],checks:[{id:'dependency-source-state',deploymentId:'legacy_dependency',
   function:'value()',args:[],expect:'4',sender:0}]},steps:[
   {operation:'send',function:'set()',args:[]},
   {operation:'call',function:'value()',args:[],expect:'7'}
  ]};
  validateSequence(mixedSequence);
  const mixedResult=await runSequence(mixedTarget,mixedSequence,mixedTransport,
   mixed.compiled.contracts,{
    preparationAbiSha256:{legacy_dependency:createHash('sha256')
     .update(JSON.stringify(mixedDependency.abi)).digest('hex')}
   });
  assert.ok(mixedResult.steps.every(step=>step.passed),JSON.stringify(mixedResult));
  assert.ok(mixedResult.steps.some(step=>step.operation==='setup'&&
   step.function==='deploy:Dependency076.sol:Dependency076'));
  assert.equal(mixedResult.steps.at(-1).actual,'7');
 }finally{await mixedTransport.disconnect();}
 // ERC-1155-like setup: a transfer without minted balance must revert,
 // but the failed transfer and unchanged balance are both recorded.
 const tokenSource=`pragma solidity ^0.8.20;
 contract TokenFixture {
   mapping(address => uint256) public balanceOf;
   function mint(address to,uint256 amount) external {balanceOf[to]+=amount;}
   function safeTransferFrom(address from,address to,uint256 amount) external {
     require(msg.sender==from,"unauthorized");
     require(balanceOf[from]>=amount,"insufficient balance");
     balanceOf[from]-=amount;balanceOf[to]+=amount;
   }
 }`;
 const tokenCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'TokenFixture.sol':{content:tokenSource}},settings:{evmVersion:'shanghai',
   outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 const tokenArtifact=tokenCompiled.contracts['TokenFixture.sol'].TokenFixture;
 const tokenTransport=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
   chain:{hardfork:'shanghai'},miner:{blockGasLimit:12000000}});
 try {
   const tokenResult=await runSequence(tokenArtifact,{constructorArgs:[],steps:[
     {operation:'observe',function:'balanceOf(address)',args:['$account0']},
     {operation:'send',function:'safeTransferFrom(address,address,uint256)',
       args:['$account0','$account1','1'],expectRevert:false},
     {operation:'observe',function:'balanceOf(address)',args:['$account0']},
     {operation:'send',function:'mint(address,uint256)',args:['$account0','2']},
     {operation:'send',function:'safeTransferFrom(address,address,uint256)',
       args:['$account0','$account1','1']},
     {operation:'call',function:'balanceOf(address)',args:['$account1'],expect:'1'}
   ]},tokenTransport);
   assert.equal(tokenResult.steps[1].reverted,true);
   assert.equal(tokenResult.steps[1].passed,false);
   assert.equal(tokenResult.steps[2].actual,'0');
   assert.equal(tokenResult.steps[4].reverted,false);
   assert.equal(tokenResult.steps[5].passed,true);
 } finally {await tokenTransport.disconnect();}
 // Regression: controller-produced source-derived state observation, rather
 // than an unrelated gated view function, runs in the real local EVM.
 const authoritySource=`pragma solidity ^0.8.20;
 contract Authority {
   address public administrator;
   address public operator;
   constructor(){administrator=msg.sender;operator=msg.sender;}
   function rotateOperator(address next) external {operator=next;}
   function changeAdministrator(address next) external {
     require(msg.sender==administrator,"only admin");administrator=next;
   }
 }`;
 const authorityCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'Authority.sol':{content:authoritySource}},settings:{evmVersion:'shanghai',
   outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.equal((authorityCompiled.errors||[]).filter(x=>x.severity==='error').length,0);
 const authority=authorityCompiled.contracts['Authority.sol'].Authority;
 const authoritySequence={constructorArgs:[],steps:[
   {operation:'observe',function:'operator()',args:[]},
   {operation:'send',function:'rotateOperator(address)',args:['$account1'],sender:1,expectRevert:true},
   {operation:'observe',function:'operator()',args:[]}
 ]};
 const providerForAuthority=()=>ganache.provider({logging:{quiet:true},
   wallet:{deterministic:true,totalAccounts:3},chain:{hardfork:'shanghai',chainId:1337,
   time:new Date('2020-01-01T00:00:00Z')},
   miner:{blockGasLimit:12000000,timestampIncrement:1}});
 const authorityTransport=providerForAuthority();
 try {
   const output=await runSequence(authority,authoritySequence,authorityTransport);
   assert.equal(output.steps[1].reverted,false);
   assert.equal(output.steps[1].passed,false,'Actual non-admin success disproves the expected revert');
   assert.equal(output.steps[2].actual,output.accounts[1]);
   assert.notEqual(output.steps[0].actual,output.steps[2].actual);
 } finally {await authorityTransport.disconnect();}
 // Controller preparation must mine and record balance/approval setup before
 // the actual transfer, without treating setup as vulnerability evidence.
 const harnessSource=`pragma solidity ^0.8.20;
 contract TomeyERC1155ProbeHarness {
   mapping(uint256=>mapping(address=>uint256)) private balances;
   mapping(address=>mapping(address=>bool)) private approvals;
   function balanceOf(address a,uint256 id) external view returns(uint256){return balances[id][a];}
   function isApprovedForAll(address a,address b) external view returns(bool){return approvals[a][b];}
   function setApprovalForAll(address b,bool approved) external {approvals[msg.sender][b]=approved;}
   function tomeyMintBatch(address a,uint256[] memory ids,uint256[] memory amounts) external {
     for(uint i=0;i<ids.length;i++)balances[ids[i]][a]+=amounts[i];
   }
   function tomeyMint(address a,uint256 id,uint256 amount) external {balances[id][a]+=amount;}
   function safeTransferFrom(address a,address b,uint256 id,uint256 amount,bytes memory) external {
     require(msg.sender==a||approvals[a][msg.sender],"approval");
     require(balances[id][a]>=amount,"balance");
     balances[id][a]-=amount;balances[id][b]+=amount;
   }
 }`;
 const hc=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'Harness.sol':{content:harnessSource}},
   settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.deepEqual((hc.errors||[]).filter(e=>e.severity==='error'),[]);
 const ha=hc.contracts['Harness.sol'].TomeyERC1155ProbeHarness;
 const ht=ganache.provider({logging:{quiet:true},wallet:{deterministic:true,totalAccounts:3},
   chain:{hardfork:'shanghai'},miner:{blockGasLimit:12000000}});
 try{
   const h=await runSequence(ha,{constructorArgs:[],steps:[
     {operation:'send',function:'safeTransferFrom(address,address,uint256,uint256,bytes)',
       args:['$account0','$account2','1','3','0x'],sender:1},
     {operation:'call',function:'balanceOf(address,uint256)',args:['$account2','1'],expect:'3'}
   ]},ht);
   assert.equal(h.steps[0].operation,'setup');
   assert.equal(h.steps[1].operation,'setup');
   assert.equal(h.steps[0].receipt.status,1);
   assert.ok(h.steps[0].receipt.transactionHash);
   assert.equal(h.steps[1].receipt.status,1);
   assert.ok(h.steps[1].receipt.transactionHash);
   assert.equal(h.steps[2].operation,'send');
   assert.equal(h.steps[2].reverted,false);
   assert.equal(h.steps[3].passed,true);
 }finally{await ht.disconnect();}

 // Regression: non-function-bearing eth_balance steps must remain executable.
 const withBalanceBefore={constructorArgs:['0','$account0'],steps:[
  {operation:'eth_balance',account:'$contract'},
  {operation:'send',function:'set(uint256)',args:['3'],sender:1,expectRevert:true},
  {operation:'eth_balance',account:'$contract'},
  {operation:'call',function:'value()',args:[],expect:'0'}
 ]};
 const balanceResult=await execute(withBalanceBefore);
 assert.equal(balanceResult.steps[0].operation,'eth_balance');
 assert.equal(balanceResult.steps[1].reverted,true);
 assert.equal(balanceResult.steps[2].operation,'eth_balance');
 assert.equal(balanceResult.steps[3].passed,true);
 assert.deepEqual(await execute(withBalanceBefore),balanceResult);
 const withBalanceAfter={constructorArgs:['0','$account0'],steps:[
  {operation:'send',function:'set(uint256)',args:['7'],sender:0},
  {operation:'eth_balance',account:'$contract'},
  {operation:'call',function:'value()',args:[],expect:'7'}
 ]};
 const afterBalanceResult=await execute(withBalanceAfter);
 assert.equal(afterBalanceResult.steps[0].reverted,false);
 assert.equal(afterBalanceResult.steps[1].operation,'eth_balance');
 assert.equal(afterBalanceResult.steps[2].passed,true);
 // Selected-function guard must tolerate balance-only steps but still
 // require a concrete function match.
 const selectedFunction='set';
 const exercisesSelected=steps=>steps.some(step=>
  typeof step.function==='string' && step.function.split('(')[0]===selectedFunction);
 assert.equal(exercisesSelected(withBalanceBefore.steps),true);
 assert.equal(exercisesSelected([{operation:'eth_balance',account:'$contract'}]),false);
 assert.equal(exercisesSelected([{operation:'eth_balance',account:'$contract'},
  {operation:'send',function:'deposit()',args:[]}]),false);
 // Genuine source factory procedure: execute creation and initialization
 // after a template deployment, then address the returned contract rather
 // than incorrectly interacting with template storage.
 const childSource='pragma solidity ^0.8.20; contract Child {'+
   'uint256 public value; function initialize(uint256 n) external {'+
   'require(value==0); value=n;} function set(uint256 n) external {value=n;} }';
 const factorySource='pragma solidity ^0.8.20; import "./Child.sol"; '+
   'contract Factory { function createChild(address template,uint256 n) external '+
   'returns(Child){ require(template!=address(0)); Child result=new Child(); '+
   'result.initialize(n); return result; } }';
 const sourceCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
   sources:{'Child.sol':{content:childSource},'Factory.sol':{content:factorySource}},
   settings:{evmVersion:'shanghai',outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.bytecode.linkReferences']}}}})));
 assert.deepEqual((sourceCompiled.errors||[]).filter(e=>e.severity==='error'),[]);
 const childArtifact=sourceCompiled.contracts['Child.sol'].Child;
 const factoryArtifact=sourceCompiled.contracts['Factory.sol'].Factory;
 const clonedTransport=ganache.provider({logging:{quiet:true},
   wallet:{deterministic:true,totalAccounts:3},chain:{hardfork:'shanghai'},
   miner:{blockGasLimit:12000000}});
 try{
   const cloneSequence={constructorArgs:[],
     preparation:{deployments:[{id:'factory',file:'Factory.sol',contract:'Factory',
       constructorArgs:[]}],operations:[],checks:[]},
     factoryClone:{deploymentId:'factory',function:'createChild(address,uint256)',
       args:['$contract','7'],sender:0},
     steps:[{operation:'call',function:'value()',args:[],expect:'7'},
       {operation:'send',function:'set(uint256)',args:['9'],sender:0},
       {operation:'call',function:'value()',args:[],expect:'9'}]};
   validateSequence(cloneSequence);
   const actual=await runSequence(childArtifact,cloneSequence,clonedTransport,
     {'Factory.sol':{Factory:factoryArtifact}});
   assert.equal(actual.steps[0].operation,'setup');
   assert.match(actual.steps[1].purpose,/created clone.*runtime code sha256/);
   assert.ok(actual.steps.every(x=>x.passed),JSON.stringify(actual));
   assert.equal(actual.steps.at(-1).actual,'9');
 }finally{await clonedTransport.disconnect();}
 // A source-acquired preparation contract may require a compiler-linked
 // Solidity library, as NFTWithSVG does through NFTDescriptor in the real
 // source inventory. Deploy the exact compiled library and link its address
 // into the preparation bytecode before running source-declared checks.
 const linkedSources={
  'NFTDescriptor.sol':{content:'pragma solidity ^0.8.20; library NFTDescriptor {'+
    'function next(uint256 value) external pure returns(uint256){return value+1;} }'},
  'NFTWithSVG.sol':{content:'pragma solidity ^0.8.20; import "./NFTDescriptor.sol"; '+
    'contract NFTWithSVG { uint256 public value; constructor(uint256 initial){'+
    'value=NFTDescriptor.next(initial);} }'},
  'ProbeTarget.sol':{content:'pragma solidity ^0.8.20; contract ProbeTarget {'+
    'function ping() external pure returns(uint256){return 1;} }'}
 };
 const linkedCompiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',
  sources:linkedSources,settings:{evmVersion:'shanghai',
   outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.bytecode.linkReferences']}}}})));
 assert.deepEqual((linkedCompiled.errors||[]).filter(e=>e.severity==='error'),[]);
 const libraryConsumer=linkedCompiled.contracts['NFTWithSVG.sol'].NFTWithSVG;
 assert.ok(Object.keys(libraryConsumer.evm.bytecode.linkReferences).length,
  'Compiler must report the source library link');
 const linkTransport=ganache.provider({logging:{quiet:true},
  wallet:{deterministic:true,totalAccounts:3},chain:{hardfork:'shanghai'},
  miner:{blockGasLimit:12000000}});
 try{
  const linkedResult=await runSequence(
   linkedCompiled.contracts['ProbeTarget.sol'].ProbeTarget,
   {constructorArgs:[],preparation:{deployments:[{id:'template',file:'NFTWithSVG.sol',
      contract:'NFTWithSVG',constructorArgs:['4']}],operations:[],checks:[
       {id:'initialized-template',deploymentId:'template',function:'value()',
        args:[],expect:'5',sender:0}
      ]},steps:[{operation:'call',function:'ping()',args:[],expect:'1'}]},
   linkTransport,linkedCompiled.contracts);
  assert.ok(linkedResult.steps.some(step=>step.operation==='setup'&&
    step.function==='deploy-library:NFTDescriptor.sol:NFTDescriptor'));
  assert.ok(linkedResult.steps.every(step=>step.passed),JSON.stringify(linkedResult));
 }finally{await linkTransport.disconnect();}
 const wrongArgs=structuredClone(sequence);wrongArgs.steps[2].args=['not an integer'];
 await assert.rejects(execute(wrongArgs),/invalid|argument/i,'Invalid ABI input cannot masquerade as an expected revert');
 const readAsSend={constructorArgs:['0','$account0'],steps:[{operation:'send',function:'value()',args:[]},sequence.steps[0]]};
 await assert.rejects(execute(readAsSend),/state-changing/);
 for(const invalid of [
  {...sequence,rpcUrl:'https://example.invalid'},
  {...sequence,constructorArgs:[9007199254740992]},
  {...sequence,steps:[]},
  {...sequence,steps:Array(17).fill(sequence.steps[0])},
  {...sequence,steps:[{...sequence.steps[0],sender:3}]},
  {...sequence,steps:[{...sequence.steps[0],function:'value(); arbitrary()'}]},
  {...sequence,constructorValueWei:'-1'},
 ])assert.throws(()=>validateSequence(invalid));
 assert.doesNotThrow(()=>validateSequence({constructorArgs:[],steps:[
  {operation:'call',function:'triple()',args:[],expect:[[[['1']]]]}
 ]}),"Nested ABI arrays must survive bounded runtime schema validation");
 assert.throws(()=>validateSequence({constructorArgs:[],steps:[
  {operation:'call',function:'triple()',args:[],expect:[[[[[[[[[['1']]]]]]]]]]}
 ]}),/bounded arrays/,"ABI nesting beyond the supported depth must fail closed");
 console.log('Solidity constructors, exact uint256, callers, payable transactions, overloads, expected/unexpected reverts, read assertions and deterministic replay: PASSED');
})().catch(e=>{console.error(e);process.exitCode=1;});
