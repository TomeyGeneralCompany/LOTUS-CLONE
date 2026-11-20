import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { SoliditySourceIndex } from '../packages/security-solver/src/solidity-source-index';
import { SourceReads } from '../packages/security-solver/src/source-inspection';
import { runLocalAudit } from '../packages/security-solver/src/local-ollama-runner';
const root=await mkdtemp(join(tmpdir(),'solidity-index-'));
try {
  const base='pragma solidity ^0.8.20; contract Base { mapping(address=>uint) internal balances; bool locked; modifier nonReentrant() { require(!locked); locked=true; _; locked=false; } function helper(uint x) internal pure returns(uint) { return x; } }';
  const source=`// Unicode before declarations: café 🦆\npragma solidity ^0.8.20;
import {Base as Parent} from "./Base.sol";
contract Vault is Parent {
 constructor(uint x) { balances[msg.sender]=x; }
 function withdraw(uint x) external nonReentrant { balances[msg.sender]-=helper(x); }
 function withdraw() external { balances[msg.sender]=0; }
 function huge() external {\n${'balances[msg.sender]++;\n'.repeat(300)}}
}`;
  await writeFile(join(root,'Base.sol'),base);await writeFile(join(root,'Vault.sol'),source);
  const index=new SoliditySourceIndex(root);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.withdraw'),true);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.constructor'),true);
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.function'),false,'placeholder is not a declared method');
  assert.equal(await index.hasFunction(join(root,'Vault.sol'),'Vault.randomMethod'),false,'invented function is not a declared method');
  const outline=await index.outline(join(root,'Vault.sol'),0,8000);
  const functions=outline.items.filter(x=>x.kind==='FunctionDefinition');
  assert.equal(functions.length,4);assert.ok(functions.some(x=>x.name==='constructor'));
  const withdraw=functions.find(x=>String(x.signature).includes('withdraw(uint'))!;
  assert.equal(source.slice(Number(withdraw.start),Number(withdraw.end)).startsWith('function withdraw(uint'),true,'Ranges must use UTF-16 even after emoji');
  await assert.rejects(index.context(join(root,'Vault.sol'),'Vault.withdraw',0,8000),/overloaded/);
  const bundle=await index.context(join(root,'Vault.sol'),String(withdraw.id),0,8000);
  assert.equal(bundle.nextOffset,null);
  assert.ok(bundle.excerpts.some(x=>x.path==='Base.sol'&&x.text.includes('modifier nonReentrant')));
  assert.ok(bundle.excerpts.some(x=>x.path==='Base.sol'&&x.text.includes('mapping(address')));
  assert.ok(bundle.excerpts.some(x=>x.text.includes('import {Base as Parent}')));
  assert.ok(bundle.helpers.some(x=>x.name==='Base.helper'));
  for(const excerpt of bundle.excerpts)assert.equal(excerpt.text,(excerpt.path==='Base.sol'?base:source).slice(excerpt.start,excerpt.end));
  const huge=functions.find(x=>x.name==='huge')!;
  let offset:number|null=0, turns=0;const evidence=new SourceReads();
  while(offset!==null) {
    const result=await index.context(join(root,'Vault.sol'),String(huge.id),offset,1500);
    assert.ok(JSON.stringify(result).length<=1500);
    for(const e of result.excerpts){assert.equal(e.text,(e.path==='Base.sol'?base:source).slice(e.start,e.end));evidence.add(e.path,e);}
    if(turns++===0)assert.equal(evidence.covers('Vault.sol',Number(huge.start),Number(huge.end)),false);
    assert.ok(result.nextOffset===null||result.nextOffset>offset);offset=result.nextOffset;
    assert.ok(turns<100);
  }
  assert.ok(evidence.covers('Vault.sol',Number(huge.start),Number(huge.end)));
  const all=[];offset=0;
  while(offset!==null) {const page=await index.outline(join(root,'Vault.sol'),offset,700);all.push(...page.items);offset=page.nextOffset;assert.ok(JSON.stringify(page).length<=700);}
  assert.deepEqual(all,outline.items);
  await writeFile(join(root,'Bad.sol'),'contract Broken { function');
  await assert.rejects(index.outline(join(root,'Bad.sol'),0,2000));
  await writeFile(join(root,'Oversize.sol'),' '.repeat(512001));
  await assert.rejects(index.outline(join(root,'Oversize.sol'),0,2000),/size limit/);
  await writeFile(join(root,'Missing.sol'),'import "@missing/Base.sol"; contract Missing is Base { function f() external {} }');
  const missing=await index.context(join(root,'Missing.sol'),'Missing.f',0,4000);
  assert.ok(missing.unresolved.some(x=>x.includes('Unresolved/ambiguous base')));
  assert.ok(missing.unresolved.some(x=>x.includes('import @missing')));
  // Explicitly supplied symlinks may not escape the hunt workspace.
  await symlink('/etc/passwd',join(root,'escape.sol'));
  await assert.rejects(index.outline(join(root,'escape.sol'),0,2000),/outside/);
  // A new acquired workspace/version must not reuse stale source from cache.
  await writeFile(join(root,'Changing.sol'),'contract C { function oldName() external {} }');
  assert.ok((await new SoliditySourceIndex(root).outline(join(root,'Changing.sol'),0,2000)).items.some(x=>x.name==='oldName'));
  await writeFile(join(root,'Changing.sol'),'contract C { function newName() external {} }');
  assert.ok((await new SoliditySourceIndex(root).outline(join(root,'Changing.sol'),0,2000)).items.some(x=>x.name==='newName'));
  // Cyclic imports terminate and unit aliases resolve without traversing outside scope.
  await writeFile(join(root,'Cycle.sol'),'import * as B from "./CycleBase.sol"; contract Cycle is B.CycleBase { function f() external {} }');
  await writeFile(join(root,'CycleBase.sol'),'import "./Cycle.sol"; contract CycleBase { uint value; }');
  assert.ok((await index.context(join(root,'Cycle.sol'),'Cycle.f',0,4000)).excerpts.some(x=>x.path==='CycleBase.sol'&&x.text.includes('uint value')));
  // Exercise the production deterministic runner without an obsolete model server.
  // An outline alone must not be counted as a source read.
  await writeFile(join(root,'Tiny.sol'),'contract Tiny { uint value; function set(uint x) external { value=x; } }');
  const oldAdapter=process.env.LOCAL_MODEL_ADAPTER;
  const oldProtocol=process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
  const oldUrl=process.env.AUTOHACK_OLLAMA_URL;
  try {
    process.env.LOCAL_MODEL_ADAPTER='deterministic';
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
    process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:1/api/chat';
    let readCount=0;
    const result=await runLocalAudit('Inspect Tiny.sol',join(root,'deterministic.log'),30000,root,
      'deterministic',undefined,{
        numCtx:8192,numPredict:512,numThreads:1,maxTurns:12,
        initialSourcePaths:['Tiny.sol'],
        onRead:(path,span)=>{assert.equal(path,'Tiny.sol');assert.ok(span.end>span.start);readCount++;},
        validateFinal:raw=>{
          const result=JSON.parse(raw);
          return Array.isArray(result.findings) && result.outcome==='no_testable_candidate'
            ? null : 'Invalid deterministic final';
        },
      });
    assert.equal(JSON.parse(result).outcome,'no_testable_candidate');
    assert.ok(readCount>0,'Deterministic inspection must actually read the source');
    const log=await readFile(join(root,'deterministic.log'),'utf8');
    assert.match(log,/\\[DETERMINISTIC_DRIVER_ACTION\\]/);
    assert.doesNotMatch(log,/\\[MODEL_REQUEST_RECOVERY\\]/);
  } finally {
    for(const [key,value] of Object.entries({
      LOCAL_MODEL_ADAPTER:oldAdapter,LOCAL_OLLAMA_TOOL_PROTOCOL:oldProtocol,
      AUTOHACK_OLLAMA_URL:oldUrl,
    })) {
      if(value===undefined)delete process.env[key];else process.env[key]=value;
    }
  }
  console.log('Solidity AST outline, aliases/inheritance/modifiers, exact spans, bounded context, cache invalidation, deterministic runner integration PASSED');
} finally {await rm(root,{recursive:true,force:true});}
