/** Deterministic production regression: polyglot candidate breadth,
 * archive provenance and long-hunt AST persistence, with no model transport.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {controllerPolyglotPlans} from '../packages/security-solver/src/controller-polyglot-plan';
import {SoliditySourceIndex} from '../packages/security-solver/src/solidity-source-index';
import {ControllerEvidenceArchive} from '../packages/security-solver/src/controller-evidence-archive';
import {evaluateDeterministicEvidenceReview,resolveLocalModelAdapter} from '../packages/security-solver/src/deterministic';

const root=await mkdtemp(join(tmpdir(),'lotus-audit-regressions-'));
try{
  assert.equal(resolveLocalModelAdapter({AUTOHACK_OLLAMA_URL:'http://127.0.0.1:11434/api/chat'}),'deterministic');
  assert.throws(()=>resolveLocalModelAdapter({LOCAL_MODEL_ADAPTER:'ollama'}),/LOTUS_MODEL_REMOVED/);
  await mkdir(join(root,'source-1'));
  const fixtures=[
    ['render.py','def safe(value):\n    return "<p>safe</p>"\ndef render(value):\n    return "<p>"+value+"</p>"\n','render'],
    ['render.cjs','exports.safe=function(value){return "<p>safe</p>";};\nexports.render=function(value){return "<p>"+value+"</p>";};','render'],
    ['Render.java','public class Render {public static String safe(String value){return "<p>safe</p>";} public static String render(String value){return "<p>"+value+"</p>";}}','Render.render'],
  ] as const;
  for(const [filename,content,selector] of fixtures){
    const path='source-1/'+filename;
    await writeFile(join(root,path),content);
    const plans=controllerPolyglotPlans(path,content);
    assert.ok(plans.some(p=>p.query===selector),
      filename+': controller must enumerate meaningful functions after decoys');
  }
  const rejected=evaluateDeterministicEvidenceReview(null);
  assert.equal(rejected.verdict,'reject');
  assert.equal(rejected.issues[0].category,'missing_typed_evidence');
  const restored=new InvestigationWorkflow();
  restored.restore({version:1,notes:['Prior navigation'],evidenceReferences:['b'.repeat(64)]});
  assert.deepEqual(restored.memory().evidenceReferences,[],
    'Prior-run archive IDs are not current-run evidence');
  const archive=new ControllerEvidenceArchive(join(root,'cold.jsonl'));
  const id=await archive.append('source',{value:1});
  const parentIds=[id];
  const child=await archive.append('probe',{status:'observed'},{parentIds});
  parentIds.length=0;
  const copy=(await archive.retrieve(child))!;
  copy.parentIds.length=0;
  (copy.payload as any).status='forged';
  assert.deepEqual((await archive.retrieve(child))?.parentIds,[id]);
  assert.deepEqual((await archive.retrieve(child))?.payload,{status:'observed'});
  // Cumulative source count/size must not disable Solidity AST enumeration.
  const solidity=new SoliditySourceIndex(root);
  for(let i=0;i<40;i++){
    const file=join(root,'source-1','Indexed'+i+'.sol');
    await writeFile(file,'// '+'x'.repeat(110000)+'\npragma solidity ^0.8.0; contract Indexed'+i+' {uint public value; function change(uint amount) public {value=amount;}}');
    assert.ok((await solidity.probeMenu(file)).some(p=>p.selector==='Indexed'+i+'.change'),
      'Solidity candidate '+i+' retains AST support');
  }
  console.log('Four-language candidate inventory, fail-closed review, cold archive and long-hunt AST regressions PASSED');
}finally{await rm(root,{recursive:true,force:true});}
