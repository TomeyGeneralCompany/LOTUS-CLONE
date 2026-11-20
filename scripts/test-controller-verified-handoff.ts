/** Four-language deterministic handoff: source reading and finalization without a model server.
 * Real reproduction and independent-review gates are covered by their own suites.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {resolveLocalModelAdapter,driveDeterministicAuditTurn} from '../packages/security-solver/src/deterministic';

const old={adapter:process.env.LOCAL_MODEL_ADAPTER,url:process.env.AUTOHACK_OLLAMA_URL,
  controller:process.env.LOCAL_CONTROLLER_OWNED_ACTIONS,full:process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX};
const root=await mkdtemp(join(tmpdir(),'lotus-verified-handoff-'));
try {
  // Explicitly forbid the former mock Ollama server path. A copied model setting must fail closed.
  assert.throws(()=>resolveLocalModelAdapter({LOCAL_MODEL_ADAPTER:'ollama'}),/LOTUS_MODEL_REMOVED/);
  process.env.LOCAL_MODEL_ADAPTER='deterministic';
  process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:1/api/chat';
  process.env.LOCAL_CONTROLLER_OWNED_ACTIONS='true';
  process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX='true';

  const fixtures=[
    ['render.py','def render(value):\\n    return "<p>"+value+"</p>"\\n'],
    ['render.cjs','exports.render=function(value){return "<p>"+value+"</p>";};'],
    ['Render.java','public class Render {public static String render(String value){return "<p>"+value+"</p>";}}'],
    ['Counter.sol','pragma solidity ^0.8.20; contract Counter {uint public value; function advance(uint by) external {value+=by;}}'],
  ] as const;
  for(const [name,source] of fixtures) {
    const path='source-1/'+name;
    await mkdir(join(root,'source-1'),{recursive:true});
    await writeFile(join(root,path),source);
    const next=driveDeterministicAuditTurn({
      initialSourcePaths:[path],readPaths:[],sources:[],
      constraints:{action:['read_file','final']},
    });
    assert.equal(next.action,'read_file',name+': deterministic controller must select unread source');
    assert.equal(next.path,path);
    const final=driveDeterministicAuditTurn({
      stage:'REPORT',sources:[{path,content:source,sha256:'a'.repeat(64)}],
      readPaths:[path],initialSourcePaths:[path],
      constraints:{action:['final']},
    });
    assert.equal(final.action,'final',name+': deterministic controller must finalize without model');
    assert.equal(JSON.parse(final.answer).outcome,'no_testable_candidate');

    const log=join(root,name+'.log');
    const answer=await runLocalAudit('Inspect the authorized source.',log,30000,root,
      'deterministic',undefined,{
      numCtx:8192,numPredict:512,numThreads:1,maxTurns:12,
      initialSourcePaths:[path],
      validateFinal:raw=>{
        const result=JSON.parse(raw);
        return Array.isArray(result.findings) && result.outcome==='no_testable_candidate'
          ? null : 'Invalid deterministic final';
      },
    });
    const result=JSON.parse(answer);
    assert.equal(result.outcome,'no_testable_candidate',name);
    assert.deepEqual(result.findings,[],name);
    const events=await readFile(log,'utf8');
    assert.match(events,/\[DETERMINISTIC_DRIVER_ACTION\]/,name+': production runner must invoke deterministic driver');
    assert.doesNotMatch(events,/\[MODEL_REQUEST_RECOVERY\]/,name+': no model retry');
  }
  console.log('Four-language deterministic source handoff and finalization PASSED');
} finally {
  for(const [key,value] of Object.entries({
    LOCAL_MODEL_ADAPTER:old.adapter,AUTOHACK_OLLAMA_URL:old.url,
    LOCAL_CONTROLLER_OWNED_ACTIONS:old.controller,LOCAL_CONTROLLER_FULL_SOURCE_INDEX:old.full,
  })){if(value===undefined)delete process.env[key];else process.env[key]=value;}
  await rm(root,{recursive:true,force:true});
}
