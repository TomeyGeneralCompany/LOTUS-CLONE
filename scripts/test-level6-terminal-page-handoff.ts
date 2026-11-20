/** Deterministic source-queue handoff: completed pages cannot consume inspection turns.
 * Exercises the production deterministic action selector without a mock inference server.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {driveDeterministicAuditTurn} from '../packages/security-solver/src/deterministic';

const root=await mkdtemp(join(tmpdir(),'lotus-terminal-source-regression-'));
const sourcePaths=Array.from({length:16},(_,i)=>
  'source-1/src/services/service_'+String(i).padStart(4,'0')+'.py');

try {
  for(const path of sourcePaths){
    const full=join(root,path);
    await mkdir(dirname(full),{recursive:true});
    await writeFile(full,'def project(value: str) -> str:\\n    return "<p>" + value + "</p>"\\n');
  }
  const readPaths:string[]=[];
  const snapshots:Array<{path:string;content:string;sha256:string}>=[];
  for(let index=0;index<sourcePaths.length;index++){
    const next=driveDeterministicAuditTurn({
      initialSourcePaths:sourcePaths,readPaths,sources:snapshots,
      constraints:{action:['read_file','final']},
    });
    assert.equal(next.action,'read_file','Controller must advance to unread source');
    assert.equal(next.path,sourcePaths[index],'Controller must use indexed authorization order');
    assert.equal(next.offset,0);
    const content=await readFile(join(root,next.path),'utf8');
    assert.ok(content.includes('def project('),'Selected source must exist on disk');
    readPaths.push(next.path);
    snapshots.push({path:next.path,content,sha256:'a'.repeat(64)});
    // After completing a page, the next request must not reread it.
    const subsequent=driveDeterministicAuditTurn({
      initialSourcePaths:sourcePaths,readPaths,sources:snapshots,
      constraints:{action:['read_file','final']},
    });
    if(index+1<sourcePaths.length){
      assert.equal(subsequent.action,'read_file');
      assert.equal(subsequent.path,sourcePaths[index+1]);
    }
  }
  assert.equal(new Set(readPaths).size,sourcePaths.length);
  const final=driveDeterministicAuditTurn({
    stage:'REPORT',initialSourcePaths:sourcePaths,readPaths,sources:snapshots,
    constraints:{action:['final']},
  });
  assert.equal(final.action,'final');
  assert.equal(JSON.parse(final.answer).outcome,'no_testable_candidate');
  console.log('Level 6 deterministic completed-page handoff and exhaustive source queue PASSED');
} finally {
  await rm(root,{recursive:true,force:true});
}
