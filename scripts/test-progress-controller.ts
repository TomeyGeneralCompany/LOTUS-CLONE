/** Production progress regression without an inference service.
 * Only novel observed source spans and probes earn controller extensions.
 */
import assert from 'node:assert/strict';
import {AuditAllowance} from '../packages/security-solver/src/audit-allowance';
import {recoverEmptyUnprobedFinal} from '../packages/security-solver/src/inspection-coverage';

const productive=new AuditAllowance(80,0,60_000,true,640,true);
for(let turn=1;turn<=85;turn++){
  productive.read('sample.py',(turn-1)*16,turn*16,turn);
  if(turn===79){
    const extended=productive.extend(turn,50_000);
    assert.ok(extended,'Real novel source evidence must extend the controller');
    assert.equal(productive.turns,120);
  }
}
assert.equal(productive.snapshot().files[0].ranges[0][0],0);
assert.equal(productive.snapshot().files[0].ranges[0][1],1360);
const noProgress=new AuditAllowance(80,0,60_000,true,640,true);
noProgress.read('sample.py',0,16,60);
for(let turn=61;turn<80;turn++)assert.equal(noProgress.read('sample.py',0,16,turn),false);
assert.equal(noProgress.extend(79,50_000),null,'Repeated model assertions are not source progress');
const unchanged={findings:[],outcome:'inspected'};
const exhausted=recoverEmptyUnprobedFinal(unchanged,0) as {findings:unknown[];outcome:string;reason:string};
assert.equal(exhausted.outcome,'no_testable_candidate');
assert.equal(exhausted.findings.length,0);
assert.match(exhausted.reason,/No supported source probe/);
assert.equal(recoverEmptyUnprobedFinal(unchanged,1),unchanged,
  'Verified observation must never disappear through no-probe recovery');
console.log('Evidence-backed controller progress and fail-closed empty-final recovery PASSED');
