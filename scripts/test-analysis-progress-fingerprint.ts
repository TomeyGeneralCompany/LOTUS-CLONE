import assert from 'node:assert/strict';
import {analysisProgressFingerprint} from '../packages/security-solver/src/local-ollama-runner';

const before=analysisProgressFingerprint({selected:18,assessed:4,deferred:2,blocked:0,
  pendingIds:['lead-5','lead-6'],inventoryResolved:4,inventoryRemaining:286,
  candidateAssessed:4,candidateRemaining:286,processedBatches:0});
const afterDisposition=analysisProgressFingerprint({selected:18,assessed:5,deferred:3,blocked:0,
  pendingIds:['lead-6'],inventoryResolved:5,inventoryRemaining:285,
  candidateAssessed:5,candidateRemaining:285,processedBatches:0});
assert.notEqual(afterDisposition,before,
  'A valid source-grounded assess/defer action is forward progress');
assert.equal(analysisProgressFingerprint({selected:18,assessed:5,deferred:3,blocked:0,
  pendingIds:['lead-6'],inventoryResolved:5,inventoryRemaining:285,
  candidateAssessed:5,candidateRemaining:285,processedBatches:0}),afterDisposition,
  'An unchanged analysis inventory remains detectable as stalled');

console.log('ANALYZE lead-disposition progress prevents false stall termination');
