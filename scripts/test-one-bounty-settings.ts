import assert from 'node:assert/strict';
import {ensureOneBountyDeterministicEngine} from './one-bounty-settings';
for(const initial of [
  {},
  {OLLAMA_MODEL:'qwen3:0.6b'},
  {LOCAL_OLLAMA_MODEL:'qwen3:4b',OLLAMA_MODEL:'other'},
  {LOCAL_MODEL_ADAPTER:'ollama',LOCAL_OLLAMA_MODEL:'qwen3:4b'},
  {LOCAL_OLLAMA_MODEL:'  ',OLLAMA_MODEL:' '},
] as NodeJS.ProcessEnv[]){
  assert.equal(ensureOneBountyDeterministicEngine(initial),'deterministic');
  assert.equal(initial.LOCAL_MODEL_ADAPTER,'deterministic');
  assert.equal(initial.LOCAL_OLLAMA_MODEL,undefined);
}
console.log('One-bounty local deterministic engine cannot reactivate Qwen PASSED');
