import {readFileSync} from 'node:fs';
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

// The live entrypoint must call the imported deterministic initializer. This
// regression caught a post-merge ReferenceError that stopped the laptop hunt.
const entrypoint=readFileSync(new URL('./one-bounty.ts',import.meta.url),'utf8');
assert.match(entrypoint,/ensureOneBountyDeterministicEngine\\(process\\.env\\)/);
assert.doesNotMatch(entrypoint,/ensureOneBountyLocalModel\\s*\\(/);
