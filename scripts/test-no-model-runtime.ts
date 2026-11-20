/** Production runtime invariant: LOTUS-CLONE must never require Qwen/Ollama.
 * Historical test fixtures may still discuss the removed transport; none may
 * reintroduce the model to an executable launch, workflow or reviewer.
 */
import assert from 'node:assert/strict';
import {existsSync,readFileSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {resolveLocalModelAdapter,isDeterministicMode} from '../packages/security-solver/src/deterministic';

const root=resolve(import.meta.dirname,'..');
const read=(path:string)=>readFileSync(resolve(root,path),'utf8');
assert.equal(resolveLocalModelAdapter({}), 'deterministic');
assert.equal(resolveLocalModelAdapter({AUTOHACK_OLLAMA_URL:'http://127.0.0.1:11434/api/chat'}),'deterministic');
assert.throws(()=>resolveLocalModelAdapter({LOCAL_MODEL_ADAPTER:'ollama'}),/LOTUS_MODEL_REMOVED/);
assert.throws(()=>resolveLocalModelAdapter({LOCAL_MODEL_ADAPTER:'qwen-agent'}),/LOTUS_MODEL_REMOVED/);
assert.equal(isDeterministicMode({LOCAL_MODEL_PROFILE:'qwen',LOCAL_OLLAMA_MODEL:'qwen3:4b'}),true);
for(const removed of [
  'packages/security-solver/src/qwen-agent-transport.ts',
  'scripts/install-qwen-agent.sh',
  'scripts/qwen-agent-bridge.py',
  'scripts/qwen-agent-requirements.txt',
]) assert.ok(!existsSync(resolve(root,removed)),removed+' must remain removed');
for(const path of [
  'orchestrator.ts',
  'packages/security-solver/src/local-program-flow.ts',
  'scripts/runtime-settings.ts',
  'run-complete-autohack.sh',
  'run-local-autohack.sh',
]) assert.doesNotMatch(read(path),/qwen3:4b|ollama\s+pull|ollama\s+serve|ollama\/ollama/i,path);
for(const file of readdirSync(resolve(root,'.github/workflows')).filter(x=>/\.ya?ml$/.test(x))){
  const path='.github/workflows/'+file;
  assert.doesNotMatch(read(path),/qwen3:4b|ollama\s+pull|ollama\s+serve|ollama\/ollama|LOCAL_MODEL_ADAPTER:\s*ollama/i,path);
}
assert.doesNotMatch(read('packages/security-solver/src/local-ollama-runner.ts'),
  /\b(?:postOllamaChat|postQwenAgentJson)\b/,'Network inference must not be reachable from investigator');
assert.doesNotMatch(read('packages/security-solver/src/evidence-only-review.ts'),
  /\b(?:postOllamaChat|postQwenAgentJson|postOllamaJson)\b/,'Independent review must not call inference');
assert.match(read('scripts/run-one-bounty.sh'),/LOCAL_MODEL_ADAPTER=deterministic/);
assert.match(read('run-complete-autohack.sh'),/LOCAL_MODEL_ADAPTER=deterministic/);
console.log('QWEN_FREE_PRODUCTION_RUNTIME_PASSED');
