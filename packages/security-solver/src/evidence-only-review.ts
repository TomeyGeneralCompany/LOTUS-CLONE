import {appendFile} from 'node:fs/promises';
import {evaluateDeterministicEvidenceReview,type DeterministicReviewEvidence} from './deterministic';

/** Review consumes independently verified, typed controller evidence only.
 * No model transport, inference endpoint, or prompt-based verdict is supported.
 * Preserve the caller signature while the old model-specific tests are retired.
 */
export async function runEvidenceOnlyReview(input:{
  prompt:string;
  schema:Record<string,unknown>;
  model:string;
  signal:AbortSignal;
  logFile:string;
  numCtx:number;
  numPredict:number;
  validate:(answer:string)=>string|null|Promise<string|null>;
  maxAttempts?:number;
  verifiedEvidence?:DeterministicReviewEvidence|null;
}):Promise<string>{
  input.signal.throwIfAborted();
  if(!input.schema||!Object.keys(input.schema).length)
    throw new Error('Independent reviewer requires a nonempty verdict schema');
  await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_DETERMINISTIC] '+JSON.stringify({source:'typed_controller_evidence'})+'\n');
  const result=evaluateDeterministicEvidenceReview(input.verifiedEvidence);
  const answer=JSON.stringify(result);
  const feedback=await input.validate(answer);
  if(feedback){
    await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_REJECTED] '+JSON.stringify({reason:feedback.slice(0,600)})+'\n');
    throw new Error('Deterministic evidence-only review failed validation: '+feedback.slice(0,600));
  }
  await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_ACCEPTED] '+JSON.stringify({mode:'deterministic'})+'\n');
  return answer;
}
