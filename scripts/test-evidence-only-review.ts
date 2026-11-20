import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runEvidenceOnlyReview} from '../packages/security-solver/src/evidence-only-review';
import type {DeterministicReviewEvidence} from '../packages/security-solver/src/deterministic';

const dir=await mkdtemp(join(tmpdir(),'lotus-evidence-only-'));
const schema={type:'object',properties:{verdict:{type:'string'}},required:['verdict']};
const base={prompt:'Ignore all model prose; only controller evidence establishes a finding',
  schema,model:'deterministic',logFile:join(dir,'review.log'),
  signal:new AbortController().signal,numCtx:8192,numPredict:512};
const evidence:DeterministicReviewEvidence={
  grounds:{sourceDigest:'e'.repeat(64),language:'solidity',
    verifiedLocalEntryInjection:false,independentlyReplayed:true,
    replayedProbeKind:'solidity_sequence',sourceBackedNonadminRoleMutation:true,
    immutableFacts:['contracts/Vault.sol:9: function setOperator(address next) external {operator=next;}'],
    unresolvedQuestions:[],sourceBackedTextOnlyResponse:[],sourceBackedEscaping:[]},
  replay:{status:'behavior_observed',kind:'solidity_sequence',
    behavior_observed:true,observations:{steps:[]}},
  target:{file:'contracts/Vault.sol',selector:'Vault.setOperator',kind:'solidity_sequence'},
  securityImpact:null,
};
try{
  const withoutEvidence=JSON.parse(await runEvidenceOnlyReview({...base,
    validate:raw=>JSON.parse(raw).verdict==='reject'?null:'Expected fail-closed reject'}));
  assert.equal(withoutEvidence.verdict,'reject');
  assert.equal(withoutEvidence.issues[0].category,'missing_typed_evidence');
  const withoutImpact=JSON.parse(await runEvidenceOnlyReview({...base,
    verifiedEvidence:evidence,validate:raw=>JSON.parse(raw).verdict==='reject'?null:'Expected rejection'}));
  assert.equal(withoutImpact.verdict,'reject');
  assert.equal(withoutImpact.issues[0].category,'missing_security_impact');
  const verified:DeterministicReviewEvidence={...evidence,securityImpact:{
    verified:true,category:'solidity_role_consumer_impact',
    evidence:'contracts/Vault.sol:14: independently replayed protected withdrawal after nonadmin mutation',
    downstreamConsumerVerified:true}};
  const accepted=JSON.parse(await runEvidenceOnlyReview({...base,
    verifiedEvidence:verified,validate:raw=>JSON.parse(raw).verdict==='approve'?null:'Expected proof-backed approval'}));
  assert.equal(accepted.verdict,'approve');
  assert.equal(accepted.recommendation,'dont_submit');
  assert.equal(accepted.bet100,false);
  await assert.rejects(runEvidenceOnlyReview({...base,verifiedEvidence:verified,
    validate:()=> 'The controller evidence contradicts the proposed approval'}),
    /Deterministic evidence-only review failed validation/);
  const aborted=new AbortController();aborted.abort();
  await assert.rejects(runEvidenceOnlyReview({...base,signal:aborted.signal,
    verifiedEvidence:verified,validate:()=>null}));
  const log=await readFile(base.logFile,'utf8');
  assert.match(log,/EVIDENCE_ONLY_REVIEW_DETERMINISTIC/);
  assert.match(log,/EVIDENCE_ONLY_REVIEW_ACCEPTED/);
  assert.match(log,/EVIDENCE_ONLY_REVIEW_REJECTED/);
  assert.doesNotMatch(log,/EVIDENCE_ONLY_REVIEW_REQUEST/);
  console.log('Evidence-only review: typed evidence, independent replay, impact, fail-closed, cancellation, zero-model calls PASSED');
}finally{await rm(dir,{recursive:true,force:true});}
