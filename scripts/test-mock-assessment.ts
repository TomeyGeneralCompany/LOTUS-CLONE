/** Deterministic production assessment regression: no model transport required. */
import assert from 'node:assert/strict';
import {assessmentFixture,checkAssessment} from './assessment-fixture';
import {assessProgram,assessFinding} from '../packages/security-analyzer/src/assessor';

const baseline=await assessProgram(assessmentFixture);
checkAssessment(baseline);
assert.equal(baseline.recommendedApproach,'code_review');
assert.ok(baseline.rubric.techStackMatch>=2);
assert.equal(baseline.topTargets[0].asset,'https://github.com/example/owned-assessment-fixture');
const again=await assessProgram(assessmentFixture);
assert.deepEqual(again,baseline,'Deterministic assessment must be repeatable');

const multi=await assessProgram({...assessmentFixture,scopeSummary:JSON.stringify({scopes:[
  {assetIdentifier:'https://example.invalid/owned',assetType:'URL',eligibleForBounty:true},
  {assetIdentifier:'https://github.com/example/owned-assessment-fixture',assetType:'SOURCE_CODE',eligibleForBounty:true},
]})});
assert.equal(multi.hasSourceCode,true);
assert.equal(multi.targetCount,2);
assert.deepEqual(multi.topTargets.map(x=>x.asset),[
  'https://github.com/example/owned-assessment-fixture','https://example.invalid/owned',
],'Source scope must be ranked first, with assets resolved from supplied scope');
assert.equal(multi.recommendedApproach,'mixed');

const duplicate=await assessProgram({...assessmentFixture,scopeSummary:JSON.stringify({scopes:[
  {assetIdentifier:'https://github.com/example/owned-assessment-fixture',assetType:'SOURCE_CODE'},
  {assetIdentifier:'https://github.com/example/owned-assessment-fixture',assetType:'SOURCE_CODE'},
]})});
assert.equal(duplicate.targetCount,1);
assert.equal(duplicate.topTargets.length,1);

for(const scopeSummary of ['[]','{}','invalid']){
  const empty=await assessProgram({...assessmentFixture,scopeSummary});
  assert.equal(empty.targetCount,0);
  assert.deepEqual(empty.topTargets,[]);
  assert.equal(empty.opportunityScore,0);
  assert.equal(empty.hasSourceCode,false);
}

const finding=await assessFinding({
  id:'owned',severity:'high',vulnerabilityType:'CWE-79',confidenceScore:0.83,
} as any,assessmentFixture);
assert.equal(finding.severity,'high');
assert.equal(finding.vulnerabilityType,'CWE-79');
assert.equal(finding.confidence,0.83);
assert.equal(finding.estimatedRewardCents,25000);
console.log('Deterministic program and finding assessment, source ranking, deduplication and empty-scope handling PASSED');
