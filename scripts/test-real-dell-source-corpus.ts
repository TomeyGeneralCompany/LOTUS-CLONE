/** Frozen real Dell source-lead manifest. This is NOT a mock experiment run:
 * its 290 records and four outcomes came from the November 23 2026 real
 * self-hosted investigation 45191376008, artifact 14831250048.
 * Preserve all original leads; a regression here means identity/coverage
 * changed, not that an unresolved obligation was magically discharged. */
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {copyFileSync,mkdirSync,readFileSync,writeFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {AnalysisProgressStore} from "../packages/security-solver/src/deterministic/analysis-progress-store";
import type {AnalysisCandidate} from "../packages/security-solver/src/deterministic/analysis-candidate-queue";

const artifactPath=fileURLToPath(new URL("./fixtures/dell-45191376008-frozen-leads.json",
  import.meta.url));
const baseline=JSON.parse(readFileSync(artifactPath,"utf8")) as {
  baselineRun:number;artifact:number;sourceCommit:string;
  originalCandidateIdsDigest:string;originalSourceIdentitiesDigest:string;
  groups:Record<"C"|"P"|"F"|"D",string[]>;
};
assert.equal(baseline.baselineRun,45191376008);
assert.equal(baseline.artifact,14831250048);
assert.match(baseline.sourceCommit,/^[a-f0-9]{40}$/);
const groupSizes={C:68,P:117,F:97,D:8} as const;
const entries:string[]=[];
const selectors:string[]=[];
for(const [category,count] of Object.entries(groupSizes)){
  const group=baseline.groups[category as keyof typeof groupSizes];
  assert.ok(Array.isArray(group));
  assert.equal(group.length,count,"Frozen original "+category+" lead count changed");
  for(const selector of group){
    assert.match(selector,/^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$/);
    entries.push(category+":"+selector);
    selectors.push(selector);
  }
}
assert.equal(entries.length,290);
const digest=createHash("sha256").update(entries.sort().join("\n")).digest("hex");
assert.equal(digest,"3af5bfb65f5f10399eb71d9bb3fb699004a73a30545f5d3b33c9bd801473a421",
  "Real original lead manifest changed without an independently audited revision");

const currentIndex=process.argv.indexOf("--current");
if(currentIndex!==-1){
  const path=process.argv[currentIndex+1];
  if(!path)throw new Error("--current requires actual Dell candidate inventory path");
  const actual=JSON.parse(readFileSync(resolve(path),"utf8")) as {
    totalCandidates:number;
    candidates:Array<{id:string;path:string;selector:string;sourceCommit:string;sourceSha256:string;lifecycle:string}>;
  };
  assert.equal(actual.totalCandidates,290,"Real Dell inventory denominator changed");
  assert.equal(actual.candidates.length,290,"Real Dell inventory records changed");
  const ids=new Set<string>();
  for(const candidate of actual.candidates){
    assert.match(candidate.id,/^[a-f0-9]{64}$/);
    assert.match(candidate.sourceSha256,/^[a-f0-9]{64}$/);
    assert.equal(candidate.sourceCommit,baseline.sourceCommit,
      "Original acquired program revision changed");
    assert.ok(!ids.has(candidate.id),"Duplicate original lead identity");
    ids.add(candidate.id);
  }
  assert.deepEqual(actual.candidates.map(x=>x.selector).sort(),selectors.sort(),
    "Real Dell original selector multiset changed or lost leads");
  // Pin the acquired original candidate and source identifiers from the
  // verified frozen baseline; never substitute a guessed identity digest.
  // SHA-256 computed directly from the original 290 candidate ID/path/
  // selector/source-commit/source-SHA tuples in artifact 14831250048.
  // Individual set hashes alone cannot detect reassignment of a candidate
  // identity to another originally acquired file.
  const originalTuples=actual.candidates.map(c=>[
    c.id,c.path,c.selector,c.sourceCommit,c.sourceSha256].join("|")).sort();
  assert.equal(createHash("sha256").update(originalTuples.join("\n")).digest("hex"),
    "3f94f7941f8ed6dbf4549eeb3671bdd1b033a5ea0bcbf05b416cb622da3d8874",
    "Original acquired lead-to-source binding changed");
  const identityDigest=createHash("sha256").update(
    [...ids].sort().join("\n")).digest("hex");
  assert.equal(identityDigest,baseline.originalCandidateIdsDigest,
    "Original lead IDs changed or the frozen original inventory was replaced");
  const sources=[...new Set(actual.candidates.map(x=>
    x.path+":"+x.sourceSha256))].sort();
  const sourceDigest=createHash("sha256").update(
    sources.join("\n")).digest("hex");
  assert.equal(sourceDigest,baseline.originalSourceIdentitiesDigest,
    "Original source revision, file identity, or frozen source set changed");
  // Baseline conclusive obligations cannot silently vanish after an engine
  // revision. This is a lifecycle regression check, not a substitute for
  // the independently verified per-property experiment certificate.
  const baselineConclusive=new Set(baseline.groups.C);
  for(const lead of actual.candidates){
    if(baselineConclusive.has(lead.selector))assert.equal(
      lead.lifecycle,"experiment_completed",
      "An originally completed source lead regressed: "+lead.selector);
  }

  // The candidate inventory preserves identities and lifecycle labels; it is
  // not itself evidence that the experiments ran. Reopen the exact durable
  // checkpoint selected by the investigation log and independently recompute
  // the per-lead experiment certificate from the saved source-bound evidence.
  const investigationLog=resolve(path).replace(/\.analysis-candidates\.json$/,"" );
  assert.notEqual(investigationLog,resolve(path),
    "Actual candidate inventory must retain its matching investigation log");
  const logText=readFileSync(investigationLog,"utf8");
  const progressLines=logText.split(/\r?\n/).filter(line=>
    line.startsWith("[ANALYSIS_CANDIDATE_INVENTORY] "));
  assert.ok(progressLines.length>0,"Investigation log must identify its durable experiment checkpoint");
  const progressRecord=JSON.parse(progressLines.at(-1)!.slice(
    "[ANALYSIS_CANDIDATE_INVENTORY] ".length)) as {progressFile?:string};
  assert.ok(progressRecord.progressFile,
    "Investigation log must identify its durable experiment checkpoint");
  const checkpointPath=resolve(progressRecord.progressFile);
  const checkpoint=JSON.parse(readFileSync(checkpointPath,"utf8")) as {
    analysisEngineRevision?:string;
  };
  assert.ok(checkpoint.analysisEngineRevision,
    "Experiment checkpoint must pin the source-analysis engine revision");
  const enginePaths=[
    "packages/security-solver/src/local-ollama-runner.ts",
    "packages/security-solver/src/controller-solidity-experiment-planner.ts",
    "packages/security-solver/src/controller-stage-lock.ts",
    "packages/security-solver/src/deterministic/analysis-progress-store.ts",
    "packages/security-solver/src/deterministic/fixture-dependency-planner.ts",
    "packages/security-solver/src/deterministic/typed-repair-routes.ts",
    "packages/security-solver/src/deterministic/hypothesis-engine.ts",
    "packages/security-solver/src/deterministic/repair-attempt-identity.ts",
    "packages/security-solver/src/deterministic/source-unavailability-verifier.ts",
    "packages/security-solver/src/solidity-source-index.ts",
    "packages/security-solver/src/solidity-sequence.ts",
    "packages/security-solver/src/source-reproduction.ts",
    "scripts/solidity_security_evidence.py",
    "scripts/reproduction-runtime/solidity-sequence.cjs",
  ];
  const currentEngineDigest=createHash("sha256");
  for(const enginePath of enginePaths)currentEngineDigest.update(enginePath)
    .update("\u0000").update(readFileSync(resolve(enginePath))).update("\u0000");
  assert.equal(checkpoint.analysisEngineRevision,currentEngineDigest.digest("hex"),
    "Experiment checkpoint must be produced by the exact controller engine under qualification");
  const store=await AnalysisProgressStore.open(checkpointPath,
    actual.candidates as AnalysisCandidate[],checkpoint.analysisEngineRevision);
  const certificate=store.experimentCertificate;
  assert.equal(certificate.total,290,"Experiment certificate denominator changed");
  assert.equal(certificate.conclusive+certificate.sourceUnavailable+
    certificate.unresolvedIds.length,290,
    "Every original lead needs exactly one experiment, verified-unavailable, or explicit unresolved disposition");
  assert.equal(certificate.sourceUnavailableIds.length,certificate.sourceUnavailable,
    "Every source-unavailable disposition must retain its original lead identity");
  assert.equal(new Set(certificate.sourceUnavailableIds).size,certificate.sourceUnavailable,
    "A source-unavailable lead must not be counted more than once");
  assert.ok(certificate.sourceUnavailableIds.every(id=>ids.has(id)),
    "Source-unavailable evidence may not introduce leads outside the frozen inventory");
  const unresolvedIds=new Set(certificate.unresolvedIds);
  const unavailableIds=new Set(certificate.sourceUnavailableIds);
  for(const lead of actual.candidates){
    const record=store.records.get(lead.id);
    assert.ok(record,"Experiment checkpoint omitted original lead: "+lead.selector);
    if(unavailableIds.has(lead.id)){
      const evidence=record.sourceUnavailable;
      assert.equal(record.lifecycle,"source_unavailable",
        "Source-unavailable disposition is not reflected in lifecycle: "+lead.selector);
      assert.ok(evidence&&evidence.leadId===lead.id&&
        evidence.sourceCommit===lead.sourceCommit&&evidence.sourceSha256===lead.sourceSha256&&
        evidence.sourceWitnesses.some(witness=>witness.includes(lead.sourceSha256))&&
        /^[a-f0-9]{64}$/.test(evidence.acquiredInventoryDigest)&&
        /^[a-f0-9]{64}$/.test(evidence.verifierDigest)&&
        /^[a-f0-9]{64}$/.test(evidence.independentReviewDigest)&&
        evidence.verifierDigest!==evidence.independentReviewDigest&&
        evidence.evidenceId.length>0&&evidence.detail.length>0,
        "Source-unavailable lead lacks independently reviewable source evidence: "+lead.selector);
    }else if(unresolvedIds.has(lead.id)){
      assert.notEqual(record.lifecycle,"experiment_completed",
        "Unresolved lead was mislabeled as experimentally complete: "+lead.selector);
      assert.notEqual(record.lifecycle,"source_unavailable",
        "Unresolved lead was mislabeled as source-unavailable: "+lead.selector);
      const reasons=certificate.pendingReasons[lead.id]||[];
      assert.ok(reasons.length>0,
        "Unresolved lead must retain an exact blocker or pending reason: "+lead.selector);
    }else{
      assert.equal(record.lifecycle,"experiment_completed",
        "Experiment-backed disposition is not reflected in lifecycle: "+lead.selector);
      assert.ok(record.properties.length>0,
        "Experiment-backed lead has no source-grounded property: "+lead.selector);
      assert.ok(record.properties.every(property=>property.state==="test_completed"&&
        property.unresolvedPrerequisites.length===0&&property.sourceWitnesses.length>0&&
        property.experimentIds.length>0),
        "Experiment-backed lead retains an unexecuted property: "+lead.selector);
    }
  }
  const evidenceDir=resolve("data/repair-feedback");
  mkdirSync(evidenceDir,{recursive:true,mode:0o700});
  const evidencePath=resolve(evidenceDir,"dell-290-analysis-progress.json");
  copyFileSync(checkpointPath,evidencePath);
  writeFileSync(resolve(evidenceDir,"dell-290-experiment-certificate.json"),
    JSON.stringify({
      sourceCommit:baseline.sourceCommit,
      sourceInventoryDigest:identityDigest,
      manifestDigest:certificate.manifestDigest,
      evidenceDigest:certificate.evidenceDigest,
      total:certificate.total,
      conclusive:certificate.conclusive,
      sourceUnavailable:certificate.sourceUnavailable,
      unresolvedIds:certificate.unresolvedIds.length,
      dispositions:{
        experimentallyCompleted:certificate.conclusive,
        sourceUnavailable:certificate.sourceUnavailable,
        explicitlyUnresolved:certificate.unresolvedIds.length,
      },
      evidenceCount:certificate.evidenceCount,
      checkpoint:"dell-290-analysis-progress.json",
    },null,2)+"\n",{mode:0o600});
}
console.log("REAL_DELL_290_LEAD_DISPOSITIONS_VERIFIED"+
  (currentIndex===-1?":baseline_only":":actual_index_verified"));
