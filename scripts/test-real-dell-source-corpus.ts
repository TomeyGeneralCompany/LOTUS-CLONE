/** Frozen real Dell source-lead manifest. This is NOT a mock experiment run:
 * its 290 records and four outcomes came from the November 23 2026 real
 * self-hosted investigation 45191376008, artifact 14831250048.
 * Preserve all original leads; a regression here means identity/coverage
 * changed, not that an unresolved obligation was magically discharged. */
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";

const artifactPath=fileURLToPath(new URL("./fixtures/dell-45191376008-frozen-leads.json",
  import.meta.url));
const baseline=JSON.parse(readFileSync(artifactPath,"utf8")) as {
  baselineRun:number;artifact:number;sourceCommit:string;
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
    candidates:Array<{id:string;selector:string;sourceCommit:string;sourceSha256:string}>;
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
}
console.log("REAL_DELL_290_ORIGINAL_LEAD_MANIFEST_PRESERVED"+
  (currentIndex===-1?":baseline_only":":actual_index_verified"));
