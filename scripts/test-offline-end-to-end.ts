/**
 * Offline end-to-end fixture: scoped program -> real local source read ->
 * deterministic reproduction -> evidence -> drafted report -> independent
 * evidence review -> intercepted provider submission -> restart/replay.
 * This NEVER calls real bounty sites and does not prove live program readiness.
 */
import "dotenv/config";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { assertAuthorizedProgram, assertAuthorizedTarget } from "../packages/core/src/scope-authorization";
import { readSubmissionOutbox, submitOnce } from "../packages/core/src/submission-outbox";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";

const savedAdapter = process.env.LOCAL_MODEL_ADAPTER;
const savedOllamaUrl = process.env.AUTOHACK_OLLAMA_URL;
const savedProtocol = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
process.env.LOCAL_MODEL_ADAPTER='deterministic';
process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
process.env.AUTOHACK_OLLAMA_URL='http://127.0.0.1:1/api/chat';
const workspace = await mkdtemp(join(tmpdir(), "autohack-full-offline-"));
const source = join(workspace, "fixture.ts");
const auditLog = join(workspace, "audit.log");
const outbox = join(workspace, "outbox.json");
const originalFetch = globalThis.fetch;
let reportsPosted = 0;
let externalFetches = 0;

try {
  // Deliberately unsafe miniature HTML renderer owned by the test itself.
  await writeFile(source, 'export function render(name: string) { return "<h1>" + name + "</h1>"; }\n');
  const programScope = JSON.stringify({scopes:[{
    assetIdentifier:"https://github.com/offline-fixture/html-render",
    assetType:"SOURCE_CODE", eligibleForBounty:true,
  }]});
  assertAuthorizedProgram(programScope);
  const target = "https://github.com/offline-fixture/html-render/fixture.ts";
  assertAuthorizedTarget(programScope,target);
  assert.throws(()=>assertAuthorizedTarget(programScope,
    "https://github.com/unrelated/other-repo"),/not within/);

  const investigation = JSON.parse(await runLocalAudit(
    'Inspect the authorized source file fixture.ts using deterministic analysis.',
    auditLog,30000,workspace,'deterministic',undefined,{
      maxTurns:12,numCtx:8192,numPredict:512,numThreads:1,
      initialSourcePaths:['fixture.ts'],
      validateFinal:raw=>{
        const outcome=JSON.parse(raw);
        return Array.isArray(outcome.findings)&&outcome.outcome==='no_testable_candidate'
          ? null : 'Invalid deterministic investigation final';
      },
    },
  ));
  assert.equal(investigation.outcome,'no_testable_candidate');
  assert.deepEqual(investigation.findings,[]);
  // The concrete hypothesis is recorded only after reading the owned source,
  // and is tested against the actual isolated renderer below.
  const sourceText=await readFile(source,'utf8');
  assert.ok(sourceText.includes('return "<h1>" + name + "</h1>"'));
  const hypothesis='HYPOTHESIS: HTML encoding missing in fixture.ts; requires deterministic replay.';
  const transcript = await readFile(auditLog,"utf8");
  assert.ok(transcript.includes("[DETERMINISTIC_DRIVER_ACTION]"));
  assert.ok(transcript.includes("[TOOL] read_file"));
  assert.ok(transcript.includes("[READ_OK] fixture.ts"));

  const { render } = await import(pathToFileURL(source).href);
  const harmlessMarker = "<em>injected-fixture-marker</em>";
  const observed = render(harmlessMarker);
  assert.equal(observed,"<h1>"+harmlessMarker+"</h1>");
  const rawSource = await readFile(source,"utf8");
  const evidence = {
    sourceSha256: createHash("sha256").update(rawSource).digest("hex"),
    request: harmlessMarker,
    observed,
    expectedSafeOutput: "<h1>&lt;em&gt;injected-fixture-marker&lt;/em&gt;</h1>",
    reproduction: "render('<em>injected-fixture-marker</em>')",
  };

  // Independent deterministic review must fail if evidence is missing or stale.
  const review = (proof: typeof evidence, actualSource: string) =>
    createHash("sha256").update(actualSource).digest("hex")===proof.sourceSha256
    && proof.observed.includes(proof.request)
    && proof.observed !== proof.expectedSafeOutput
    && proof.reproduction.length > 0;
  assert.equal(review(evidence,rawSource),true);
  assert.equal(review({...evidence,observed:"no issue"},rawSource),false);
  assert.equal(review(evidence,rawSource+"stale"),false);

  const reportBody = "OFFLINE FIXTURE ONLY\n" + hypothesis +
    "\nTarget: " + target +
    "\nReproduction: " + evidence.reproduction +
    "\nObserved: " + evidence.observed +
    "\nExpected encoded output: " + evidence.expectedSafeOutput +
    "\nEvidence SHA256: " + evidence.sourceSha256;
  assert.ok(reportBody.includes("SHA256:"));
  process.env.GITHUB_TOKEN = "offline-only";
  process.env.HACKERONE_USERNAME = "offline-only";
  process.env.HACKERONE_API_TOKEN = "offline-only";
  const { submitReport } = await import("../packages/security-discovery/src/hackerone-client");

  globalThis.fetch = async(url,init)=>{
    if(String(url)!=="https://api.hackerone.com/v1/hackers/reports") {
      externalFetches++;
      throw new Error("Unexpected external request blocked in fixture: "+url);
    }
    reportsPosted++;
    const json = JSON.parse(String(init?.body));
    assert.equal(json.data.attributes.team_handle,"offline-fixture");
    assert.ok(json.data.attributes.vulnerability_information.includes(evidence.sourceSha256));
    return new Response(JSON.stringify({data:{id:"offline-receipt-1",
      attributes:{url:"https://hackerone.com/reports/offline-receipt-1"}}}),{
      status:201,headers:{"Content-Type":"application/json"},
    });
  };
  const payload = {title:"Fixture: missing HTML encoding", vulnerability_information:reportBody,
    impact:"Only the isolated fixture is affected", severity_rating:"medium" as const};
  const result = await submitOnce("offline-fixture-1","offline-fixture",payload,
    ()=>submitReport({teamHandle:"offline-fixture",payload}),outbox);
  assert.equal(result.reportId,"offline-receipt-1");
  assert.equal(reportsPosted,1);
  assert.equal(externalFetches,0);
  assert.equal(readSubmissionOutbox(outbox)["offline-fixture-1"].state,"confirmed");
  await assert.rejects(()=>submitOnce("offline-fixture-1","offline-fixture",payload,
    ()=>submitReport({teamHandle:"offline-fixture",payload}),outbox),/already attempted/);
  assert.equal(reportsPosted,1);
  console.log("Deterministic audit -> owned source fixture -> replay -> report -> review -> MOCK submit -> recovery PASSED");
} catch (error) {
  console.error((await readFile(auditLog,"utf8").catch(()=>"No model transcript produced")).slice(-2000));
  throw error;
} finally {
  globalThis.fetch = originalFetch;
  if(savedAdapter===undefined)delete process.env.LOCAL_MODEL_ADAPTER;
  else process.env.LOCAL_MODEL_ADAPTER=savedAdapter;
  if (savedProtocol === undefined) delete process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
  else process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = savedProtocol;
  if (savedOllamaUrl === undefined) delete process.env.AUTOHACK_OLLAMA_URL;
  else process.env.AUTOHACK_OLLAMA_URL = savedOllamaUrl;
  await rm(workspace,{recursive:true,force:true});
}
