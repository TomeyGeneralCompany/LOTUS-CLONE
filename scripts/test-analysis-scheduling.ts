/** Real dashboard queue test, using deterministic assessment without an inference server. */
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";

const root=mkdtempSync(join(tmpdir(),"autohack-analysis-scheduling-"));
Object.assign(process.env,{
  PROJECT_ROOT:root,DB_PATH:join(root,"fixture.sqlite"),
  GITHUB_TOKEN:"owned-fixture",CLAUDE_BACKEND:"cli",
  LOCAL_MODEL_ADAPTER:"ollama",
  LOCAL_OLLAMA_MODEL:"qwen3:4b",
  AUTOHACK_OLLAMA_URL:"http://127.0.0.1:1/api/chat",
});
async function until(check:()=>boolean){
  const end=Date.now()+10000;
  while(!check()){
    assert.ok(Date.now()<end,"Timed out waiting for deterministic assessment");
    await new Promise(r=>setTimeout(r,10));
  }
}
try {
  execFileSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{stdio:"pipe"});
  const {getDb,schema}=await import("../packages/core/src/db/index");
  const {appRouter}=await import("../packages/dashboard/src/server/router");
  const {securityAnalyzeState:state}=await import("../packages/dashboard/src/server/job-state");
  const {eq}=await import("drizzle-orm");
  const db=getDb();
  for(let i=0;i<5;i++)db.insert(schema.securityPrograms).values({
    id:"fixture-"+i,name:"Fixture "+i,provider:"fixture",status:"active",
    rewardMaxCents:100000-i,discoveredAt:new Date(),updatedAt:new Date(),
    scopeSummary:JSON.stringify({
      ...(i===0?{policy:"preserve concurrent policy",huntCoverage:{status:"partial",detail:"preserve concurrent coverage"}}:{}),
      scopes:[{assetType:"SOURCE_CODE",assetIdentifier:"https://github.com/fixture/owned",eligibleForBounty:true}],
    }),
  }).run();
  const caller=appRouter.createCaller({});
  const started=await caller.securityAnalyzePrograms();
  assert.equal(started.total,5);
  assert.equal(started.started,true);
  await until(()=>!state.running);
  assert.equal(state.completed,5);
  assert.deepEqual(state.errors,[]);
  for(let i=0;i<5;i++){
    const item=db.select().from(schema.securityPrograms).where(eq(schema.securityPrograms.id,"fixture-"+i)).get()!;
    const metadata=JSON.parse(item.scopeSummary!);
    assert.ok(metadata.assessment?.opportunityScore>0,"Fixture "+i+": missing deterministic assessment");
  }
  const first=db.select().from(schema.securityPrograms).where(eq(schema.securityPrograms.id,"fixture-0")).get()!;
  const initial=JSON.parse(first.scopeSummary!);
  assert.equal(initial.policy,"preserve concurrent policy");
  assert.equal(initial.huntCoverage.detail,"preserve concurrent coverage");
  assert.equal((await caller.securityAnalyzePrograms()).total,0);
  const child=execFileSync(process.execPath,["--import","tsx","scripts/assessment-restart-check.ts"],
    {encoding:"utf8",timeout:15000});
  assert.match(child,/RESTART_RESULT=.*"total":0/);
  const {writePipelineStatus}=await import("../packages/core/src/pipeline");
  const {getConfig}=await import("../packages/core/src/config");
  writePipelineStatus({phase:"analyzing",total:7,completed:3,currentName:"Background fixture"});
  const status=await caller.securityAnalyzeStatus();
  assert.equal(status.running,true);assert.equal(status.completed,3);
  await caller.securityStopAnalyze();
  assert.equal(getConfig().SECURITY_AUTO_HUNT_ENABLED,false);
  await caller.securityReassessPrograms();
  const reloaded=JSON.parse(db.select().from(schema.securityPrograms)
    .where(eq(schema.securityPrograms.id,"fixture-0")).get()!.scopeSummary!);
  assert.equal(reloaded.assessment,undefined);
  assert.equal(reloaded.policy,"preserve concurrent policy");
  assert.equal(reloaded.huntCoverage.detail,"preserve concurrent coverage");
  console.log("Dashboard deterministic assessment, persistence, metadata and stop/restart PASSED");
}finally{rmSync(root,{recursive:true,force:true});}
