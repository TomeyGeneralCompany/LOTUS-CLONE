/** Stable source-identity + unmet security obligations for deterministic
 * repair fixed-point scheduling. The key changes when a fresh experiment
 * independently changes the lead's evidence/blockers, but cannot change
 * merely because a no-op repair retry appended audit history. */
import {createHash} from "node:crypto";
import type {CandidateProgress} from "./analysis-progress-store";
export function repairAttemptIdentity(record:CandidateProgress):string {
  const properties=record.properties.map(p=>[
    p.id,p.state,
    [...p.unresolvedPrerequisites].sort(),
    [...p.experimentIds].sort(),
    [...p.sourceWitnesses].sort(),
    p.supersededBy||""
  ]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const incomplete=(record.inconclusiveAttempts||[]).map(a=>[
    a.experimentId,a.status,a.replacedBy||"",a.reason
  ]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const verified=(record.experimentEvidence||[]).map(e=>[
    e.experimentId,e.sourceSha256,e.result
  ]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return createHash("sha256").update(JSON.stringify({
    sourceCommit:record.sourceCommit,sourceSha256:record.sourceSha256,
    properties,incomplete,verified
  })).digest("hex");
}
