/**
 * Conservative, source-bound evidence for a genuinely unexecutable
 * interface lead at the immutable acquired revision. Not a generic "no
 * property found" escape hatch. A caller, implementer, malformed import,
 * incomplete acquisition, or contradictory source leaves the lead UNRESOLVED.
 *
 * The two checks have different failure modes: the first uses parsed source
 * plus the acquired ABI/receiver resolvers, while the second independently
 * scans every acquired body for potential implementers/callers and verifies
 * the complete source inventory digest. A source-independent human review
 * can still require additional evidence before publishing.
 */
import {createHash} from "node:crypto";
import {parse} from "@solidity-parser/parser";
import {resolveAcquiredConcreteImplementations,resolveAcquiredInterfaceCallers} from
  "./fixture-dependency-planner";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";
import type {SourceUnavailableEvidence} from "./analysis-progress-store";

type SourceLead={id:string;path:string;selector:string;sourceCommit:string;sourceSha256:string};
type Proposal={lead:SourceLead;sourceWitnesses:string[];acquiredInventoryDigest:string;verifierDigest:string;detail:string};

const digest=(value:unknown)=>createHash("sha256").update(JSON.stringify(value)).digest("hex");
const sha=(value:string)=>createHash("sha256").update(value).digest("hex");
const ast=(value:string):any=>parse(value,{range:true,loc:true});
const descendants=(root:any):any[]=>{
  const out:any[]=[];
  const visit=(value:any,depth:number):void=>{
    if(depth>48||!value||typeof value!=="object")return;
    if(Array.isArray(value)){for(const child of value)visit(child,depth+1);return;}
    if(typeof value.type==="string")out.push(value);
    for(const [key,child] of Object.entries(value))
      if(!["loc","range","comments"].includes(key))visit(child,depth+1);
  };
  visit(root,0);
  return out;
};
const parsedFunction=(node:any,name:string)=>((node.subNodes||[]) as any[])
  .filter(m=>m.type==="FunctionDefinition"&&m.name===name&&!m.isConstructor);

export function proposeInterfaceUnavailability(
  lead:SourceLead,sources:readonly SourceSnapshot[],
  expectedAcquiredPaths:readonly string[]
):Proposal|null {
  if(!/^[a-f0-9]{64}$/.test(lead.id)||
    !/^[a-f0-9]{40}$/.test(lead.sourceCommit)||
    !/^[a-f0-9]{64}$/.test(lead.sourceSha256))return null;
  const expected=[...new Set(expectedAcquiredPaths)].sort();
  const actual=[...new Set(sources.map(s=>s.path))].sort();
  if(expected.length!==sources.length||
    JSON.stringify(expected)!==JSON.stringify(actual))return null;
  if(sources.some(s=>sha(s.content)!==s.sha256))return null;
  const source=sources.find(s=>s.path===lead.path&&s.sha256===lead.sourceSha256);
  if(!source)return null;
  const last=lead.selector.lastIndexOf(".");
  if(last<1||last===lead.selector.length-1)return null;
  const contractName=lead.selector.slice(0,last),method=lead.selector.slice(last+1);
  if(!/^[A-Za-z_]\w*$/.test(contractName)||!/^[A-Za-z_]\w*$/.test(method))return null;
  let parsed:any;
  try{parsed=ast(source.content);}catch{return null;}
  const contract=(parsed.children||[]).find((n:any)=>
    n.type==="ContractDefinition"&&n.kind==="interface"&&n.name===contractName);
  if(!contract)return null;
  const declared=parsedFunction(contract,method);
  if(declared.length!==1||declared[0].body)return null;
  // A verifier of this exact acquired source must reject ANY possible
  // acquired implementation or typed consumer; it cannot infer "unavailable"
  // merely from the interface lacking its own EVM bytecode.
  try{
    if(resolveAcquiredConcreteImplementations(source,contractName,method,sources).length||
      resolveAcquiredInterfaceCallers(source,contractName,method,sources).length)return null;
  }catch{return null;}
  const acquiredInventoryDigest=digest(sources.map(s=>[s.path,s.sha256]).sort((a,b)=>
    String(a[0]).localeCompare(String(b[0]))));
  const witness=lead.path+":"+lead.sourceSha256+":"+
    contractName+"."+method+":"+
    String(declared[0].loc?.start?.line||1)+"-"+
    String(declared[0].loc?.end?.line||1);
  const sourceWitnesses=[witness];
  const detail="Parsed interface method has no bytecode and the complete "+
    "acquired source inventory contains no verified concrete implementation "+
    "or typed callsite for the requested entrypoint";
  return {lead:{...lead},sourceWitnesses,acquiredInventoryDigest,
    verifierDigest:digest([lead,sourceWitnesses,acquiredInventoryDigest,
      "parsed_interface_no_implementation_or_caller_v1"]),
    detail};
}

/** Independent conservative check. Any possible acquired invocation or
 * concrete body of the same name prevents a terminal determination even
 * if the more precise type resolver failed to establish a connection.
 */
export function independentlyReviewInterfaceUnavailability(
  proposed:Proposal,sources:readonly SourceSnapshot[],
  expectedAcquiredPaths:readonly string[]
):SourceUnavailableEvidence|null {
  const rerun=proposeInterfaceUnavailability(proposed.lead,sources,expectedAcquiredPaths);
  if(!rerun||rerun.verifierDigest!==proposed.verifierDigest||
    rerun.acquiredInventoryDigest!==proposed.acquiredInventoryDigest||
    JSON.stringify(rerun.sourceWitnesses)!==JSON.stringify(proposed.sourceWitnesses))
    return null;
  const lead=proposed.lead;
  const method=lead.selector.split(".").pop()!;
  const allCalls:string[]=[];
  for(const source of sources){
    let parsed:any;
    try{parsed=ast(source.content);}catch{return null;}
    for(const node of descendants(parsed)){
      // An acquired third-party implementation with a matching entrypoint
      // could still be instantiated indirectly, even without an explicit
      // inheritance clause in its available source.
      if(source.path!==lead.path&&node.type==="FunctionDefinition"&&
        node.name===method&&node.body&&
        ["public","external"].includes(node.visibility))return null;
      if(source.path!==lead.path&&node.type==="FunctionCall"&&
        node.expression?.type==="MemberAccess"&&
        node.expression.memberName===method)return null;
    }
    allCalls.push(source.path+":"+sha(source.content));
  }
  const independentReviewDigest=digest([
    lead.id,lead.sourceSha256,proposed.acquiredInventoryDigest,
    allCalls.sort(),"independent_ast_negative_callsite_review_v1"]);
  if(independentReviewDigest===proposed.verifierDigest)return null;
  return {kind:"interface_without_acquired_implementation",
    leadId:lead.id,sourceCommit:lead.sourceCommit,sourceSha256:lead.sourceSha256,
    sourceWitnesses:proposed.sourceWitnesses,
    acquiredInventoryDigest:proposed.acquiredInventoryDigest,
    verifierDigest:proposed.verifierDigest,independentReviewDigest,
    evidenceId:"source-unavailable:"+independentReviewDigest,
    detail:proposed.detail};
}
