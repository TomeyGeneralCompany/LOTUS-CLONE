/**
 * Strict one-hop acquired-source deployment planning.
 * A compatible interface name is not proof of behavior: callers must establish
 * a property-specific invariant independently before treating a fixture as evidence.
 */
import {parse} from "@solidity-parser/parser";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";

export interface PreparedDeployment {
  id:string;file:string;contract:string;constructorArgs:string[];
}
export interface FixtureSourceWitness {file:string;line:number;contract:string;}
export type FixtureResolution =
  | {status:"resolved";deployments:PreparedDeployment[];substitutions:Record<string,string>;witnesses:FixtureSourceWitness[]}
  | {status:"unresolved";missingDependencies:string[];attemptedResolvers:string[];witnesses:FixtureSourceWitness[]};

const astOf=(src:SourceSnapshot):any|null=>{
  try{return parse(src.content,{loc:true,tolerant:true}) as any;}catch{return null;}
};
const getType=(n:any):string=>
  n?.type==="UserDefinedTypeName"?String(n.namePath||""):
  n?.type==="ElementaryTypeName"?String(n.name||""):"";
const ctorOf=(node:any)=>(node.subNodes||[]).find((n:any)=>
  n.type==="FunctionDefinition"&&n.isConstructor);
const isConcrete=(node:any)=>node?.type==="ContractDefinition"&&node.kind!=="interface"&&
  node.kind!=="library"&&!node.abstract;
export function resolveSourceFixtureDependencies(
  target:SourceSnapshot,contractName:string,sources:readonly SourceSnapshot[],
):FixtureResolution{
  const parsed=astOf(target);
  const targetNode=(parsed?.children||[]).find((n:any)=>n.type==="ContractDefinition"&&n.name===contractName);
  if(!targetNode)return {status:"unresolved",missingDependencies:["target_contract_not_found"],attemptedResolvers:[],witnesses:[]};
  const ctor=ctorOf(targetNode);
  const params=ctor?.parameters||[];
  if(!params.length)return {status:"resolved",deployments:[],substitutions:{},witnesses:[]};
  const scanned= sources.flatMap(src=>{
    const ast=astOf(src);
    return (ast?.children||[]).filter((n:any)=>n.type==="ContractDefinition")
      .map((node:any)=>({src,node}));
  });
  const deployments:PreparedDeployment[]=[];
  const substitutions:Record<string,string>={};
  const witnesses:FixtureSourceWitness[]=[];
  const missing:string[]=[];
  const attempts:string[]=[];
  for(const param of params){
    const typ=getType(param.typeName);
    const name=String(param.name||"");
    // Plain address inputs must not be guessed to be a specific dependency.
    if(!typ||typ==="address"){missing.push(name||"address_constructor_parameter");continue;}
    attempts.push(typ);
    const implementations=scanned.filter(({node})=>
      isConcrete(node) &&
      (node.name===typ || (node.baseContracts||[]).some((b:any)=>b.baseName?.namePath===typ)) &&
      (!ctorOf(node)||!(ctorOf(node).parameters||[]).length));
    if(implementations.length!==1){
      missing.push(typ+(implementations.length===0?":no_acquired_concrete_implementation":":ambiguous_implementation"));
      continue;
    }
    const match=implementations[0];
    const id="dependency"+(deployments.length+1);
    deployments.push({id,file:match.src.path,contract:match.node.name,constructorArgs:[]});
    substitutions[name||typ]="$deployment:"+id;
    witnesses.push({file:match.src.path,line:match.node.loc?.start?.line||1,contract:match.node.name});
  }
  if(missing.length)return {status:"unresolved",missingDependencies:missing,
    attemptedResolvers:[...new Set(attempts)],witnesses};
  return {status:"resolved",deployments,substitutions,witnesses};
}
