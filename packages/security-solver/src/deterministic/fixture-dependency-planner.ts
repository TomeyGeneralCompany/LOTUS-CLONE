/** Deterministic, source-identified preparation graph. No guessed protocol behavior. */
import {parse} from "@solidity-parser/parser";
import {posix} from "node:path";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";
export interface PreparedDeployment {id:string;file:string;contract:string;constructorArgs:string[];}
export interface FixtureSourceWitness {file:string;line:number;contract:string;sourceSha256?:string;parameter?:string;stateVariable?:string;}
export interface VerifiedDependencyBinding {parameter:string;receiver:string;typeName:string;deploymentId:string;file:string;sourceSha256:string;}
export type FixtureResolution=
  | {status:"resolved";deployments:PreparedDeployment[];substitutions:Record<string,string>;bindings:VerifiedDependencyBinding[];witnesses:FixtureSourceWitness[];initializerOperations:PreparedInitializerOperation[];}
  | {status:"unresolved";missingDependencies:string[];attemptedResolvers:string[];witnesses:FixtureSourceWitness[];};
export interface PreparedInitializerOperation {id:string;deploymentId:string;function:string;args:string[];sender:0;}
type ContractEntry={source:SourceSnapshot;node:any};
// Source-revision cache avoids reparsing the complete 88mph inventory for
// each assessed candidate. Immutable source hashes prevent stale reuse.
const parsedCache=new Map<string,any|null>();
const astOf=(src:SourceSnapshot):any|null=>{
  if(parsedCache.has(src.sha256))return parsedCache.get(src.sha256)!;
  let result:any|null=null;
  try{result=parse(src.content,{loc:true,range:true,tolerant:true}) as any;}catch{}
  if(parsedCache.size>=512)parsedCache.delete(parsedCache.keys().next().value!);
  parsedCache.set(src.sha256,result);
  return result;
};
const typeOf=(node:any):string=>node?.type==="UserDefinedTypeName"?String(node.namePath||""):
  node?.type==="ElementaryTypeName"?String(node.name||""):"";
const ctorOf=(node:any)=>(node.subNodes||[]).find((x:any)=>x.type==="FunctionDefinition"&&x.isConstructor);
const initOf=(node:any)=>(node.subNodes||[]).find((x:any)=>x.type==="FunctionDefinition"&&
  /^(?:initialize|init)$/i.test(x.name||"")&&x.body&&["public","external"].includes(x.visibility));
const isConcrete=(node:any)=>node?.type==="ContractDefinition"&&
  node.kind!=="interface"&&node.kind!=="library"&&!node.abstract&&!node.isAbstract&&
  !(node.subNodes||[]).some((x:any)=>x.type==="FunctionDefinition"&&!x.body);
/** Some parser versions omit an abstract flag from ContractDefinition.
 * Read the authenticated declaration header to reject abstract bytecode. */
const isDeclaredAbstract=(source:SourceSnapshot,node:any):boolean=>{
  const start=Array.isArray(node.range)?node.range[0]:undefined;
  if(Number.isInteger(start)){
    const header=source.content.slice(start,Math.min(source.content.length,start+180));
    if(/^\s*abstract\s+contract\s+/.test(header))return true;
  }
  const name=String(node.name||"");
  if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))return true;
  return new RegExp("\\babstract\\s+contract\\s+"+name+"\\b").test(source.content);
};
function descendants(node:any):any[]{
  const out:any[]=[];const visited=new Set<any>();
  const walk=(v:any)=>{if(!v||typeof v!=="object"||visited.has(v))return;visited.add(v);
    if(Array.isArray(v)){for(const item of v)walk(item);return;}
    out.push(v);for(const [k,value] of Object.entries(v))if(k!=="loc"&&k!=="range")walk(value);};
  walk(node);return out;
}
function initializerStateBindings(node:any):Array<{parameter:string;receiver:string;typeName:string;line:number}>{
  const vars=new Map<string,string>();
  for(const item of node.subNodes||[])if(item.type==="StateVariableDeclaration")
    for(const v of item.variables||[])if(v.name&&typeOf(v.typeName))vars.set(v.name,typeOf(v.typeName));
  const out:Array<{parameter:string;receiver:string;typeName:string;line:number}>=[];
  for(const fn of (node.subNodes||[]).filter((x:any)=>x.type==="FunctionDefinition"&&x.body&&
    /^(?:initialize|init|__.*init.*)$/i.test(x.name||""))){
    for(const n of descendants(fn.body)){
      if(n.type!=="BinaryOperation"||n.operator!=="=")continue;
      const receiver=String(n.left?.name||"");
      const declared=vars.get(receiver);
      const cast=n.right;
      if(!declared||cast?.type!=="FunctionCall"||cast.expression?.type!=="Identifier"||
        String(cast.expression.name)!==declared||!Array.isArray(cast.arguments)||cast.arguments.length!==1)continue;
      const parameter=String(cast.arguments[0]?.name||"");
      if(!parameter)continue;
      out.push({parameter,receiver,typeName:declared,line:n.loc?.start?.line||fn.loc?.start?.line||1});
    }
  }
  return out;
}
export interface AcquiredConcreteImplementation {
  path:string;contract:string;selector:string;sourceSha256:string;
  inputs:string[];witness:string;
}
/** Map an abstract/interface function into actual acquired source, never
 * synthesize a behavior-bearing mock or assume an external dependency exists.
 * Only a direct source-declared implementation and verifiable import/inheritance
 * edge are eligible for isolated execution.
 */
export function resolveAcquiredConcreteImplementations(
  abstractSource:SourceSnapshot,abstractContract:string,method:string,
  sources:readonly SourceSnapshot[],
):AcquiredConcreteImplementation[]{
  const rootAst=astOf(abstractSource);
  const root=(rootAst?.children||[]).find((x:any)=>
    x.type==="ContractDefinition"&&x.name===abstractContract);
  if(!root)return [];
  const entries=sources.flatMap(source=>(astOf(source)?.children||[])
    .filter((node:any)=>node.type==="ContractDefinition")
    .map((node:any)=>({source,node})));
  const sourceByPath=new Map(sources.map(s=>[s.path,s]));
  const importedPaths=(source:SourceSnapshot):Set<string>=>{
    const paths=new Set<string>();
    const pending=[source.path];
    while(pending.length){
      const current=pending.pop()!;
      if(paths.has(current))continue;
      paths.add(current);
      const acquired=sourceByPath.get(current);
      if(!acquired)continue;
      for(const imp of (astOf(acquired)?.children||[]).filter((x:any)=>x.type==="ImportDirective")){
        const ref=String(imp.path||"");
        if(!ref)continue;
        const path=ref.startsWith(".")?
          posix.normalize(posix.join(posix.dirname(current),ref)):ref;
        if(sourceByPath.has(path)&&!paths.has(path))pending.push(path);
      }
    }
    return paths;
  };
  const basesOf=(entry:ContractEntry):ContractEntry[][]=>{
    const reachable=importedPaths(entry.source);
    return (entry.node.baseContracts||[]).map((b:any)=>{
      const baseName=String(b.baseName?.namePath||"").split(".").pop();
      return entries.filter(e=>e.node.name===baseName&&
        reachable.has(e.source.path)&&e.node!==entry.node);
    });
  };
  const scalarAbi=(p:any):string|null=>{
    const type=p?.typeName;
    if(type?.type==="UserDefinedTypeName")return "address";
    const kind=String(type?.name||"");
    if(kind==="uint")return "uint256";
    if(kind==="int")return "int256";
    if(kind==="address"||kind==="bool"||kind==="string"||kind==="bytes"||
      /^(?:u?int[0-9]{1,3}|bytes(?:[1-9]|[12][0-9]|3[012]))$/.test(kind))
      return kind;
    return null;
  };
  const identities=(fn:any):string|null=>{
    const types=(fn.parameters||[]).map(scalarAbi);
    return types.some((type:string|null)=>type===null)?null:
      String(fn.name)+"("+types.join(",")+")";
  };
  const targetFunctions=(root.subNodes||[]).filter((n:any)=>
    n.type==="FunctionDefinition"&&n.name===method);
  if(!targetFunctions.length)return [];
  const targetIds=new Set(targetFunctions.map(identities).filter(Boolean));
  const result:AcquiredConcreteImplementation[]=[];
  for(const candidate of entries){
    if(candidate.node.name===abstractContract&&candidate.source.path===abstractSource.path)continue;
    if(!isConcrete(candidate.node)||isDeclaredAbstract(candidate.source,candidate.node))continue;
    const traversed=new Set<string>(),chain:ContractEntry[]=[];
    let invalid=false;
    const walk=(entry:ContractEntry):void=>{
      const key=entry.source.path+":"+entry.node.name;
      if(traversed.has(key))return;
      traversed.add(key);chain.push(entry);
      for(const choices of basesOf(entry)){
        // Ambiguous names cannot prove an inheritance edge.
        if(choices.length!==1){invalid=true;continue;}
        walk(choices[0]);
      }
    };
    walk(candidate);
    if(invalid||!chain.some(e=>e.source.path===abstractSource.path&&
      e.node.name===abstractContract))continue;
    const implemented=new Map<string,{entry:ContractEntry;fn:any}>();
    const declarations=new Set<string>();
    for(const entry of [...chain].reverse()){
      for(const fn of (entry.node.subNodes||[]).filter((n:any)=>
        n.type==="FunctionDefinition"&&!n.isConstructor&&n.name)){
        const id=identities(fn);
        if(!id){invalid=true;continue;}
        declarations.add(id);
        if(fn.body)implemented.set(id,{entry,fn});
        else implemented.delete(id);
      }
      for(const variable of (entry.node.subNodes||[])
        .filter((n:any)=>n.type==="StateVariableDeclaration")
        .flatMap((n:any)=>n.variables||[])){
        if(variable.visibility==="public"&&variable.name){
          // A public scalar generates a getter satisfying a base declaration.
          const typ=variable.typeName;
          if(typ?.type==="ElementaryTypeName")implemented.set(
            variable.name+"()",{entry,fn:variable});
        }
      }
    }
    if(invalid||[...declarations].some(id=>!implemented.has(id)))continue;
    for(const id of targetIds){
      const proof=implemented.get(id);
      if(!proof||proof.fn.type!=="FunctionDefinition"||!proof.fn.body)continue;
      const types=(proof.fn.parameters||[]).map(scalarAbi);
      if(types.some((type:string|null)=>type===null))continue;
      result.push({path:candidate.source.path,contract:candidate.node.name,
        selector:candidate.node.name+"."+method,sourceSha256:candidate.source.sha256,
        inputs:types as string[],
        witness:proof.entry.source.path+":"+proof.entry.source.sha256+":"+
          String(proof.fn.loc?.start?.line||1)+":"+String(proof.fn.loc?.end?.line||1)});
    }
  }
  return result.sort((a,b)=>a.path.localeCompare(b.path)||
    a.contract.localeCompare(b.contract)||a.inputs.join(",").localeCompare(b.inputs.join(",")));
}
export interface AcquiredInterfaceCaller {
  path:string;selector:string;sourceSha256:string;interfaceName:string;
  method:string;receiver:string;witness:string;
}
/** Interface-only leads have no executable bytecode. Find the acquired,
 * directly-importing consumer and its actual call site; the experiment then
 * exercises caller behavior with an explicit scope instead of pretending an
 * interface declaration is a deployable security property.
 */
export function resolveAcquiredInterfaceCallers(
  interfaceSource:SourceSnapshot,interfaceName:string,method:string,
  sources:readonly SourceSnapshot[],
):AcquiredInterfaceCaller[] {
  const original=astOf(interfaceSource);
  const iface=(original?.children||[]).find((x:any)=>
    x.type==='ContractDefinition'&&x.name===interfaceName&&
    (x.kind==='interface'||x.kind==='contract'));
  if(!iface||!(iface.subNodes||[]).some((x:any)=>
    x.type==='FunctionDefinition'&&x.name===method))return [];
  const callers:AcquiredInterfaceCaller[]=[];
  for(const source of sources){
    if(source.path===interfaceSource.path||!source.path.endsWith('.sol')||
      source.path.split('/').some(part=>/^(?:mocks?|tests?|fixtures?|echidna)$/i.test(part)))continue;
    const ast=astOf(source);if(!ast)continue;
    const importProof=(ast.children||[]).some((x:any)=>{
      if(x.type!=='ImportDirective'||typeof x.path!=='string'||!x.path.startsWith('.'))
        return false;
      if(posix.normalize(posix.join(posix.dirname(source.path),x.path))!==interfaceSource.path)
        return false;
      return !Array.isArray(x.symbolAliases)||!x.symbolAliases.length||
        x.symbolAliases.some(([original,alias]:[string,string|null])=>
          original===interfaceName||(alias||original)===interfaceName);
    });
    if(!importProof)continue;
    for(const contract of (ast.children||[]).filter((x:any)=>
      x.type==='ContractDefinition'&&x.kind!=='interface'&&x.kind!=='library')){
      const receivers=(contract.subNodes||[]).filter((x:any)=>
        x.type==='StateVariableDeclaration').flatMap((x:any)=>x.variables||[])
        .filter((v:any)=>v.typeName?.type==='UserDefinedTypeName'&&
          v.typeName.namePath===interfaceName).map((v:any)=>String(v.name));
      if(!receivers.length)continue;
      for(const fn of (contract.subNodes||[]).filter((x:any)=>
        x.type==='FunctionDefinition'&&x.body&&x.name&&
        ['external','public'].includes(x.visibility))){
        const bodyStart=fn.body?.range?.[0]??fn.range?.[0];
        const bodyEnd=fn.body?.range?.[1]??fn.range?.[1];
        if(!Number.isInteger(bodyStart)||!Number.isInteger(bodyEnd))continue;
        const sourceBody=source.content.slice(bodyStart,bodyEnd+1);
        for(const receiver of receivers){
          if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(receiver))continue;
          if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(method))continue;
          const expression=new RegExp('\\b'+receiver+'\\s*\\.\\s*'+method+'\\s*\\(');
          if(!expression.test(sourceBody))continue;
          callers.push({path:source.path,selector:contract.name+'.'+fn.name,
            sourceSha256:source.sha256,interfaceName,method,receiver,
            witness:source.path+':'+source.sha256+':'+
              String(fn.loc?.start?.line||1)+':'+String(fn.loc?.end?.line||1)});
        }
      }
    }
  }
  return callers.sort((a,b)=>a.path.localeCompare(b.path)||
    a.selector.localeCompare(b.selector)||a.receiver.localeCompare(b.receiver));
}

/** Canonical callable identity, derived from acquired Solidity declarations. */
function callableTypes(parameters:readonly any[]):string[]|null {
  const types:string[]=[];
  for(const p of parameters){
    const t=p.typeName;
    if(t?.type==="UserDefinedTypeName"){types.push("address");continue;}
    if(t?.type!=="ElementaryTypeName")return null;
    const type=String(t.name||"");
    const canonical=type==="uint"?"uint256":type==="int"?"int256":type==="address payable"?"address":type;
    if(!/^(?:address|bool|string|bytes|bytes(?:[1-9]|[12][0-9]|3[012])|u?int(?:[0-9]{1,3})?)$/.test(canonical))return null;
    types.push(canonical);
  }
  return types;
}
function callableIdentity(fn:any):string|null {
  const types=callableTypes(fn.parameters||[]);
  return types===null?null:String(fn.name||"")+"("+types.join(",")+")";
}
function callableReturns(fn:any):string[]|null {
  return callableTypes(fn.returnParameters||[]);
}
/** A receiver can be substituted only if the actual deployed acquired contract
 * supplies every source-declared interface call, including its return ABI.
 * A declaration without a body is not executable; inherited bodies are eligible.
 */
export function verifyAcquiredReceiverMethods(
  interfaceType:string,methods:readonly string[],implementationFile:string,
  implementationContract:string,sources:readonly SourceSnapshot[],
):{ok:boolean;missing:string[]} {
  if(!methods.length)return {ok:true,missing:[]};
  const entries=sources.flatMap(source=>(astOf(source)?.children||[])
    .filter((node:any)=>node.type==="ContractDefinition")
    .map((node:any)=>({source,node})));
  const concrete=entries.find(e=>e.source.path===implementationFile&&
    e.node.name===implementationContract);
  if(!concrete||!isConcrete(concrete.node))return {ok:false,missing:["concrete_deployment_not_found"]};
  const declared=entries.filter(e=>e.node.name===interfaceType);
  const sourcePaths=new Map(sources.map(s=>[s.path,s]));
  const reachable=new Set<string>(),pending=[implementationFile];
  while(pending.length){
    const path=pending.pop()!;
    if(reachable.has(path))continue;
    reachable.add(path);
    const source=sourcePaths.get(path);
    if(!source)continue;
    for(const imp of (astOf(source)?.children||[]).filter((n:any)=>n.type==="ImportDirective")){
      const impPath=String(imp.path||"");
      if(!impPath)continue;
      const normalized=impPath.startsWith(".")?
        posix.normalize(posix.join(posix.dirname(path),impPath)):impPath;
      if(sourcePaths.has(normalized))pending.push(normalized);
    }
  }
  const chain:ContractEntry[]=[],visited=new Set<string>();
  let ambiguousBase=false;
  const collect=(entry:ContractEntry)=>{
    const key=entry.source.path+":"+entry.node.name;
    if(visited.has(key))return;
    visited.add(key);
    for(const base of entry.node.baseContracts||[]){
      const name=String(base.baseName?.namePath||"").split(".").pop();
      const choices=entries.filter(e=>e.node.name===name&&reachable.has(e.source.path));
      if(choices.length!==1){ambiguousBase=true;continue;}
      collect(choices[0]);
    }
    chain.push(entry);
  };
  collect(concrete);
  if(ambiguousBase)return {ok:false,missing:["ambiguous_or_missing_inheritance"]};
  const implemented=new Map<string,{returns:string[]|null}>();
  for(const entry of chain){
    for(const fn of (entry.node.subNodes||[]).filter((n:any)=>
      n.type==="FunctionDefinition"&&!n.isConstructor&&n.name)){
      const identity=callableIdentity(fn);
      if(!identity)continue;
      if(fn.body&&["public","external"].includes(fn.visibility))
        implemented.set(identity,{returns:callableReturns(fn)});
      else if(!fn.body)implemented.delete(identity);
    }
    for(const v of (entry.node.subNodes||[]).filter((n:any)=>
      n.type==="StateVariableDeclaration").flatMap((n:any)=>n.variables||[])){
      if(v.visibility==="public"&&v.name&&v.typeName?.type==="ElementaryTypeName")
        implemented.set(v.name+"()",{returns:callableTypes([{typeName:v.typeName}])});
    }
  }
  const missing:string[]=[];
  for(const method of new Set(methods)){
    const required=declared.flatMap(e=>(e.node.subNodes||[]).filter((fn:any)=>
      fn.type==="FunctionDefinition"&&fn.name===method));
    // If no interface ABI is acquired, the receiver cannot be authenticated.
    if(!required.length){missing.push(method+":interface_abi_not_acquired");continue;}
    for(const fn of required){
      const identity=callableIdentity(fn);
      const expected=callableReturns(fn);
      const actual=identity?implemented.get(identity):undefined;
      if(!identity||expected===null||!actual||actual.returns===null||
        JSON.stringify(actual.returns)!==JSON.stringify(expected))
        missing.push((identity||method)+":missing_or_incompatible_abi");
    }
  }
  return {ok:missing.length===0,missing};
}

export function resolveSourceFixtureDependencies(
  target:SourceSnapshot,contractName:string,sources:readonly SourceSnapshot[],
):FixtureResolution {
  const ast=astOf(target);
  const targetNode=(ast?.children||[]).find((n:any)=>n.type==="ContractDefinition"&&n.name===contractName);
  if(!targetNode)return {status:"unresolved",missingDependencies:["target_contract_not_found"],attemptedResolvers:[],witnesses:[]};
  const scanned:ContractEntry[]=sources.flatMap(source=>{const parsed=astOf(source);
    return (parsed?.children||[]).filter((node:any)=>node.type==="ContractDefinition").map((node:any)=>({source,node}));
  });
  const entryByName=new Map<string,ContractEntry[]>();
  for(const entry of scanned){const group=entryByName.get(entry.node.name)||[];group.push(entry);entryByName.set(entry.node.name,group);}
  const extendsType=(node:any,typ:string,seen=new Set<string>()):boolean=>{
    if(node.name===typ)return true;
    if(seen.has(node.name))return false;seen.add(node.name);
    for(const base of node.baseContracts||[]){
      const baseName=String(base.baseName?.namePath||"");
      if(baseName===typ)return true;
      for(const parent of entryByName.get(baseName)||[])
        if(extendsType(parent.node,typ,seen))return true;
    }
    return false;
  };
  const attempts:string[]=[],missing:string[]=[],witnesses:FixtureSourceWitness[]=[],bindings:VerifiedDependencyBinding[]=[];
  const deployments:PreparedDeployment[]=[],initializers:PreparedInitializerOperation[]=[];
  const substitutions:Record<string,string>={};
  const visited=new Map<string,string>(),stack=new Set<string>();
  let nextDeploymentId=1;
  // Prove caller demand from the acquired source, not from a guessed fixture.
  const requiredReceiverMethods=new Map<string,string[]>();
  const targetBindings=initializerStateBindings(targetNode);
  for(const binding of targetBindings){
    const methods=[...target.content.matchAll(new RegExp(
      "\\b"+binding.receiver+"\\s*\\.\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(","g"))]
      .map(match=>match[1]);
    requiredReceiverMethods.set(binding.receiver,[...new Set(methods)]);
  }
  const MAX_DEPTH=6,MAX_NODES=8;
  const resolve=(typ:string,depth:number):string|null=>{
    attempts.push(typ);
    if(depth>MAX_DEPTH){missing.push(typ+":max_dependency_depth");return null;}
    const choices=scanned.filter(({node,source})=>isConcrete(node)&&
      !isDeclaredAbstract(source,node)&&extendsType(node,typ));
    // A source-proven ABI can distinguish concrete implementations. Without
    // proof, multiple candidates remain ambiguous rather than guessed.
    const receiverMethods=[...new Set(targetBindings.filter(b=>b.typeName===typ)
      .flatMap(b=>requiredReceiverMethods.get(b.receiver)||[]))];
    const qualified=choices.length>1&&receiverMethods.length?
      choices.filter(choice=>verifyAcquiredReceiverMethods(typ,receiverMethods,
        choice.source.path,choice.node.name,sources).ok):choices;
    if(qualified.length!==1){missing.push(typ+(qualified.length===0?
      ":no_acquired_abi_compatible_implementation":":ambiguous_implementation"));return null;}
    const selected=qualified[0],key=selected.source.path+":"+selected.node.name;
    if(stack.has(key)){missing.push(typ+":dependency_cycle");return null;}
    if(visited.has(key))return visited.get(key)!;
    if(deployments.length>=MAX_NODES){missing.push(typ+":max_dependency_nodes");return null;}
    stack.add(key);
    const args:string[]=[];let valid=true;
    for(const p of ctorOf(selected.node)?.parameters||[]){
      const argType=typeOf(p.typeName);
      if(!argType){missing.push(key+":unknown_constructor_type");valid=false;break;}
      if(p.typeName?.type==="UserDefinedTypeName"){const dep=resolve(argType,depth+1);
        if(!dep){valid=false;break;}args.push("$deployment:"+dep);}
      else if(argType==="address")args.push("$account0");
      else if(/^(?:u?int(?:[0-9]+)?|bytes[0-9]+)$/.test(argType))args.push("0");
      else if(argType==="bool")args.push("false");
      else {missing.push(key+":unsupported_constructor_type:"+argType);valid=false;break;}
    }
    if(!valid){stack.delete(key);return null;}
    const id="dependency"+nextDeploymentId++;
    // Reserve a stable ID before initializer recursion can add deployments.
    deployments.push({id,file:selected.source.path,contract:selected.node.name,constructorArgs:args});
    visited.set(key,id);stack.delete(key);
    witnesses.push({file:selected.source.path,line:selected.node.loc?.start?.line||1,
      contract:selected.node.name,sourceSha256:selected.source.sha256});
    // Initialization can be planned only when all parameters have verified dependency
    // bindings or are ordinary role/scalar values; anything else remains unresolved.
    const initializer=initOf(selected.node);
    if(initializer){
      const initArgs:string[]=[];
      const initBindings=initializerStateBindings(selected.node);
      for(const p of initializer.parameters||[]){
        const name=String(p.name||""),argType=typeOf(p.typeName);
        const matching=initBindings.find(x=>x.parameter===name);
        if(matching){const dep=resolve(matching.typeName,depth+1);
          if(!dep){missing.push(key+":initializer_dependency:"+name);break;}initArgs.push("$deployment:"+dep);}
        else if(argType==="address")initArgs.push("$account0");
        else if(/^(?:u?int(?:[0-9]+)?)$/.test(argType))initArgs.push("1");
        else if(argType==="bool")initArgs.push("false");
        else {missing.push(key+":unsupported_initializer_parameter:"+name);break;}
      }
      if(initArgs.length!==(initializer.parameters||[]).length){
        // A partially bound initializer is not an executable fixture. The
        // dependency graph must fail closed instead of reporting resolution.
        missing.push(key+":incomplete_initializer_arguments");
      }else{
        const sigTypes=(initializer.parameters||[]).map((p:any)=>p.typeName?.type==="UserDefinedTypeName"?"address":typeOf(p.typeName));
        initializers.push({id:"setup"+(initializers.length+1),deploymentId:id,
          function:"initialize("+sigTypes.join(",")+")",args:initArgs,sender:0});
      }
    }
    return id;
  };
  // Constructor and initializer parameter-to-state assignments establish a
  // binding edge. Arbitrary address arguments are never treated as dependencies.
  const params=[...(ctorOf(targetNode)?.parameters||[])];
  for(const p of params)if(p.typeName?.type==="UserDefinedTypeName"){
    const name=String(p.name||""),typ=typeOf(p.typeName),dep=resolve(typ,0);
    if(dep){substitutions[name]="$deployment:"+dep;bindings.push({parameter:name,receiver:name,typeName:typ,
      deploymentId:dep,file:target.path,sourceSha256:target.sha256});}
  }
  for(const binding of targetBindings){
    const dep=resolve(binding.typeName,0);
    if(dep){substitutions[binding.parameter]="$deployment:"+dep;
      substitutions[binding.receiver]="$deployment:"+dep;
      bindings.push({parameter:binding.parameter,receiver:binding.receiver,typeName:binding.typeName,
        deploymentId:dep,file:target.path,sourceSha256:target.sha256});
      witnesses.push({file:target.path,line:binding.line,contract:contractName,
        sourceSha256:target.sha256,parameter:binding.parameter,stateVariable:binding.receiver});}
  }
  // All listed contracts must be deployable, and initialization transactions
  // are ordered after their transitive dependencies. Missing work never becomes
  // a synthesized protocol implementation.
  if(missing.length)return {status:"unresolved",missingDependencies:[...new Set(missing)],
    attemptedResolvers:[...new Set(attempts)],witnesses};
  // A consumer may acquire additional dependencies while resolving its initializer.
  // Order the entire acquired deployment graph, not just constructor recursion.
  // Keep stable deployment IDs so substitutions and proof bindings remain valid.
  const byId=new Map(deployments.map(d=>[d.id,d]));
  const dependencies=(id:string):string[]=>{
    const deployment=byId.get(id);
    const args=[...(deployment?.constructorArgs||[]),
      ...initializers.filter(op=>op.deploymentId===id).flatMap(op=>op.args)];
    return [...new Set(args.filter(arg=>arg.startsWith("$deployment:"))
      .map(arg=>arg.slice("$deployment:".length)))];
  };
  const ordered:PreparedDeployment[]=[];
  const permanent=new Set<string>(),active=new Set<string>();
  const visit=(id:string):boolean=>{
    if(permanent.has(id))return true;
    if(active.has(id)||!byId.has(id))return false;
    active.add(id);
    for(const dep of dependencies(id))if(!visit(dep))return false;
    active.delete(id);permanent.add(id);ordered.push(byId.get(id)!);
    return true;
  };
  for(const deployment of deployments)if(!visit(deployment.id))
    return {status:"unresolved",missingDependencies:["deployment_graph_cycle_or_missing_node"],
      attemptedResolvers:[...new Set(attempts)],witnesses};
  const rank=new Map(ordered.map((d,index)=>[d.id,index]));
  const orderedInitializers=[...initializers].sort((a,b)=>
    (rank.get(a.deploymentId)??Infinity)-(rank.get(b.deploymentId)??Infinity));
  return {status:"resolved",deployments:ordered,substitutions,bindings,witnesses,
    initializerOperations:orderedInitializers};
}
