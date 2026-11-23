/** Deterministic, source-identified preparation graph. No guessed protocol behavior. */
import {parse} from "@solidity-parser/parser";
import {posix} from "node:path";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";
type PreparedArg=string|boolean|string[]|Array<string|boolean|string[]>;
export interface PreparedDeployment {id:string;file:string;contract:string;constructorArgs:PreparedArg[];}
export interface FixtureSourceWitness {file:string;line:number;contract:string;sourceSha256?:string;parameter?:string;stateVariable?:string;}
export interface VerifiedDependencyBinding {parameter:string;receiver:string;typeName:string;deploymentId:string;file:string;sourceSha256:string;}
export type FixtureResolution=
  | {status:"resolved";deployments:PreparedDeployment[];substitutions:Record<string,string>;bindings:VerifiedDependencyBinding[];witnesses:FixtureSourceWitness[];initializerOperations:PreparedInitializerOperation[];}
  | {status:"unresolved";missingDependencies:string[];attemptedResolvers:string[];witnesses:FixtureSourceWitness[];};
export interface PreparedInitializerOperation {id:string;deploymentId:string;function:string;args:PreparedArg[];sender:0;}
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
/** Construct ABI-typed zero/one fixture values only for known elementary
 * and bounded one-dimensional array types. Solidity constructor/initializer
 * reverts remain real executor failures, never presumed successes. */
function primitiveFixtureArg(type:any,nonzero=false,contract?:any):PreparedArg|null {
  if(type?.type==="UserDefinedTypeName"&&contract){
    const name=String(type.namePath||"").split(".").pop();
    const declarations=(contract.subNodes||[]).filter((n:any)=>
      n.type==="StructDefinition"&&n.name===name);
    if(declarations.length!==1)return null;
    const parts=(declarations[0].members||[]).map((field:any)=>
      primitiveFixtureArg(field.typeName,nonzero,contract));
    if(parts.some((part:any)=>part===null))return null;
    return parts as PreparedArg;
  }
  if(type?.type==="ArrayTypeName"){
    const base=primitiveFixtureArg(type.baseTypeName,nonzero,contract);
    if(typeof base!=="string")return null;
    if(!type.length)return [];
    const len=type.length?.type==="NumberLiteral"?Number(type.length.number):NaN;
    if(!Number.isSafeInteger(len)||len<0||len>32)return null;
    return Array(len).fill(base);
  }
  if(type?.type!=="ElementaryTypeName")return null;
  const k=String(type.name||"");
  if(k==="address"||k==="address payable")return "$account0";
  if(k==="bool")return false;
  if(k==="string")return "";
  if(k==="bytes")return "0x";
  const bytes=k.match(/^bytes([1-9]|[12][0-9]|3[012])$/);
  if(bytes)return "0x"+"00".repeat(Number(bytes[1]));
  if(/^(?:u?int)(?:[0-9]{1,3})?$/.test(k))return nonzero?"1":"0";
  return null;
}
/** Derive a scalar fixture value from literal require() bounds in the exact
 * acquired constructor/initializer AST. Unknown or relational conditions are
 * still checked by the executor; this never certifies a deployment receipt. */
function constrainedFixtureArg(type:any,parameter:string,fn:any,nonzero:boolean,contract:any):PreparedArg|null {
  const fallback=primitiveFixtureArg(type,nonzero,contract);
  if(type?.type!=="ElementaryTypeName"||!parameter||!fn?.body)return fallback;
  const match=String(type.name||"").match(/^(u?int)([0-9]{0,3})$/);
  if(!match)return fallback;
  const bits=match[2]?Number(match[2]):256;
  if(bits<8||bits>256||bits%8!==0)return fallback;
  const signed=match[1]==="int";
  let lower=signed?-(1n<<BigInt(bits-1)):0n;
  let upper=signed?(1n<<BigInt(bits-1))-1n:(1n<<BigInt(bits))-1n;
  const excluded=new Set<string>();
  const reverse:Record<string,string>={">":"<","<":">",">=":"<=","<=":">=","==":"==","!=":"!="};
  const apply=(expr:any):void=>{
    if(expr?.type!=="BinaryOperation")return;
    if(expr.operator==="&&"){apply(expr.left);apply(expr.right);return;}
    let op=String(expr.operator||"");
    let literal=expr.right;
    if(expr.left?.type==="NumberLiteral"&&expr.right?.type==="Identifier"&&
      expr.right.name===parameter){op=reverse[op]||"";literal=expr.left;}
    else if(expr.left?.type!=="Identifier"||expr.left.name!==parameter)return;
    if(literal?.type!=="NumberLiteral"||!reverse[op])return;
    const representation=String(literal.number||"").replace(/_/g,"");
    if(!/^(?:0|[1-9][0-9]*)$/.test(representation))return;
    const value=BigInt(representation);
    switch(op){
      case ">": if(value+1n>lower)lower=value+1n;break;
      case ">=": if(value>lower)lower=value;break;
      case "<": if(value-1n<upper)upper=value-1n;break;
      case "<=": if(value<upper)upper=value;break;
      case "==": lower=lower>value?lower:value;upper=upper<value?upper:value;break;
      case "!=": excluded.add(value.toString());break;
    }
  };
  for(const call of descendants(fn.body))if(call.type==="FunctionCall"&&
    call.expression?.type==="Identifier"&&call.expression.name==="require"&&
    Array.isArray(call.arguments)&&call.arguments.length>0)apply(call.arguments[0]);
  if(lower>upper)return null;
  let candidate=typeof fallback==="string"&&/^-?[0-9]+$/.test(fallback)?BigInt(fallback):lower;
  if(candidate<lower)candidate=lower;
  if(candidate>upper)candidate=upper;
  while(excluded.has(candidate.toString())&&candidate<upper)candidate++;
  if(excluded.has(candidate.toString()))return null;
  return candidate.toString();
}
/** The compiler ABI represents a struct as a tuple of its acquired fields.
 * This does not infer any business-level property or nondefault configuration. */
function fixtureAbiType(type:any,contract:any,depth=0):string|null {
  if(depth>5)return null;
  if(type?.type==="ArrayTypeName"){
    const base=fixtureAbiType(type.baseTypeName,contract,depth+1);
    if(!base)return null;
    const len=type.length;
    if(len&&(!/^\\d+$/.test(String(len.number||""))))return null;
    return base+"["+(len?String(len.number):"")+"]";
  }
  if(type?.type==="UserDefinedTypeName"){
    const name=String(type.namePath||"").split(".").pop();
    const structs=(contract.subNodes||[]).filter((n:any)=>
      n.type==="StructDefinition"&&n.name===name);
    if(structs.length===0)return "address";
    if(structs.length!==1)return null;
    const fields=(structs[0].members||[]).map((field:any)=>
      fixtureAbiType(field.typeName,contract,depth+1));
    return fields.every((f:any)=>typeof f==="string"&&f.length)?
      "("+fields.join(",")+")":null;
  }
  return callableType(type);
}
function initializerStateBindings(node:any,source:SourceSnapshot):Array<{parameter:string;receiver:string;typeName:string;line:number}>{
  // UserDefinedTypeName also denotes struct, enum and user-defined value types.
  // Check declarations BEFORE making a deployment edge; those types are values,
  // not contracts. Qualified names retain their actual declaration namespace.
  const nonDeployable=new Set<string>();
  const collectValueTypes=(owner:any,prefix="")=>{
    for(const declaration of owner.subNodes||[]){
      if(!["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition"].includes(declaration.type)||
        !declaration.name)continue;
      nonDeployable.add(prefix+String(declaration.name));
    }
  };
  collectValueTypes(node);
  const parsed=astOf(source);
  for(const declaration of parsed?.children||[]){
    if(declaration.type==="ContractDefinition")collectValueTypes(declaration,declaration.name+".");
    else if(["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition"].includes(declaration.type)&&
      declaration.name)nonDeployable.add(String(declaration.name));
  }
  const vars=new Map<string,string>();
  for(const item of node.subNodes||[])if(item.type==="StateVariableDeclaration")
    for(const v of item.variables||[])if(v.name&&v.typeName?.type==="UserDefinedTypeName"&&
      typeOf(v.typeName)&&!nonDeployable.has(typeOf(v.typeName)))vars.set(v.name,typeOf(v.typeName));
  const out:Array<{parameter:string;receiver:string;typeName:string;line:number}>=[];
  for(const fn of (node.subNodes||[]).filter((x:any)=>x.type==="FunctionDefinition"&&x.body&&
    /^(?:initialize|init|__.*init.*)$/i.test(x.name||""))){
    for(const n of descendants(fn.body)){
      if(n.type!=="BinaryOperation"||n.operator!=="=")continue;
      const receiver=String(n.left?.name||"");
      const declared=vars.get(receiver);
      const cast=n.right;
      const params=new Map((fn.parameters||[]).map((p:any)=>[
        String(p.name||""),typeOf(p.typeName)]));
      // Both "receiver = Interface(paramAddress)" and the directly typed
      // "receiver = interfaceParameter" are compiler-valid binding edges.
      let parameter="";
      if(cast?.type==="FunctionCall"&&cast.expression?.type==="Identifier"&&
        String(cast.expression.name)===declared&&
        Array.isArray(cast.arguments)&&cast.arguments.length===1)
        parameter=String(cast.arguments[0]?.name||"");
      else if(cast?.type==="Identifier"&&params.get(String(cast.name||""))===declared)
        parameter=String(cast.name);
      if(!declared||!parameter)continue;
      out.push({parameter,receiver,typeName:declared,line:n.loc?.start?.line||fn.loc?.start?.line||1});
    }
  }
  return out;
}
/** A canonical OpenZeppelin import proves a standard package edge exists,
 * not that an unavailable source has been independently analyzed. */
function hasCanonicalPackageBase(entry:ContractEntry,name:string):boolean {
  return (astOf(entry.source)?.children||[]).some((imp:any)=>{
    if(imp.type!=="ImportDirective"||typeof imp.path!=="string"||
      !/^@openzeppelin\/contracts(?:-upgradeable)?\/.+\.sol$/.test(imp.path))return false;
    const declared=posix.basename(imp.path,".sol");
    if(Array.isArray(imp.symbolAliases)&&imp.symbolAliases.length)
      return imp.symbolAliases.some(([original,alias]:[string,string|null])=>
        original===declared&&(alias||original)===name);
    return declared===name;
  });
}

/** The ABI of canonical inherited OpenZeppelin entrypoints. Only credit an
 * exact directly imported standard base; actual deployments still require
 * compilation and execution of its installed implementation. */
const standardInheritedAbi:Readonly<Record<string,Readonly<Record<string,readonly string[]>>>>={
  Ownable:{'owner()':['address'],'transferOwnership(address)':[],'renounceOwnership()':[]},
  OwnableUpgradeable:{'owner()':['address'],'transferOwnership(address)':[],'renounceOwnership()':[]},
  ERC20:{'balanceOf(address)':['uint256'],'totalSupply()':['uint256'],
    'allowance(address,address)':['uint256'],'transfer(address,uint256)':['bool'],
    'approve(address,uint256)':['bool'],'transferFrom(address,address,uint256)':['bool']},
  ERC20Upgradeable:{'balanceOf(address)':['uint256'],'totalSupply()':['uint256'],
    'allowance(address,address)':['uint256'],'transfer(address,uint256)':['bool'],
    'approve(address,uint256)':['bool'],'transferFrom(address,address,uint256)':['bool']},
  ERC721:{'balanceOf(address)':['uint256'],'ownerOf(uint256)':['address'],
    'getApproved(uint256)':['address'],'isApprovedForAll(address,address)':['bool'],
    'transferFrom(address,address,uint256)':[]},
  ERC721Upgradeable:{'balanceOf(address)':['uint256'],'ownerOf(uint256)':['address'],
    'getApproved(uint256)':['address'],'isApprovedForAll(address,address)':['bool'],
    'transferFrom(address,address,uint256)':[]},
};
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
    const imports=(astOf(entry.source)?.children||[]).filter((n:any)=>
      n.type==="ImportDirective"&&typeof n.path==="string");
    return (entry.node.baseContracts||[]).map((b:any)=>{
      const baseName=String(b.baseName?.namePath||"").split(".").pop();
      // Solidity resolves a declaration in the current compilation unit
      // before considering imports, even if other imported files expose the
      // same identifier. Never discard a real concrete child for this.
      const local=entries.filter(e=>e.source.path===entry.source.path&&
        e.node.name===baseName&&e.node!==entry.node);
      if(local.length)return local;
      // Imported aliases are source identities: import {Base as Renamed}
      // cannot be resolved by looking for a contract named Renamed.
      const directlyImported:ContractEntry[]=[];
      for(const imp of imports){
        const referenced=String(imp.path);
        const importPath=referenced.startsWith(".")?
          posix.normalize(posix.join(posix.dirname(entry.source.path),referenced)):referenced;
        if(!reachable.has(importPath))continue;
        const aliases=imp.symbolAliases;
        if(Array.isArray(aliases)&&aliases.length){
          for(const [original,alias] of aliases as [string,string|null][]){
            if((alias||original)!==baseName)continue;
            directlyImported.push(...entries.filter(e=>e.source.path===importPath&&
              e.node.name===original));
          }
        }else{
          directlyImported.push(...entries.filter(e=>e.source.path===importPath&&
            e.node.name===baseName));
        }
      }
      if(directlyImported.length)return [...new Map(directlyImported.map(e=>[
        e.source.path+":"+e.node.name,e])).values()];
      // An explicitly acquired transitive re-export can still establish a
      // base, but ambiguity must remain unresolved, not arbitrarily selected.
      return entries.filter(e=>e.node.name===baseName&&
        reachable.has(e.source.path)&&e.node!==entry.node);
    });
  };
  const typeAbi=(type:any):string|null=>{
    if(!type)return null;
    if(type.type==="ArrayTypeName"){
      const base=typeAbi(type.baseTypeName);
      if(!base)return null;
      const len=type.length?.type==="NumberLiteral"?String(type.length.number):"";
      return base+"["+len+"]";
    }
    if(type.type==="UserDefinedTypeName")return "address";
    const kind=String(type.name||"");
    if(kind==="uint")return "uint256";
    if(kind==="int")return "int256";
    if(kind==="address"||kind==="bool"||kind==="string"||kind==="bytes"||
      /^(?:u?int[0-9]{1,3}|bytes(?:[1-9]|[12][0-9]|3[012]))$/.test(kind))
      return kind;
    return null;
  };
  const scalarAbi=(p:any):string|null=>typeAbi(p?.typeName);
  const identities=(fn:any):string|null=>{
    const types=(fn.parameters||[]).map(scalarAbi);
    return types.some((type:string|null)=>type===null)?null:
      String(fn.name)+"("+types.join(",")+")";
  };
  const targetFunctions=(root.subNodes||[]).filter((n:any)=>
    n.type==="FunctionDefinition"&&n.name===method);
  if(!targetFunctions.length)return [];
  const targetIds=new Set<string>(targetFunctions.map(identities).filter((id:string|null):id is string=>id!==null));
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
      const inherited=entry.node.baseContracts||[];
      const resolved=basesOf(entry);
      for(let i=0;i<inherited.length;i++){
        const choices=resolved[i]||[];
        // Only explicit canonical package imports may lack an acquired
        // source node. Never fabricate user-defined or ambiguous ancestors.
        const name=String(inherited[i]?.baseName?.namePath||"").split(".").pop();
        if(choices.length===0&&name&&hasCanonicalPackageBase(entry,name))continue;
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
        if(!id){if(!fn.body)invalid=true;continue;}
        declarations.add(id);
        if(fn.body)implemented.set(id,{entry,fn});
        else implemented.delete(id);
      }
      for(const variable of (entry.node.subNodes||[])
        .filter((n:any)=>n.type==="StateVariableDeclaration")
        .flatMap((n:any)=>n.variables||[])){
        if(variable.visibility==="public"&&variable.name){
          // Public scalar, contract/interface reference, and mapping state variables
          // generate ABI getters satisfying matching base interface/abstract declarations.
          const typ=variable.typeName;
          if(typ?.type==="ElementaryTypeName"||typ?.type==="UserDefinedTypeName"){
            implemented.set(variable.name+"()",{entry,fn:variable});
          } else if(typ?.type==="Mapping"){
            const keyTypes:string[]=[];
            let cur:any=typ,ok=true;
            while(cur?.type==="Mapping"){
              const kt=typeAbi(cur.keyType);
              if(!kt){ok=false;break;}
              keyTypes.push(kt);
              cur=cur.valueType;
            }
            if(ok&&keyTypes.length)implemented.set(
              variable.name+"("+keyTypes.join(",")+")",{entry,fn:variable});
          }
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
    // Follow only acquired import edges, including intermediate re-exports.
    // An import cycle is harmless; a same-named unlinked type is not proof.
    const reachable=new Set<string>(),pending=[source.path];
    let importProof=false;
    while(pending.length){
      const current=pending.pop()!;
      if(reachable.has(current))continue;
      reachable.add(current);
      const currentSource=sources.find(s=>s.path===current);
      if(!currentSource)continue;
      for(const imp of (astOf(currentSource)?.children||[]).filter((x:any)=>
        x.type==='ImportDirective'&&typeof x.path==='string')){
        const target=imp.path.startsWith('.')?
          posix.normalize(posix.join(posix.dirname(current),imp.path)):imp.path;
        if(target===interfaceSource.path){
          const aliases=imp.symbolAliases;
          if(!Array.isArray(aliases)||!aliases.length||
            aliases.some(([original,alias]:[string,string|null])=>
              original===interfaceName&&(alias===null||alias===interfaceName)))
            importProof=true;
        }
        if(sources.some(s=>s.path===target)&&!reachable.has(target))pending.push(target);
      }
    }
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
function callableType(type:any):string|null {
  if(type?.type==="ArrayTypeName"){
    const item=callableType(type.baseTypeName);
    if(!item)return null;
    if(type.length && (type.length.type!=="NumberLiteral"||
      !/^(?:0|[1-9][0-9]*)$/.test(String(type.length.number))))return null;
    return item+"["+(type.length?type.length.number:"")+"]";
  }
  if(type?.type==="UserDefinedTypeName")return "address";
  if(type?.type!=="ElementaryTypeName")return null;
  const t=String(type.name||"");
  const canonical=t==="uint"?"uint256":t==="int"?"int256":t==="address payable"?"address":t;
  return /^(?:address|bool|string|bytes|bytes(?:[1-9]|[12][0-9]|3[012])|u?int(?:[0-9]{1,3})?)$/.test(canonical)?
    canonical:null;
}
function callableTypes(parameters:readonly any[]):string[]|null {
  const types=parameters.map(p=>callableType(p.typeName));
  return types.some(x=>x===null)?null:types as string[];
}
/** Compiler-generated public getter signature for scalar, mapping and array
 * state. The source type, not a symbol-name guess, determines its ABI. */
function publicGetter(variable:any):{identity:string;returns:string[]}|null {
  if(variable.visibility!=="public"||!variable.name)return null;
  let type=variable.typeName;
  const inputs:string[]=[];
  while(type?.type==="Mapping"||type?.type==="ArrayTypeName"){
    if(type.type==="Mapping"){
      const key=callableType(type.keyType);
      if(!key)return null;
      inputs.push(key);
      type=type.valueType;
    }else{
      inputs.push("uint256");
      type=type.baseTypeName;
    }
  }
  const output=callableType(type);
  return output?{identity:variable.name+"("+inputs.join(",")+")",returns:[output]}:null;
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
  const packageMethods=new Map<string,{returns:string[]}>();
  let ambiguousBase=false;
  const collect=(entry:ContractEntry)=>{
    const key=entry.source.path+":"+entry.node.name;
    if(visited.has(key))return;
    visited.add(key);
    for(const base of entry.node.baseContracts||[]){
      const name=String(base.baseName?.namePath||"").split(".").pop();
      const local=entries.filter(e=>e.node.name===name&&
        e.source.path===entry.source.path&&e.node!==entry.node);
      const choices=local.length?local:entries.filter(e=>e.node.name===name&&reachable.has(e.source.path));
      if(choices.length===0&&name&&hasCanonicalPackageBase(entry,name)){
        const signatures=standardInheritedAbi[name];
        if(signatures)for(const [signature,returns] of Object.entries(signatures))
          packageMethods.set(signature,{returns:[...returns]});
        continue;
      }
      if(choices.length!==1){ambiguousBase=true;continue;}
      collect(choices[0]);
    }
    chain.push(entry);
  };
  collect(concrete);
  if(ambiguousBase)return {ok:false,missing:["ambiguous_or_missing_inheritance"]};
  const implemented=new Map<string,{returns:string[]|null}>(packageMethods);
  const inheritedDeclarations=new Set<string>();
  for(const entry of chain){
    for(const fn of (entry.node.subNodes||[]).filter((n:any)=>
      n.type==="FunctionDefinition"&&!n.isConstructor&&n.name)){
      const identity=callableIdentity(fn);
      if(!identity)continue;
      if(["public","external"].includes(fn.visibility))inheritedDeclarations.add(identity);
      if(fn.body&&["public","external"].includes(fn.visibility))
        implemented.set(identity,{returns:callableReturns(fn)});
      else if(!fn.body)implemented.delete(identity);
    }
    for(const v of (entry.node.subNodes||[]).filter((n:any)=>
      n.type==="StateVariableDeclaration").flatMap((n:any)=>n.variables||[])){
      const getter=publicGetter(v);
      if(getter)implemented.set(getter.identity,{returns:getter.returns});
    }
  }
  const missing:string[]=[];
  // An inherited abstract declaration without a surviving implementation
  // prevents deployment even when the specifically requested method exists.
  for(const identity of inheritedDeclarations)if(!implemented.has(identity))
    missing.push(identity+":unimplemented_inherited_abstract");
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
  const targetBindings=initializerStateBindings(targetNode,target);
  // Source-referenced constructor-injected dependencies must also contribute
  // receiver ABI requirements to implementation disambiguation.
  const constructorDemands=new Map<string,string[]>();
  for(const p of ctorOf(targetNode)?.parameters||[]){
    if(p.typeName?.type!=="UserDefinedTypeName"||!p.name)continue;
    const name=String(p.name);
    if(!/^[A-Za-z_]\w*$/.test(name))continue;
    constructorDemands.set(typeOf(p.typeName),[...new Set([...target.content.matchAll(
      new RegExp("\\b"+name+"\\s*\\.\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\(","g")
    )].map(m=>m[1]))]);
  }
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
    const receiverMethods=[...new Set([
      ...targetBindings.filter(b=>b.typeName===typ)
        .flatMap(b=>requiredReceiverMethods.get(b.receiver)||[]),
      ...(constructorDemands.get(typ)||[])
    ])];
    const qualified=receiverMethods.length?
      choices.filter(choice=>verifyAcquiredReceiverMethods(typ,receiverMethods,
        choice.source.path,choice.node.name,sources).ok):choices;
    if(qualified.length!==1){missing.push(typ+(qualified.length===0?
      ":no_acquired_abi_compatible_implementation":":ambiguous_implementation"));return null;}
    const selected=qualified[0],key=selected.source.path+":"+selected.node.name;
    if(stack.has(key)){missing.push(typ+":dependency_cycle");return null;}
    if(visited.has(key))return visited.get(key)!;
    if(deployments.length>=MAX_NODES){missing.push(typ+":max_dependency_nodes");return null;}
    stack.add(key);
    const args:PreparedArg[]=[];let valid=true;
    for(const p of ctorOf(selected.node)?.parameters||[]){
      const argType=typeOf(p.typeName);
      const struct=p.typeName?.type==="UserDefinedTypeName"&&
        (selected.node.subNodes||[]).some((n:any)=>
          n.type==="StructDefinition"&&n.name===String(p.typeName.namePath||"").split(".").pop());
      if(p.typeName?.type==="UserDefinedTypeName"&&!struct){
        const dep=resolve(argType,depth+1);
        if(!dep){valid=false;break;}args.push("$deployment:"+dep);
      }else{
        const literal=constrainedFixtureArg(p.typeName,String(p.name||""),ctorOf(selected.node),false,selected.node);
        if(literal===null){
          missing.push(key+":unsupported_constructor_type:"+(argType||p.typeName?.type||"unknown"));
          valid=false;break;
        }
        args.push(literal);
      }
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
      const initArgs:PreparedArg[]=[];
      const initBindings=initializerStateBindings(selected.node,selected.source);
      for(const p of initializer.parameters||[]){
        const name=String(p.name||""),argType=typeOf(p.typeName);
        const matching=initBindings.find(x=>x.parameter===name);
        if(matching){
          const dep=resolve(matching.typeName,depth+1);
          if(!dep){missing.push(key+":initializer_dependency:"+name);break;}
          initArgs.push("$deployment:"+dep);
        }else{
          const literal=constrainedFixtureArg(p.typeName,name,initializer,true,selected.node);
          if(literal===null){
            missing.push(key+":unsupported_initializer_parameter:"+name+":"+
              (argType||p.typeName?.type||"unknown"));break;
          }
          initArgs.push(literal);
        }
      }
      if(initArgs.length!==(initializer.parameters||[]).length){
        // A partially bound initializer is not an executable fixture. The
        // dependency graph must fail closed instead of reporting resolution.
        missing.push(key+":incomplete_initializer_arguments");
      }else{
        const sigTypes=(initializer.parameters||[]).map((p:any)=>
          fixtureAbiType(p.typeName,selected.node));
        if(sigTypes.some((value:any)=>value===null))
          missing.push(key+":unsupported_initializer_abi");
        else initializers.push({id:"setup"+(initializers.length+1),deploymentId:id,
          function:String(initializer.name)+"("+sigTypes.join(",")+")",args:initArgs,sender:0});
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
    // Only constructors establish deployment-before-deployment edges.
    // The isolated executor deploys the entire graph before sending ANY
    // initializer; cross-referencing initializer parameters are legal.
    const args=byId.get(id)?.constructorArgs||[];
    return [...new Set(args.filter((arg):arg is string=>
      typeof arg==="string"&&arg.startsWith("$deployment:"))
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
