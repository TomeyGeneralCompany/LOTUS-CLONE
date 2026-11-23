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
/** Source-global struct, enum and value-type declarations must participate in
 * ABI resolution even when their acquired file declares no contract at all.
 * The synthetic namespace below is NOT a deployable contract, fixture, mock,
 * or compiler substitute; it only carries actual parsed source declarations.
 */
function acquiredTypeEntries(sources:readonly SourceSnapshot[]):ContractEntry[]{
  return sources.flatMap(source=>{
    const children:any[]=astOf(source)?.children||[];
    const contracts=children.filter(node=>node.type==="ContractDefinition")
      .map(node=>({source,node}));
    const globals=children.filter(node=>
      ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(node.type));
    // The installed parser may reject the 0.8.8+ global UDVT syntax
    // altogether. Keep that exact source in the acquired namespace so the
    // validated lexical declaration can resolve through real import edges.
    const lexicalGlobalValue=/(?:^|\n)\s*type\s+[A-Za-z_]\w*\s+is\s+(?:u?int(?:[0-9]{1,3})?|address|bool|bytes(?:[0-9]{1,2})?)\s*;/m
      .test(source.content);
    return globals.length||lexicalGlobalValue?
      [...contracts,{source,node:{type:"ContractDefinition",kind:"library",
        name:"__acquired_global_types_"+source.sha256.slice(0,16),
        subNodes:globals,baseContracts:[]}}]:contracts;
  });
}
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
/** Resolve a UDT declaration only through an actual local declaration or
 * acquired relative import. Prevent a same-named type in an unrelated file
 * from masquerading as a constructor value. */
function acquiredValueDeclaration(type:any,owner:any,source?:SourceSnapshot,
  acquired:readonly SourceSnapshot[]=[]):
  {node:any;owner:any;source?:SourceSnapshot}|null {
  if(type?.type!=="UserDefinedTypeName")return null;
  const qualified=String(type.namePath||"").split(".");
  const name=qualified.pop()||"";
  if(!/^[A-Za-z_]\w*$/.test(name))return null;
  const kinds=new Set(["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"]);
  const local=(owner.subNodes||[]).filter((node:any)=>
    node.name===name&&kinds.has(node.type));
  if(local.length===1&&(qualified.length===0||qualified.join(".")===owner.name))
    return {node:local[0],owner,source};
  if(local.length!==0)return null;
  if(!source)return null;
  const byPath=new Map(acquired.map(s=>[s.path,s]));
  byPath.set(source.path,source);
  const candidates:Array<{node:any;owner:any;source:SourceSnapshot}>=[];
  const paths=new Set<string>(),pending=[source.path];
  while(pending.length&&paths.size<256){
    const path=pending.shift()!;
    if(paths.has(path))continue;
    paths.add(path);
    const src=byPath.get(path);
    if(!src)continue;
    for(const top of (astOf(src)?.children||[])){
      if(top.type==="ContractDefinition"&&
        (qualified.length===0||qualified.join(".")===top.name))
        for(const inner of top.subNodes||[])
          if(inner.name===name&&kinds.has(inner.type))
            candidates.push({node:inner,owner:top,source:src});
      else if(qualified.length===0&&top.name===name&&kinds.has(top.type))
        candidates.push({node:top,owner:top,source:src});
    }
    for(const imp of (astOf(src)?.children||[]).filter((x:any)=>
      x.type==="ImportDirective"&&typeof x.path==="string")){
      const next=imp.path.startsWith(".")?
        posix.normalize(posix.join(posix.dirname(path),imp.path)):imp.path;
      if(byPath.has(next)&&!paths.has(next))pending.push(next);
    }
  }
  // An unqualified local type takes precedence. Imported ambiguities do not.
  const exact=candidates.filter(c=>qualified.length!==0?
    c.owner.name===qualified.join("."):true);
  return exact.length===1?exact[0]:null;
}
/** Construct ABI-typed zero/one fixture values only for known elementary
 * and bounded one-dimensional array types. Solidity constructor/initializer
 * reverts remain real executor failures, never presumed successes. */
function primitiveFixtureArg(type:any,nonzero=false,contract?:any,source?:SourceSnapshot,
  acquired:readonly SourceSnapshot[]=[],depth=0):PreparedArg|null {
  if(depth>8)return null;
  if(type?.type==="UserDefinedTypeName"&&contract){
    const found=acquiredValueDeclaration(type,contract,source,acquired);
    if(!found)return null;
    const declaration=found.node;
    if(declaration.type==="EnumDefinition")return (declaration.members||[]).length>0?"0":null;
    if(["UserDefinedValueTypeDefinition","TypeDefinition"].includes(declaration.type))
      return primitiveFixtureArg(declaration.underlyingType||declaration.typeName||declaration.definition,
        nonzero,found.owner,found.source,acquired,depth+1);
    const parts=(declaration.members||[]).map((field:any)=>
      primitiveFixtureArg(field.typeName,nonzero,found.owner,found.source,acquired,depth+1));
    if(parts.some((part:any)=>part===null))return null;
    return parts as PreparedArg;
  }
  if(type?.type==="ArrayTypeName"){
    const base=primitiveFixtureArg(type.baseTypeName,nonzero,contract,source,acquired,depth+1);
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
function constrainedFixtureArg(type:any,parameter:string,fn:any,nonzero:boolean,contract:any,
  source?:SourceSnapshot,acquired:readonly SourceSnapshot[]=[]):PreparedArg|null {
  const fallback=primitiveFixtureArg(type,nonzero,contract,source,acquired);
  if(type?.type!=="ElementaryTypeName"||!parameter||!fn?.body)return fallback;
  const match=String(type.name||"").match(/^(u?int)([0-9]{0,3})$/);
  if(!match)return fallback;
  const bits=match[2]?Number(match[2]):256;
  if(bits<8||bits>256||bits%8!==0)return fallback;
  const signed=match[1]==="int";
  let lower=signed?-(1n<<BigInt(bits-1)):0n;
  let upper=signed?(1n<<BigInt(bits-1))-1n:(1n<<BigInt(bits))-1n;
  const excluded=new Set<string>();
  const constants=new Map<string,any>();
  for(const declaration of contract.subNodes||[])
    if(declaration.type==="StateVariableDeclaration")
      for(const variable of declaration.variables||[])
        if(variable.name&&variable.isDeclaredConst&&variable.expression)
          constants.set(variable.name,variable.expression);
  const evaluateConstant=(expr:any,depth=0,visited=new Set<string>()):bigint|null=>{
    if(!expr||depth>16)return null;
    if(expr.type==="Identifier"){
      const name=String(expr.name||"");
      const value=constants.get(name);
      if(!value||visited.has(name))return null;
      const seen=new Set(visited);seen.add(name);
      return evaluateConstant(value,depth+1,seen);
    }
    if(expr.type==="NumberLiteral"){
      const num=String(expr.number||"").replace(/_/g,"");
      const scientific=num.match(/^([0-9]+)[eE]([0-9]{1,2})$/);
      const canonical=scientific?
        BigInt(scientific[1])*10n**BigInt(scientific[2]):
        /^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(num)?BigInt(num):null;
      if(canonical===null)return null;
      const denomination=String(expr.subdenomination||"");
      const units:Record<string,bigint>={
        "":1n,wei:1n,gwei:1000000000n,ether:1000000000000000000n,
        seconds:1n,minutes:60n,hours:3600n,days:86400n,weeks:604800n};
      const unit=units[denomination];
      return unit===undefined?null:canonical*unit;
    }
    if(expr.type==="TupleExpression"&&expr.components?.length===1)
      return evaluateConstant(expr.components[0],depth+1,visited);
    if(expr.type==="UnaryOperation"){
      const operand=evaluateConstant(expr.subExpression,depth+1,visited);
      if(operand===null)return null;
      return expr.operator==="-"?-operand:expr.operator==="+"?operand:null;
    }
    if(expr.type!=="BinaryOperation")return null;
    const left=evaluateConstant(expr.left,depth+1,visited);
    const right=evaluateConstant(expr.right,depth+1,visited);
    if(left===null||right===null)return null;
    switch(expr.operator){
      case "+":return left+right;
      case "-":return left-right;
      case "*":return left*right;
      case "/":return right!==0n?left/right:null;
      case "%":return right!==0n?left%right:null;
      case "**":return right>=0n&&right<=78n?left**right:null;
      default:return null;
    }
  };
  const reverse:Record<string,string>={">":"<","<":">",">=":"<=","<=":">=","==":"==","!=":"!="};
  const apply=(expr:any):void=>{
    if(expr?.type!=="BinaryOperation")return;
    if(expr.operator==="&&"){apply(expr.left);apply(expr.right);return;}
    let op=String(expr.operator||"");
    let other=expr.right;
    if(expr.right?.type==="Identifier"&&expr.right.name===parameter){
      op=reverse[op]||"";other=expr.left;
    }else if(expr.left?.type!=="Identifier"||expr.left.name!==parameter)return;
    if(!reverse[op])return;
    const value=evaluateConstant(other);
    if(value===null)return;
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
function fixtureAbiType(type:any,contract:any,depth=0,source?:SourceSnapshot,
  acquired:readonly SourceSnapshot[]=[]):string|null {
  if(depth>5)return null;
  if(source){
    const entries:ContractEntry[]=acquired.flatMap(s=>
      (astOf(s)?.children||[]).filter((n:any)=>n.type==="ContractDefinition")
        .map((n:any)=>({source:s,node:n})));
    const actual=callableType(type,{source,node:contract},entries);
    if(actual!==null)return actual;
    // A failed acquired UDT ABI identity is not automatically an address.
    if(type?.type==="UserDefinedTypeName")return null;
  }
  if(type?.type==="ArrayTypeName"){
    const base=fixtureAbiType(type.baseTypeName,contract,depth+1);
    if(!base)return null;
    const len=type.length;
    if(len&&(!/^\\d+$/.test(String(len.number||""))))return null;
    return base+"["+(len?String(len.number):"")+"]";
  }
  if(type?.type==="UserDefinedTypeName"){
    const name=String(type.namePath||"").split(".").pop();
    const values=(contract.subNodes||[]).filter((n:any)=>
      ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(n.type)&&n.name===name);
    if(values.length>1)return null;
    if(values.length===0)return "address";
    const definition=values[0];
    if(definition.type==="EnumDefinition")return (definition.members||[]).length<=256?"uint8":null;
    if(["UserDefinedValueTypeDefinition","TypeDefinition"].includes(definition.type))
      return fixtureAbiType(definition.underlyingType||definition.typeName,contract,depth+1);
    const fields=(definition.members||[]).map((field:any)=>
      fixtureAbiType(field.typeName,contract,depth+1));
    return fields.length>0&&fields.every((f:any)=>typeof f==="string"&&f.length)?
      "("+fields.join(",")+")":null;
  }
  if(type?.type!=="ElementaryTypeName")return null;
  const raw=String(type.name||"");
  const standard=raw==="uint"?"uint256":raw==="int"?"int256":
    raw==="address payable"?"address":raw;
  return /^(?:address|bool|string|bytes|bytes(?:[1-9]|[12][0-9]|3[012])|u?int(?:[0-9]{1,3})?)$/.test(standard)?
    standard:null;
}
function initializerStateBindings(
  node:any,source:SourceSnapshot,sources:readonly SourceSnapshot[]
):Array<{parameter:string;receiver:string;typeName:string;line:number}>{
  // Solidity user-defined names also denote structs, enums and value types,
  // including qualified declarations imported from other acquired files.
  // Verify the actual acyclic import namespace before constructing ANY
  // deployment edge; a struct parameter cannot be a concrete contract.
  const byPath=new Map(sources.map(s=>[s.path,s]));
  byPath.set(source.path,source);
  const nonDeployable=new Set<string>();
  const visited=new Set<string>(),pending=[source.path];
  while(pending.length&&visited.size<512){
    const path=pending.shift()!;
    if(visited.has(path))continue;
    visited.add(path);
    const snapshot=byPath.get(path);
    if(!snapshot)continue;
    const ast=astOf(snapshot);
    for(const declaration of ast?.children||[]){
      if(declaration.type==="ContractDefinition"){
        for(const nested of declaration.subNodes||[]){
          if(!["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"]
            .includes(nested.type)||!nested.name)continue;
          nonDeployable.add(String(nested.name));
          nonDeployable.add(String(declaration.name)+"."+nested.name);
        }
      }else if(["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"]
        .includes(declaration.type)&&declaration.name)
        nonDeployable.add(String(declaration.name));
    }
    for(const imp of (ast?.children||[]).filter((i:any)=>
      i.type==="ImportDirective"&&typeof i.path==="string")){
      const imported=imp.path.startsWith(".")?
        posix.normalize(posix.join(posix.dirname(path),imp.path)):imp.path;
      if(byPath.has(imported)&&!visited.has(imported))pending.push(imported);
    }
  }
  // Explicitly local contract/interface declarations take precedence over
  // homonymous imported types. The compiler will still reject invalid
  // cross-file symbols during the real isolated EVM compilation.
  const localContracts=new Set((astOf(source)?.children||[]).filter((d:any)=>
    d.type==="ContractDefinition").map((d:any)=>String(d.name||"")));
  const vars=new Map<string,string>();
  for(const item of node.subNodes||[])if(item.type==="StateVariableDeclaration")
    for(const v of item.variables||[])if(v.name&&v.typeName?.type==="UserDefinedTypeName"&&
      typeOf(v.typeName)&&(!localContracts.has(typeOf(v.typeName))?
        !nonDeployable.has(typeOf(v.typeName)):true))
      vars.set(v.name,typeOf(v.typeName));
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
/** ABI entries from EXACT acquired source declarations. The caller must first
 * establish a real inheritance/import path before adding these methods to
 * the compiled subclass menu; this never fabricates an inherited function. */
export interface AcquiredInheritedAbiEntry {
  selector:string;operation:"call"|"send";inputs:string[];outputs:string[];
  sourceSha256:string;sourceFile:string;
}
export function enumerateAcquiredInheritedAbi(
  source:SourceSnapshot,contractName:string,derivedContract:string,
  allSources:readonly SourceSnapshot[]
):AcquiredInheritedAbiEntry[]{
  const root=(astOf(source)?.children||[]).find((n:any)=>
    n.type==="ContractDefinition"&&n.name===contractName);
  if(!root||!/^[A-Za-z_]\w*$/.test(derivedContract))return [];
  const entries:ContractEntry[]=allSources.flatMap(s=>
    (astOf(s)?.children||[]).filter((node:any)=>
      node.type==="ContractDefinition").map((node:any)=>({source:s,node})));
  const context={source,node:root};
  const output:AcquiredInheritedAbiEntry[]=[];
  for(const declaration of root.subNodes||[]){
    if(declaration.type==="FunctionDefinition"&&declaration.name&&
      ["public","external"].includes(declaration.visibility)){
      const inputs=callableTypes(declaration.parameters||[],context,entries);
      const returns=callableReturns(declaration,context,entries);
      if(inputs===null||returns===null)continue;
      output.push({selector:derivedContract+"."+declaration.name,
        operation:["pure","view"].includes(declaration.stateMutability)?"call":"send",
        inputs,outputs:returns,sourceSha256:source.sha256,sourceFile:source.path});
    }
    if(declaration.type==="StateVariableDeclaration")for(const v of declaration.variables||[]){
      const getter=publicGetter(v,context,entries);
      if(getter)output.push({selector:derivedContract+"."+v.name,operation:"call",
        inputs:getter.identity.slice(getter.identity.indexOf("(")+1,-1).split(",").filter(Boolean),
        outputs:getter.returns,sourceSha256:source.sha256,sourceFile:source.path});
    }
  }
  return output;
}

export interface AcquiredConcreteImplementation {
  path:string;contract:string;selector:string;sourceSha256:string;
  inputs:string[];operation:"call"|"send";witness:string;
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
  const entries=acquiredTypeEntries(sources);
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
  const typeAbi=(type:any,entry:ContractEntry):string|null=>
    callableType(type,entry,entries);
  const scalarAbi=(p:any,entry:ContractEntry):string|null=>
    typeAbi(p?.typeName,entry);
  const identities=(fn:any,entry:ContractEntry):string|null=>{
    const types=(fn.parameters||[]).map((p:any)=>scalarAbi(p,entry));
    return types.some((type:string|null)=>type===null)?null:
      String(fn.name)+"("+types.join(",")+")";
  };
  // Abstract interfaces can inherit the requested entrypoint from another
  // acquired interface. Resolve its true declaration/ABI through imported
  // parent edges, not through the selected interface's empty local body.
  const rootEntry:ContractEntry={source:abstractSource,node:root};
  const targetDeclarations:Array<{entry:ContractEntry;fn:any}>=[];
  let targetInvalid=false;
  const seenTargetEntries=new Set<string>();
  const visitTarget=(entry:ContractEntry,ancestors=new Set<string>(),depth=0):void=>{
    const identity=entry.source.path+":"+entry.node.name;
    if(ancestors.has(identity)||depth>12){targetInvalid=true;return;}
    if(seenTargetEntries.has(identity))return;
    seenTargetEntries.add(identity);
    const nextAncestors=new Set(ancestors);nextAncestors.add(identity);
    for(const fn of entry.node.subNodes||[])
      if(fn.type==="FunctionDefinition"&&fn.name===method&&!fn.isConstructor)
        targetDeclarations.push({entry,fn});
    const inherited=entry.node.baseContracts||[],parents=basesOf(entry);
    for(let i=0;i<inherited.length;i++){
      const possibilities=parents[i]||[];
      if(possibilities.length!==1){targetInvalid=true;continue;}
      visitTarget(possibilities[0],nextAncestors,depth+1);
    }
  };
  visitTarget(rootEntry);
  if(targetInvalid||!targetDeclarations.length)return [];
  const targetIds=new Set<string>();
  const targetReturns=new Map<string,string[]>();
  for(const {fn,entry} of targetDeclarations){
    const id=identities(fn,entry),returns=callableReturns(fn,entry,entries);
    if(!id||!returns)return [];
    const existing=targetReturns.get(id);
    if(existing&&JSON.stringify(existing)!==JSON.stringify(returns))return [];
    targetIds.add(id);targetReturns.set(id,returns);
  }
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
        const id=identities(fn,entry);
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
              const kt=typeAbi(cur.keyType,entry);
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
      const types=(proof.fn.parameters||[]).map((p:any)=>scalarAbi(p,proof.entry));
      if(types.some((type:string|null)=>type===null))continue;
      const actualReturns=callableReturns(proof.fn,proof.entry,entries);
      const expectedReturns=targetReturns.get(id);
      if(!actualReturns||!expectedReturns||
        JSON.stringify(actualReturns)!==JSON.stringify(expectedReturns))continue;
      result.push({path:candidate.source.path,contract:candidate.node.name,
        selector:candidate.node.name+"."+method,sourceSha256:candidate.source.sha256,
        inputs:types as string[],
        operation:['pure','view'].includes(proof.fn.stateMutability)?'call':'send',
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
  if(!iface)return [];
  // Interfaces can inherit the original callable ABI without redeclaring
  // the function. Follow acquired imports and only uniquely bound ancestors;
  // a name match in an unrelated source is not a source-grounded callsite.
  const byPath=new Map(sources.map(source=>[source.path,source]));
  const methodDeclared=(node:any,sourcePath:string,
    ancestors=new Set<string>(),depth=0):boolean=>{
    if(depth>12)return false;
    const id=sourcePath+':'+String(node.name||'');
    if(ancestors.has(id))return false;
    if((node.subNodes||[]).some((fn:any)=>
      fn.type==='FunctionDefinition'&&fn.name===method))return true;
    const source=byPath.get(sourcePath);
    if(!source)return false;
    const visited=new Set(ancestors);visited.add(id);
    const reachable=new Set<string>(),pending=[sourcePath];
    while(pending.length&&reachable.size<=256){
      const path=pending.shift()!;
      if(reachable.has(path))continue;
      reachable.add(path);
      const item=byPath.get(path);
      if(!item)continue;
      for(const imp of (astOf(item)?.children||[]).filter((v:any)=>
        v.type==='ImportDirective'&&typeof v.path==='string')){
        const resolved=imp.path.startsWith('.')?
          posix.normalize(posix.join(posix.dirname(path),imp.path)):imp.path;
        if(byPath.has(resolved)&&!reachable.has(resolved))pending.push(resolved);
      }
    }
    let foundMethod=false;
    for(const base of node.baseContracts||[]){
      const name=String(base.baseName?.namePath||'').split('.').pop();
      if(!name)return false;
      const declarations=(path:string,symbol:string):Array<{path:string;node:any}>=>
        (astOf(byPath.get(path)!)?.children||[])
          .filter((n:any)=>n.type==='ContractDefinition'&&n.name===symbol)
          .map((n:any)=>({path,node:n}));
      // Resolve lexical local declarations before acquired imports.
      const local=declarations(sourcePath,name);
      let parents=local;
      if(parents.length===0){
        for(const imp of (astOf(source)?.children||[]).filter((n:any)=>
          n.type==='ImportDirective'&&typeof n.path==='string')){
          const importPath=imp.path.startsWith('.')?
            posix.normalize(posix.join(posix.dirname(sourcePath),imp.path)):imp.path;
          if(!byPath.has(importPath)||!reachable.has(importPath))continue;
          const aliases=imp.symbolAliases;
          if(Array.isArray(aliases)&&aliases.length){
            for(const [original,alias] of aliases as [string,string|null][])
              if((alias||original)===name)
                parents.push(...declarations(importPath,original));
          }else parents.push(...declarations(importPath,name));
        }
      }
      if(parents.length===0)
        parents=[...reachable].flatMap(path=>declarations(path,name));
      // A missing or ambiguous inherited declaration invalidates the whole
      // interface proof even when some other branch supplies this method.
      const unique=[...new Map(parents.map(entry=>[
        entry.path+':'+entry.node.name,entry])).values()];
      if(unique.length!==1)return false;
      if(methodDeclared(unique[0].node,unique[0].path,visited,depth+1))
        foundMethod=true;
    }
    return foundMethod;
  };
  if(!methodDeclared(iface,interfaceSource.path))return [];
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
      // The caller can reference a receiver declared in an acquired base
      // contract. Resolve each inherited source edge through the same
      // authenticated import closure; never borrow a same-named foreign base.
      const getReceivers=(node:any,ownerPath:string,
        seen=new Set<string>(),depth=0):string[]=>{
        const key=ownerPath+':'+String(node.name||'');
        if(seen.has(key)||depth>12)return [];
        seen.add(key);
        const own=(node.subNodes||[])
          .filter((x:any)=>x.type==='StateVariableDeclaration')
          .flatMap((x:any)=>x.variables||[])
          .filter((v:any)=>v.typeName?.type==='UserDefinedTypeName'&&
            v.typeName.namePath===interfaceName)
          .map((v:any)=>String(v.name));
        for(const base of node.baseContracts||[]){
          const baseName=String(base.baseName?.namePath||'').split('.').pop();
          if(!baseName)continue;
          const possible=sources.flatMap(candidate=>
            (astOf(candidate)?.children||[])
              .filter((item:any)=>item.type==='ContractDefinition'&&item.name===baseName)
              .map((item:any)=>({source:candidate,node:item})))
            .filter(candidate=>reachable.has(candidate.source.path));
          const local=possible.filter(candidate=>candidate.source.path===ownerPath);
          const eligible=local.length?local:possible;
          if(eligible.length!==1)continue;
          own.push(...getReceivers(eligible[0].node,eligible[0].source.path,seen,depth+1));
        }
        return own;
      };
      const receivers=[...new Set(getReceivers(contract,source.path))];
      if(!receivers.length)continue;
      for(const fn of (contract.subNodes||[]).filter((x:any)=>
        x.type==='FunctionDefinition'&&x.body&&x.name&&
        ['external','public'].includes(x.visibility))){
        // A real caller edge is a compiler-parsed method invocation, not a
        // substring in a comment, quoted string or unrelated expression.
        const astNodes=descendants(fn.body);
        for(const receiver of receivers){
          if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(receiver))continue;
          if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(method))continue;
          if((fn.parameters||[]).some((p:any)=>p.name===receiver)||
            astNodes.some((n:any)=>n.type==="VariableDeclaration"&&n.name===receiver))continue;
          const actualCall=astNodes.find((n:any)=>
            n.type==="FunctionCall"&&n.expression?.type==="MemberAccess"&&
            n.expression.memberName===method&&
            n.expression.expression?.type==="Identifier"&&
            n.expression.expression.name===receiver);
          if(!actualCall)continue;
          callers.push({path:source.path,selector:contract.name+'.'+fn.name,
            sourceSha256:source.sha256,interfaceName,method,receiver,
            witness:source.path+':'+source.sha256+':'+
              String(actualCall.loc?.start?.line||fn.loc?.start?.line||1)+':'+
              String(actualCall.loc?.end?.line||fn.loc?.end?.line||1)});
        }
      }
    }
  }
  return callers.sort((a,b)=>a.path.localeCompare(b.path)||
    a.selector.localeCompare(b.selector)||a.receiver.localeCompare(b.receiver));
}

/** Canonical callable identity, derived from acquired Solidity declarations. */
/** Canonical Solidity ABI from authenticated source declarations. Contract,
 * struct, enum and value types are distinct; unresolvable names fail closed.
 * The isolated compiler and EVM must still verify the deployed ABI and receipt. */
function callableType(type:any,owner:ContractEntry,entries:readonly ContractEntry[],depth=0):string|null {
  if(depth>8)return null;
  if(type?.type==="ArrayTypeName"){
    const item=callableType(type.baseTypeName,owner,entries,depth+1);
    if(!item)return null;
    if(type.length&&(type.length.type!=="NumberLiteral"||
      !/^(?:0|[1-9][0-9]*)$/.test(String(type.length.number))))return null;
    return item+"["+(type.length?String(type.length.number):"")+"]";
  }
  if(type?.type==="UserDefinedTypeName"){
    const namePath=String(type.namePath||"");
    const parts=namePath.split("."),name=parts.pop()||"";
    if(!/^[A-Za-z_]\w*$/.test(name))return null;
    const local=(owner.node.subNodes||[]).filter((n:any)=>n.name===name&&
      ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(n.type));
    const sourceByPath=new Map(entries.map(e=>[e.source.path,e.source]));
    const reachable=new Set<string>(),queue=[owner.source.path];
    while(queue.length&&reachable.size<=256){
      const path=queue.shift()!;
      if(reachable.has(path))continue;
      reachable.add(path);
      const source=sourceByPath.get(path);
      if(!source)continue;
      for(const imp of (astOf(source)?.children||[]).filter((n:any)=>
        n.type==="ImportDirective"&&typeof n.path==="string")){
        const normalized=imp.path.startsWith(".")?
          posix.normalize(posix.join(posix.dirname(path),imp.path)):imp.path;
        if(sourceByPath.has(normalized)&&!reachable.has(normalized))queue.push(normalized);
      }
    }
    const nested=entries.filter(e=>reachable.has(e.source.path)&&
      (parts.length===0||parts.join(".")===e.node.name))
      .flatMap(e=>(e.node.subNodes||[]).filter((n:any)=>n.name===name&&
        ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(n.type)));
    const defs=local.length?local:nested;
    if(defs.length!==0){
      if(defs.length!==1)return null;
      const def=defs[0];
      if(def.type==="StructDefinition"){
        const fields=(def.members||[]).map((m:any)=>
          callableType(m.typeName,owner,entries,depth+1));
        return fields.length&&fields.every((t:any)=>t!==null)?
          "("+fields.join(",")+")":null;
      }
      if(def.type==="EnumDefinition")return (def.members||[]).length<=256?"uint8":null;
      return callableType(def.underlyingType||def.typeName||def.definition,owner,entries,depth+1);
    }
    // solidity-parser releases used by the offline index can omit the
    // Solidity 0.8.8+ top-level "type X is T" AST. Preserve the *exact
    // acquired source text* declaration as the type witness; never infer an
    // ABI from the name alone. The actual compiler must still approve it.
    const matchingValueTypes:Array<{underlying:string;path:string}>=[];
    if(parts.length===0){
      const escapedName=name;
      const typePattern=new RegExp("(?:^|\\n)\\s*type\\s+"+escapedName+
        "\\s+is\\s+(u?int(?:[0-9]{1,3})?|address|bool|bytes(?:[0-9]{1,2})?)\\s*;","g");
      for(const path of reachable){
        const text=sourceByPath.get(path)?.content||"";
        for(const match of text.matchAll(typePattern))
          matchingValueTypes.push({underlying:match[1],path});
      }
    }
    if(matchingValueTypes.length>1)return null;
    if(matchingValueTypes.length===1){
      const underlying=matchingValueTypes[0].underlying;
      return callableType({type:"ElementaryTypeName",name:underlying},
        owner,entries,depth+1);
    }
    const contractDefs=entries.filter(e=>e.node.name===name&&
      reachable.has(e.source.path)&&
      (parts.length===0||parts.join(".")===e.node.name));
    return contractDefs.length===1?"address":null;
  }
  if(type?.type!=="ElementaryTypeName")return null;
  const t=String(type.name||"");
  const canonical=t==="uint"?"uint256":t==="int"?"int256":
    t==="address payable"?"address":t;
  return /^(?:address|bool|string|bytes|bytes(?:[1-9]|[12][0-9]|3[012])|u?int(?:[0-9]{1,3})?)$/.test(canonical)?
    canonical:null;
}
function callableTypes(parameters:readonly any[],owner:ContractEntry,
  entries:readonly ContractEntry[]):string[]|null {
  const types=parameters.map(p=>callableType(p.typeName,owner,entries));
  return types.some(x=>x===null)?null:types as string[];
}
function publicGetter(variable:any,owner:ContractEntry,
  entries:readonly ContractEntry[]):{identity:string;returns:string[]}|null {
  if(variable.visibility!=="public"||!variable.name)return null;
  let type=variable.typeName;
  const inputs:string[]=[];
  while(type?.type==="Mapping"||type?.type==="ArrayTypeName"){
    if(type.type==="Mapping"){
      const key=callableType(type.keyType,owner,entries);
      if(!key)return null;
      inputs.push(key);
      type=type.valueType;
    }else{
      inputs.push("uint256");
      type=type.baseTypeName;
    }
  }
  const output=callableType(type,owner,entries);
  if(!output)return null;
  // Solidity public STRUCT getters return an ABI list of elementary fields,
  // not a single tuple output. Flatten only the known all-scalar shape;
  // nested mappings/tuples remain unresolved pending compiler ABI evidence.
  if(type?.type==="UserDefinedTypeName"&&
    output.startsWith("(")&&output.endsWith(")")){
    const fields=output.slice(1,-1).split(",");
    if(!fields.length||fields.some(t=>!t||/[()[\]]/.test(t)))return null;
    return {identity:variable.name+"("+inputs.join(",")+")",returns:fields};
  }
  return {identity:variable.name+"("+inputs.join(",")+")",returns:[output]};
}
function callableIdentity(fn:any,owner:ContractEntry,entries:readonly ContractEntry[]):string|null {
  const types=callableTypes(fn.parameters||[],owner,entries);
  return types===null?null:String(fn.name||"")+"("+types.join(",")+")";
}
function callableReturns(fn:any,owner:ContractEntry,entries:readonly ContractEntry[]):string[]|null {
  return callableTypes(fn.returnParameters||[],owner,entries);
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
  const entries=acquiredTypeEntries(sources);
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
      const identity=callableIdentity(fn,entry,entries);
      if(!identity)continue;
      if(["public","external"].includes(fn.visibility))inheritedDeclarations.add(identity);
      if(fn.body&&["public","external"].includes(fn.visibility))
        implemented.set(identity,{returns:callableReturns(fn,entry,entries)});
      else if(!fn.body)implemented.delete(identity);
    }
    for(const v of (entry.node.subNodes||[]).filter((n:any)=>
      n.type==="StateVariableDeclaration").flatMap((n:any)=>n.variables||[])){
      const getter=publicGetter(v,entry,entries);
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
      const origin=declared.find(e=>(e.node.subNodes||[]).includes(fn));
      if(!origin){missing.push(method+":declaring_contract_missing");continue;}
      const identity=callableIdentity(fn,origin,entries);
      const expected=callableReturns(fn,origin,entries);
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
  limits:Readonly<{maxDepth?:number;maxNodes?:number}>={},
):FixtureResolution {
  const ast=astOf(target);
  const targetNode=(ast?.children||[]).find((n:any)=>n.type==="ContractDefinition"&&n.name===contractName);
  if(!targetNode)return {status:"unresolved",missingDependencies:["target_contract_not_found"],attemptedResolvers:[],witnesses:[]};
  const scanned:ContractEntry[]=sources.flatMap(source=>{const parsed=astOf(source);
    return (parsed?.children||[]).filter((node:any)=>node.type==="ContractDefinition").map((node:any)=>({source,node}));
  });
  // UserDefinedTypeName includes contracts, libraries, structs, enums and
  // user-defined value types. Resolve the actual declaration class before
  // constructing an EVM deployment edge. A missing/ambiguous symbol stays
  // unresolved rather than silently becoming an implementation request.
  const acquiredByPath=new Map(sources.map(src=>[src.path,src]));
  const classifyUserType=(source:SourceSnapshot,node:any,typ:string):
    "contract"|"value"|"unknown"=>{
    const segments=String(typ||"").split(".");
    const name=segments.pop()||"";
    if(!/^[A-Za-z_]\w*$/.test(name))return "unknown";
    const local=(node.subNodes||[]).filter((n:any)=>n.name===name&&
      ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(n.type));
    if(local.length)return local.length===1?"value":"unknown";
    const reachable=new Set<string>(),pending=[source.path];
    while(pending.length&&reachable.size<=256){
      const current=pending.shift()!;
      if(reachable.has(current))continue;
      reachable.add(current);
      const src=acquiredByPath.get(current);
      if(!src)continue;
      for(const imp of (astOf(src)?.children||[]).filter((n:any)=>
        n.type==="ImportDirective"&&typeof n.path==="string")){
        const candidate=imp.path.startsWith(".")?
          posix.normalize(posix.join(posix.dirname(current),imp.path)):imp.path;
        if(acquiredByPath.has(candidate)&&!reachable.has(candidate))pending.push(candidate);
      }
    }
    const declarations:("contract"|"value")[]=[];
    for(const path of reachable){
      const src=acquiredByPath.get(path)!;
      for(const declaration of astOf(src)?.children||[]){
        if(declaration.type==="ContractDefinition"){
          if(!segments.length&&declaration.name===name)declarations.push("contract");
          if(segments.length&&segments.join(".")===declaration.name)
            for(const sub of declaration.subNodes||[])
              if(sub.name===name&&["StructDefinition","EnumDefinition",
                "UserDefinedValueTypeDefinition","TypeDefinition"].includes(sub.type))
                declarations.push("value");
        }else if(!segments.length&&declaration.name===name&&
          ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(declaration.type))
          declarations.push("value");
      }
    }
    if(declarations.length===1)return declarations[0];
    if(declarations.length>1)return "unknown";
    // Source bundles can carry a separately acquired, uniquely declared
    // contract/interface without reproducing the original import directive.
    // Preserve its declaration kind, but never guess between multiple names.
    if(!segments.length){
      const compatible=scanned.filter(e=>e.node.name===name);
      const conflicting=sources.some(src=>(astOf(src)?.children||[]).some((d:any)=>
        d.name===name&&["StructDefinition","EnumDefinition",
          "UserDefinedValueTypeDefinition","TypeDefinition"].includes(d.type)));
      if(compatible.length===1&&!conflicting)return "contract";
    }
    return "unknown";
  };
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
  const targetBindings=initializerStateBindings(targetNode,target,sources);
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
  // Planner resource limits are independently bounded by the execution schema
  // and local gas/sequence limits. A deep acquired dependency chain is not a
  // missing implementation simply because a historical fixture budget was 8.
  const MAX_DEPTH=limits.maxDepth===undefined?10:limits.maxDepth;
  const MAX_NODES=limits.maxNodes===undefined?16:limits.maxNodes;
  if(!Number.isSafeInteger(MAX_DEPTH)||MAX_DEPTH<1||MAX_DEPTH>12||
     !Number.isSafeInteger(MAX_NODES)||MAX_NODES<1||MAX_NODES>16)
    return {status:"unresolved",missingDependencies:["invalid_fixture_resource_budget"],
      attemptedResolvers:[],witnesses:[]};
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
    // Constructors resolve their transitive arguments BEFORE the parent is
    // inserted into deployments. Count active recursion nodes as reserved
    // deployment capacity, or an 11-node chain bypasses an eight-node budget.
    if(deployments.length+stack.size>=MAX_NODES){
      missing.push(typ+":max_dependency_nodes");return null;
    }
    stack.add(key);
    const args:PreparedArg[]=[];let valid=true;
    for(const p of ctorOf(selected.node)?.parameters||[]){
      const argType=typeOf(p.typeName);
      const struct=p.typeName?.type==="UserDefinedTypeName"&&
        (selected.node.subNodes||[]).some((n:any)=>
          n.type==="StructDefinition"&&n.name===String(p.typeName.namePath||"").split(".").pop());
      const typeClass=p.typeName?.type==="UserDefinedTypeName"?
        classifyUserType(selected.source,selected.node,argType):"value";
      if(p.typeName?.type==="UserDefinedTypeName"&&!struct&&typeClass==="contract"){
        const dep=resolve(argType,depth+1);
        if(!dep){valid=false;break;}args.push("$deployment:"+dep);
      }else{
        const literal=typeClass==="unknown"?null:
          constrainedFixtureArg(p.typeName,String(p.name||""),ctorOf(selected.node),false,selected.node,selected.source,sources);
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
      const initBindings=initializerStateBindings(selected.node,selected.source,sources);
      for(const p of initializer.parameters||[]){
        const name=String(p.name||""),argType=typeOf(p.typeName);
        const matching=initBindings.find(x=>x.parameter===name);
        if(matching){
          const dep=resolve(matching.typeName,depth+1);
          if(!dep){missing.push(key+":initializer_dependency:"+name);break;}
          initArgs.push("$deployment:"+dep);
        }else{
          const literal=constrainedFixtureArg(p.typeName,name,initializer,true,selected.node,selected.source,sources);
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
          fixtureAbiType(p.typeName,selected.node,0,selected.source,sources));
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
  for(const p of params)if(p.typeName?.type==="UserDefinedTypeName"&&
    classifyUserType(target,targetNode,typeOf(p.typeName))==="contract"){
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
