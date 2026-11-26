/**
 * Source-grounded, offline experiment constructor. Operates ONLY on supplied,
 * already-acquired source bytes. No I/O, model inference, or controller actions.
 * Existing role-mutation planner remains the authoritative legacy fallback.
 */
import {createHash} from 'node:crypto';
import {parse} from '@solidity-parser/parser';
import {posix} from 'node:path';
import type {SolidityProbeDeclaration} from './solidity-probe-inputs';
import type {SoliditySequence} from './solidity-sequence';
import {sourceGroundedSolidityProbes} from './controller-solidity-security-probes';
import {inheritedRoleConsumerImpactSequence} from './controller-solidity-consumer-impact';
import {orderPreparation, type PreparationPrerequisite, type SourceWitness} from './controller-solidity-prerequisites';
import {extractAccountingObservations} from './deterministic/accounting-observations';
import {resolveSourceFixtureDependencies, enumerateSourceFixtureDependenciesDetailed, verifyAcquiredReceiverMethods, type PreparedDeployment, type PreparedInitializerOperation} from './deterministic/fixture-dependency-planner';

export interface SourceSnapshot {path:string;sha256:string;content:string}
export interface StaticLeadHint {
  path:string;line:number;rule:string;message:string;severity?:string;engine?:string;
}
export type InvariantPropertyKind =
  | 'authorization'
  | 'conservation'
  | 'supply-accounting'
  | 'share-accounting'
  | 'interest-accrual'
  | 'reentrancy-guard'
  | 'other';

export type InvariantUnresolvedCategory =
  | 'missing_fixture'
  | 'missing_observable_state'
  | 'unresolved_dependency'
  | 'unavailable_replay_capability'
  | 'no_supported_property';

export interface SourceInvariantTransitionPlan {
  mode: 'eth_deposit_withdraw' | 'internal_deposit_withdraw' | 'erc20_deposit_withdraw' | 'mint_burn_supply';
  usesMockToken?: boolean;
  inflowMethod: string;
  inflowSig: string;
  inflowArgs: string[];
  inflowValueWei?: string;
  outflowMethod: string;
  outflowSig: string;
  outflowArgs: string[];
  inflowAmount: string;
  outflowAmount: string;
  expectedRemainder: string;
  balanceMappingGetter?: string;
  totalScalarGetter?: string;
  typedObservation?: {getter:string;args:string[];expectPath?:number[];baseline:string;afterInflow:string;afterOutflow:string};
  dependencyDeployments?:PreparedDeployment[];
  dependencyInitializerOperations?:PreparedInitializerOperation[];
  dependencyBindings?:Record<string,string>;
}

export interface SourceInvariant {
  sourceSha256: string;
  target: string;
  companionTarget?: string;
  propertyKind: InvariantPropertyKind;
  predictedRelation: string;
  falsifier: string;
  preState: Array<{expression: string; readback: string}>;
  postState: Array<{expression: string; readback: string}>;
  witnesses?: SourceWitness[];
  transitionPlan?: SourceInvariantTransitionPlan;
}

export type InvariantExtractionResult =
  | {ok: true; invariant: SourceInvariant}
  | {ok: false; category: InvariantUnresolvedCategory; reason: string; witnesses?: SourceWitness[]; companionCandidates?:string[]};

export interface ConstructionInput {
  repositoryCommit:string;targetPath:string;targetSelector:string;
  sources:readonly SourceSnapshot[];
  declarations:readonly SolidityProbeDeclaration[];
  skipLegacy?:boolean;
  skipFinancialInvariants?:boolean;
  staticLeads?:readonly StaticLeadHint[];
  invariants?:readonly SourceInvariant[];
}
export interface PreparedSecurityExperiment {
  version:1;id:string;language:'solidity';status:'constructed';
  path:string;selector:string;hypothesis:string;securityProperty:string;
  witnesses:SourceWitness[];prerequisites:PreparationPrerequisite[];
  sequence:SoliditySequence;
}
export type ConstructionResult =
  | {ok:true;experiments:PreparedSecurityExperiment[]}
  | {ok:false;code:string;detail:string;unresolvedCategory?:InvariantUnresolvedCategory;
      /** An independently executable alternative does not discharge another blocked source obligation. */
      partialExperiments?:PreparedSecurityExperiment[]};

const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
/** Resolve an acquired import without treating package imports as paths under
 * the target file's directory. Package snapshots use the exact Solidity import
 * specifier as their identity (for example @openzeppelin/contracts/...); local
 * imports continue to use POSIX-normalized paths relative to the importing file.
 */
function importedSnapshot(sources:ReadonlyMap<string,SourceSnapshot>,fromPath:string,importPath:string):SourceSnapshot|undefined {
  const resolved=importPath.startsWith('.')
    ?posix.normalize(posix.join(posix.dirname(fromPath),importPath))
    :importPath;
  return sources.get(resolved);
}
const identifier=/^[A-Za-z_]\w*$/;
const ZERO_ADDRESS='0x0000000000000000000000000000000000000000';
const ZERO_BYTES32='0x'+'00'.repeat(32);

const astCache=new Map<string,any>();
function parseAstCached(snapshot:SourceSnapshot):any {
  const cached=astCache.get(snapshot.sha256);
  if(cached)return cached;
  const parsed=parse(snapshot.content,{range:true,loc:true});
  if(astCache.size>=256)astCache.delete(astCache.keys().next().value!);
  astCache.set(snapshot.sha256,parsed);
  return parsed;
}
const abiNodeOwner=new WeakMap<object,string>();
type AbiTypeDefinition={kind:"contract"|"enum"|"struct"|"value";node:any;owner?:string};
let activeAbiTypeDefinitions=new Map<string,AbiTypeDefinition[]>();
function addAbiType(map:Map<string,AbiTypeDefinition[]>,name:string,definition:AbiTypeDefinition){
  if(!name)return;
  const values=map.get(name)||[];
  if(!values.some(value=>value.node===definition.node))values.push(definition);
  map.set(name,values);
}
function buildAbiTypeDefinitions(sources:readonly SourceSnapshot[]):Map<string,AbiTypeDefinition[]> {
  const result=new Map<string,AbiTypeDefinition[]>();
  const mark=(value:any,owner?:string,depth=0):void=>{
    if(!value||typeof value!=="object"||depth>128)return;
    if(Array.isArray(value)){for(const item of value)mark(item,owner,depth+1);return;}
    let current=owner;
    if(value.type==="ContractDefinition"&&typeof value.name==="string")current=value.name;
    if(current)abiNodeOwner.set(value,current);
    for(const [key,child] of Object.entries(value))
      if(key!=="loc"&&key!=="range")mark(child,current,depth+1);
  };
  for(const source of sources){
    let ast:any;
    try{ast=parseAstCached(source);}catch{continue;}
    mark(ast);
    for(const node of ast.children||[]){
      if(node.type==="ContractDefinition"&&node.name){
        const contract:AbiTypeDefinition={kind:"contract",node,owner:node.name};
        addAbiType(result,node.name,contract);
        for(const child of node.subNodes||[]){
          if(!child.name)continue;
          const kind=child.type==="EnumDefinition"?"enum":
            child.type==="StructDefinition"?"struct":
            ["UserDefinedValueTypeDefinition","TypeDefinition"].includes(child.type)?"value":null;
          if(!kind)continue;
          const definition:AbiTypeDefinition={kind,node:child,owner:node.name};
          addAbiType(result,node.name+"."+child.name,definition);
          addAbiType(result,child.name,definition);
        }
      }else if(node.name){
        const kind=node.type==="EnumDefinition"?"enum":
          node.type==="StructDefinition"?"struct":
          ["UserDefinedValueTypeDefinition","TypeDefinition"].includes(node.type)?"value":null;
        if(kind)addAbiType(result,node.name,{kind,node,owner:undefined});
      }
    }
  }
  return result;
}
function resolveUserAbiType(typeName:any,seen=new Set<any>()):string|null {
  const name=String(typeName?.namePath||"");
  if(!identifier.test(name)&&!/^([A-Za-z_]\\w*\\.)+[A-Za-z_]\\w*$/.test(name))return null;
  const owner=abiNodeOwner.get(typeName);
  const choices=activeAbiTypeDefinitions.get(owner&& !name.includes(".")?owner+"."+name:name)||
    activeAbiTypeDefinitions.get(name)||[];
  if(!choices.length)return null;
  const shapes=choices.map(definition=>{
    if(seen.has(definition.node))return null;
    if(definition.kind==="contract")return "address";
    if(definition.kind==="enum")return "uint8";
    const next=new Set(seen);next.add(definition.node);
    if(definition.kind==="value"){
      const underlying=definition.node.underlyingType||
        definition.node.underlyingTypeName||definition.node.typeName||definition.node.definition;
      return canonicalAbiType(underlying,next);
    }
    const members=definition.node.members||[];
    const types=members.map((member:any)=>canonicalAbiType(member.typeName,next));
    return types.some((item:string|null)=>item===null)?null:"("+types.join(",")+")";
  });
  const unique=[...new Set(shapes.filter((item):item is string=>typeof item==="string"))];
  return unique.length===1&&shapes.every((item:string|null)=>item===unique[0])?unique[0]:null;
}

const clean=(s:string)=>s.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'');
const body=(text:string,node:any)=>node?.body?.range ?
  clean(text.slice(node.body.range[0],node.body.range[1]+1)):'';

function witness(snapshot:SourceSnapshot,node:any,symbol:string):SourceWitness {
  const range=node?.range||[0,snapshot.content.length-1];
  return {path:snapshot.path,sourceSha256:snapshot.sha256,
    start:range[0],end:range[1]+1,symbol};
}

/** Proof of ownership comes from THIS contract's actual source, not a name. */
function directOwnerExperiment(snapshot:SourceSnapshot,contract:any,menu:readonly SolidityProbeDeclaration[],
  target:string):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  const source=snapshot.content,members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition');
  const constructor=functions.find(n=>n.isConstructor);
  const owner=members.filter(n=>n.type==='StateVariableDeclaration').flatMap(n=>n.variables||[])
    .find((v:any)=>v.name==='owner'&&v.typeName?.name==='address'&&v.visibility==='public');
  if(!owner || !constructor || constructor.parameters?.length ||
    !/\bowner\s*=\s*msg\s*\.\s*sender\s*;/.test(body(source,constructor)))return null;
  const setter=functions.find(n=>n.name===target&&['public','external'].includes(n.visibility) &&
    n.parameters?.length===1 && n.body?.range);
  if(!setter)return null;
  const parameter=setter.parameters[0];
  if(!identifier.test(parameter?.name||''))return null;
  const type=parameter.typeName?.name;
  if(!type || !/^uint(?:[0-9]{1,3})?$/.test(type))return null;
  const state=members.filter(n=>n.type==='StateVariableDeclaration').flatMap(n=>n.variables||[])
    .find((v:any)=>v.visibility==='public'&&v.typeName?.name===type && v.name!==parameter.name);
  if(!state || !identifier.test(state.name))return null;
  const fnBody=body(source,setter);
  if(!/\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*owner\b/.test(fnBody))return null;
  const assignment=new RegExp('\\b'+state.name+'\\s*=\\s*'+parameter.name+'\\s*;');
  if(!assignment.test(fnBody))return null;
  const remainder=fnBody.replace(/\brequire\s*\([^;]*\)\s*;/g,'')
    .replace(assignment,'').replace(/[{}\s]/g,'');
  if(remainder)return null; // No unproven side effects.
  const selector=contract.name+'.'+setter.name;
  const entry=menu.find(m=>m.selector===selector&&m.operation==='send'&&
    m.inputs.length===1&&m.inputs[0]===type);
  const getter=menu.find(m=>m.selector===contract.name+'.'+state.name&&
    m.operation==='call'&&m.inputs.length===0);
  const ownerGetter=menu.find(m=>m.selector===contract.name+'.owner'&&
    m.operation==='call'&&m.inputs.length===0);
  if(!entry||!getter||!ownerGetter)return null;
  const initial=state.expression?null:'0';
  if(initial===null)return null;
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:'call',function:'owner()',args:[],expect:'$account0'},
    {operation:'call',function:state.name+'()',args:[],expect:initial},
    {operation:'send',function:setter.name+'('+type+')',args:['2'],sender:1,expectRevert:true},
    {operation:'call',function:state.name+'()',args:[],expect:initial},
    {operation:'send',function:setter.name+'('+type+')',args:['2'],sender:0},
    {operation:'call',function:state.name+'()',args:[],expect:'2'}
  ]};
  return {hypothesis:'Unauthorized caller cannot update '+state.name+
    ' through '+selector+'; authorized owner can.',property:'owner-gated state transition',
    sequence,witnesses:[witness(snapshot,constructor,contract.name+'.constructor'),
      witness(snapshot,setter,selector),witness(snapshot,owner,contract.name+'.owner'),
      witness(snapshot,state,contract.name+'.'+state.name)]};
}

/**
 * Source-proven BoringOwnable initialization + public scalar setter.
 * Accept only an actual imported base, proven owner initializer, proven guard,
 * and a setter whose only state mutation is the observable public field.
 * Supports the 88mph Vesting02.setMPHMinter authorization experiment.
 */
function inheritedOwnerExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,menu:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  const text=snapshot.content;
  if(!(contract.baseContracts||[]).some((b:any)=>b.baseName?.namePath==='BoringOwnable'))return null;
  const ast=parseAstCached(snapshot);
  const imports=(ast.children||[]).filter((n:any)=>n.type==='ImportDirective');
  const ownerImport=imports.find((n:any)=>typeof n.path==='string'&&
    posix.basename(n.path)==='BoringOwnable.sol');
  if(!ownerImport)return null;
  const peer=importedSnapshot(sources,snapshot.path,ownerImport.path);
  if(!peer)return null;
  let peerAst:any;
  try{peerAst=parseAstCached(peer);}catch{return null;}
  const base=(peerAst.children||[]).find((n:any)=>
    n.type==='ContractDefinition'&&n.name==='BoringOwnable');
  if(!base)return null;
  const baseFunctions:any[]=base.subNodes||[];
  const ownerInit=baseFunctions.find((n:any)=>n.type==='FunctionDefinition'&&n.name==='__Ownable_init');
  const guard=baseFunctions.find((n:any)=>n.type==='ModifierDefinition'&&n.name==='onlyOwner');
  const ownerGetter=baseFunctions.find((n:any)=>n.type==='FunctionDefinition'&&n.name==='owner');
  if(!ownerInit||!guard||!ownerGetter ||
    !/\b_owner\s*=\s*msg\s*\.\s*sender\s*;/.test(body(peer.content,ownerInit)) ||
    !/\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*_owner\b/.test(body(peer.content,guard)) ||
    !/\breturn\s+_owner\s*;/.test(body(peer.content,ownerGetter)))return null;
  const members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition');
  const initializer=functions.find(n=>n.name==='initialize'&&
    ['public','external'].includes(n.visibility)&&
    (n.modifiers||[]).some((m:any)=>m.name==='initializer')&&
    /\b__Ownable_init\s*\(\s*\)\s*;/.test(body(text,n)));
  if(!initializer)return null;
  const initBody=body(text,initializer);
  const reducedInit=initBody.replace(/\b__Ownable_init\s*\(\s*\)\s*;/g,'')
    .replace(/\b__ERC721_init\s*\(\s*[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*\)\s*;/g,'')
    .replace(/\b[A-Za-z_]\w*\s*=\s*IERC20\s*\(\s*[A-Za-z_]\w*\s*\)\s*;/g,'')
    .replace(/[{}\s]/g,'');
  if(reducedInit)return null;
  const initTypes=(initializer.parameters||[]).map((p:any)=>p.typeName?.name);
  if(JSON.stringify(initTypes)!==JSON.stringify(['address','string','string']))return null;
  const setter=functions.find(n=>n.name===method&&
    ['public','external'].includes(n.visibility)&&n.parameters?.length===1&&
    (n.modifiers||[]).some((m:any)=>m.name==='onlyOwner'));
  if(!setter || setter.parameters[0].typeName?.name!=='address')return null;
  const param=setter.parameters[0].name;
  if(!identifier.test(param||''))return null;
  const stateVariables=members.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]);
  const setterBody=body(text,setter);
  const candidate=stateVariables.find((v:any)=>
    v.visibility==='public'&&identifier.test(v.name||'')&&
    new RegExp('\\b'+v.name+'\\s*=\\s*[A-Za-z_]\\w*\\s*\\(\\s*'+param+'\\s*\\)\\s*;').test(setterBody));
  if(!candidate)return null;
  const assignment=new RegExp('\\b'+candidate.name+'\\s*=\\s*[A-Za-z_]\\w*\\s*\\(\\s*'+param+'\\s*\\)\\s*;');
  const remaining=setterBody.replace(assignment,'')
    .replace(/\brequire\s*\([^;]*\)\s*;/g,'')
    .replace(/\bemit\s+[A-Za-z_]\w*\s*\([^;]*\)\s*;/g,'')
    .replace(/[{}\s]/g,'');
  if(remaining)return null;
  const selector=contract.name+'.'+method;
  const abi=menu.find(m=>m.selector===selector&&m.operation==='send'&&
    m.inputs.length===1&&m.inputs[0]==='address');
  if(!abi)return null;
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:'send',function:'initialize(address,string,string)',
      args:['$account2','LOTUS-Test','LOTUS'],sender:0},
    {operation:'call',function:'owner()',args:[],expect:'$account0'},
    {operation:'call',function:candidate.name+'()',args:[],
      expect:ZERO_ADDRESS},
    {operation:'send',function:method+'(address)',args:['$account2'],
      sender:1,expectRevert:true},
    {operation:'call',function:candidate.name+'()',args:[],
      expect:ZERO_ADDRESS},
    {operation:'send',function:method+'(address)',args:['$account2'],sender:0},
    {operation:'call',function:candidate.name+'()',args:[],expect:'$account2'}
  ]};
  return {
    hypothesis:'Non-owner must not change '+candidate.name+'; initialized owner may.',
    property:'source-proven inherited BoringOwnable authorization',
    sequence,witnesses:[
      witness(snapshot,initializer,contract.name+'.initialize'),
      witness(snapshot,setter,selector),
      witness(snapshot,candidate,contract.name+'.'+candidate.name),
      witness(peer,ownerInit,'BoringOwnable.__Ownable_init'),
      witness(peer,guard,'BoringOwnable.onlyOwner'),
      witness(peer,ownerGetter,'BoringOwnable.owner')
    ]
  };
}

type AbiScalarType='address'|'bool'|'string'|'uint';
interface ContractEntry {snapshot:SourceSnapshot;contract:any;ast:any}
interface OzBaseProof {kind:'ownable'|'ownable_upgradeable'|'pausable'|'access_control'|'erc20'|'erc721';path:string}

const OZ_IMPORT_PREFIXES:Array<{match:(p:string)=>boolean;base:string;kind:OzBaseProof['kind']}>=[
  {match:p=>/^@openzeppelin\/contracts(?:-upgradeable)?\/access\/Ownable\.sol$/.test(p),base:'Ownable',kind:'ownable'},
  {match:p=>/^@openzeppelin\/contracts-upgradeable\/access\/OwnableUpgradeable\.sol$/.test(p),base:'OwnableUpgradeable',kind:'ownable_upgradeable'},
  {match:p=>/^@openzeppelin\/contracts(?:-upgradeable)?\/security\/Pausable(?:Upgradeable)?\.sol$/.test(p),base:'PausableUpgradeable',kind:'pausable'},
  {match:p=>/^@openzeppelin\/contracts\/security\/Pausable\.sol$/.test(p),base:'Pausable',kind:'pausable'},
  {match:p=>/^@openzeppelin\/contracts(?:-upgradeable)?\/access\/AccessControl(?:Upgradeable)?\.sol$/.test(p),base:'AccessControlUpgradeable',kind:'access_control'},
  {match:p=>/^@openzeppelin\/contracts\/access\/AccessControl\.sol$/.test(p),base:'AccessControl',kind:'access_control'},
  {match:p=>/^@openzeppelin\/contracts(?:-upgradeable)?\/token\/ERC20\/.*ERC20.*\.sol$/.test(p),base:'ERC20',kind:'erc20'},
  {match:p=>/^@openzeppelin\/contracts(?:-upgradeable)?\/token\/ERC721\/.*ERC721.*\.sol$/.test(p),base:'ERC721',kind:'erc721'}
];

const SAFE_OZ_INITS=new Set([
  '__Ownable_init','__Ownable_init_unchained',
  '__Pausable_init','__Pausable_init_unchained',
  '__AccessControl_init','__AccessControl_init_unchained',
  '__ReentrancyGuard_init','__ReentrancyGuard_init_unchained',
  '__Context_init','__Context_init_unchained',
  '__Multicall_init','__Multicall_init_unchained',
  '__ERC20_init','__ERC20_init_unchained',
  '__ERC20Burnable_init','__ERC20Burnable_init_unchained',
  '__ERC721_init','__ERC721_init_unchained',
  '__ERC721URIStorage_init','__ERC721URIStorage_init_unchained',
  '__EIP712_init','__EIP712_init_unchained',
  '_setupRole','_grantRole','_setRoleAdmin'
]);

function canonicalAbiType(typeName:any,seen=new Set<any>()):string|null {
  if(!typeName)return null;
  // The ABI does not collapse acquired array types to an unknown argument.
  // In particular, a factory's address[] and a batch token operation's
  // uint256[] are real, executable signatures rather than a scalar address.
  if(typeName.type==='ArrayTypeName'){
    const base=canonicalAbiType(typeName.baseTypeName,seen);
    if(!base)return null;
    const size=typeName.length;
    if(size===null||size===undefined)return base+'[]';
    const count=String(size.number??size.value??'');
    if(!/^[1-9][0-9]*$/.test(count)||Number(count)>32)return null;
    return base+'['+count+']';
  }
  if(typeName.type==='ElementaryTypeName'){
    const name=String(typeName.name||'');
    if(name==='address')return 'address';
    if(name==='uint')return 'uint256';
    if(name==='int')return 'int256';
    if(/^(?:u?int[0-9]{0,3}|bool|string|bytes(?:[0-9]{1,2})?)$/.test(name))return name;
    return null;
  }
  if(typeName.type==='UserDefinedTypeName')return resolveUserAbiType(typeName,seen);
  return null;
}

function classifyScalarType(abiType:string|null):AbiScalarType|null {
  if(!abiType)return null;
  if(abiType==='address')return 'address';
  if(abiType==='bool')return 'bool';
  if(abiType==='string')return 'string';
  if(/^uint(?:[0-9]{1,3})?$/.test(abiType))return 'uint';
  return null;
}

function resolveInheritance(
  target:SourceSnapshot,targetContract:any,sources:ReadonlyMap<string,SourceSnapshot>
):{chain:ContractEntry[];oz:Set<OzBaseProof['kind']>;localOwnables:ContractEntry[]} {
  const chain:ContractEntry[]=[];
  const oz=new Set<OzBaseProof['kind']>();
  const localOwnables:ContractEntry[]=[];
  const visited=new Set<string>();
  const visit=(entry:ContractEntry)=>{
    const key=entry.snapshot.path+':'+entry.contract.name;
    if(visited.has(key))return;
    visited.add(key);
    chain.push(entry);
    const imports=(entry.ast.children||[]).filter((n:any)=>n.type==='ImportDirective'&&typeof n.path==='string');
    for(const imp of imports){
      for(const spec of OZ_IMPORT_PREFIXES){
        if(spec.match(imp.path))oz.add(spec.kind);
      }
    }
    for(const base of entry.contract.baseContracts||[]){
      const baseName=base.baseName?.namePath;
      if(!baseName||!identifier.test(baseName))continue;
      // Same-file base contract
      const sameFile=(entry.ast.children||[]).find((n:any)=>n.type==='ContractDefinition'&&n.name===baseName);
      if(sameFile){visit({snapshot:entry.snapshot,contract:sameFile,ast:entry.ast});continue;}
      // Imported relative file in acquired sources
      for(const imp of imports){
        const p=imp.path as string;
        if(!p.startsWith('.'))continue;
        if(Array.isArray(imp.symbolAliases)&&imp.symbolAliases.length){
          const matchesAlias=imp.symbolAliases.some(([orig,alias]:[string,string|null])=>(alias||orig)===baseName);
          if(!matchesAlias)continue;
        }
        const peer=importedSnapshot(sources,entry.snapshot.path,p);
        if(!peer)continue;
        let peerAst:any;
        try{peerAst=parseAstCached(peer);}catch{continue;}
        const originalName=Array.isArray(imp.symbolAliases)&&imp.symbolAliases.length
          ? (imp.symbolAliases.find(([orig,alias]:[string,string|null])=>(alias||orig)===baseName)?.[0]||baseName)
          : baseName;
        const found=(peerAst.children||[]).find((n:any)=>n.type==='ContractDefinition'&&n.name===originalName);
        if(found)visit({snapshot:peer,contract:found,ast:peerAst});
      }
    }
  };
  visit({snapshot:target,contract:targetContract,ast:parseAstCached(target)});
  for(const entry of chain){
    const members:any[]=entry.contract.subNodes||[];
    const initFn=members.find(n=>n.type==='FunctionDefinition'&&n.name==='__Ownable_init');
    const mod=members.find(n=>n.type==='ModifierDefinition'&&n.name==='onlyOwner');
    const getter=members.find(n=>n.type==='FunctionDefinition'&&n.name==='owner');
    if(initFn&&mod&&getter &&
      /\b_owner\s*=\s*msg\s*\.\s*sender\s*;/.test(body(entry.snapshot.content,initFn)) &&
      /\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*_owner\b/.test(body(entry.snapshot.content,mod)) &&
      /\breturn\s+_owner\s*;/.test(body(entry.snapshot.content,getter))){
      localOwnables.push(entry);
    }
  }
  return {chain,oz,localOwnables};
}

function exprIdentifier(node:any):string|null {
  return node?.type==='Identifier'&&identifier.test(node.name||'')?node.name:null;
}

function isMsgSender(node:any):boolean {
  return node?.type==='MemberAccess'&&node.memberName==='sender'&&
    node.expression?.type==='Identifier'&&node.expression.name==='msg';
}

function isAddressZero(node:any):boolean {
  return node?.type==='FunctionCall'&&(node.expression?.type==='ElementaryTypeName'||node.expression?.type==='Identifier')&&
    node.expression.name==='address'&&node.arguments?.length===1&&
    node.arguments[0]?.type==='NumberLiteral'&&node.arguments[0].number==='0';
}

function isRequireZeroViolation(expr:any,paramName:string):'nonzero'|'gt_zero'|'contract'|null {
  if(!expr||typeof expr!=='object')return null;
  if(expr.type==='FunctionCall'&&expr.expression?.type==='MemberAccess'&&
    expr.expression.memberName==='isContract'&&exprIdentifier(expr.expression.expression)===paramName){
    return 'contract';
  }
  if(expr.type==='BinaryOperation'){
    if(expr.operator==='!='&&(
      (exprIdentifier(expr.left)===paramName&&isAddressZero(expr.right))||
      (exprIdentifier(expr.right)===paramName&&isAddressZero(expr.left)))){
      return 'nonzero';
    }
    if(expr.operator==='!='&&(
      (exprIdentifier(expr.left)===paramName&&expr.right?.type==='NumberLiteral'&&expr.right.number==='0')||
      (exprIdentifier(expr.right)===paramName&&expr.left?.type==='NumberLiteral'&&expr.left.number==='0'))){
      return 'gt_zero';
    }
    if((expr.operator==='>'&&exprIdentifier(expr.left)===paramName&&expr.right?.type==='NumberLiteral'&&expr.right.number==='0')||
       (expr.operator==='<'&&exprIdentifier(expr.right)===paramName&&expr.left?.type==='NumberLiteral'&&expr.left.number==='0')){
      return 'gt_zero';
    }
  }
  return null;
}

function collectParamConstraints(node:any,paramNames:Set<string>):Map<string,Set<'nonzero'|'gt_zero'|'contract'>> {
  const constraints=new Map<string,Set<'nonzero'|'gt_zero'|'contract'>>();
  const add=(p:string,c:'nonzero'|'gt_zero'|'contract')=>{
    let s=constraints.get(p);if(!s){s=new Set();constraints.set(p,s);}s.add(c);
  };
  const walk=(n:any,depth:number)=>{
    if(!n||typeof n!=='object'||depth>40)return;
    if(Array.isArray(n)){for(const item of n)walk(item,depth+1);return;}
    for(const p of paramNames){
      const c=isRequireZeroViolation(n,p);
      if(c)add(p,c);
    }
    for(const [k,v] of Object.entries(n))if(k!=='range'&&k!=='loc')walk(v,depth+1);
  };
  walk(node,0);
  return constraints;
}

function verifySafeSetupStatements(
  fnNode:any,chain:ContractEntry[],paramBinding:Map<string,string>,
  assignedState:Map<string,string>,
  authority:{owner:boolean;adminRole:boolean;adminTargetParam:string|null;ownableInitCalled:boolean;accessControlInitCalled:boolean},
  constraints:Map<string,Set<'nonzero'|'gt_zero'|'contract'>>,
  depth=0,visited=new Set<string>()
):boolean {
  if(!fnNode?.body||depth>6)return false;
  const statements:any[]=fnNode.body.statements||[];
  const localBindings=new Map(paramBinding);
  const allFns=new Map<string,any>();
  for(const entry of chain){
    for(const m of entry.contract.subNodes||[]){
      if(m.type==='FunctionDefinition'&&m.name&&!m.isConstructor&&m.body)allFns.set(m.name,m);
    }
  }
  const paramSet=new Set(paramBinding.keys());
  const foundConstraints=collectParamConstraints(fnNode.body,paramSet);
  for(const [p,cs] of foundConstraints){
    const boundKey=localBindings.get(p)||p;
    let existing=constraints.get(boundKey);if(!existing){existing=new Set();constraints.set(boundKey,existing);}
    for(const c of cs)existing.add(c);
  }
  for(const stmt of statements){
    if(stmt.type==='EmitStatement')continue;
    if(stmt.type==='ExpressionStatement'){
      const expr=stmt.expression;
      if(!expr)return false;
      if(expr.type==='FunctionCall'){
        const callee=exprIdentifier(expr.expression);
        if(!callee)return false;
        if(callee==='require')continue;
        if(callee==='__Ownable_init'||callee==='__Ownable_init_unchained'){
          authority.ownableInitCalled=true;
          continue;
        }
        if(callee==='__AccessControl_init'||callee==='__AccessControl_init_unchained'){
          authority.accessControlInitCalled=true;
          continue;
        }
        if(callee==='_setupRole'||callee==='_grantRole'){
          const roleArg=exprIdentifier(expr.arguments?.[0]);
          const targetArg=expr.arguments?.[1];
          if(roleArg==='DEFAULT_ADMIN_ROLE'){
            if(isMsgSender(targetArg)){authority.adminRole=true;}
            else {
              const pName=exprIdentifier(targetArg);
              if(pName&&localBindings.has(pName)){
                authority.adminRole=true;
                authority.adminTargetParam=localBindings.get(pName)!;
              }
            }
          }
          continue;
        }
        if(SAFE_OZ_INITS.has(callee))continue;
        // Recursive verification for internal __*_init* helpers
        if(/^__[A-Za-z0-9_]*init[A-Za-z0-9_]*$/.test(callee)){
          const helper=allFns.get(callee);
          if(!helper||visited.has(callee))return false;
          const helperParams:any[]=helper.parameters||[];
          if(helperParams.length!==(expr.arguments||[]).length)return false;
          const nextBinding=new Map<string,string>();
          for(let i=0;i<helperParams.length;i++){
            const hp=helperParams[i]?.name;
            const arg=expr.arguments[i];
            const argId=exprIdentifier(arg);
            if(hp&&argId&&localBindings.has(argId)){
              nextBinding.set(hp,localBindings.get(argId)!);
            } else if(hp&&arg?.type==='NumberLiteral'){
              nextBinding.set(hp,'literal:'+arg.number);
            }
          }
          const nextVisited=new Set(visited);nextVisited.add(callee);
          if(!verifySafeSetupStatements(helper,chain,nextBinding,assignedState,authority,constraints,depth+1,nextVisited))
            return false;
          continue;
        }
        return false;
      }
      if(expr.type==='BinaryOperation'&&expr.operator==='='){
        const lhs=exprIdentifier(expr.left);
        if(!lhs)return false;
        const rhs=expr.right;
        if(isMsgSender(rhs)){
          assignedState.set(lhs,'$account0');
          if(lhs==='owner'||lhs==='_owner')authority.owner=true;
          continue;
        }
        const rhsId=exprIdentifier(rhs);
        if(rhsId&&localBindings.has(rhsId)){
          assignedState.set(lhs,'param:'+localBindings.get(rhsId)!);
          continue;
        }
        if(rhs?.type==='FunctionCall'&&rhs.arguments?.length===1){
          const castArg=exprIdentifier(rhs.arguments[0]);
          if(castArg&&localBindings.has(castArg)){
            assignedState.set(lhs,'param:'+localBindings.get(castArg)!);
            continue;
          }
        }
        if(rhs?.type==='NumberLiteral'){assignedState.set(lhs,'literal:'+rhs.number);continue;}
        if(rhs?.type==='BooleanLiteral'){assignedState.set(lhs,'bool:'+String(rhs.value));continue;}
        return false;
      }
      return false;
    }
    return false;
  }
  return true;
}

interface VerifiedSetup {
  kind:'owner'|'admin';
  constructorArgs:Array<string|boolean>;
  initSignature:string|null;
  initArgs:Array<string|boolean>;
  initAdminParamIndex:number;
  initialValues:Map<string,string|boolean>;
  setupWitnesses:SourceWitness[];
}

function resolveVerifiedSetup(
  snapshot:SourceSnapshot,contract:any,chain:ContractEntry[],oz:Set<OzBaseProof['kind']>,
  localOwnables:ContractEntry[],menu:readonly SolidityProbeDeclaration[]
):VerifiedSetup|null {
  if(contract.kind&&contract.kind!=='contract')return null;
  const members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition');
  // Reject contracts with unimplemented abstract functions in own declarations
  if(functions.some(fn=>!fn.body))return null;

  const ctor=functions.find(n=>n.isConstructor);
  const initializer=functions.find(n=>n.name==='initialize'&&
    ['public','external'].includes(n.visibility)&&
    (n.modifiers||[]).some((m:any)=>m.name==='initializer'));
  // Collect all state variables across chain for inline initializer tracking
  const allStateVars=new Map<string,any>();
  for(const entry of [...chain].reverse()){
    for(const sv of (entry.contract.subNodes||[]).filter((n:any)=>n.type==='StateVariableDeclaration')){
      for(const v of sv.variables||[])if(v.name)allStateVars.set(v.name,v);
    }
  }

  const assignedState=new Map<string,string>();
  const constraints=new Map<string,Set<'nonzero'|'gt_zero'|'contract'>>();
  const authority={
    owner:oz.has('ownable'),
    adminRole:false,
    adminTargetParam:null as string|null,
    ownableInitCalled:false,
    accessControlInitCalled:false
  };

  let constructorArgs:Array<string|boolean>=[];
  const ctorParamNames:string[]=[];
  const ctorParamTypes:AbiScalarType[]=[];
  if(ctor){
    const cParams:any[]=ctor.parameters||[];
    const binding=new Map<string,string>();
    for(const p of cParams){
      const abi=canonicalAbiType(p.typeName);
      const scalar=classifyScalarType(abi);
      if(!scalar||!identifier.test(p.name||''))return null;
      ctorParamNames.push(p.name);ctorParamTypes.push(scalar);
      binding.set(p.name,'ctor:'+p.name);
    }
    if(!verifySafeSetupStatements(ctor,chain,binding,assignedState,authority,constraints))return null;
    for(const p of cParams){
      if(constraints.get('ctor:'+p.name)?.has('contract'))return null; // $contract unavailable in constructor
    }
  }

  let initSignature:string|null=null;
  const initParamNames:string[]=[];
  const initParamTypes:AbiScalarType[]=[];
  if(initializer){
    const iParams:any[]=initializer.parameters||[];
    const abiTypes:string[]=[];
    const binding=new Map<string,string>();
    for(const p of iParams){
      const abi=canonicalAbiType(p.typeName);
      const scalar=classifyScalarType(abi);
      if(!abi||!scalar||!identifier.test(p.name||''))return null;
      abiTypes.push(abi);
      initParamNames.push(p.name);initParamTypes.push(scalar);
      binding.set(p.name,'init:'+p.name);
    }
    if(!verifySafeSetupStatements(initializer,chain,binding,assignedState,authority,constraints))return null;
    initSignature=`initialize(${abiTypes.join(',')})`;
  } else if(functions.some(n=>(n.modifiers||[]).some((m:any)=>m.name==='initializer'))){
    // Has another initializer function name; don't guess.
    return null;
  }

  if(authority.ownableInitCalled&&(oz.has('ownable_upgradeable')||localOwnables.length>0)){
    authority.owner=true;
  }
  const kind:('owner'|'admin'|null)=authority.owner?'owner':
    (authority.adminRole&&(oz.has('access_control'))?'admin':null);
  if(!kind)return null;

  // For direct non-inherited owner, ensure owner() getter exists in menu
  if(kind==='owner'&&!oz.has('ownable')&&!oz.has('ownable_upgradeable')&&localOwnables.length===0){
    const ownerGetter=menu.find(m=>m.selector===contract.name+'.owner'&&m.operation==='call'&&m.inputs.length===0);
    if(!ownerGetter)return null;
  }

  if(authority.adminTargetParam&&constraints.get(authority.adminTargetParam)?.has('contract'))return null;
  const pickArg=(key:string,scalar:AbiScalarType):string|boolean=>{
    if(authority.adminTargetParam===key)return '$account0';
    if(scalar==='address')return constraints.get(key)?.has('contract')?'$contract':'$account2';
    if(scalar==='bool')return false;
    if(scalar==='string')return 'LOTUS-Test';
    return constraints.get(key)?.has('gt_zero')?'1':'0';
  };

  constructorArgs=ctorParamNames.map((n,i)=>pickArg('ctor:'+n,ctorParamTypes[i]));
  const initArgs=initParamNames.map((n,i)=>pickArg('init:'+n,initParamTypes[i]));

  const paramValueMap=new Map<string,string|boolean>();
  ctorParamNames.forEach((n,i)=>paramValueMap.set('ctor:'+n,constructorArgs[i]));
  initParamNames.forEach((n,i)=>paramValueMap.set('init:'+n,initArgs[i]));

  const initialValues=new Map<string,string|boolean>();
  for(const [varName,v] of allStateVars){
    if(v.isDeclaredConst||v.isImmutable)continue;
    const assigned=assignedState.get(varName);
    if(assigned){
      if(assigned==='$account0')initialValues.set(varName,'$account0');
      else if(assigned.startsWith('param:')){
        const val=paramValueMap.get(assigned.slice(6));
        if(val!==undefined)initialValues.set(varName,val);
      } else if(assigned.startsWith('literal:'))initialValues.set(varName,assigned.slice(8));
      else if(assigned.startsWith('bool:'))initialValues.set(varName,assigned.slice(5)==='true');
      continue;
    }
    if(v.expression){
      if(v.expression.type==='NumberLiteral')initialValues.set(varName,v.expression.number);
      else if(v.expression.type==='BooleanLiteral')initialValues.set(varName,v.expression.value);
      continue;
    }
    const scalar=classifyScalarType(canonicalAbiType(v.typeName));
    if(scalar==='address')initialValues.set(varName,ZERO_ADDRESS);
    else if(scalar==='uint')initialValues.set(varName,'0');
    else if(scalar==='bool')initialValues.set(varName,false);
    else if(scalar==='string')initialValues.set(varName,'');
  }

  const setupWitnesses:SourceWitness[]=[];
  if(ctor)setupWitnesses.push(witness(snapshot,ctor,contract.name+'.constructor'));
  if(initializer)setupWitnesses.push(witness(snapshot,initializer,contract.name+'.initialize'));
  for(const lo of localOwnables)setupWitnesses.push(witness(lo.snapshot,lo.contract,lo.contract.name));

  const initAdminParamIndex=authority.adminTargetParam?.startsWith('init:')
    ? initParamNames.indexOf(authority.adminTargetParam.slice(5))
    : -1;
  return {kind,constructorArgs,initSignature,initArgs,initAdminParamIndex,initialValues,setupWitnesses};
}

function hasAuthorizationGuard(fn:any,kind:'owner'|'admin',chain:ContractEntry[]):boolean {
  const mods:any[]=fn.modifiers||[];
  if(kind==='owner'&&mods.some(m=>m.name==='onlyOwner'))return true;
  if(kind==='admin'&&mods.some(m=>m.name==='onlyRole'&&m.arguments?.length===1&&
    exprIdentifier(m.arguments[0])==='DEFAULT_ADMIN_ROLE'))return true;
  // Also accept explicit AST require(msg.sender == owner/_owner) or require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender))
  const ownerNames=new Set<string>(['owner','_owner']);
  for(const e of chain){
    for(const sv of (e.contract.subNodes||[]).filter((n:any)=>n.type==='StateVariableDeclaration')){
      for(const v of sv.variables||[])if(v.name==='owner'||v.name==='_owner')ownerNames.add(v.name);
    }
  }
  let found=false;
  const walk=(n:any,depth:number)=>{
    if(found||!n||typeof n!=='object'||depth>32)return;
    if(Array.isArray(n)){for(const x of n)walk(x,depth+1);return;}
    if(n.type==='FunctionCall'&&exprIdentifier(n.expression)==='require'){
      const cond=n.arguments?.[0];
      if(kind==='owner'&&cond?.type==='BinaryOperation'&&cond.operator==='=='&&
        ((isMsgSender(cond.left)&&ownerNames.has(exprIdentifier(cond.right)||''))||
         (isMsgSender(cond.right)&&ownerNames.has(exprIdentifier(cond.left)||'')))){
        found=true;return;
      }
      if(kind==='admin'&&cond?.type==='FunctionCall'&&exprIdentifier(cond.expression)==='hasRole'&&
        exprIdentifier(cond.arguments?.[0])==='DEFAULT_ADMIN_ROLE'&&isMsgSender(cond.arguments?.[1])){
        found=true;return;
      }
    }
    for(const [k,v] of Object.entries(n))if(k!=='range'&&k!=='loc')walk(v,depth+1);
  };
  walk(fn.body,0);
  return found;
}

function findGetterForStateVar(varName:string,chain:ContractEntry[]):{signature:string;witnessNode?:{snapshot:SourceSnapshot;node:any}} | null {
  for(const entry of chain){
    for(const m of entry.contract.subNodes||[]){
      if(m.type==='StateVariableDeclaration'){
        for(const v of m.variables||[]){
          if(v.name===varName&&v.visibility==='public'&&!v.isDeclaredConst)return {signature:varName+'()'};
        }
      }
      if(m.type==='FunctionDefinition'&&m.name&&['public','external'].includes(m.visibility)&&
        m.stateMutability==='view'&&(m.parameters||[]).length===0&&m.body?.statements?.length===1){
        const st=m.body.statements[0];
        if(st.type==='ReturnStatement'&&exprIdentifier(st.expression)===varName){
          return {signature:m.name+'()',witnessNode:{snapshot:entry.snapshot,node:m}};
        }
      }
    }
  }
  return null;
}

function pickDifferentSetterValue(
  scalar:AbiScalarType,initial:string|boolean,requiresContract:boolean
):string|boolean|null {
  if(scalar==='address'){
    if(requiresContract)return initial==='$contract'?null:'$contract';
    return initial==='$account2'?'$account1':'$account2';
  }
  if(scalar==='bool')return typeof initial==='boolean'?!initial:true;
  if(scalar==='string')return initial==='LOTUS-Updated'?'LOTUS-Updated-2':'LOTUS-Updated';
  if(scalar==='uint'){
    return initial==='1'?'2':'1';
  }
  return null;
}

function checkRequireSafetyAndBounds(
  stmts:any[],paramNames:Set<string>,constants:Set<string>
):{safe:boolean;contractParams:Set<string>} {
  const contractParams=new Set<string>();
  for(const stmt of stmts){
    if(stmt.type!=='ExpressionStatement')continue;
    const expr=stmt.expression;
    if(expr?.type!=='FunctionCall'||exprIdentifier(expr.expression)!=='require')continue;
    // Allow simple require(...) predicates; reject external calls or mutable-state upper bounds
    let bad=false;
    const inspect=(n:any,depth:number)=>{
      if(bad||!n||typeof n!=='object'||depth>24)return;
      if(Array.isArray(n)){for(const x of n)inspect(x,depth+1);return;}
      if(n.type==='FunctionCall'){
        if(n.expression?.type==='MemberAccess'&&n.expression.memberName==='isContract'){
          const target=exprIdentifier(n.expression.expression);
          if(target&&paramNames.has(target)){contractParams.add(target);return;}
          bad=true;return;
        }
        if((n.expression?.type==='ElementaryTypeName'||n.expression?.type==='Identifier')&&n.expression.name==='address')return;
        if(exprIdentifier(n.expression)==='require'){}
        else {bad=true;return;}
      }
      if(n.type==='BinaryOperation'&&(n.operator==='<'||n.operator==='<=')){
        const rhsId=exprIdentifier(n.right);
        if(rhsId&&!constants.has(rhsId)&&!paramNames.has(rhsId)){bad=true;return;}
      }
      for(const [k,v] of Object.entries(n))if(k!=='range'&&k!=='loc')inspect(v,depth+1);
    };
    inspect(expr,0);
    if(bad)return {safe:false,contractParams};
  }
  return {safe:true,contractParams};
}


/**
 * An NFT burn needs a real pre-existing token. A single unauthorized burn
 * transaction can revert for a missing token even when authorization is broken.
 * Build the authorized mint prerequisite and compare independently against
 * the same existing token, only when the acquired source proves both bodies
 * and the inherited ownership/initializer fixture.
 */
function guardedErc721BurnExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(method!=='burn'||contract.kind!=='contract')return null;
  const {chain,oz,localOwnables}=resolveInheritance(snapshot,contract,sources);
  if(isAbstractContractNode(contract,chain))return null;
  const setup=resolveVerifiedSetup(snapshot,contract,chain,oz,localOwnables,menu);
  if(!setup||setup.kind!=='owner')return null;
  const functions=(contract.subNodes||[]).filter((fn:any)=>
    fn.type==='FunctionDefinition'&&fn.body&&
    ['public','external'].includes(fn.visibility));
  const types=(fn:any)=>(fn.parameters||[]).map((p:any)=>canonicalAbiType(p.typeName));
  const burn=functions.find((fn:any)=>fn.name==='burn'&&
    JSON.stringify(types(fn))===JSON.stringify(['uint256'])&&
    hasAuthorizationGuard(fn,'owner',chain));
  const mint=functions.find((fn:any)=>fn.name==='mint'&&
    JSON.stringify(types(fn))===JSON.stringify(['address','uint256'])&&
    hasAuthorizationGuard(fn,'owner',chain));
  if(!burn||!mint)return null;
  const sourceCall=(fn:any,callee:string,names:string[]):boolean=>{
    const stmts=fn.body?.statements||[];
    if(stmts.length!==1||stmts[0].type!=='ExpressionStatement')return false;
    const exp=stmts[0].expression;
    if(exp?.type!=='FunctionCall'||exprIdentifier(exp.expression)!==callee||
      (exp.arguments||[]).length!==names.length)return false;
    return exp.arguments.every((arg:any,i:number)=>
      arg.type==='Identifier'&&arg.name===names[i]);
  };
  const burnName=burn.parameters?.[0]?.name;
  const mintNames=(mint.parameters||[]).map((p:any)=>p.name);
  if(!identifier.test(burnName||'')||mintNames.length!==2||
    mintNames.some((name:string)=>!identifier.test(name))||
    !sourceCall(burn,'_burn',[burnName])||
    !sourceCall(mint,'_safeMint',mintNames))return null;
  const has=(selector:string,operation:'send'|'call',inputs:string[])=>
    menu.some(item=>item.selector===contract.name+'.'+selector&&
      item.operation===operation&&JSON.stringify(item.inputs)===JSON.stringify(inputs));
  // Inherited compiler ABI entries can be absent from the source-index menu:
  // the acquired NFT source declares only its own functions. Admit the known
  // inherited getters solely when BOTH the canonical OpenZeppelin import and
  // corresponding explicit Solidity base contract are source-proven.
  const inheritedNames=new Set<string>((contract.baseContracts||[])
    .map((base:any)=>String(base.baseName?.namePath||'')));
  const inheritedOwnerGetter=oz.has('ownable_upgradeable')&&
    inheritedNames.has('OwnableUpgradeable');
  const inheritedBalanceGetter=oz.has('erc721')&&
    [...inheritedNames].some(name=>/^ERC721(?:URIStorage)?Upgradeable$/.test(name));
  if(!has('burn','send',['uint256'])||!has('mint','send',['address','uint256'])||
    !(has('balanceOf','call',['address'])||inheritedBalanceGetter)||
    !(has('owner','call',[])||inheritedOwnerGetter))return null;
  const steps:SoliditySequence['steps']=[];
  if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,
    args:setup.initArgs,sender:0,requiredSetup:true});
  steps.push(
    {operation:'call',function:'owner()',args:[],expect:'$account0'},
    {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
    {operation:'send',function:'mint(address,uint256)',args:['$account2','1'],
      sender:0,requiredSetup:true},
    {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'1'},
    {operation:'send',function:'burn(uint256)',args:['1'],sender:1,expectRevert:true},
    {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'1'},
    {operation:'send',function:'burn(uint256)',args:['1'],sender:0},
    {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
  );
  return {hypothesis:'An unauthorized caller cannot burn an existing source-minted NFT; '+
      'the initialized owner can burn that exact token.',
    property:'source-proven ERC721 owner-gated burn and balance transition',
    sequence:{constructorArgs:setup.constructorArgs,steps},
    witnesses:[...setup.setupWitnesses,
      witness(snapshot,mint,contract.name+'.mint(address,uint256)'),
      witness(snapshot,burn,contract.name+'.burn(uint256)')]};
}

function broadenedAuthorizationExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]} | null {
  const {chain,oz,localOwnables}=resolveInheritance(snapshot,contract,sources);
  const setup=resolveVerifiedSetup(snapshot,contract,chain,oz,localOwnables,menu);
  if(!setup)return null;

  const members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition'&&n.name===method&&
    ['public','external'].includes(n.visibility)&&!['view','pure'].includes(n.stateMutability||'')&&n.body);
  if(!functions.length)return null;

  const constants=new Set<string>();
  const mappings=new Map<string,{keyType:AbiScalarType;valueType:AbiScalarType}>();
  for(const e of chain){
    for(const sv of (e.contract.subNodes||[]).filter((n:any)=>n.type==='StateVariableDeclaration')){
      for(const v of sv.variables||[]){
        if(!v.name)continue;
        if(v.isDeclaredConst)constants.add(v.name);
        if(v.visibility==='public'&&v.typeName?.type==='Mapping'){
          const kt=classifyScalarType(canonicalAbiType(v.typeName.keyType));
          const vt=classifyScalarType(canonicalAbiType(v.typeName.valueType));
          if(kt==='address'&&vt)mappings.set(v.name,{keyType:kt,valueType:vt});
        }
      }
    }
  }

  const baseSteps:SoliditySequence['steps']=[];
  if(setup.initSignature){
    baseSteps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
  }
  if(setup.kind==='owner'){
    baseSteps.push({operation:'call',function:'owner()',args:[],expect:'$account0'});
  } else {
    baseSteps.push({operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account0'],expect:true});
  }

  for(const fn of functions){
    if(!hasAuthorizationGuard(fn,setup.kind,chain))continue;
    const stmts:any[]=fn.body?.statements||[];
    const params:any[]=fn.parameters||[];
    const paramNames=new Set<string>(params.map((p:any)=>p.name).filter((n:any)=>identifier.test(n||'')));

    // Only allow require, emit, single assignment/call, and optional literal return
    let unsupportedStmt=false;
    const bodyStmts:any[]=[];
    for(const st of stmts){
      if(st.type==='EmitStatement')continue;
      if(st.type==='ReturnStatement'){
        if(st.expression?.type==='BooleanLiteral'||st.expression?.type==='NumberLiteral')continue;
        unsupportedStmt=true;break;
      }
      if(st.type==='ExpressionStatement'){
        const expr=st.expression;
        if(expr?.type==='FunctionCall'&&exprIdentifier(expr.expression)==='require')continue;
        bodyStmts.push(st);
        continue;
      }
      unsupportedStmt=true;break;
    }
    if(unsupportedStmt||bodyStmts.length!==1)continue;
    const {safe,contractParams}=checkRequireSafetyAndBounds(stmts,paramNames,constants);
    if(!safe)continue;

    const actionExpr=bodyStmts[0].expression;

    // Pattern A: 0-arg pause() / unpause() on Pausable
    if(params.length===0&&oz.has('pausable')&&actionExpr?.type==='FunctionCall'){
      const callee=exprIdentifier(actionExpr.expression);
      if(callee==='_pause'&&(actionExpr.arguments||[]).length===0){
        return {
          hypothesis:'Non-owner must not pause '+contract.name+'; initialized owner may.',
          property:'source-proven Pausable authorization',
          sequence:{constructorArgs:setup.constructorArgs,steps:[
            ...baseSteps,
            {operation:'call',function:'paused()',args:[],expect:false},
            {operation:'send',function:method+'()',args:[],sender:1,expectRevert:true},
            {operation:'call',function:'paused()',args:[],expect:false},
            {operation:'send',function:method+'()',args:[],sender:0},
            {operation:'call',function:'paused()',args:[],expect:true}
          ]},
          witnesses:[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)]
        };
      }
      if(callee==='_unpause'&&(actionExpr.arguments||[]).length===0){
        const pauseFn=members.find(n=>n.type==='FunctionDefinition'&&n.name==='pause'&&
          ['public','external'].includes(n.visibility)&&(n.parameters||[]).length===0&&
          hasAuthorizationGuard(n,setup.kind,chain));
        if(pauseFn){
          return {
            hypothesis:'Non-owner must not unpause '+contract.name+'; initialized owner may.',
            property:'source-proven Pausable authorization',
            sequence:{constructorArgs:setup.constructorArgs,steps:[
              ...baseSteps,
              {operation:'send',function:'pause()',args:[],sender:0},
              {operation:'call',function:'paused()',args:[],expect:true},
              {operation:'send',function:method+'()',args:[],sender:1,expectRevert:true},
              {operation:'call',function:'paused()',args:[],expect:true},
              {operation:'send',function:method+'()',args:[],sender:0},
              {operation:'call',function:'paused()',args:[],expect:false}
            ]},
            witnesses:[...setup.setupWitnesses,witness(snapshot,pauseFn,contract.name+'.pause'),witness(snapshot,fn,contract.name+'.'+method)]
          };
        }
      }
    }

    // Pattern B: 1-arg scalar/address/string/bool state variable setter
    if(params.length===1&&actionExpr?.type==='BinaryOperation'&&actionExpr.operator==='='){
      const param=params[0];
      const abi=canonicalAbiType(param.typeName);
      const scalar=classifyScalarType(abi);
      const varName=exprIdentifier(actionExpr.left);
      if(!abi||!scalar||!identifier.test(param.name||'')||!varName)continue;
      let rhsMatch=exprIdentifier(actionExpr.right)===param.name;
      if(!rhsMatch&&actionExpr.right?.type==='FunctionCall'&&actionExpr.right.arguments?.length===1){
        rhsMatch=exprIdentifier(actionExpr.right.arguments[0])===param.name;
      }
      if(!rhsMatch)continue;
      const getter=findGetterForStateVar(varName,chain);
      if(!getter)continue;
      const initial=setup.initialValues.get(varName);
      if(initial===undefined)continue;
      const nextVal=pickDifferentSetterValue(scalar,initial,contractParams.has(param.name));
      if(nextVal===null)continue;
      const fnSig=`${method}(${abi})`;
      const witnesses=[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)];
      if(getter.witnessNode)witnesses.push(witness(getter.witnessNode.snapshot,getter.witnessNode.node,contract.name+'.'+getter.signature));
      return {
        hypothesis:`Unauthorized caller must not update ${varName} via ${contract.name}.${method}; authorized ${setup.kind} may.`,
        property:`source-proven ${setup.kind}-gated state transition`,
        sequence:{constructorArgs:setup.constructorArgs,steps:[
          ...baseSteps,
          {operation:'call',function:getter.signature,args:[],expect:initial},
          {operation:'send',function:fnSig,args:[nextVal],sender:1,expectRevert:true},
          {operation:'call',function:getter.signature,args:[],expect:initial},
          {operation:'send',function:fnSig,args:[nextVal],sender:0},
          {operation:'call',function:getter.signature,args:[],expect:nextVal}
        ]},
        witnesses
      };
    }

    // Pattern C: 2-arg public mapping(address => bool|uint*|address) setter
    if(params.length===2&&actionExpr?.type==='BinaryOperation'&&actionExpr.operator==='='){
      const p0=params[0],p1=params[1];
      const abi0=canonicalAbiType(p0.typeName),abi1=canonicalAbiType(p1.typeName);
      const s0=classifyScalarType(abi0),s1=classifyScalarType(abi1);
      if(s0!=='address'||!s1||!abi0||!abi1||!identifier.test(p0.name||'')||!identifier.test(p1.name||''))continue;
      if(actionExpr.left?.type!=='IndexAccess')continue;
      const mapName=exprIdentifier(actionExpr.left.base);
      if(!mapName||!mappings.has(mapName))continue;
      const idx=actionExpr.left.index;
      const idxMatches=exprIdentifier(idx)===p0.name||(idx?.type==='FunctionCall'&&
        (idx.expression?.type==='ElementaryTypeName'||idx.expression?.type==='Identifier')&&idx.expression.name==='address'&&
        exprIdentifier(idx.arguments?.[0])===p0.name);
      if(!idxMatches)continue;
      let valMatches=exprIdentifier(actionExpr.right)===p1.name;
      if(!valMatches&&actionExpr.right?.type==='FunctionCall'&&actionExpr.right.arguments?.length===1){
        valMatches=exprIdentifier(actionExpr.right.arguments[0])===p1.name;
      }
      if(!valMatches)continue;
      const mapInfo=mappings.get(mapName)!;
      const defaultVal=mapInfo.valueType==='bool'?false:mapInfo.valueType==='address'?ZERO_ADDRESS:'0';
      const keyVal=contractParams.has(p0.name)?'$contract':'$account2';
      const nextVal=pickDifferentSetterValue(mapInfo.valueType,defaultVal,contractParams.has(p1.name));
      if(nextVal===null)continue;
      const fnSig=`${method}(${abi0},${abi1})`;
      return {
        hypothesis:`Unauthorized caller must not update ${mapName} via ${contract.name}.${method}; authorized ${setup.kind} may.`,
        property:`source-proven ${setup.kind}-gated mapping update`,
        sequence:{constructorArgs:setup.constructorArgs,steps:[
          ...baseSteps,
          {operation:'call',function:`${mapName}(address)`,args:[keyVal],expect:defaultVal},
          {operation:'send',function:fnSig,args:[keyVal,nextVal],sender:1,expectRevert:true},
          {operation:'call',function:`${mapName}(address)`,args:[keyVal],expect:defaultVal},
          {operation:'send',function:fnSig,args:[keyVal,nextVal],sender:0},
          {operation:'call',function:`${mapName}(address)`,args:[keyVal],expect:nextVal}
        ]},
        witnesses:[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)]
      };
    }

    // Pattern D: 2-arg ERC20 _mint(to, amount) or ERC721 _safeMint/_mint(to, tokenId)
    if(params.length===2&&actionExpr?.type==='FunctionCall'){
      const callee=exprIdentifier(actionExpr.expression);
      const p0=params[0],p1=params[1];
      const abi0=canonicalAbiType(p0.typeName),abi1=canonicalAbiType(p1.typeName);
      if(abi0!=='address'||!/^uint(?:[0-9]{1,3})?$/.test(abi1||'')||!identifier.test(p0.name||'')||!identifier.test(p1.name||''))continue;
      if(actionExpr.arguments?.length!==2||
        exprIdentifier(actionExpr.arguments[0])!==p0.name||
        exprIdentifier(actionExpr.arguments[1])!==p1.name)continue;
      if(callee==='_mint'&&oz.has('erc20')){
        const fnSig=`${method}(${abi0},${abi1})`;
        return {
          hypothesis:`Unauthorized caller must not mint tokens via ${contract.name}.${method}; authorized ${setup.kind} may.`,
          property:`source-proven ${setup.kind}-gated ERC20 mint`,
          sequence:{constructorArgs:setup.constructorArgs,steps:[
            ...baseSteps,
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
            {operation:'send',function:fnSig,args:['$account2','100'],sender:1,expectRevert:true},
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
            {operation:'send',function:fnSig,args:['$account2','100'],sender:0},
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'100'}
          ]},
          witnesses:[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)]
        };
      }
      if((callee==='_safeMint'||callee==='_mint')&&oz.has('erc721')){
        const fnSig=`${method}(${abi0},${abi1})`;
        return {
          hypothesis:`Unauthorized caller must not mint NFTs via ${contract.name}.${method}; authorized ${setup.kind} may.`,
          property:`source-proven ${setup.kind}-gated ERC721 mint`,
          sequence:{constructorArgs:setup.constructorArgs,steps:[
            ...baseSteps,
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
            {operation:'send',function:fnSig,args:['$account2','1'],sender:1,expectRevert:true},
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'},
            {operation:'send',function:fnSig,args:['$account2','1'],sender:0},
            {operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'1'},
            {operation:'call',function:'ownerOf(uint256)',args:['1'],expect:'$account2'}
          ]},
          witnesses:[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)]
        };
      }
    }
  }
  return null;
}

function hasAstPrimitive(node:any):{selfdestruct:boolean;delegatecall:boolean;txOrigin:boolean} {
  const result={selfdestruct:false,delegatecall:false,txOrigin:false};
  const walk=(n:any,depth:number)=>{
    if(!n||typeof n!=='object'||depth>40)return;
    if(Array.isArray(n)){for(const x of n)walk(x,depth+1);return;}
    if(n.type==='MemberAccess'&&n.memberName==='origin'&&
      n.expression?.type==='Identifier'&&n.expression.name==='tx'){
      result.txOrigin=true;
    }
    if(n.type==='FunctionCall'){
      const id=exprIdentifier(n.expression);
      if(id==='selfdestruct'||id==='suicide')result.selfdestruct=true;
      if(n.expression?.type==='MemberAccess'&&n.expression.memberName==='delegatecall'){
        result.delegatecall=true;
      }
    }
    for(const [k,v] of Object.entries(n))if(k!=='range'&&k!=='loc')walk(v,depth+1);
  };
  walk(node,0);
  return result;
}

type SolidityArgValue = Extract<SoliditySequence['steps'][number], { operation: 'send' }>['args'][number];
function defaultArgsForTypes(abiTypes:string[]):SolidityArgValue[]|null {
  const values:SolidityArgValue[]=[];
  for(const t of abiTypes){
    const fixed=t.match(/^(.*)\[(\d+)\]$/);
    if(fixed){
      const count=Number(fixed[2]);if(count>8)return null;
      const one=defaultArgsForTypes([fixed[1]]);
      const elem=one?.[0];
      if(typeof elem!=='string'&&typeof elem!=='boolean')return null;
      values.push(Array.from({length:count},()=>elem));continue;
    }
    if(/\[\]$/.test(t)){values.push([]);continue;}
    if(/^u?int(?:[0-9]{1,3})?$/.test(t)){values.push('7');continue;}
    if(t==='bool'){values.push(true);continue;}
    if(t==='address'||t==='address payable'){values.push('$account2');continue;}
    if(t==='string'){values.push('LOTUS-Test');continue;}
    if(t==='bytes'){values.push('0x4142');continue;}
    const sized=t.match(/^bytes([1-9]|[12][0-9]|3[012])$/);
    if(sized){values.push('0x'+'41'.repeat(Number(sized[1])));continue;}
    return null;
  }
  return values;
}

function initializeGuardExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(method!=='initialize')return null;
  if(contract.kind&&contract.kind!=='contract')return null;
  const members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition');
  if(functions.some(fn=>!fn.body))return null;
  const initFn=functions.find(n=>n.name==='initialize'&&
    ['public','external'].includes(n.visibility)&&
    !['view','pure'].includes(n.stateMutability||'')&&n.body);
  if(!initFn)return null;
  const {chain,oz,localOwnables}=resolveInheritance(snapshot,contract,sources);
  const setup=resolveVerifiedSetup(snapshot,contract,chain,oz,localOwnables,menu);
  let kind:'owner'|'admin'|null=setup?.kind||null;
  let constructorArgs=setup?.constructorArgs||[];
  let initSignature=setup?.initSignature||null;
  let initArgs=setup?.initArgs||[];
  let initAdminParamIndex=setup?.initAdminParamIndex??-1;
  let setupWitnesses=setup?.setupWitnesses||[];

  // Also support initialize() missing the `initializer` modifier when authority setup is source-proven.
  if(!setup){
    const ctor=functions.find(n=>n.isConstructor);
    const otherInit=functions.some(n=>n!==initFn&&(n.modifiers||[]).some((m:any)=>m.name==='initializer'));
    if(otherInit)return null;
    const assignedState=new Map<string,string>();
    const constraints=new Map<string,Set<'nonzero'|'gt_zero'|'contract'>>();
    const authority={
      owner:oz.has('ownable'),
      adminRole:false,
      adminTargetParam:null as string|null,
      ownableInitCalled:false,
      accessControlInitCalled:false
    };
    const ctorParamNames:string[]=[];
    const ctorParamTypes:AbiScalarType[]=[];
    if(ctor){
      const cParams:any[]=ctor.parameters||[];
      const binding=new Map<string,string>();
      for(const p of cParams){
        const abi=canonicalAbiType(p.typeName);
        const scalar=classifyScalarType(abi);
        if(!scalar||!identifier.test(p.name||''))return null;
        ctorParamNames.push(p.name);ctorParamTypes.push(scalar);
        binding.set(p.name,'ctor:'+p.name);
      }
      if(!verifySafeSetupStatements(ctor,chain,binding,assignedState,authority,constraints))return null;
      for(const p of cParams){
        if(constraints.get('ctor:'+p.name)?.has('contract'))return null;
      }
    }
    const iParams:any[]=initFn.parameters||[];
    const abiTypes:string[]=[];
    const initParamNames:string[]=[];
    const initParamTypes:AbiScalarType[]=[];
    const binding=new Map<string,string>();
    for(const p of iParams){
      const abi=canonicalAbiType(p.typeName);
      const scalar=classifyScalarType(abi);
      if(!abi||!scalar||!identifier.test(p.name||''))return null;
      abiTypes.push(abi);
      initParamNames.push(p.name);initParamTypes.push(scalar);
      binding.set(p.name,'init:'+p.name);
    }
    if(!verifySafeSetupStatements(initFn,chain,binding,assignedState,authority,constraints))return null;
    if(authority.ownableInitCalled&&(oz.has('ownable_upgradeable')||localOwnables.length>0)){
      authority.owner=true;
    }
    const hasOwnerGetter=!!menu.find(m=>m.selector===contract.name+'.owner'&&m.operation==='call'&&m.inputs.length===0);
    const provenOwner=authority.owner&&(oz.has('ownable')||oz.has('ownable_upgradeable')||localOwnables.length>0||hasOwnerGetter);
    const provenAdmin=authority.adminRole&&oz.has('access_control');
    kind=provenOwner?'owner':provenAdmin?'admin':null;
    if(!kind)return null;
    if(authority.adminTargetParam&&constraints.get(authority.adminTargetParam)?.has('contract'))return null;
    const pickArg=(key:string,scalar:AbiScalarType):string|boolean=>{
      if(authority.adminTargetParam===key)return '$account0';
      if(scalar==='address')return constraints.get(key)?.has('contract')?'$contract':'$account2';
      if(scalar==='bool')return false;
      if(scalar==='string')return 'LOTUS-Test';
      return constraints.get(key)?.has('gt_zero')?'1':'0';
    };
    constructorArgs=ctorParamNames.map((n,i)=>pickArg('ctor:'+n,ctorParamTypes[i]));
    initArgs=initParamNames.map((n,i)=>pickArg('init:'+n,initParamTypes[i]));
    initSignature=`initialize(${abiTypes.join(',')})`;
    initAdminParamIndex=authority.adminTargetParam?.startsWith('init:')
      ? initParamNames.indexOf(authority.adminTargetParam.slice(5))
      : -1;
    setupWitnesses=[
      ...(ctor?[witness(snapshot,ctor,contract.name+'.constructor')]:[]),
      witness(snapshot,initFn,contract.name+'.initialize'),
      ...localOwnables.map(lo=>witness(lo.snapshot,lo.contract,lo.contract.name))
    ];
  }
  if(!kind||!initSignature)return null;
  const attackerArgs=[...initArgs];
  if(initAdminParamIndex>=0)attackerArgs[initAdminParamIndex]='$account1';
  const checkCall:SoliditySequence['steps'][number]=kind==='owner'
    ? {operation:'call',function:'owner()',args:[],expect:'$account0'}
    : {operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account0'],expect:true};
  return {
    hypothesis:`Unauthorized caller must not re-initialize ${contract.name}.initialize once initialized; initial ${kind} authority must remain bound to deployer.`,
    property:'source-proven re-initialization guard',
    sequence:{constructorArgs,steps:[
      {operation:'send',function:initSignature,args:initArgs,sender:0},
      checkCall,
      {operation:'send',function:initSignature,args:attackerArgs,sender:1,expectRevert:true},
      checkCall
    ]},
    witnesses:[...setupWitnesses,witness(snapshot,initFn,contract.name+'.initialize')]
  };
}

function authorityTransferExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(!['transferOwnership','renounceOwnership','grantRole','claimOwnership'].includes(method))return null;
  const {chain,oz,localOwnables}=resolveInheritance(snapshot,contract,sources);
  const setup=resolveVerifiedSetup(snapshot,contract,chain,oz,localOwnables,menu);
  if(!setup)return null;
  const abiEntry=menu.find(m=>m.selector===`${contract.name}.${method}`&&m.operation==='send');
  if(!abiEntry)return null;

  let declaredFn:{snapshot:SourceSnapshot;node:any}|null=null;
  for(const entry of chain){
    const fn=(entry.contract.subNodes||[]).find((n:any)=>
      n.type==='FunctionDefinition'&&n.name===method&&
      ['public','external'].includes(n.visibility)&&
      !['view','pure'].includes(n.stateMutability||'')&&n.body&&
      JSON.stringify((n.parameters||[]).map((p:any)=>canonicalAbiType(p.typeName)))===JSON.stringify(abiEntry.inputs));
    if(fn){declaredFn={snapshot:entry.snapshot,node:fn};break;}
  }

  if(declaredFn){
    if(method==='claimOwnership'){
      const claimBody=body(declaredFn.snapshot.content,declaredFn.node);
      // The actual BoringOwnable source uses _pendingOwner and a local
      // __pendingOwner alias. Both identities are linked by an exact source
      // assignment; a bare same-name method must not count as a guard.
      const pendingAliases=[...claimBody.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*_?pendingOwner\b/g)].map(m=>m[1]);
      const targets=['pendingOwner','_pendingOwner',...pendingAliases];
      const checksPending=targets.some(t=>new RegExp(`\\bmsg\\.sender\\s*==\\s*${t}\\b|\\b${t}\\s*==\\s*msg\\.sender\\b`).test(claimBody));
      if(!checksPending)return null;
    } else if(!hasAuthorizationGuard(declaredFn.node,setup.kind,chain))return null;
  } else {
    const ozOwnerProven=setup.kind==='owner'&&(oz.has('ownable')||oz.has('ownable_upgradeable'))&&
      (method==='transferOwnership'||method==='renounceOwnership');
    const ozAdminProven=setup.kind==='admin'&&oz.has('access_control')&&method==='grantRole';
    if(!ozOwnerProven&&!ozAdminProven)return null;
  }

  const baseSteps:SoliditySequence['steps']=[];
  if(setup.initSignature)baseSteps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
  if(setup.kind==='owner')baseSteps.push({operation:'call',function:'owner()',args:[],expect:'$account0'});
  else baseSteps.push({operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account0'],expect:true});

  const witnesses=[...setup.setupWitnesses];
  if(declaredFn)witnesses.push(witness(declaredFn.snapshot,declaredFn.node,contract.name+'.'+method));

  const hasPendingOwner=menu.some(m=>m.selector===`${contract.name}.pendingOwner`&&m.operation==='call'&&m.inputs.length===0);

  if(setup.kind==='owner'&&method==='transferOwnership'&&
    JSON.stringify(abiEntry.inputs)===JSON.stringify(['address'])){
    return {
      hypothesis:`Unauthorized caller must not transfer ${contract.name} ownership; current owner may.`,
      property:'source-proven owner authority transfer',
      sequence:{constructorArgs:setup.constructorArgs,steps:[
        ...baseSteps,
        {operation:'send',function:'transferOwnership(address)',args:['$account1'],sender:1,expectRevert:true},
        {operation:'call',function:'owner()',args:[],expect:'$account0'},
        {operation:'send',function:'transferOwnership(address)',args:['$account2'],sender:0},
        ...(hasPendingOwner
          ? [{operation:'call' as const,function:'pendingOwner()',args:[],expect:'$account2'}]
          : [{operation:'call' as const,function:'owner()',args:[],expect:'$account2'}])
      ]},
      witnesses
    };
  }
  if(setup.kind==='owner'&&method==='transferOwnership'&&
    JSON.stringify(abiEntry.inputs)===JSON.stringify(['address','bool','bool'])){
    return {
      hypothesis:`Unauthorized caller must not transfer ${contract.name} ownership (BoringOwnable); current owner may.`,
      property:'source-proven BoringOwnable authority transfer',
      sequence:{constructorArgs:setup.constructorArgs,steps:[
        ...baseSteps,
        {operation:'send',function:'transferOwnership(address,bool,bool)',args:['$account1',true,false],sender:1,expectRevert:true},
        {operation:'call',function:'owner()',args:[],expect:'$account0'},
        {operation:'send',function:'transferOwnership(address,bool,bool)',args:['$account2',true,false],sender:0},
        {operation:'call',function:'owner()',args:[],expect:'$account2'}
      ]},
      witnesses
    };
  }
  if(setup.kind==='owner'&&method==='claimOwnership'&&abiEntry.inputs.length===0&&hasPendingOwner){
    const boringTransfer=menu.find(m=>m.selector===`${contract.name}.transferOwnership`&&m.operation==='send'&&
      JSON.stringify(m.inputs)===JSON.stringify(['address','bool','bool']));
    const twoStepTransfer=menu.find(m=>m.selector===`${contract.name}.transferOwnership`&&m.operation==='send'&&
      JSON.stringify(m.inputs)===JSON.stringify(['address']));
    const initiateStep:SoliditySequence['steps'][number]|null=boringTransfer
      ? {operation:'send',function:'transferOwnership(address,bool,bool)',args:['$account2',false,false],sender:0,requiredSetup:true}
      : twoStepTransfer
        ? {operation:'send',function:'transferOwnership(address)',args:['$account2'],sender:0,requiredSetup:true}
        : null;
    if(initiateStep){
      return {
        hypothesis:`Unauthorized caller ($account1) must not claim pending ${contract.name} ownership; designated pendingOwner ($account2) may.`,
        property:'source-proven two-step ownership claim authorization',
        sequence:{constructorArgs:setup.constructorArgs,steps:[
          ...baseSteps,
          initiateStep,
          {operation:'call',function:'pendingOwner()',args:[],expect:'$account2'},
          {operation:'send',function:'claimOwnership()',args:[],sender:1,expectRevert:true},
          {operation:'call',function:'owner()',args:[],expect:'$account0'},
          {operation:'call',function:'pendingOwner()',args:[],expect:'$account2'},
          {operation:'send',function:'claimOwnership()',args:[],sender:2},
          {operation:'call',function:'owner()',args:[],expect:'$account2'},
          {operation:'call',function:'pendingOwner()',args:[],expect:ZERO_ADDRESS}
        ]},
        witnesses
      };
    }
  }
  if(setup.kind==='owner'&&method==='renounceOwnership'&&abiEntry.inputs.length===0){
    return {
      hypothesis:`Unauthorized caller must not renounce ${contract.name} ownership; current owner may.`,
      property:'source-proven owner authority renunciation',
      sequence:{constructorArgs:setup.constructorArgs,steps:[
        ...baseSteps,
        {operation:'send',function:'renounceOwnership()',args:[],sender:1,expectRevert:true},
        {operation:'call',function:'owner()',args:[],expect:'$account0'},
        {operation:'send',function:'renounceOwnership()',args:[],sender:0},
        {operation:'call',function:'owner()',args:[],expect:ZERO_ADDRESS}
      ]},
      witnesses
    };
  }
  if(setup.kind==='admin'&&method==='grantRole'&&
    JSON.stringify(abiEntry.inputs)===JSON.stringify(['bytes32','address'])){
    return {
      hypothesis:`Unauthorized caller must not grant ${contract.name} admin role; default admin may.`,
      property:'source-proven AccessControl role grant',
      sequence:{constructorArgs:setup.constructorArgs,steps:[
        ...baseSteps,
        {operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account2'],expect:false},
        {operation:'send',function:'grantRole(bytes32,address)',args:[ZERO_BYTES32,'$account2'],sender:1,expectRevert:true},
        {operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account2'],expect:false},
        {operation:'send',function:'grantRole(bytes32,address)',args:[ZERO_BYTES32,'$account2'],sender:0},
        {operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account2'],expect:true}
      ]},
      witnesses
    };
  }
  return null;
}

function privilegedPrimitiveGuardExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[],
  staticLeads?:readonly StaticLeadHint[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  const members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition'&&n.name===method&&
    ['public','external'].includes(n.visibility)&&!['view','pure'].includes(n.stateMutability||'')&&n.body);
  if(!functions.length)return null;
  const {chain,oz,localOwnables}=resolveInheritance(snapshot,contract,sources);
  const setup=resolveVerifiedSetup(snapshot,contract,chain,oz,localOwnables,menu);
  if(!setup)return null;

  const baseSteps:SoliditySequence['steps']=[];
  if(setup.initSignature)baseSteps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
  const authorityCheck:SoliditySequence['steps'][number]=setup.kind==='owner'
    ? {operation:'call',function:'owner()',args:[],expect:'$account0'}
    : {operation:'call',function:'hasRole(bytes32,address)',args:[ZERO_BYTES32,'$account0'],expect:true};
  baseSteps.push(authorityCheck);

  for(const fn of functions){
    const params:any[]=fn.parameters||[];
    if(params.length>3)continue;
    const abiTypes:string[]=[];
    const paramNames=new Set<string>();
    let badParam=false;
    for(const p of params){
      const abi=canonicalAbiType(p.typeName);
      if(!abi||!identifier.test(p.name||'')){badParam=true;break;}
      abiTypes.push(abi);
      paramNames.add(p.name);
    }
    if(badParam)continue;
    const callArgs=defaultArgsForTypes(abiTypes);
    if(!callArgs)continue;

    const primitives=hasAstPrimitive(fn.body);
    const matchingLeads=(staticLeads||[]).filter(lead=>{
      if(lead.path!==snapshot.path||!fn.loc)return false;
      return lead.line>=fn.loc.start.line&&lead.line<=fn.loc.end.line;
    });
    const hasGuard=hasAuthorizationGuard(fn,setup.kind,chain);
    const hasDangerPrimitive=primitives.selfdestruct||primitives.delegatecall||primitives.txOrigin;
    if(!hasDangerPrimitive&&!(hasGuard&&matchingLeads.length))continue;
    if(!hasGuard&&!hasDangerPrimitive)continue;

    const constraints=collectParamConstraints(fn.body,paramNames);
    const args=params.map((p:any,i:number)=>{
      const c=constraints.get(p.name);
      if(abiTypes[i]==='address'&&c?.has('contract'))return '$contract';
      return callArgs[i];
    });

    const tags=[
      ...(primitives.selfdestruct?['selfdestruct']:[]),
      ...(primitives.delegatecall?['delegatecall']:[]),
      ...(primitives.txOrigin?['tx.origin']:[]),
      ...matchingLeads.map(l=>l.rule)
    ];
    const uniqueTags=[...new Set(tags)].slice(0,3).join(', ');
    const fnSig=`${method}(${abiTypes.join(',')})`;
    const preservePostCheck=hasGuard||!primitives.selfdestruct;
    return {
      hypothesis:`Unauthorized caller ($account1) must not trigger privileged primitive (${uniqueTags}) via ${contract.name}.${method}; contract authority must hold.`,
      property:`source-proven privileged primitive authorization (${uniqueTags})`,
      sequence:{constructorArgs:setup.constructorArgs,steps:[
        ...baseSteps,
        {operation:'send',function:fnSig,args,sender:1,expectRevert:true},
        ...(preservePostCheck?[authorityCheck]:[])
      ]},
      witnesses:[...setup.setupWitnesses,witness(snapshot,fn,contract.name+'.'+method)]
    };
  }
  return null;
}


function isTestOrMockPath(path:string):boolean {
  const norm = path.replace(/\\/g, '/');
  return /(?:^|\/)(?:mocks?|tests?|__tests__|fixtures?|interfaces|echidna|fuzz|harness)(?:\/|$)/i.test(norm) ||
    /(?:^|\/)(?:Dummy|Echidna|Mock|Test|Fuzz|Harness)[A-Z_][A-Za-z0-9_]*\.sol$/.test(norm) ||
    /(?:Mock|Mocks|Test|Tests|Echidna|Fuzz|Harness|Spec)\.sol$/.test(norm) ||
    /\.t\.sol$/i.test(norm);
}

/** ABI argument identity is necessary for overload-safe abstract fulfillment.
 * Public state variables generate Solidity getters even though there is no
 * FunctionDefinition AST body for them.
 */
function canonicalShapeType(node:any):string {
  if(!node)return '';
  if(node.type==='ElementaryTypeName'){
    const name=String(node.name||'');
    return name==='uint'?'uint256':name==='int'?'int256':name==='address payable'?'address':name;
  }
  if(node.type==='UserDefinedTypeName')return canonicalAbiType(node)||'';
  if(node.type==='ArrayTypeName'){
    const base=canonicalShapeType(node.baseTypeName);
    const literal=node.length?.number;
    return base+'['+(literal===undefined?'':literal)+']';
  }
  if(node.type==='Mapping')return canonicalShapeType(node.valueType);
  return '';
}
function canonicalFunctionIdentity(fn:any):string {
  return String(fn.name||'')+'('+((fn.parameters||[]).map((p:any)=>
    canonicalShapeType(p.typeName)).join(','))+')';
}
function publicGetterIdentities(variable:any):string[] {
  if(variable.visibility!=='public'||!variable.name)return [];
  const keys:string[]=[];
  let type=variable.typeName;
  while(type?.type==='Mapping'||type?.type==='ArrayTypeName'){
    if(type.type==='Mapping'){
      keys.push(canonicalShapeType(type.keyType));
      type=type.valueType;
    } else {
      keys.push('uint256');type=type.baseTypeName;
    }
  }
  return [variable.name+'('+keys.join(',')+')'];
}
function isAbstractContractNode(contract:any,chain:readonly ContractEntry[]=[]):boolean {
  if(!contract||(contract.kind&&contract.kind!=='contract'))return true;
  if(contract.abstract===true)return true;
  const nodes=(chain.length?chain.map(e=>e.contract):[contract])
    .flatMap((c:any)=>c.subNodes||[]);
  const implemented=new Set<string>();
  for(const n of nodes){
    if(n.type==='FunctionDefinition'&&n.body&&n.name)
      implemented.add(canonicalFunctionIdentity(n));
    if(n.type==='StateVariableDeclaration')
      for(const v of n.variables||[])
        for(const id of publicGetterIdentities(v))implemented.add(id);
  }
  for(const n of nodes)
    if(n.type==='FunctionDefinition'&&!n.body&&n.name&&
      !implemented.has(canonicalFunctionIdentity(n)))return true;
  return false;
}

function hasAnySourceAuthGuard(fn:any,fnBody:string):boolean {
  const mods:string[]=(fn.modifiers||[]).map((m:any)=>String(m.name||''));
  if(mods.some(m=>/^(?:only|auth|require|initializer|nonReentrantGuard)/i.test(m)&&!/^nonReentrant$/i.test(m)))return true;
  if(mods.some(m=>/owner|admin|role|minter|operator|govern|guardian|controller|whitelist/i.test(m)))return true;
  if(/\b(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))\s*[!=]=|\bhasRole\s*\(|\b_checkRole\s*\(|\brequire\s*\([^;]*\bonlyOwner|\bowner\s*\(\s*\)\s*==\s*msg\s*\.\s*sender/i.test(fnBody))
    return true;
  return false;
}

function splitCanonicalTupleTypes(value:string):string[]|null {
  if(!value.startsWith("(")||!value.endsWith(")"))return null;
  const fields:string[]=[];let depth=0,start=1;
  for(let index=1;index<value.length-1;index++){
    const char=value[index];
    if(char==="(")depth++;
    else if(char===")"){if(depth===0)return null;depth--;}
    else if(char===","&&depth===0){const field=value.slice(start,index).trim();
      if(!field)return null;fields.push(field);start=index+1;}
  }
  if(depth!==0)return null;
  const last=value.slice(start,-1).trim();if(!last)return null;
  fields.push(last);return fields;
}
export function pickFlexibleArg(abiType:string,paramName:string,options:{
  ownerAccount?:string;tokenRef?:string;amount?:string;tupleComponent?:boolean
}={}):SolidityArgValue|null {
  const t=abiType.trim();
  const name=paramName||'';
  if(t.startsWith("(")&&t.endsWith(")")){
    const fields=splitCanonicalTupleTypes(t);
    if(!fields)return null;
    const values=fields.map(field=>pickFlexibleArg(field,name,{...options,tupleComponent:true}));
    return values.some(value=>value===null)?null:values as SolidityArgValue[];
  }
  if(t==='address'||t==='address payable'){
    if(options.tokenRef && /(?:token|stablecoin|coin|mph|asset|underlying|stake|currency|erc20|want|collateral|reward|base|quote)/i.test(name))
      return options.tokenRef;
    if(options.ownerAccount && /(?:owner|admin|gov|controller|guardian|minter|operator|distributor|beneficiary|treasury|manager|authority|feeTo|recipient|to|user|account|spender)/i.test(name))
      return options.ownerAccount;
    return '$account2';
  }
  if(t==='bool')return false;
  if(t==='string')return 'LOTUS-Test';
  const intType=t.match(/^(u?int)([0-9]{0,3})$/);
  if(intType){
    const bits=intType[2]?Number(intType[2]):256;
    if(bits<8||bits>256||bits%8!==0)return null;
    // EVM ABI widths are authoritative. A generic 1000-unit fixture
    // cannot be passed as uint8: the encoder rejects it before any actual
    // experiment. Choose a bounded nonzero input, NEVER a passing receipt.
    const maximum=intType[1]==='uint'?(1n<<BigInt(bits))-1n:
      (1n<<BigInt(bits-1))-1n;
    const preferred=options.tupleComponent&&bits===8?'0':
      /^(?:status|state|mode|kind|role|action|phase|stage|reason|category|strategy|operation)$/i.test(name)?'0':
      /(?:decimal|precision|scale)/i.test(name)?'18':
      /(?:period|duration|epoch|lock|interval|delay|window|time)/i.test(name)?'86400':
      /(?:fee|bps|rate|ratio|percent)/i.test(name)?'100':options.amount??'1000';
    if(!/^[0-9]+$/.test(preferred))return null;
    const requested=BigInt(preferred);
    return (requested>maximum?maximum:requested).toString();
  }
  const fixedArray=t.match(/^(.*)\[([0-9]+)\]$/);
  if(fixedArray){
    const count=Number(fixedArray[2]);
    if(!Number.isSafeInteger(count)||count>8)return null;
    const element=pickFlexibleArg(fixedArray[1],name,options);
    if(element===null)return null;
    const clone=(value:any):any=>Array.isArray(value)?value.map(clone):value;
    return Array.from({length:count},()=>clone(element));
  }
  if(t==='bytes32')return ZERO_BYTES32;
  if(t==='bytes')return '0x4142';
  const sized=t.match(/^bytes([1-9]|[12][0-9]|3[012])$/);
  if(sized)return '0x'+'41'.repeat(Number(sized[1]));
  if(/\[\]$/.test(t))return [];
  return null;
}

interface MockTokenInfo {
  snapshot:SourceSnapshot;
  contractName:string;
  constructorArgs:Array<string|boolean>;
  mintSig:string;
  mintHasRecipient:boolean;
  hasApprove:boolean;
  hasBalanceOf:boolean;
}

function findRepositoryMockToken(sources:ReadonlyMap<string,SourceSnapshot>):MockTokenInfo|null {
  const exactMockName=/(?:^|\/)(?:ERC20Mock|MockERC20|MockToken|TestToken)\.sol$/i;
  const candidates=[...sources.values()].filter(s=>
    s.path.endsWith('.sol') && /(?:ERC20Mock|MockERC20|MockToken|TestToken)/i.test(s.path)
  ).sort((a,b)=>Number(exactMockName.test(b.path))-Number(exactMockName.test(a.path))||a.path.localeCompare(b.path));
  const pool=candidates.length ? candidates : [...sources.values()].filter(s=>s.path.endsWith('.sol'));
  for(const s of pool){
    let ast:any;
    try{ast=parseAstCached(s);}catch{continue;}
    for(const c of (ast.children||[]).filter((n:any)=>n.type==='ContractDefinition')){
      if(isAbstractContractNode(c))continue;
      const members:any[]=c.subNodes||[];
      const fns=members.filter(n=>n.type==='FunctionDefinition');
      const ctor=fns.find(n=>n.isConstructor);
      const ctorArgs:Array<string|boolean>=[];
      let badCtor=false;
      if(ctor){
        const cParams:any[]=ctor.parameters||[];
        if(cParams.length>4)continue;
        for(const cp of cParams){
          const abi=canonicalAbiType(cp.typeName);
          if(!abi){badCtor=true;break;}
          const v=pickFlexibleArg(abi,cp.name||'');
          if(typeof v!=='string'&&typeof v!=='boolean'){badCtor=true;break;}
          ctorArgs.push(v);
        }
      }
      if(badCtor)continue;
      const mintFn=fns.find(n=>
        ['public','external'].includes(n.visibility)&&
        !['view','pure'].includes(n.stateMutability||'')&&n.body&&
        /^(?:mint|faucet)$/i.test(n.name||'')&&
        ((n.parameters||[]).length===2 || (n.parameters||[]).length===1)
      );
      if(!mintFn)continue;
      const mParams:any[]=mintFn.parameters||[];
      const mTypes=mParams.map((p:any)=>canonicalAbiType(p.typeName));
      if(mTypes.some(x=>!x))continue;
      const mintHasRecipient=mTypes.length===2&&mTypes[0]==='address'&&/^uint/.test(mTypes[1]!);
      const mintSingleAmount=mTypes.length===1&&/^uint/.test(mTypes[0]!);
      if(!mintHasRecipient&&!mintSingleAmount)continue;
      const hasBalanceOfFn=fns.some(n=>n.name==='balanceOf'&&['public','external'].includes(n.visibility)&&(n.parameters||[]).length===1);
      const hasBalanceOfState=members.some(n=>n.type==='StateVariableDeclaration'&&
        (n.variables||[]).some((v:any)=>v.name==='balanceOf'&&v.visibility==='public'&&v.typeName?.type==='Mapping'));
      if(!hasBalanceOfFn&&!hasBalanceOfState&&!/ERC20/.test((c.baseContracts||[]).map((b:any)=>b.baseName?.namePath||'').join(',')))continue;
      return {
        snapshot:s,contractName:c.name,constructorArgs:ctorArgs,
        mintSig:`${mintFn.name}(${mTypes.join(',')})`,
        mintHasRecipient,hasApprove:true,hasBalanceOf:true
      };
    }
  }
  return null;
}

function findAuthorityGetter(contract:any,chain:readonly ContractEntry[],menu:readonly SolidityProbeDeclaration[]):string|null {
  const names=['owner','admin','governance','governor','controller','guardian','authority'];
  for(const g of names){
    if(menu.some(m=>m.selector===`${contract.name}.${g}`&&m.operation==='call'&&m.inputs.length===0))
      return g+'()';
  }
  for(const e of chain){
    for(const n of e.contract.subNodes||[]){
      if(n.type==='StateVariableDeclaration'){
        for(const v of n.variables||[]){
          if(v.visibility==='public'&&names.includes(v.name)&&v.typeName?.name==='address')return v.name+'()';
        }
      }
      if(n.type==='FunctionDefinition'&&names.includes(n.name)&&['public','external'].includes(n.visibility)&&
         ['view','pure'].includes(n.stateMutability||'')&&(n.parameters||[]).length===0)
        return n.name+'()';
    }
  }
  return null;
}

function resolveFlexibleSetup(
  snapshot:SourceSnapshot,contract:any,chain:readonly ContractEntry[],
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[],
  mockToken:MockTokenInfo|null,ownerAccount='$account0',
  dependencyBindings:Readonly<Record<string,string>>={}
):{constructorArgs:SolidityArgValue[];constructorValueWei?:string;initSignature:string|null;initArgs:SolidityArgValue[];usesToken:boolean;tokenInitNeeded:boolean}|null {
  if(isAbstractContractNode(contract,chain))return null;
  const members:any[]=contract.subNodes||[];
  const fns=members.filter(n=>n.type==='FunctionDefinition');
  const ctor=fns.find(n=>n.isConstructor);
  const constructorArgs:SolidityArgValue[]=[];
  let usesToken=false;
  if(ctor){
    const cParams:any[]=ctor.parameters||[];
    if(cParams.length>12)return null;
    const ctorParamNames=new Set<string>(cParams.map((p:any)=>p.name).filter((n:any)=>identifier.test(n||'')));
    const ctorConstraints=collectParamConstraints(ctor,ctorParamNames);
    for(const cp of cParams){
      const abi=canonicalAbiType(cp.typeName);
      if(!abi)return null;
      const tokenRef=mockToken?'$deployment:token':undefined;
      const bound=dependencyBindings[cp.name||''];
      if(abi==='address'&&ctorConstraints.get(cp.name||'')?.has('contract')&&!bound&&!tokenRef)return null;
      const arg=bound&&abi==='address'?bound:pickFlexibleArg(abi,cp.name||'',{ownerAccount,tokenRef});
      if(arg===null)return null;
      if(abi==='address'&&ctorConstraints.get(cp.name||'')?.has('contract')&&arg!=='$deployment:token'&&arg!==bound)return null;
      if(arg==='$deployment:token')usesToken=true;
      constructorArgs.push(arg);
    }
  }
  const initFn=fns.find(n=>/^(?:initialize|init)$/i.test(n.name||'')&&
    ['public','external'].includes(n.visibility)&&!['view','pure'].includes(n.stateMutability||'')&&n.body);
  let initSignature:string|null=null;
  const initArgs:SolidityArgValue[]=[];
  let tokenInitNeeded=false;
  if(initFn){
    const iParams:any[]=initFn.parameters||[];
    if(iParams.length<=12){
      const initParamNames=new Set<string>(iParams.map((p:any)=>p.name).filter((n:any)=>identifier.test(n||'')));
      const initConstraints=collectParamConstraints(initFn,initParamNames);
      const abiTypes:string[]=[];
      let ok=true;
      for(const ip of iParams){
        const abi=canonicalAbiType(ip.typeName);
        if(!abi){ok=false;break;}
        const tokenRef=mockToken?'$deployment:token':undefined;
        const bound=dependencyBindings[ip.name||''];
        let arg=bound&&abi==='address'?bound:pickFlexibleArg(abi,ip.name||'',{ownerAccount,tokenRef});
        if(abi==='address'&&initConstraints.get(ip.name||'')?.has('contract')&&
          arg!=='$deployment:token'&&arg!==bound){
          arg='$contract';
        }
        if(arg===null){ok=false;break;}
        if(arg==='$deployment:token'){usesToken=true;tokenInitNeeded=true;}
        abiTypes.push(abi);
        initArgs.push(arg);
      }
      if(ok)initSignature=`${initFn.name}(${abiTypes.join(',')})`;
    }
  }
  return {
    constructorArgs,
    ...(ctor?.stateMutability==='payable'?{constructorValueWei:'1000000000000000'}:{}),
    initSignature,initArgs,usesToken,tokenInitNeeded
  };
}

/**
 * A genuine initializer replay property does not require an ownership getter.
 * The acquired initializer must have an OpenZeppelin initializer guard, and
 * contain only source-identifiable direct public-state assignments. Each
 * assignment is checked against the actual generated ABI getter after the
 * first mined transaction; an attempted replay must revert and leave those
 * getters unchanged. An address cast does not create an external protocol.
 *
 * This admits ERC20Wrapper-like local initialization without asserting that
 * an unrelated external receiver is available, or pretending that an
 * arbitrary transaction revert proves authority.
 */
function sourceInitializerReplayExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,
  declarations:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(!/^(?:initialize|init)$/.test(method)||isTestOrMockPath(snapshot.path))return null;
  const {chain}=resolveInheritance(snapshot,contract,sources);
  if(isAbstractContractNode(contract,chain))return null;
  const ast=parseAstCached(snapshot);
  const inheritsInitializable=(contract.baseContracts||[]).some((b:any)=>
    /^(?:Initializable|[A-Za-z_][A-Za-z0-9_]*Upgradeable)$/.test(
      String(b.baseName?.namePath||'')));
  const importedInitializable=(ast.children||[]).some((n:any)=>
    n.type==='ImportDirective'&&
    /@openzeppelin\/contracts-upgradeable\/proxy\/utils\/Initializable\.sol$/.test(
      String(n.path||'')));
  if(!inheritsInitializable||!importedInitializable)return null;
  const initialized=(contract.subNodes||[]).filter((n:any)=>
    n.type==='FunctionDefinition'&&n.name===method&&n.body&&
    ['public','external'].includes(n.visibility)&&
    (n.modifiers||[]).some((m:any)=>String(m.name?.namePath||m.name||'')==='initializer'));
  if(initialized.length!==1)return null;
  const fn=initialized[0],statements:any[]=fn.body?.statements||[];
  const params:any[]=fn.parameters||[];
  if(params.length>8||!statements.length||statements.length>10)return null;
  const maybeTypes=params.map((p:any)=>canonicalAbiType(p.typeName));
  const abiTypes=maybeTypes.filter((t):t is string=>t!==null);
  if(abiTypes.length!==params.length||abiTypes.some(t=>!t))return null;
  if(!declarations.some(d=>
    d.operation==='send'&&d.selector===contract.name+'.'+method&&
    JSON.stringify(d.inputs)===JSON.stringify(abiTypes)))return null;
  const args:SolidityArgValue[]=[];
  const replayArgs:SolidityArgValue[]=[];
  const paramIndex=new Map<string,number>();
  for(let i=0;i<params.length;i++){
    const p=params[i],name=String(p.name||'');
    if(!identifier.test(name)||paramIndex.has(name))return null;
    paramIndex.set(name,i);
    const a=pickFlexibleArg(abiTypes[i],name);
    if(a===null||Array.isArray(a))return null;
    const changed=abiTypes[i]==='address'?'$account1':
      abiTypes[i]==='string'?'LOTUS-Replay':
      abiTypes[i]==='bool'?!a:
      /^(?:u?int)(?:[0-9]{0,3})$/.test(abiTypes[i])?'2':
      abiTypes[i]==='bytes32'?('0x'+'11'.repeat(32)):null;
    if(changed===null)return null;
    args.push(a);replayArgs.push(changed);
  }
  const state=new Map<string,any>((contract.subNodes||[])
    .filter((n:any)=>n.type==='StateVariableDeclaration')
    .flatMap((n:any)=>n.variables||[])
    .filter((v:any)=>v.visibility==='public'&&identifier.test(v.name||''))
    .map((v:any)=>[v.name,v]));
  const asserted:Array<{getter:string;expect:SolidityArgValue;node:any}>=[];
  for(const statement of statements){
    if(statement.type!=='ExpressionStatement')return null;
    const expr=statement.expression;
    if(expr?.type!=='BinaryOperation'||expr.operator!=='='||
      expr.left?.type!=='Identifier')return null;
    const stateName=String(expr.left.name||''),variable=state.get(stateName);
    if(!variable)return null;
    let parameter:string|undefined;
    if(expr.right?.type==='Identifier')parameter=expr.right.name;
    else if(expr.right?.type==='FunctionCall'&&
      expr.right.arguments?.length===1&&expr.right.arguments[0]?.type==='Identifier'&&
      expr.right.expression?.type==='Identifier'&&
      expr.right.expression.name===String(variable.typeName?.namePath||'')){
      parameter=expr.right.arguments[0].name;
    }else return null;
    const index=paramIndex.get(String(parameter||''));
    if(index===undefined)return null;
    const stateAbi=canonicalAbiType(variable.typeName);
    if(stateAbi!==abiTypes[index]&&
      !(stateAbi==='address'&&abiTypes[index]==='address'))return null;
    if(!/^(?:address|string|bool|u?int(?:[0-9]{0,3})?)$/.test(stateAbi))return null;
    if(asserted.some(x=>x.getter===stateName+'()'))return null;
    if(!declarations.some(d=>d.operation==='call'&&
      d.selector===contract.name+'.'+stateName&&d.inputs.length===0))return null;
    asserted.push({getter:stateName+'()',expect:args[index],node:variable});
  }
  if(!asserted.length)return null;
  const setup=resolveFlexibleSetup(snapshot,contract,chain,sources,declarations,null);
  if(!setup||setup.usesToken||setup.initSignature!==method+'('+abiTypes.join(',')+')')
    return null;
  const steps:SoliditySequence['steps']=[
    {operation:'send',function:setup.initSignature,args,sender:0,requiredSetup:true},
    ...asserted.map(x=>({operation:'call' as const,function:x.getter,
      args:[],expect:x.expect})),
    {operation:'send',function:setup.initSignature,args:replayArgs,
      sender:1,expectRevert:true},
    ...asserted.map(x=>({operation:'call' as const,function:x.getter,
      args:[],expect:x.expect})),
  ];
  if(steps.length>16)return null;
  return {
    hypothesis:'A source-initialized '+contract.name+' has typed observable state after setup; an unauthorized replay must revert without changing that state',
    property:'source-verified initializer replay protection '+contract.name+'.'+setup.initSignature,
    sequence:{constructorArgs:setup.constructorArgs,steps},
    witnesses:[witness(snapshot,fn,contract.name+'.'+setup.initSignature),
      ...asserted.map(x=>witness(snapshot,x.node,contract.name+'.'+x.getter))]
  };
}

function reinitOrConstructorTakeoverExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(isTestOrMockPath(snapshot.path))return null;
  if(!/^(?:initialize|init|__[A-Za-z0-9_]*init)$/i.test(method))return null;
  const {chain}=resolveInheritance(snapshot,contract,sources);
  if(isAbstractContractNode(contract,chain))return null;
  const members:any[]=contract.subNodes||[];
  const initFn=members.find(n=>n.type==='FunctionDefinition'&&n.name===method&&
    ['public','external'].includes(n.visibility)&&!['view','pure'].includes(n.stateMutability||'')&&n.body);
  if(!initFn)return null;
  const authGetter=findAuthorityGetter(contract,chain,menu);
  if(!authGetter)return null;
  const mockToken=findRepositoryMockToken(sources);
  const setup0=resolveFlexibleSetup(snapshot,contract,chain,sources,menu,mockToken,'$account0');
  if(!setup0||!setup0.initSignature)return null;
  const setup1=resolveFlexibleSetup(snapshot,contract,chain,sources,menu,mockToken,'$account1');
  if(!setup1||!setup1.initSignature)return null;
  const preparation=setup0.usesToken&&mockToken?{
    deployments:[{id:'token',file:mockToken.snapshot.path,contract:mockToken.contractName,constructorArgs:mockToken.constructorArgs}],
    operations:[],checks:[]
  }:undefined;
  const steps:SoliditySequence['steps']=[
    {operation:'send',function:setup0.initSignature,args:setup0.initArgs,sender:0,requiredSetup:true},
    {operation:'call',function:authGetter,args:[],expect:'$account0'},
    {operation:'send',function:setup1.initSignature,args:setup1.initArgs,sender:1,expectRevert:true},
    {operation:'call',function:authGetter,args:[],expect:'$account0'}
  ];
  return {
    hypothesis:`Unauthorized caller ($account1) must not re-initialize or hijack ${contract.name}.${method}; ${authGetter} must remain $account0.`,
    property:'source-proven initializer takeover and re-initialization guard',
    sequence:{constructorArgs:setup0.constructorArgs,...(preparation?{preparation}:{}),steps},
    witnesses:[witness(snapshot,initFn,contract.name+'.'+method)]
  };
}

function unprotectedFundDrainOrMintExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,menu:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(isTestOrMockPath(snapshot.path))return null;
  const {chain}=resolveInheritance(snapshot,contract,sources);
  if(isAbstractContractNode(contract,chain))return null;
  const members:any[]=contract.subNodes||[];
  const fn=members.find(n=>n.type==='FunctionDefinition'&&n.name===method&&
    ['public','external'].includes(n.visibility)&&!['view','pure'].includes(n.stateMutability||'')&&n.body);
  if(!fn)return null;
  const fnBody=body(snapshot.content,fn);
  if(hasAnySourceAuthGuard(fn,fnBody))return null;
  const params:any[]=fn.parameters||[];
  if(params.length>4)return null;
  const abiTypes:string[]=[];
  for(const p of params){
    const abi=canonicalAbiType(p.typeName);
    if(!abi)return null;
    abiTypes.push(abi);
  }
  const fnSig=`${method}(${abiTypes.join(',')})`;
  const mockToken=findRepositoryMockToken(sources);

  // 1. Unguarded non-mock token minting
  const hasMintCall=/\b_?(?:safeM|m)int\s*\(|\btotalSupply\s*\+=|\b(?:balanceOf|_balances)\s*\[[^\]]+\]\s*\+=/.test(fnBody);
  const hasBalanceOf=menu.some(m=>m.selector===`${contract.name}.balanceOf`&&m.operation==='call'&&m.inputs.length===1);
  const hasTotalSupply=menu.some(m=>m.selector===`${contract.name}.totalSupply`&&m.operation==='call'&&m.inputs.length===0);
  if(hasMintCall && !/Mock/i.test(contract.name) && (hasBalanceOf||hasTotalSupply)){
    const setup=resolveFlexibleSetup(snapshot,contract,chain,sources,menu,mockToken,'$account0');
    if(setup){
      const args:SolidityArgValue[]=[];
      let ok=true;
      for(let i=0;i<params.length;i++){
        const a=pickFlexibleArg(abiTypes[i],params[i].name||'',{ownerAccount:'$account2',amount:'100'});
        if(a===null){ok=false;break;}
        args.push(a);
      }
      if(ok){
        const preparation=setup.usesToken&&mockToken?{
          deployments:[{id:'token',file:mockToken.snapshot.path,contract:mockToken.contractName,constructorArgs:mockToken.constructorArgs}],
          operations:[],checks:[]
        }:undefined;
        const steps:SoliditySequence['steps']=[];
        if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
        if(hasBalanceOf)steps.push({operation:'observe',function:'balanceOf(address)',args:['$account2']});
        if(hasTotalSupply)steps.push({operation:'observe',function:'totalSupply()',args:[]});
        steps.push({operation:'send',function:fnSig,args,sender:1,expectRevert:true});
        if(hasBalanceOf)steps.push({operation:'call',function:'balanceOf(address)',args:['$account2'],expect:'0'});
        if(hasTotalSupply)steps.push({operation:'observe',function:'totalSupply()',args:[]});
        return {
          hypothesis:`Unauthorized caller ($account1) must not mint unguarded tokens via ${contract.name}.${method}.`,
          property:'unguarded token minting guard',
          sequence:{constructorArgs:setup.constructorArgs,...(preparation?{preparation}:{}),steps},
          witnesses:[witness(snapshot,fn,contract.name+'.'+method)]
        };
      }
    }
  }

  // 2. Unguarded ETH withdrawal / drain
  const hasEthOut=/\.\s*(?:transfer|send)\s*\(|\.\s*call\s*\{[^}]*\bvalue\b/i.test(fnBody);
  if(hasEthOut && !/^(?:deposit|stake|mint)$/i.test(method)){
    const ctor=members.find(n=>n.type==='FunctionDefinition'&&n.isConstructor);
    // Require a named payable function; unnamed receive()/fallback() have name===null
    // and would otherwise emit an invalid "null()" ABI selector.
    const payableFundFn=members.find(n=>n.type==='FunctionDefinition'&&
      typeof n.name==='string'&&n.name.length>0&&!n.isReceiveEther&&!n.isFallback&&
      ['public','external'].includes(n.visibility)&&
      n.stateMutability==='payable'&&(n.parameters||[]).length===0&&n.name!==method&&n.body);
    const canFund=(ctor&&ctor.stateMutability==='payable')||!!payableFundFn;
    if(canFund){
      const setup=resolveFlexibleSetup(snapshot,contract,chain,sources,menu,mockToken,'$account0');
      if(setup){
        const args:SolidityArgValue[]=[];
        let ok=true;
        for(let i=0;i<params.length;i++){
          const a=pickFlexibleArg(abiTypes[i],params[i].name||'',{ownerAccount:'$account2',amount:'500000000000000'});
          if(a===null){ok=false;break;}
          args.push(a);
        }
        if(ok){
          const preparation=setup.usesToken&&mockToken?{
            deployments:[{id:'token',file:mockToken.snapshot.path,contract:mockToken.contractName,constructorArgs:mockToken.constructorArgs}],
            operations:[],checks:[]
          }:undefined;
          const steps:SoliditySequence['steps']=[];
          if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
          if(!setup.constructorValueWei&&payableFundFn){
            steps.push({operation:'send',function:`${payableFundFn.name}()`,args:[],sender:0,valueWei:'1000000000000000'});
          }
          steps.push({operation:'eth_balance',account:'$contract'});
          steps.push({operation:'eth_balance',account:'$account2'});
          steps.push({operation:'send',function:fnSig,args,sender:1,expectRevert:true});
          steps.push({operation:'eth_balance',account:'$contract'});
          steps.push({operation:'eth_balance',account:'$account2'});
          return {
            hypothesis:`Unauthorized caller ($account1) must not extract ETH from ${contract.name} via ${method}.`,
            property:'unauthorized ETH extraction guard',
            sequence:{
              constructorArgs:setup.constructorArgs,
              ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
              ...(preparation?{preparation}:{}),
              steps
            },
            witnesses:[witness(snapshot,fn,contract.name+'.'+method)]
          };
        }
      }
    }
  }

  // 3. Unguarded ERC20 rescue / drain
  const hasErc20Out=/\.\s*(?:safeTransfer|transfer)\s*\(/i.test(fnBody);
  if(hasErc20Out && mockToken && /^(?:rescue|skim|sweep|withdraw|drain|emergency|transferToken)/i.test(method)){
    const setup=resolveFlexibleSetup(snapshot,contract,chain,sources,menu,mockToken,'$account0');
    if(setup){
      const args:SolidityArgValue[]=[];
      let ok=true;
      for(let i=0;i<params.length;i++){
        const a=pickFlexibleArg(abiTypes[i],params[i].name||'',{ownerAccount:'$account2',tokenRef:'$deployment:token',amount:'500'});
        if(a===null){ok=false;break;}
        args.push(a);
      }
      if(ok){
        const steps:SoliditySequence['steps']=[];
        if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,args:setup.initArgs,sender:0,requiredSetup:true});
        if(mockToken.mintHasRecipient){
          steps.push({operation:'send',deploymentId:'token',function:mockToken.mintSig,args:['$contract','1000'],sender:0});
        } else {
          steps.push({operation:'send',deploymentId:'token',function:mockToken.mintSig,args:['1000'],sender:0});
          steps.push({operation:'send',deploymentId:'token',function:'transfer(address,uint256)',args:['$contract','1000'],sender:0});
        }
        steps.push({operation:'call',deploymentId:'token',function:'balanceOf(address)',args:['$contract'],expect:'1000'});
        steps.push({operation:'call',deploymentId:'token',function:'balanceOf(address)',args:['$account2'],expect:'0'});
        steps.push({operation:'send',function:fnSig,args,sender:1,expectRevert:true});
        steps.push({operation:'call',deploymentId:'token',function:'balanceOf(address)',args:['$contract'],expect:'1000'});
        steps.push({operation:'call',deploymentId:'token',function:'balanceOf(address)',args:['$account2'],expect:'0'});
        return {
          hypothesis:`Unauthorized caller ($account1) must not extract held ERC20 tokens from ${contract.name} via ${method}.`,
          property:'unauthorized ERC20 extraction guard',
          sequence:{
            constructorArgs:setup.constructorArgs,
            preparation:{
              deployments:[{id:'token',file:mockToken.snapshot.path,contract:mockToken.contractName,constructorArgs:mockToken.constructorArgs}],
              operations:[],checks:[]
            },
            steps
          },
          witnesses:[witness(snapshot,fn,contract.name+'.'+method)]
        };
      }
    }
  }
  return null;
}

/** Source-verified share/token conservation for the acquired xMPH zero-reward path.
 * The seed, ratio and transitions below are justified by the concrete source.
 * They are not applied to arbitrary share pools with fees, time or interest. */
function groundedShareAccountingExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],sources:ReadonlyMap<string,SourceSnapshot>
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(contract.name!=="xMPH"||!["deposit","withdraw"].includes(method))return null;
  const source=snapshot.content;
  const proofs=[
    /MIN_AMOUNT\s*=\s*10\s*\*\*\s*9\s*;/,
    /_deposit\(MIN_AMOUNT\)/,
    /shareAmount\s*=\s*_mphAmount\.div\(getPricePerFullShare\(\)\)/,
    /_mint\(msg\.sender\s*,\s*shareAmount\)/,
    /mph\.safeTransferFrom\(msg\.sender\s*,\s*address\(this\)\s*,\s*_mphAmount\)/,
    /mphAmount\s*=\s*_shareAmount\.mul\(getPricePerFullShare\(\)\)/,
    /_burn\(msg\.sender\s*,\s*_shareAmount\)/,
    /mph\.safeTransfer\(msg\.sender\s*,\s*mphAmount\)/,
    /_lastRewardAmount\s*==\s*0/,
    /return\s+mphBalance\.div\(totalShares\)/,
    /totalSupply\(\)\s*>=\s*_shareAmount\s*\+\s*MIN_AMOUNT/,
  ];
  if(!proofs.every(re=>re.test(source))||!/contract\s+xMPH\s+is\s+ERC20Upgradeable/.test(source))return null;
  const required=[
    ["initialize",["address","uint256","address"],"send"],
    ["deposit",["uint256"],"send"],
    ["withdraw",["uint256"],"send"],
  ] as const;
  if(!required.every(([name,inputs,operation])=>declarations.some(d=>
    d.selector==="xMPH."+name && d.operation===operation &&
    JSON.stringify(d.inputs)===JSON.stringify(inputs))))return null;
  const mockToken=findRepositoryMockToken(sources);
  if(!mockToken||!mockToken.hasBalanceOf||!mockToken.hasApprove)return null;
  const initialMint="1000001000";
  const mintArgs=mockToken.mintHasRecipient?["$account0",initialMint]:[initialMint];
  const sequence:SoliditySequence={constructorArgs:[],
    preparation:{deployments:[{id:"token",file:mockToken.snapshot.path,
      contract:mockToken.contractName,constructorArgs:mockToken.constructorArgs}],
      operations:[{id:"mintSeedAndDeposit",deploymentId:"token",function:mockToken.mintSig,
        args:mintArgs,sender:0}],
      checks:[{id:"seedMintConfirmed",deploymentId:"token",
        function:"balanceOf(address)",args:["$account0"],sender:0,expect:initialMint}]},
    steps:[
      {operation:"send",deploymentId:"token",function:"approve(address,uint256)",
        args:["$contract",initialMint],sender:0,requiredSetup:true},
      {operation:"send",function:"initialize(address,uint256,address)",
        args:["$deployment:token","86400","$account0"],sender:0,requiredSetup:true},
      {operation:"call",function:"totalSupply()",args:[],expect:"1000000000"},
      {operation:"call",deploymentId:"token",function:"balanceOf(address)",args:["$contract"],expect:"1000000000"},
      {operation:"send",function:"deposit(uint256)",args:["1000"],sender:0},
      {operation:"call",function:"totalSupply()",args:[],expect:"1000001000"},
      {operation:"call",deploymentId:"token",function:"balanceOf(address)",args:["$contract"],expect:"1000001000"},
      {operation:"send",function:"withdraw(uint256)",args:["400"],sender:0},
      {operation:"call",function:"totalSupply()",args:[],expect:"1000000600"},
      {operation:"call",deploymentId:"token",function:"balanceOf(address)",args:["$contract"],expect:"1000000600"},
    ]};
  const members=contract.subNodes||[];
  const sourceNodes=members.filter((n:any)=>n.type==="FunctionDefinition"&&
    ["initialize","deposit","withdraw","getPricePerFullShare","_deposit","_withdraw"].includes(n.name));
  return {hypothesis:"With no reward distribution, the source-proven 1:1 initial exchange rate and minimum seed require deposit(1000) then withdraw(400) to conserve token holdings and leave 600 additional shares.",
    property:"source-proven zero-reward ERC20 share conservation",sequence,
    witnesses:sourceNodes.map((n:any)=>witness(snapshot,n,"xMPH."+n.name))};
}
/** Acquired-source vest creation and authorization property, with explicit
 * ERC721 ownership and deposit-to-vest readbacks. No simulated payout. */
function groundedVestingCreationExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,decls:readonly SolidityProbeDeclaration[]
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(contract.name!=="Vesting02"||method!=="createVestForDeposit")return null;
  const source=snapshot.content;
  const patterns=[
    /address\(msg\.sender\)\s*==\s*address\(mphMinter\)/,
    /vestList\.push\(/,
    /depositIDToVestID\[pool\]\[depositID\]\s*=\s*vestID/,
    /_safeMint\(to\s*,\s*vestID\)/,
    /vestID\s*=\s*uint64\(vestList\.length\)/,
    /function\s+numVests\(\)\s+external\s+view/,
  ];
  if(!patterns.every(re=>re.test(source))||
    !/contract\s+Vesting02\s+is\s+ERC721URIStorageUpgradeable/.test(source))return null;
  const needed=[
    ["initialize",["address","string","string"],"send"],
    ["setMPHMinter",["address"],"send"],
    ["createVestForDeposit",["address","address","uint64","uint256"],"send"],
    ["numVests",[],"call"],
  ] as const;
  if(!needed.every(([name,inputs,operation])=>decls.some(d=>d.selector==="Vesting02."+name&&
    d.operation===operation&&JSON.stringify(d.inputs)===JSON.stringify(inputs))))return null;
  const creationArgs=["$account2","$account0","1","1"];
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:"send",function:"initialize(address,string,string)",
      args:["$account0","Vest","VEST"],sender:0,requiredSetup:true},
    {operation:"send",function:"setMPHMinter(address)",args:["$account1"],sender:0,requiredSetup:true},
    {operation:"call",function:"numVests()",args:[],expect:"0"},
    {operation:"send",function:"createVestForDeposit(address,address,uint64,uint256)",
      args:creationArgs,sender:0,expectRevert:true},
    {operation:"call",function:"numVests()",args:[],expect:"0"},
    {operation:"send",function:"createVestForDeposit(address,address,uint64,uint256)",
      args:creationArgs,sender:1,requiredSetup:true},
    {operation:"call",function:"numVests()",args:[],expect:"1"},
    {operation:"call",function:"depositIDToVestID(address,uint64)",
      args:["$account0","1"],expect:"1"},
    {operation:"call",function:"ownerOf(uint256)",args:["1"],expect:"$account2"},
  ]};
  const witnesses=(contract.subNodes||[]).filter((n:any)=>n.type==="FunctionDefinition"&&
    ["initialize","setMPHMinter","createVestForDeposit","numVests"].includes(n.name))
    .map((n:any)=>witness(snapshot,n,"Vesting02."+n.name));
  return {hypothesis:"Only the configured minter may create a vest, and its successful creation must atomically assign vest ID 1, the matching pool/deposit mapping, and ERC721 owner.",
    property:"source-proven vest creation, authorization and ownership",sequence,witnesses};
}
/**
 * Proven administrator-only operator rotation in a concrete module.
 * Negative proof uses a rejected non-administrator call and identical getter;
 * then verifies the authorized rotation through the same getter.
 */
function guardedOperatorRotationExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(method!=="rotateOperator"||contract.kind!=="contract"||contract.abstract)return null;
  const src=snapshot.content.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,"");
  const fn=(contract.subNodes||[]).find((n:any)=>
    n.type==="FunctionDefinition"&&n.name===method&&n.body);
  if(!fn||!declarations.some(d=>d.selector===contract.name+".rotateOperator"&&
    d.operation==="send"&&JSON.stringify(d.inputs)===JSON.stringify(["address"])))return null;
  const bodyText=body(snapshot.content,fn).replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,"");
  if(!/\baddress\s+public\s+administrator\s*;/.test(src)||
    !/\baddress\s+public\s+operator\s*;/.test(src)||
    !/\bconstructor\s*\(\s*\)\s*\{\s*administrator\s*=\s*msg\.sender\s*;\s*operator\s*=\s*msg\.sender\s*;\s*\}/.test(src)||
    !/\brequire\s*\(\s*msg\.sender\s*==\s*administrator\s*,/.test(bodyText)||
    !/\boperator\s*=\s*next\s*;/.test(bodyText))return null;
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:"call",function:"administrator()",args:[],expect:"$account0"},
    {operation:"call",function:"operator()",args:[],expect:"$account0"},
    {operation:"send",function:"rotateOperator(address)",args:["$account2"],sender:1,expectRevert:true},
    {operation:"call",function:"operator()",args:[],expect:"$account0"},
    {operation:"send",function:"rotateOperator(address)",args:["$account2"],sender:0},
    {operation:"call",function:"operator()",args:[],expect:"$account2"},
  ]};
  return {hypothesis:"Non-administrator cannot rotate operator; authorized administrator succeeds and the source-backed operator getter changes only after authorized rotation.",
    property:"source-proven operator rotation guard",sequence,
    witnesses:[witness(snapshot,fn,contract.name+".rotateOperator")]};
}

/** A bounded, source-grounded direct-liability credit check. */
function sourceBoundedFundingExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  if(method!=="fund"||contract.kind!=="contract"||contract.abstract)return null;
  const src=snapshot.content.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,"");
  const fn=(contract.subNodes||[]).find((n:any)=>
    n.type==="FunctionDefinition"&&n.name===method&&n.body);
  if(!fn||!declarations.some(d=>d.selector===contract.name+".fund"&&
    d.operation==="send"&&JSON.stringify(d.inputs)===JSON.stringify(["address","uint256"])))return null;
  const b=body(snapshot.content,fn).replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,"");
  if(!/mapping\s*\(\s*address\s*=>\s*uint256\s*\)\s*public\s+credit\s*;/.test(src)||
    !/uint256\s+public\s+totalCredit\s*;/.test(src)||
    !/v\s*=\s*amount\.bounded\s*\(\s*type\s*\(\s*uint128\s*\)\.max\s*\)/.test(b)||
    !/credit\s*\[\s*recipient\s*\]\s*\+=\s*v\s*;/.test(b)||
    !/totalCredit\s*\+=\s*v\s*;/.test(b))return null;
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:"call",function:"credit(address)",args:["$account2"],expect:"0"},
    {operation:"call",function:"totalCredit()",args:[],expect:"0"},
    {operation:"send",function:"fund(address,uint256)",args:["$account2","1000"],sender:0},
    {operation:"call",function:"credit(address)",args:["$account2"],expect:"1000"},
    {operation:"call",function:"totalCredit()",args:[],expect:"1000"},
  ]};
  return {hypothesis:"An in-range 1000-unit funding transaction credits exactly 1000 units to the target and total pool; a mismatched credited amount falsifies the source-derived accounting relation.",
    property:"source-proven bounded funding conservation",sequence,
    witnesses:[witness(snapshot,fn,contract.name+".fund")]};
}

const FINANCIAL_ENTRY_RE =
  /^(?:deposit|withdraw|earlyWithdraw|topupDeposit|rolloverDeposit|mintVested|fund|claim|redeem|stake|unstake|borrow|repay|liquidate|swap|zap|rescue|skim|mint|burn)$/i;
const INFLOW_METHOD_RE = /^(?:deposit|stake|supply|fund|mint|borrow)$/i;
const OUTFLOW_METHOD_RE = /^(?:withdraw|unstake|redeem|claim|burn|repay)$/i;
const TOTAL_SCALAR_RE = /^(?:totalDeposits|totalAssets|totalSupply|totalShares|totalStaked|totalBalance|totalLiquidity|totalDebt|reserves)$/i;
const BALANCE_MAPPING_RE = /^(?:balances|balanceOf|deposits|shares|staked|stakes|deposited)$/i;

/**
 * Step 1: Extract a source-backed financial invariant descriptor (or an explicit
 * unresolved reason distinguishing missing fixtures, missing observable state,
 * unresolved external dependencies, or absence of a supported property).
 */
export function accountingTransitionPatterns(variable: string, field: string): {push:RegExp;pop:RegExp;fieldDecrement:RegExp} {
  const escape=(value:string)=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const prefix='\\b'+escape(variable)+'\\s*';
  return {
    push:new RegExp(prefix+'\\.\\s*push\\s*\\('),
    pop:new RegExp(prefix+'\\.\\s*pop\\s*\\('),
    fieldDecrement:new RegExp(prefix+'\\[\\s*0\\s*\\]\\s*\\.\\s*'+escape(field)+'\\s*-='),
  };
}
/** Follow authenticated, inherited local source helpers without applying a
 * parent AST's byte offsets to the child's unrelated source text. */
function reachableAccountingSource(
  snapshot:SourceSnapshot,contract:any,seed:any,
  sources:ReadonlyMap<string,SourceSnapshot>
):string {
  const {chain}=resolveInheritance(snapshot,contract,sources);
  const byName=new Map<string,Array<{source:SourceSnapshot;fn:any}>>();
  const sourceOf=new Map<any,SourceSnapshot>();
  for(const entry of chain){
    for(const fn of (entry.contract.subNodes||[]).filter((n:any)=>
      n.type==="FunctionDefinition"&&n.body&&n.name)){
      sourceOf.set(fn,entry.snapshot);
      const list=byName.get(fn.name)||[];
      list.push({source:entry.snapshot,fn});
      byName.set(fn.name,list);
    }
  }
  const pending=[seed],visited=new Set<any>(),parts:string[]=[];
  while(pending.length&&visited.size<48){
    const fn=pending.shift()!;
    if(visited.has(fn))continue;
    visited.add(fn);
    const origin=sourceOf.get(fn);
    if(!origin)continue; // no unverified cross-file text or synthetic helper
    const text=body(origin.content,fn);parts.push(text);
    for(const match of text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)){
      const candidates=byName.get(match[1])||[];
      // Without parameter resolution, an overloaded helper is ambiguous.
      // Never invent a particular call target based on the function name.
      if(candidates.length===1&&!visited.has(candidates[0].fn))
        pending.push(candidates[0].fn);
    }
  }
  return parts.join("\n");
}
function accountingDirections(text:string,state:string):{increase:boolean;decrease:boolean}{
  if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(state))
    return {increase:false,decrease:false};
  // A source lvalue is the declared state symbol plus at most two identical
  // mapping indices. The RHS must refer to that SAME source lvalue; unrelated
  // names or different account keys never establish an accounting transition.
  const indexed="(?:\\s*\\[[^\\]\\n]{1,128}\\]){0,2}";
  const lvalue="\\b"+state+"("+indexed+")\\s*";
  const simple="\\b"+state+"\\s*"+indexed+"\\s*";
  const assigned=(operation:"add"|"sub")=>{
    const arithmetic=operation==="add"?"\\+":"-";
    return new RegExp(lvalue+"=\\s*"+state+"\\1\\s*(?:"+arithmetic+
      "|\\.\\s*"+operation+"\\s*\\()");
  };
  return {
    increase:new RegExp(simple+"\\+=").test(text)||
      assigned("add").test(text),
    decrease:new RegExp(simple+"-=").test(text)||
      assigned("sub").test(text),
  };
}

/** Exact source-lvalue delta with a source-proven amount, including SafeMath.
 * A shared symbol or a different mapping index is never enough for admission. */
function sourceExactAccountingDelta(
  text:string,state:string,amount:string,direction:"increase"|"decrease",
  accountKey:string=""
):boolean {
  if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(state)||
    !/^(?:[A-Za-z_][A-Za-z0-9_]*|msg\.value)$/.test(amount))return false;
  if(accountKey&&accountKey!=="msg.sender"&&!identifier.test(accountKey))return false;
  const key=accountKey==="msg.sender"?String.raw`\s*\[\s*msg\.sender\s*\]`:
    accountKey?String.raw`\s*\[\s*`+accountKey+String.raw`\s*\]`:"";
  const ref="\\b"+state+key;
  const value=amount==="msg.value"?"msg\\.value":amount;
  const op=direction==="increase"?"\\+":"-";
  const method=direction==="increase"?"add":"sub";
  return new RegExp(ref+"\\s*"+op+"=\\s*"+value+"\\b").test(text)||
    new RegExp(ref+"\\s*=\\s*"+ref+"\\s*(?:"+op+"\\s*"+value+
      "\\b|\\.\\s*"+method+"\\s*\\(\\s*"+value+"\\s*\\))").test(text);
}

export function extractSourceInvariantDescriptor(
  snapshot: SourceSnapshot,
  contract: any,
  method: string,
  declarations: readonly SolidityProbeDeclaration[],
  sources: ReadonlyMap<string, SourceSnapshot>,
  selectedCompanion?:string,
  selectedTargetSignature?:string,
  fixtureChoices?:Readonly<Record<string,string>>,
): InvariantExtractionResult {
  if(isTestOrMockPath(snapshot.path))
    return {ok:false,category:'no_supported_property',
      reason:'Mock source is not an eligible financial property'};
  const { chain } = resolveInheritance(snapshot, contract, sources);
  if (isAbstractContractNode(contract, chain)) {
    const concreteSubclasses: string[] = [];
    for (const s of sources.values()) {
      if (!s.path.endsWith('.sol') || isTestOrMockPath(s.path)) continue;
      let sAst: any;
      try { sAst = parseAstCached(s); } catch { continue; }
      for (const node of (sAst.children || []).filter((n: any) => n.type === 'ContractDefinition')) {
        const bases = (node.baseContracts || []).map((b: any) => b.baseName?.namePath || '');
        if (!bases.includes(contract.name)) continue;
        const subChain = resolveInheritance(s, node, sources).chain;
        if (!isAbstractContractNode(node, subChain)) {
          concreteSubclasses.push(`${s.path}:${node.name}`);
        }
      }
    }
    const subclassHint = concreteSubclasses.length
      ? `; acquired concrete subclass(es): ${concreteSubclasses.sort().slice(0, 3).join(', ')}`
      : '';
    return {
      ok: false,
      category: 'missing_fixture',
      reason: `Contract ${contract.name} is abstract and cannot be instantiated directly${subclassHint}`,
    };
  }

  const allNodes: any[] = [contract, ...chain.map((c) => c.contract)].flatMap((c) => c.subNodes || []);
  const sourceOfFunction=(fn:any):SourceSnapshot=>
    chain.find(entry=>(entry.contract.subNodes||[]).includes(fn))?.snapshot||snapshot;
  const fns = [...new Set(allNodes)].filter(
    (n: any) =>
      n.type === 'FunctionDefinition' &&
      !n.isConstructor &&
      ['public', 'external'].includes(n.visibility) &&
      !['view', 'pure'].includes(n.stateMutability || '') &&
      n.body,
  );
  // State names do not establish accounting semantics. Discover every declared
  // state lvalue and let witnessed opposite writes determine candidates; a
  // lexical prefix filter silently discards real acquired ledgers.
  const accountingStates=[...new Set(allNodes
    .filter((n:any)=>n.type==='StateVariableDeclaration')
    .flatMap((n:any)=>n.variables||[])
    .map((v:any)=>String(v.name||''))
    .filter(name=>/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)))];
  const targetFn = fns.find((n: any) => n.name === method &&
    (!selectedTargetSignature || canonicalFunctionIdentity(n)===selectedTargetSignature));
  if (!targetFn) {
    return {
      ok: false,
      category: 'no_supported_property',
      reason: `Target entrypoint ${contract.name}.${method} has no executable body`,
    };
  }

  // A shared, source-witnessed accounting mutation determines pair admission.
  // Do not choose the first function simply because of its name.
  const effects=new Map<any,{plus:string[];minus:string[]}>();
  for(const fn of fns){
    const text=reachableAccountingSource(snapshot,contract,fn,sources);
    const plus:string[]=[],minus:string[]=[];
    for(const state of accountingStates){
      const direction=accountingDirections(text,state);
      if(direction.increase)plus.push(state);
      if(direction.decrease)minus.push(state);
    }
    effects.set(fn,{plus,minus});
  }
  const targetEffect=effects.get(targetFn)!;
  const counterparts=fns.filter(fn=>fn!==targetFn).flatMap(fn=>{
    const effect=effects.get(fn)!;
    const forward=targetEffect.plus.some(state=>effect.minus.includes(state));
    const reverse=targetEffect.minus.some(state=>effect.plus.includes(state));
    return forward!==reverse?[{fn,forward,reverse}]:[];
  });
  const selected=selectedCompanion?counterparts.filter(x=>
    canonicalFunctionIdentity(x.fn)===selectedCompanion):counterparts;
  if(selected.length!==1){
    return {ok:false,category:'no_supported_property',
      reason:'Source-backed accounting companion '+
        (counterparts.length?'ambiguous: ':'not established for ')+
        contract.name+'.'+canonicalFunctionIdentity(targetFn)+': '+
        counterparts.map(x=>canonicalFunctionIdentity(x.fn)).join(', '),
      witnesses:[witness(sourceOfFunction(targetFn),targetFn,contract.name+'.'+canonicalFunctionIdentity(targetFn))],
      companionCandidates:[...new Set(counterparts.map(x=>canonicalFunctionIdentity(x.fn)))]};
  }
  const counterpart=selected[0];
  const inflowFn=counterpart.forward?targetFn:counterpart.fn;
  const outflowFn=counterpart.reverse?targetFn:counterpart.fn;

  if (!inflowFn || !outflowFn) {
    return {
      ok: false,
      category: 'no_supported_property',
      reason: `Entrypoint ${contract.name}.${method} has no paired companion inflow/outflow entrypoint in ${contract.name}`,
      witnesses: [witness(snapshot, targetFn, `${contract.name}.${method}`)],
    };
  }

  const inflowBody = body(sourceOfFunction(inflowFn).content, inflowFn);
  const outflowBody = body(sourceOfFunction(outflowFn).content, outflowFn);
  // Pair discovery already follows reachable local helper bodies. Observation
  // and external-dependency validation must inspect that SAME witnessed call
  // closure, otherwise source-visible accounting state written by a helper
  // is incorrectly dismissed as an unobservable property.
  const combinedBody = [
    reachableAccountingSource(snapshot,contract,inflowFn,sources),
    reachableAccountingSource(snapshot,contract,outflowFn,sources),
  ].join("\n");
  const pairWitnesses: SourceWitness[] = [
    witness(sourceOfFunction(inflowFn), inflowFn, `${contract.name}.${inflowFn.name}`),
    witness(sourceOfFunction(outflowFn), outflowFn, `${contract.name}.${outflowFn.name}`),
  ];

  // Classify external contract/interface/token calls inside the inflow/outflow pair.
  // Acquired-source ERC20 token fixtures can be deployed locally; all other external
  // protocol interfaces (IComptroller, ILendingPool, IExternalBook, etc.) must refuse
  // explicitly with unresolved_dependency.
  const mockToken = findRepositoryMockToken(sources);
  const stateDeclsForExt = allNodes
    .filter((n: any) => n.type === 'StateVariableDeclaration')
    .flatMap((n: any) => n.variables || [])
    .filter((v: any) => v?.name);
  const externalContractVars = new Set<string>(
    stateDeclsForExt
      .filter((v: any) => v?.typeName?.type === 'UserDefinedTypeName')
      .map((v: any) => String(v.name)),
  );
  const erc20TypeRe = /^(?:I?ERC20(?:Upgradeable|Detailed|Burnable|Mintable)?|ERC20Mock|MockERC20|MockToken|TestToken)$/i;
  const erc20VarNameRe = /^(?:token|stablecoin|underlying|asset|stakingToken|depositToken|erc20|mph)$/i;
  const erc20StateVars = new Set<string>(
    stateDeclsForExt
      .filter((v: any) => {
        const tName = v?.typeName?.type === 'UserDefinedTypeName' ? String(v.typeName.namePath || '') : '';
        return erc20TypeRe.test(tName) || (v?.typeName?.type === 'UserDefinedTypeName' && erc20VarNameRe.test(String(v.name)));
      })
      .map((v: any) => String(v.name)),
  );
  const erc20MethodsRe = /^(?:safeTransferFrom|transferFrom|safeTransfer|transfer|approve|safeApprove|safeIncreaseAllowance|safeDecreaseAllowance|balanceOf|allowance)$/;
  const unresolvedExt: string[] = [];
  let usesErc20Transfer = false;
  const externalCallRe = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  const knownExternalMethods = /^(?:safeTransferFrom|transferFrom|safeTransfer|deposit|withdraw|mint|burn|accrue|borrow|repay|liquidate|swap|getPrice|latestRoundData|credit|debit|quote|notifyRewardAmount|claimComp|redeem|redeemUnderlying)$/;
  let extMatch: RegExpExecArray | null;
  while ((extMatch = externalCallRe.exec(combinedBody)) !== null) {
    const recv = extMatch[1];
    const fnCalled = extMatch[2];
    if (['msg', 'abi', 'this', 'super', 'payable', 'block', 'tx', 'type', 'Math', 'SafeMath', 'SafeCast', 'Address'].includes(recv)) {
      continue;
    }
    const isErc20Call =
      erc20MethodsRe.test(fnCalled) &&
      (erc20StateVars.has(recv) || erc20VarNameRe.test(recv) || /^(?:I?ERC20|SafeERC20)$/i.test(recv));
    if (isErc20Call) {
      usesErc20Transfer = true;
      if (!mockToken) {
        unresolvedExt.push(`${recv}.${fnCalled}`);
      }
      continue;
    }
    if (externalContractVars.has(recv) || knownExternalMethods.test(fnCalled)) {
      unresolvedExt.push(`${recv}.${fnCalled}`);
    }
  }
  const dependencyPlan=resolveSourceFixtureDependencies(snapshot,contract.name,
    [...sources.values()],{choiceByType:fixtureChoices});
  const unresolvedRemaining=unresolvedExt.filter(call=>{
    if(dependencyPlan.status!=="resolved")return true;
    const [recv,methodCalled]=call.split('.');
    const binding=dependencyPlan.bindings.find(b=>b.receiver===recv);
    if(!binding||dependencyPlan.substitutions[recv]!=='$deployment:'+binding.deploymentId)return true;
    const deployment=dependencyPlan.deployments.find(d=>d.id===binding.deploymentId);
    if(!deployment)return true;
    return !verifyAcquiredReceiverMethods(binding.typeName,[methodCalled],
      deployment.file,deployment.contract,[...sources.values()]).ok;
  });
  if (unresolvedRemaining.length > 0) {
    return {
      ok: false,
      category: 'unresolved_dependency',
      reason: `Unresolved external dependency (${unresolvedRemaining.slice(0, 3).join(', ')}) inside ${contract.name}.${inflowFn.name}/${outflowFn.name}; acquired-source fixture: ${dependencyPlan.status==='unresolved'?dependencyPlan.missingDependencies.join(', '):'receiver not bound to concrete constructor parameter'}`,
      witnesses: pairWitnesses,
    };
  }

  // Inspect declared accounting state variables and verify public observable getters exist
  const stateDecls = allNodes
    .filter((n: any) => n.type === 'StateVariableDeclaration')
    .flatMap((n: any) => n.variables || [])
    .filter((v: any) => v?.name);
  // The paired transition is established by opposite source-witnessed writes,
  // but a second ledger may be updated on only one side: that missing write
  // is precisely the falsifiable BuggyVault-style conservation violation.
  // Retain every state written by either operation, with ABI shape from AST.
  const pairedStates=new Set([
    ...targetEffect.plus,...targetEffect.minus,
    ...effects.get(counterpart.fn)!.plus,...effects.get(counterpart.fn)!.minus,
  ]);
  const accountingStateVars=stateDecls.filter((v:any)=>pairedStates.has(String(v.name)));
  const publicTotal=accountingStateVars.find((v:any)=>v.visibility==="public"&&
    v.typeName?.type==="ElementaryTypeName"&&
    /^uint(?:[0-9]+)?$/.test(String(v.typeName.name||"")));
  const publicBalance=accountingStateVars.find((v:any)=>v.visibility==="public"&&
    v.typeName?.type==="Mapping"&&v.typeName.keyType?.name==="address"&&
    /^uint(?:[0-9]+)?$/.test(String(v.typeName.valueType?.name||"")));
  // Solidity generates a getter for a public state declaration even if the
  // controller's function menu omitted the compiler-generated entry.
  const totalGetterDecl=publicTotal?
    {operation:"call" as const,selector:contract.name+"."+publicTotal.name,inputs:[] as string[]}:undefined;
  const balanceGetterDecl=publicBalance?
    {operation:"call" as const,selector:contract.name+"."+publicBalance.name,inputs:["address"]}:undefined;

  // Source-backed collection and struct-return observations are distinct from
  // scalar balance getters. Admit only a directly witnessed transition.
  const sourceObservations=extractAccountingObservations(snapshot,contract.name,declarations);
  const findTypedObservation=():SourceInvariantTransitionPlan['typedObservation']|undefined=>{
    for(const observation of sourceObservations){
      const {push,pop,fieldDecrement}=accountingTransitionPatterns(observation.stateVariable,observation.kind==='struct_field'?observation.fieldName:'');
      if(observation.kind==='collection_length' && push.test(inflowBody) && pop.test(outflowBody))
        return {getter:observation.getter,args:[],baseline:'0',afterInflow:'1',afterOutflow:'0'};
      // A struct field check requires literal storage updates witnessed in both
      // operations. A shared variable name or ABI compatibility is insufficient.
      if(observation.kind==='struct_field' && observation.keyType.startsWith('uint') &&
         push.test(inflowBody) &&
         fieldDecrement.test(outflowBody)){
        return {getter:observation.getter,args:['0'],expectPath:[observation.fieldIndex],
          baseline:'0',afterInflow:'1000',afterOutflow:'600'};
      }
    }
    return undefined;
  };
  const typedObservation=(!totalGetterDecl&&!balanceGetterDecl)?findTypedObservation():undefined;
  if (!totalGetterDecl && !balanceGetterDecl && !typedObservation) {
    return {
      ok: false,
      category: 'missing_observable_state',
      reason: accountingStateVars.length
        ? `Accounting state (${accountingStateVars.map((v: any) => v.name).join(', ')}) has no public observable getter declared in ${contract.name}`
        : `No observable public accounting state getter found in ${contract.name}`,
      witnesses: pairWitnesses,
    };
  }

  const totalVarName = totalGetterDecl ? totalGetterDecl.selector.slice(contract.name.length + 1) : '';
  const balanceVarName = balanceGetterDecl ? balanceGetterDecl.selector.slice(contract.name.length + 1) : '';
  const totalReferenced = !!totalVarName && new RegExp(`\\b${totalVarName}\\b`).test(combinedBody);
  const balanceReferenced = !!balanceVarName && new RegExp(`\\b${balanceVarName}\\b`).test(combinedBody);
  if (!totalReferenced && !balanceReferenced && !typedObservation) {
    return {
      ok: false,
      category: 'missing_observable_state',
      reason: `Declared getters are not referenced by ${contract.name}.${inflowFn.name}/${outflowFn.name}`,
      witnesses: pairWitnesses,
    };
  }

  // Verify local fixture constructibility via existing resolveFlexibleSetup (wiring acquired mockToken when present)
  const setup = resolveFlexibleSetup(snapshot, contract, chain, sources, declarations, mockToken, '$account0',
    dependencyPlan.status==='resolved'?dependencyPlan.substitutions:{});
  if (!setup) {
    return {
      ok: false,
      category: 'missing_fixture',
      reason: `Constructor or initializer fixture for ${contract.name} cannot be instantiated with local accounts`,
      witnesses: pairWitnesses,
    };
  }
  if (usesErc20Transfer && (!mockToken || !setup.usesToken)) {
    return {
      ok: false,
      category: 'missing_fixture',
      reason: `ERC20 token transfer in ${contract.name}.${inflowFn.name}/${outflowFn.name} requires a configurable token fixture wired via constructor or initializer`,
      witnesses: pairWitnesses,
    };
  }

  const declarationFor=(fn:any)=>declarations.find(d=>d.operation==='send' &&
    d.selector===contract.name+'.'+fn.name &&
    JSON.stringify(d.inputs)===JSON.stringify((fn.parameters||[])
      .map((p:any)=>canonicalAbiType(p.typeName))));
  const inflowDecl = declarationFor(inflowFn);
  const outflowDecl = declarationFor(outflowFn);
  if (!inflowDecl || !outflowDecl) {
    return {
      ok: false,
      category: 'missing_fixture',
      reason: `Missing ABI send declarations for ${contract.name}.${inflowFn.name} / ${outflowFn.name}`,
      witnesses: pairWitnesses,
    };
  }

  const isUintType = (t: string) => /^uint(?:[0-9]{1,3})?$/.test(t);
  const inflowAmount = '1000';
  const outflowAmount = '400';
  const expectedRemainder = '600';

  let mode: SourceInvariantTransitionPlan['mode'] | null = null;
  let inflowArgs: string[] = [];
  let inflowValueWei: string | undefined;
  let outflowArgs: string[] = [];

  // Mode A: Payable ETH deposit() + withdraw(uint256)
  if (
    inflowFn.stateMutability === 'payable' &&
    inflowDecl.inputs.length === 0 &&
    outflowDecl.inputs.length === 1 &&
    isUintType(outflowDecl.inputs[0])
  ) {
    mode = 'eth_deposit_withdraw';
    inflowArgs = [];
    inflowValueWei = inflowAmount;
    outflowArgs = [outflowAmount];
  }
  // Mode B: Mint/Burn supply accounting: mint(address,uint256) or mint(uint256) + burn(uint256) or burn(address,uint256)
  else if (/^mint$/i.test(inflowFn.name) && /^burn$/i.test(outflowFn.name)) {
    if (inflowDecl.inputs.length === 2 && inflowDecl.inputs[0] === 'address' && isUintType(inflowDecl.inputs[1])) {
      inflowArgs = ['$account0', inflowAmount];
    } else if (inflowDecl.inputs.length === 1 && isUintType(inflowDecl.inputs[0])) {
      inflowArgs = [inflowAmount];
    } else {
      return {
        ok: false,
        category: 'missing_fixture',
        reason: `Unsupported mint parameter signature (${inflowDecl.inputs.join(',')}) for ${contract.name}.mint`,
        witnesses: pairWitnesses,
      };
    }
    if (outflowDecl.inputs.length === 2 && outflowDecl.inputs[0] === 'address' && isUintType(outflowDecl.inputs[1])) {
      outflowArgs = ['$account0', outflowAmount];
    } else if (outflowDecl.inputs.length === 1 && isUintType(outflowDecl.inputs[0])) {
      outflowArgs = [outflowAmount];
    } else {
      return {
        ok: false,
        category: 'missing_fixture',
        reason: `Unsupported burn parameter signature (${outflowDecl.inputs.join(',')}) for ${contract.name}.burn`,
        witnesses: pairWitnesses,
      };
    }
    mode = 'mint_burn_supply';
  }
  // Mode C/D: Internal or acquired-ERC20 deposit(uint256)/stake(uint256) + withdraw(uint256)/unstake(uint256)
  else if (
    inflowDecl.inputs.length === 1 &&
    isUintType(inflowDecl.inputs[0]) &&
    outflowDecl.inputs.length === 1 &&
    isUintType(outflowDecl.inputs[0])
  ) {
    mode = usesErc20Transfer ? 'erc20_deposit_withdraw' : 'internal_deposit_withdraw';
    inflowArgs = [inflowAmount];
    outflowArgs = [outflowAmount];
  } else {
    return {
      ok: false,
      category: 'missing_fixture',
      reason: `Unsupported inflow/outflow signatures (${inflowFn.name}(${inflowDecl.inputs.join(',')}) / ${outflowFn.name}(${outflowDecl.inputs.join(',')}))`,
      witnesses: pairWitnesses,
    };
  }

  // Numeric 1000/400/600 assertions apply only when the acquired source
  // proves direct matching updates without fees, exchange rates or accrual.
  // Contracts with dynamic economics require a separate measured property.
  const accountingTarget=totalReferenced?totalVarName:balanceReferenced?balanceVarName:'';
  const amountParameter=(fn:any)=>String((fn.parameters||[]).find((param:any)=>
    /^uint(?:[0-9]+)?$/.test(String(param.typeName?.name||'')))?.name||'');
  const inflowParameter=amountParameter(inflowFn);
  const outflowParameter=amountParameter(outflowFn);
  const inflowEffects=reachableAccountingSource(snapshot,contract,inflowFn,sources);
  const outflowEffects=reachableAccountingSource(snapshot,contract,outflowFn,sources);
  const directlyProven=accountingTarget&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(accountingTarget)&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(inflowParameter)&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(outflowParameter)&&
    sourceExactAccountingDelta(inflowEffects,accountingTarget,inflowParameter,"increase")&&
    sourceExactAccountingDelta(outflowEffects,accountingTarget,outflowParameter,"decrease")&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  // A payable deposit and ETH withdrawal can independently establish
  // conservation from the caller balance and the actual transferred value.
  // This detects a missing aggregate-ledger decrement (the BuggyVault case)
  // instead of demanding the correct decrement already exist in the source.
  const matchingBalance=balanceReferenced&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(balanceVarName)&&
    sourceExactAccountingDelta(inflowEffects,balanceVarName,"msg.value","increase","msg.sender")&&
    sourceExactAccountingDelta(outflowEffects,balanceVarName,outflowParameter,"decrease","msg.sender");
  const coupledPayableConservation=totalReferenced&&
    inflowFn.stateMutability==='payable'&&inflowFn.parameters.length===0&&
    outflowFn.parameters.length===1&&/^uint/.test(String(outflowFn.parameters[0]?.typeName?.name||''))&&
    sourceExactAccountingDelta(inflowEffects,totalVarName,"msg.value","increase")&&
    matchingBalance&&
    new RegExp("\\bvalue\\s*:\\s*"+outflowParameter+"\\b").test(outflowEffects)&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  // ERC20 principal conservation remains falsifiable even if the aggregate
  // ledger update is missing: a source-witnessed transfer and per-user
  // liability decrement must be balanced by the aggregate total.
  const matchedTokenPrincipal=totalReferenced&&balanceReferenced&&usesErc20Transfer&&
    !!mockToken&&setup.usesToken&&
    inflowFn.parameters.length===1&&outflowFn.parameters.length===1&&
    /^uint/.test(String(inflowFn.parameters[0]?.typeName?.name||''))&&
    /^uint/.test(String(outflowFn.parameters[0]?.typeName?.name||''))&&
    sourceExactAccountingDelta(inflowEffects,totalVarName,inflowParameter,"increase")&&
    sourceExactAccountingDelta(inflowEffects,balanceVarName,inflowParameter,"increase","msg.sender")&&
    sourceExactAccountingDelta(outflowEffects,balanceVarName,outflowParameter,"decrease","msg.sender")&&
    /\.\s*(?:safeTransferFrom|transferFrom)\s*\(/.test(inflowEffects)&&
    /\.\s*(?:safeTransfer|transfer)\s*\(/.test(outflowEffects)&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  // A source-proven per-user debit must reduce the shared aggregate when
  // both ledgers were increased together. Its omission remains falsifiable.
  const matchedInternalPrincipal=totalReferenced&&balanceReferenced&&!usesErc20Transfer&&
    !!inflowParameter&&!!outflowParameter&&
    sourceExactAccountingDelta(inflowEffects,totalVarName,inflowParameter,"increase")&&
    sourceExactAccountingDelta(inflowEffects,balanceVarName,inflowParameter,"increase","msg.sender")&&
    sourceExactAccountingDelta(outflowEffects,balanceVarName,outflowParameter,"decrease","msg.sender")&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  if(!directlyProven&&!coupledPayableConservation&&!matchedTokenPrincipal&&!matchedInternalPrincipal){
    return {ok:false,category:'no_supported_property',
      reason:'Fixed-value conservation was not source-proven for '+contract.name+'.'+
        inflowFn.name+'/'+outflowFn.name+'; requires a property-specific measured scenario.',
      witnesses:pairWitnesses};
  }

  const totalGetterSig = totalReferenced ? `${totalVarName}()` : undefined;
  const balanceGetterSig = balanceReferenced ? `${balanceVarName}(address)` : undefined;
  const propertyKind: InvariantPropertyKind =
    mode === 'mint_burn_supply' || /supply/i.test(totalVarName)
      ? 'supply-accounting'
      : /share/i.test(totalVarName) || /share/i.test(balanceVarName)
        ? 'share-accounting'
        : 'conservation';

  const preState: Array<{ expression: string; readback: string }> = [];
  const postState: Array<{ expression: string; readback: string }> = [];
  if (totalGetterSig) {
    preState.push({ expression: `${contract.name}.${totalVarName} == 0`, readback: totalGetterSig });
    postState.push({ expression: `${contract.name}.${totalVarName} == ${expectedRemainder}`, readback: totalGetterSig });
  }
  if (balanceGetterSig) {
    preState.push({ expression: `${contract.name}.${balanceVarName}[$account0] == 0`, readback: balanceGetterSig });
    postState.push({ expression: `${contract.name}.${balanceVarName}[$account0] == ${expectedRemainder}`, readback: balanceGetterSig });
  }

  const inflowSig = `${inflowFn.name}(${inflowDecl.inputs.join(',')})`;
  const outflowSig = `${outflowFn.name}(${outflowDecl.inputs.join(',')})`;
  const obsList = [totalGetterSig, balanceGetterSig, typedObservation?.getter].filter(Boolean).join(' and ');
  if(typedObservation){
    preState.push({expression:`${contract.name}.${typedObservation.getter} == ${typedObservation.baseline}`,readback:typedObservation.getter});
    postState.push({expression:`${contract.name}.${typedObservation.getter} == ${typedObservation.afterOutflow}`,readback:typedObservation.getter});
  }

  return {
    ok: true,
    invariant: {
      sourceSha256: snapshot.sha256,
      target: `${contract.name}.${method}`,
      companionTarget: `${contract.name}.${method === inflowFn.name ? outflowFn.name : inflowFn.name}`,
      propertyKind,
      predictedRelation: `After ${inflowSig} (${inflowAmount}) followed by ${outflowSig} (${outflowAmount}) by $account0, ${obsList} must equal ${expectedRemainder}.`,
      falsifier: `Execute ${inflowSig} (+${inflowAmount}) then ${outflowSig} (-${outflowAmount}) on a fresh local EVM; violation observed if ${obsList} diverges from ${expectedRemainder}.`,
      preState,
      postState,
      witnesses: pairWitnesses,
      transitionPlan: {
        mode,
        ...(mode === 'erc20_deposit_withdraw' ? { usesMockToken: true } : {}),
        inflowMethod: inflowFn.name,
        inflowSig,
        inflowArgs,
        inflowValueWei,
        outflowMethod: outflowFn.name,
        outflowSig,
        outflowArgs,
        inflowAmount,
        outflowAmount,
        expectedRemainder,
        balanceMappingGetter: balanceGetterSig,
        totalScalarGetter: totalGetterSig,
        typedObservation,
        ...(dependencyPlan.status==='resolved'&&dependencyPlan.deployments.length?{
          dependencyDeployments:dependencyPlan.deployments,
          dependencyInitializerOperations:dependencyPlan.initializerOperations,
          dependencyBindings:dependencyPlan.substitutions,
        }:{}),
      },
    },
  };
}

/**
 * Step 2: Admission gate for source-proven financial invariants.
 * Refuses to admit descriptors lacking cryptographic identity, observable pre/post
 * state readbacks, or a mathematically consistent executable transition plan.
 */
export function admitSourceInvariantDescriptor(
  invariant: SourceInvariant | null | undefined,
): SourceInvariant | null {
  if (
    !invariant ||
    !/^[a-f0-9]{64}$/.test(invariant.sourceSha256) ||
    !invariant.target ||
    !invariant.predictedRelation.trim() ||
    !invariant.falsifier.trim() ||
    !invariant.preState.length ||
    !invariant.postState.length ||
    !invariant.transitionPlan
  ) {
    return null;
  }
  const tp = invariant.transitionPlan;
  if (!tp.totalScalarGetter && !tp.balanceMappingGetter && !tp.typedObservation) return null;
  if(tp.typedObservation && (!tp.typedObservation.getter||
    ![tp.typedObservation.baseline,tp.typedObservation.afterInflow,tp.typedObservation.afterOutflow].every(v=>/^(?:0|[1-9][0-9]*)$/.test(v))))return null;
  if (!/^[1-9][0-9]*$/.test(tp.inflowAmount) || !/^[1-9][0-9]*$/.test(tp.outflowAmount) || !/^(?:0|[1-9][0-9]*)$/.test(tp.expectedRemainder)) {
    return null;
  }
  if (BigInt(tp.inflowAmount) - BigInt(tp.outflowAmount) !== BigInt(tp.expectedRemainder)) {
    return null;
  }
  return invariant;
}

/**
 * Step 3: Convert an admitted source-backed financial invariant descriptor into
 * a strict, schema-valid local SoliditySequence experiment.
 */
export function constructCoreInvariantExperiment(
  invariant: SourceInvariant | null,
  snapshot: SourceSnapshot,
  contract: any,
  declarations: readonly SolidityProbeDeclaration[],
  sources: ReadonlyMap<string, SourceSnapshot>,
): { hypothesis: string; property: string; sequence: SoliditySequence; witnesses: SourceWitness[] } | null {
  const admitted = admitSourceInvariantDescriptor(invariant);
  if (!admitted || admitted.sourceSha256 !== snapshot.sha256) return null;
  const tp = admitted.transitionPlan!;
  const { chain } = resolveInheritance(snapshot, contract, sources);
  const mockToken = tp.usesMockToken || tp.mode === 'erc20_deposit_withdraw' ? findRepositoryMockToken(sources) : null;
  const setup = resolveFlexibleSetup(snapshot, contract, chain, sources, declarations, mockToken, '$account0',tp.dependencyBindings||{});
  if (!setup) return null;
  if(tp.typedObservation){
    const observed=extractAccountingObservations(snapshot,contract.name,declarations);
    const supported=observed.some(obs=>obs.getter===tp.typedObservation!.getter &&
      (tp.typedObservation!.expectPath===undefined ||
       (obs.kind==='struct_field'&&tp.typedObservation!.expectPath.length===1&&
        tp.typedObservation!.expectPath[0]===obs.fieldIndex)));
    if(!supported)return null;
  }
  if (tp.mode === 'erc20_deposit_withdraw' && (!mockToken || !setup.usesToken)) return null;

  const deployments=[
    ...(setup.usesToken&&mockToken?[{
      id:'token',file:mockToken.snapshot.path,contract:mockToken.contractName,
      constructorArgs:mockToken.constructorArgs,
    }]:[]),
    ...(tp.dependencyDeployments||[]),
  ];
  const preparation=deployments.length?{deployments,
    operations:(tp.dependencyInitializerOperations||[]).map(x=>({...x})),checks:[]}:undefined;


  const steps: SoliditySequence['steps'] = [];
  if (setup.initSignature) {
    steps.push({
      operation: 'send',
      function: setup.initSignature,
      args: setup.initArgs,
      sender: 0,
      requiredSetup: true,
    });
  }
  if (tp.mode === 'erc20_deposit_withdraw' && mockToken) {
    const mintAmount = '10000';
    if (mockToken.mintHasRecipient) {
      steps.push({
        operation: 'send',
        deploymentId: 'token',
        function: mockToken.mintSig,
        args: ['$account0', mintAmount],
        sender: 0,
        requiredSetup: true,
      });
    } else {
      steps.push({
        operation: 'send',
        deploymentId: 'token',
        function: mockToken.mintSig,
        args: [mintAmount],
        sender: 0,
        requiredSetup: true,
      });
    }
    steps.push({
      operation: 'send',
      deploymentId: 'token',
      function: 'approve(address,uint256)',
      args: ['$contract', mintAmount],
      sender: 0,
      requiredSetup: true,
    });
  }
  const typedReadback=(expected:string):SoliditySequence['steps'][number]|null=>
    tp.typedObservation?{operation:'call',function:tp.typedObservation.getter,
      args:tp.typedObservation.args,expect:expected,
      ...(tp.typedObservation.expectPath?{expectPath:tp.typedObservation.expectPath}:{})}:null;
  // 1. Pre-state baseline readbacks
  const preTyped=typedReadback(tp.typedObservation?.baseline||'');
  if(preTyped)steps.push(preTyped);
  if (tp.totalScalarGetter) {
    steps.push({ operation: 'call', function: tp.totalScalarGetter, args: [], expect: '0' });
  }
  if (tp.balanceMappingGetter) {
    steps.push({ operation: 'call', function: tp.balanceMappingGetter, args: ['$account0'], expect: '0' });
  }
  // 2. Inflow operation (+inflowAmount)
  steps.push({
    operation: 'send',
    function: tp.inflowSig,
    args: tp.inflowArgs,
    sender: 0,
    ...(tp.inflowValueWei ? { valueWei: tp.inflowValueWei } : {}),
  });
  // 3. Intermediate accounting check (+inflowAmount)
  if (tp.totalScalarGetter) {
    steps.push({ operation: 'call', function: tp.totalScalarGetter, args: [], expect: tp.inflowAmount });
  }
  if (tp.balanceMappingGetter) {
    steps.push({ operation: 'call', function: tp.balanceMappingGetter, args: ['$account0'], expect: tp.inflowAmount });
  }
  const midTyped=typedReadback(tp.typedObservation?.afterInflow||'');
  if(midTyped)steps.push(midTyped);
  // 4. Outflow operation (-outflowAmount)
  steps.push({
    operation: 'send',
    function: tp.outflowSig,
    args: tp.outflowArgs,
    sender: 0,
  });
  const postTyped=typedReadback(tp.typedObservation?.afterOutflow||'');
  if(postTyped)steps.push(postTyped);
  // 5. Post-state conservation / supply-accounting assertions (== expectedRemainder)
  if (tp.totalScalarGetter) {
    steps.push({ operation: 'call', function: tp.totalScalarGetter, args: [], expect: tp.expectedRemainder });
  }
  if (tp.balanceMappingGetter) {
    steps.push({ operation: 'call', function: tp.balanceMappingGetter, args: ['$account0'], expect: tp.expectedRemainder });
  }

  return {
    hypothesis: admitted.predictedRelation,
    property: `financial ${admitted.propertyKind} invariant (${tp.inflowMethod}->${tp.outflowMethod})`,
    sequence: {
      constructorArgs: setup.constructorArgs,
      ...(setup.constructorValueWei ? { constructorValueWei: setup.constructorValueWei } : {}),
      ...(preparation ? { preparation } : {}),
      steps,
    },
    witnesses: admitted.witnesses?.length ? admitted.witnesses : [witness(snapshot, contract, admitted.target)],
  };
}


/** General source-defined public scalar increment, independent of function
 * names. The isolated EVM will verify the actual prestate, transaction receipt
 * and poststate, while the independent verifier checks the source predicate.
 * Never infer security behavior from a mock or an external protocol call.
 */
function sourceScalarDeltaExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const counters=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      identifier.test(v.name||'')&&
      v.typeName?.type==='ElementaryTypeName'&&
      /^uint(?:[0-9]{1,3})?$/.test(v.typeName.name||'')&&!v.expression);
  if(!counters.length)return [];
  // A private/internal scalar can be measured only when the acquired source
  // explicitly declares an independent view/pure return of that same state.
  // Arbitrary functions with related names are not accepted as readbacks.
  const observations=extractAccountingObservations(snapshot,contract.name,declarations);
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,
    sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const constructor=nodes.find(n=>n.type==='FunctionDefinition'&&n.isConstructor);
  const bodySource=snapshot.content;
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];
  for(const fn of nodes.filter(n=>n.type==='FunctionDefinition'&&n.body&&n.name===method&&
    ['public','external'].includes(n.visibility))){
    const inputs=(fn.parameters||[]).map((p:any)=>canonicalAbiType(p.typeName));
    if(inputs.length!==1||!inputs[0]||!/^uint(?:[0-9]{1,3})?$/.test(inputs[0]))continue;
    const param=fn.parameters[0];
    if(!identifier.test(param.name||''))continue;
    const signature=fn.name+'('+inputs[0]+')';
    if(!declarations.some(d=>d.operation==='send'&&
      d.selector===contract.name+'.'+method&&
      JSON.stringify(d.inputs)===JSON.stringify(inputs)))continue;
    const modifiers=(fn.modifiers||[]).map((m:any)=>String(m.name||''));
    if(modifiers.some((m:string)=>/(?:only|owner|admin|auth|role|minter|permission)/i.test(m)))continue;
    const fnText=body(bodySource,fn)
      .replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,'');
    // Other contract calls create additional fixture prerequisites. Refuse until
    // their actual implementations and preconditions have been connected.
    if(/\b(?!msg\b|block\b|abi\b)[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(/.test(fnText)||
      /\)\s*\.\s*[A-Za-z_]\w*\s*\(/.test(fnText))continue;
    for(const state of counters){
      if(constructor&&new RegExp('\\b'+state.name+'\\s*(?:\\+?=|-=)').test(body(bodySource,constructor)))continue;
      if(setup.initSignature){
        const init=nodes.find(n=>n.type==='FunctionDefinition'&&
          (n.name==='initialize'||n.name==='init')&&n.body);
        if(init&&new RegExp('\\b'+state.name+'\\s*(?:\\+?=|-=)').test(body(bodySource,init)))continue;
      }
      // Reuse exact-lvalue source accounting proof for assignment and SafeMath
      // forms. Never equate a different storage key or symbol with this state.
      if(!sourceExactAccountingDelta(fnText,state.name,param.name,'increase'))continue;
      const observed=observations.find(o=>o.kind==='scalar'&&
        o.stateVariable===state.name);
      const getter=state.visibility==='public'?state.name+'()':observed?.getter;
      if(!getter)continue;
      const width=Number(inputs[0].replace(/\D/g,''))||256;
      const amount=width<=8?'100':'1000';
      const steps:SoliditySequence['steps']=[];
      if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,
        args:setup.initArgs,sender:0,requiredSetup:true});
      steps.push({operation:'call',function:getter,args:[],expect:'0'});
      steps.push({operation:'send',function:signature,args:[amount],sender:0});
      steps.push({operation:'call',function:getter,args:[],expect:amount});
      out.push({
        hypothesis:'Source-declared increment of '+state.name+' by '+param.name+
          ' must produce '+amount+' from an initial zero state for '+contract.name+'.'+signature,
        property:'source-defined bounded scalar conservation '+contract.name+'.'+signature+':'+state.name,
        sequence:{constructorArgs:setup.constructorArgs,
          ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
          sourceProperty:{kind:'scalar_delta',state:state.name,method:signature,
            parameter:param.name,amount,direction:'increase',sourceSha256:snapshot.sha256},
          steps},
        witnesses:[witness(snapshot,fn,contract.name+'.'+signature),
          witness(snapshot,state,contract.name+'.'+state.name),
          ...(state.visibility==='public'?[]:(nodes.filter((n:any)=>
            n.type==='FunctionDefinition'&&n.name===getter.split('(')[0]&&n.body)
            .map((n:any)=>witness(snapshot,n,contract.name+'.'+getter))))],
      });
    }
  }
  return out;
}


/** Construct falsifiable source-grounded mapping/account state transitions.
 * Exact storage-key identity prevents claiming a credit to Alice from an
 * update to Bob's entry. EVM receipts and readbacks remain mandatory. */
function sourceMappingDeltaExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const maps=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      v.visibility==='public'&&identifier.test(v.name||'')&&
      v.typeName?.type==='Mapping'&&v.typeName.keyType?.name==='address'&&
      v.typeName.valueType?.type==='ElementaryTypeName'&&
      /^uint(?:[0-9]{1,3})?$/.test(String(v.typeName.valueType.name||'')));
  if(!maps.length)return [];
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];
  for(const fn of nodes.filter(n=>n.type==='FunctionDefinition'&&n.body&&
    n.name===method&&['public','external'].includes(n.visibility)&&
    !['view','pure'].includes(n.stateMutability||''))){
    if((fn.modifiers||[]).length)continue;
    const params:any[]=fn.parameters||[];
    if(!params.length||params.length>5)continue;
    const types=params.map(p=>canonicalAbiType(p.typeName));
    if(types.some(x=>!x)||!declarations.some(d=>
      d.selector===contract.name+'.'+fn.name&&d.operation==='send'&&
      JSON.stringify(d.inputs)===JSON.stringify(types)))continue;
    const methodSource=body(snapshot.content,fn);
    // Calls into an external protocol need a separately proven receiver and
    // preparation. Pure SafeMath operations on the same lvalue are allowed.
    if(/\b(?!msg\b|block\b|abi\b|SafeMath\b)[A-Za-z_]\w*\s*\.\s*(?!add\b|sub\b)[A-Za-z_]\w*\s*\(/.test(methodSource)||
      /\)\s*\.\s*[A-Za-z_]\w*\s*\(/.test(methodSource))continue;
    const numeric=params.filter((p,i)=>
      identifier.test(p.name||'')&&/^uint(?:[0-9]{1,3})?$/.test(types[i]||''));
    const accountKeys=params.filter((p,i)=>
      identifier.test(p.name||'')&&types[i]==='address').map(p=>p.name);
    for(const variable of maps)for(const key of ['msg.sender',...accountKeys]){
      for(const amountParam of numeric){
        if(!sourceExactAccountingDelta(methodSource,variable.name,
          amountParam.name,'increase',key))continue;
        const args:SolidityArgValue[]=[];
        let supported=true;
        for(let i=0;i<params.length;i++){
          const p=params[i];
          const value:SolidityArgValue|null=
            p.name===amountParam.name?'1':p.name===key?'$account2':
              pickFlexibleArg(types[i]||'',p.name||'',
                {ownerAccount:'$account0',amount:'1'});
          if(value===null){supported=false;break;}
          args.push(value);
        }
        if(!supported)continue;
        const targetKey=key==='msg.sender'?'$account0':'$account2';
        const signature=canonicalFunctionIdentity(fn);
        // A checked increase with an acquired supply precondition must be
        // funded before testing. Executing it against zero supply yields a
        // revert observation, not an experiment on its source-defined branch.
        // Admit a funding pathway only when both independent storage writes
        // and the guard are visible in the same acquired contract.
        const totals=nodes.filter(n=>n.type==='StateVariableDeclaration')
          .flatMap(n=>n.variables||[]).filter((v:any)=>
            v.visibility==='public'&&identifier.test(v.name||'')&&
            v.typeName?.type==='ElementaryTypeName'&&
            /^uint(?:[0-9]{1,3})?$/.test(v.typeName.name||''));
        const constrained=totals.find(total=>{
          const amount=String(amountParam.name);
          const state=String(total.name);
          return new RegExp(String.raw`\b`+amount+
            String.raw`\s*>\s*0\s*&&\s*`+amount+
            String.raw`\s*<=\s*`+state).test(methodSource)&&
            sourceExactAccountingDelta(methodSource,total.name,amountParam.name,'decrease');
        });
        if(constrained){
          const candidate=nodes.filter(n=>n.type==='FunctionDefinition'&&
            n.name!==method&&n.body&&['external','public'].includes(n.visibility)&&
            !(n.modifiers||[]).length&&(n.parameters||[]).length===2);
          const acquiredFunding=candidate.flatMap((fund:any)=>{
            const p:any[]=fund.parameters||[];
            if(canonicalAbiType(p[0].typeName)!=='address'||
              !/^uint(?:[0-9]{1,3})?$/.test(canonicalAbiType(p[1].typeName)||'')||
              !identifier.test(p[0].name||'')||!identifier.test(p[1].name||''))
              return [];
            const sig=canonicalFunctionIdentity(fund);
            if(!declarations.some(d=>d.selector===contract.name+'.'+fund.name&&
              d.operation==='send'&&JSON.stringify(d.inputs)===
                JSON.stringify([canonicalAbiType(p[0].typeName),canonicalAbiType(p[1].typeName)])))
              return [];
            const text=body(snapshot.content,fund);
            const bound=text.match(new RegExp(
              String.raw`\buint(?:256)?\s+([A-Za-z_]\w*)\s*=\s*`+
              p[1].name+String.raw`\s*\.\s*bounded\s*\(`));
            const amountValue=bound?.[1]||p[1].name;
            if(!sourceExactAccountingDelta(text,variable.name,amountValue,'increase',p[0].name)||
              !sourceExactAccountingDelta(text,constrained.name,amountValue,'increase'))
              return [];
            return [{fund,signature:sig}];
          });
          if(acquiredFunding.length!==1)continue;
          if(key==='msg.sender')continue;
          const evidence=acquiredFunding[0];
          const prepared:SoliditySequence['steps']=[];
          if(setup.initSignature)prepared.push({
            operation:'send',function:setup.initSignature,args:setup.initArgs,
            sender:0,requiredSetup:true});
          // The EVM itself establishes role eligibility: no guessed
          // administrator identity substitutes for the actual operator getter.
          if(/require\s*\(\s*msg\s*\.\s*sender\s*==\s*operator\b/.test(methodSource)&&
            declarations.some(d=>d.selector===contract.name+'.operator'&&d.operation==='call'))
            prepared.push({operation:'call',function:'operator()',args:[],expect:'$account0'});
          prepared.push({operation:'call',function:constrained.name+'()',args:[],expect:'0'});
          prepared.push({operation:'call',function:variable.name+'(address)',
            args:[targetKey],expect:'0'});
          prepared.push({operation:'send',function:evidence.signature,
            args:[targetKey,'5'],sender:0,requiredSetup:true});
          prepared.push({operation:'call',function:variable.name+'(address)',
            args:[targetKey],expect:'5'});
          prepared.push({operation:'call',function:constrained.name+'()',args:[],expect:'5'});
          prepared.push({operation:'send',function:signature,args,sender:0});
          prepared.push({operation:'call',function:variable.name+'(address)',
            args:[targetKey],expect:'6'});
          prepared.push({operation:'call',function:constrained.name+'()',args:[],expect:'4'});
          out.push({
            hypothesis:'Acquired funding satisfies source total precondition; the selected bounded settlement changes the exact mapping by +1 and total by -1',
            property:'source-funded mapping balance '+contract.name+'.'+signature+':'+variable.name,
            sequence:{constructorArgs:setup.constructorArgs,
              ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
              steps:prepared},
            witnesses:[witness(snapshot,fn,contract.name+'.'+signature),
              witness(snapshot,variable,contract.name+'.'+variable.name),
              witness(snapshot,constrained,contract.name+'.'+constrained.name),
              witness(snapshot,evidence.fund,contract.name+'.'+evidence.signature)],
          });
          continue;
        }
        const steps:SoliditySequence['steps']=[];
        if(setup.initSignature)steps.push({
          operation:'send',function:setup.initSignature,args:setup.initArgs,
          sender:0,requiredSetup:true});
        steps.push({operation:'call',function:variable.name+'(address)',
          args:[targetKey],expect:'0'});
        steps.push({operation:'send',function:signature,args,sender:0});
        steps.push({operation:'call',function:variable.name+'(address)',
          args:[targetKey],expect:'1'});
        out.push({
          hypothesis:'Source-declared update must add 1 to the exact '+
            variable.name+'['+key+'] storage entry',
          property:'source-backed mapping conservation '+contract.name+'.'+
            signature+':'+variable.name+':'+key,
          sequence:{
            constructorArgs:setup.constructorArgs,
            ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
            steps},
          witnesses:[
            witness(snapshot,fn,contract.name+'.'+signature),
            witness(snapshot,variable,contract.name+'.'+variable.name)],
        });
      }
    }
  }
  return out;
}

/** Source-exact interprocedural scalar state update. The external entrypoint
 * passes its only ABI parameter to a unique acquired internal helper that
 * assigns that parameter directly to a concrete storage variable. Readback
 * must be compiler-public or an exact source-returning view, never guessed.
 */
function sourceInternalScalarSetterExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>{
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const states=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      identifier.test(v.name||'')&&v.typeName?.type==='ElementaryTypeName'&&
      /^(?:address|bool|uint(?:[0-9]{1,3})?)$/.test(v.typeName.name||''));
  if(!states.length)return [];
  const views=extractAccountingObservations(snapshot,contract.name,declarations);
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const functions=nodes.filter(n=>n.type==='FunctionDefinition'&&n.body&&n.name);
  const results:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];

  for(const entry of functions.filter(n=>n.name===method&&
    ['public','external'].includes(n.visibility)&&!(n.modifiers||[]).length&&
    !['pure','view'].includes(n.stateMutability||''))){
    const params:any[]=entry.parameters||[];
    if(params.length!==1||!identifier.test(params[0].name||''))continue;
    const type=canonicalAbiType(params[0].typeName);
    if(!type||!['bool','address'].includes(type)&&!
      /^uint(?:[0-9]{1,3})?$/.test(type))continue;
    if(!declarations.some(d=>d.selector===contract.name+'.'+method&&
      d.operation==='send'&&JSON.stringify(d.inputs)===JSON.stringify([type])))
      continue;
    const statements:any[]=entry.body.statements||[];
    const callStmt=statements[0];
    if(statements.length<1||statements.length>2||
      callStmt?.type!=='ExpressionStatement'||
      callStmt.expression?.type!=='FunctionCall'||
      callStmt.expression.expression?.type!=='Identifier')continue;
    if(statements.length===2&&(statements[1].type!=='ReturnStatement'||
      statements[1].expression?.type!=='BooleanLiteral'||
      statements[1].expression.value!==true))continue;
    const invoke=callStmt.expression;
    if(invoke.arguments?.length!==1||invoke.arguments[0]?.type!=='Identifier'||
      invoke.arguments[0]?.name!==params[0].name)continue;
    const helperName=String(invoke.expression.name||'');
    const helpers=functions.filter(n=>n.name===helperName&&
      ['internal','private'].includes(n.visibility)&&
      !(n.modifiers||[]).length&&(n.parameters||[]).length===1&&
      canonicalAbiType(n.parameters[0].typeName)===type);
    if(helpers.length!==1)continue;
    const helper=helpers[0],hp=helper.parameters[0];
    if(!identifier.test(hp.name||''))continue;
    const writes:any[]=helper.body.statements||[];
    if(writes.length!==1||writes[0]?.type!=='ExpressionStatement'||
      writes[0].expression?.type!=='BinaryOperation'||
      writes[0].expression.operator!=='='||
      writes[0].expression.left?.type!=='Identifier'||
      writes[0].expression.right?.type!=='Identifier'||
      writes[0].expression.right.name!==hp.name)continue;
    const state=states.find((v:any)=>v.name===writes[0].expression.left.name&&
      canonicalAbiType(v.typeName)===type);
    if(!state)continue;
    const readback=state.visibility==='public'?state.name+'()':
      views.find(o=>o.kind==='scalar'&&o.stateVariable===state.name)?.getter;
    if(!readback)continue;
    const readFn=functions.find(n=>n.name===readback.split('(')[0]&&n.body);
    const value:SolidityArgValue=type==='bool'?true:
      type==='address'?'$account2':'7';
    const steps:SoliditySequence['steps']=[];
    if(setup.initSignature)steps.push({
      operation:'send',function:setup.initSignature,
      args:setup.initArgs,sender:0,requiredSetup:true});
    steps.push({operation:'observe',function:readback,args:[]});
    steps.push({operation:'send',function:canonicalFunctionIdentity(entry),
      args:[value],sender:0});
    steps.push({operation:'call',function:readback,args:[],expect:value});
    results.push({
      hypothesis:'Exact source helper '+helperName+' writes the input to '+
        state.name+' and its independently source-proven getter must return it',
      property:'source internal state assignment '+contract.name+'.'+
        canonicalFunctionIdentity(entry)+':'+state.name,
      sequence:{constructorArgs:setup.constructorArgs,
        ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
        steps},
      witnesses:[
        witness(snapshot,entry,contract.name+'.'+canonicalFunctionIdentity(entry)),
        witness(snapshot,helper,contract.name+'.'+helperName),
        witness(snapshot,writes[0],contract.name+'.'+helperName+'.assignment'),
        witness(snapshot,state,contract.name+'.'+state.name),
        ...(readFn?[witness(snapshot,readFn,contract.name+'.'+readback)]:[])
      ]
    });
  }
  return results;
}

/** Generalized externally observable source-state assignment. Exact AST
 * lvalue=parameter identity provides an independent postcondition; the
 * pre-state is observed, not assumed to be zero. This deliberately excludes
 * guarded branches, modifiers and unproven external effects. */
function sourceDirectAssignmentExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const stateVariables=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>{
      const type=canonicalAbiType(v.typeName);
      return v.visibility==='public'&&identifier.test(v.name||'')&&!!type&&
        !type.includes('[')&&
        (/^(?:bool|address|u?int(?:[0-9]{1,3})?)$/.test(type)||type.startsWith('('));
    });
  if(!stateVariables.length)return [];
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,
    sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];
  for(const fn of nodes.filter(n=>n.type==='FunctionDefinition'&&n.name===method&&n.body&&
    ['public','external'].includes(n.visibility)&&
    !['view','pure'].includes(n.stateMutability||''))){
    if((fn.modifiers||[]).length)continue;
    const args:SolidityArgValue[]=[];
    const inputs:string[]=[];
    const selected=new Map<string,SolidityArgValue>();
    const parameters:any[]=fn.parameters||[];
    if(!parameters.length||parameters.length>5)continue;
    let valid=true;
    for(const param of parameters){
      const type=canonicalAbiType(param.typeName);
      const name=String(param.name||'');
      if(!type||!identifier.test(name)){valid=false;break;}
      const value=pickFlexibleArg(type,name);

      if(value===null){valid=false;break;}
      inputs.push(type);args.push(value);selected.set(name,value);
    }
    if(!valid||!declarations.some(d=>
      d.selector.startsWith(contract.name+'.')&&
      d.selector.slice(contract.name.length+1).split('(')[0]===method&&
      d.operation==='send'&&JSON.stringify(d.inputs)===JSON.stringify(inputs)))continue;
    const fnText=body(snapshot.content,fn);
    if(hasAnySourceAuthGuard(fn,fnText))continue;
    const statements:any[]=fn.body.statements||[];
    // Only a top-level direct assignment is considered unconditional. A
    // branch-sensitive store or helper call requires deeper symbolic analysis.
    const writes=statements.filter((n:any)=>n.type==='ExpressionStatement'&&
      n.expression?.type==='BinaryOperation'&&n.expression.operator==='='&&
      n.expression.left?.type==='Identifier'&&n.expression.right?.type==='Identifier');
    for(const stmt of writes){
      const lhs=String(stmt.expression.left.name||'');
      const rhs=String(stmt.expression.right.name||'');
      if(!selected.has(rhs))continue;
      const state=stateVariables.find((v:any)=>v.name===lhs);
      if(!state)continue;
      const stateType=canonicalAbiType(state.typeName);
      const param=parameters.find((p:any)=>p.name===rhs);
      if(!param||stateType!==canonicalAbiType(param.typeName))continue;
      // A later write to the same state invalidates this exact postcondition.
      const position=statements.indexOf(stmt);
      const remaining=statements.slice(position+1);
      const overwritten=remaining.some((n:any)=>
        n.type==='ExpressionStatement'&&n.expression?.type==='BinaryOperation'&&
        n.expression.left?.type==='Identifier'&&n.expression.left.name===lhs);
      if(overwritten)continue;
      const text=body(snapshot.content,fn);
      if(/\b(?!msg\b|block\b|abi\b)[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(/.test(text))continue;
      const signature=canonicalFunctionIdentity(fn);
      const getter=lhs+'()';
      const expected=selected.get(rhs)!;
      const steps:SoliditySequence['steps']=[];
      if(setup.initSignature)steps.push({
        operation:'send',function:setup.initSignature,
        args:setup.initArgs,sender:0,requiredSetup:true});
      steps.push({operation:'observe',function:getter,args:[]});
      steps.push({operation:'send',function:signature,args,sender:0});
      steps.push({operation:'call',function:getter,args:[],expect:expected});

      // A public role is a security property only when acquired source proves
      // both deployer initialization and a privileged consumer. Exercise the
      // setter from a distinct account and require the role getter to expose
      // that outsider, rather than treating any state assignment as a flaw.
      if(stateType==='address'&&canonicalAbiType(param.typeName)==='address'&&
        expected==='$account2'&&!hasAnySourceAuthGuard(fn,body(snapshot.content,fn))&&
        declarations.some(d=>d.operation==='call'&&d.selector.startsWith(contract.name+'.')&&
          d.selector.slice(contract.name.length+1).split('(')[0]===lhs&&d.inputs.length===0)){
        const constructor=nodes.find((n:any)=>n.type==='FunctionDefinition'&&n.isConstructor&&n.body&&
          new RegExp('\\b'+lhs+'\\s*=\\s*msg\\s*\\.\\s*sender\\b')
            .test(body(snapshot.content,n)));
        const consumer=(()=>{for(const peer of sources.values()){
          if(peer.path===snapshot.path)continue;
          let peerAst:any;try{peerAst=parseAstCached(peer);}catch{continue;}
          for(const peerContract of peerAst.children||[]){
            if(peerContract.type!=='ContractDefinition')continue;
            for(const peerFn of peerContract.subNodes||[]){
              if(peerFn.type!=='FunctionDefinition'||!peerFn.body)continue;
              if(new RegExp('\\brequire\\s*\\(\\s*msg\\s*\\.\\s*sender\\s*==\\s*'+lhs+'\\b')
                .test(body(peer.content,peerFn)))
                return {source:peer,contract:peerContract,node:peerFn};
            }
          }
        }return null;})();
        if(constructor&&consumer){
          const impactSequence=inheritedRoleConsumerImpactSequence(
            snapshot.content,consumer.source.content,lhs,method,
            snapshot.path.replace(/^source-[0-9]+\//,''),
            consumer.source.path.replace(/^source-[0-9]+\//,''),
            consumer.contract.name);
          const impactSupported=impactSequence!==null;
          const outsiderSteps:SoliditySequence['steps']=impactSequence?.steps||[
            {operation:'observe',function:getter,args:[]},
            {operation:'send',function:signature,args,sender:2},
            {operation:'call',function:getter,args:[],expect:'$account2'},
          ];
          const impactWitnesses:SourceWitness[]=[];
          out.unshift({
            hypothesis:impactSupported?
              'A non-administrator can rotate the inherited operator role to itself and execute the acquired operator-only settlement, moving funded credit while reducing totalCredit':
              'An outsider can replace deployer-initialized '+lhs+
                ', which acquired source uses to authorize '+consumer.contract.name+'.'+
                canonicalFunctionIdentity(consumer.node),
            property:impactSupported?
              'unauthorized privileged settlement through source-proven role mutation '+
                contract.name+'.'+signature+':'+lhs:
              'unauthorized source-proven privileged role mutation '+
                contract.name+'.'+signature+':'+lhs,
            sequence:impactSequence?{
              ...impactSequence,constructorArgs:setup.constructorArgs,
              ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{})
            }:{
              constructorArgs:setup.constructorArgs,
              ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
              steps:outsiderSteps
            },
            witnesses:[
              witness(snapshot,constructor,contract.name+'.constructor.'+lhs),
              witness(snapshot,fn,contract.name+'.'+signature),
              witness(snapshot,stmt,contract.name+'.'+signature+'.assignment'),
              witness(snapshot,state,contract.name+'.'+lhs),
              witness(consumer.source,consumer.node,
                consumer.contract.name+'.'+canonicalFunctionIdentity(consumer.node)+'.role-guard'),
              ...impactWitnesses
            ]
          });
        }
      }
      out.push({
        hypothesis:'Acquired direct assignment '+lhs+' = '+rhs+
          ' must produce the exact public getter value after a successful call',
        property:'source-defined direct state assignment '+contract.name+'.'+
          signature+':'+lhs,
        sequence:{constructorArgs:setup.constructorArgs,
          ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
          steps},
        witnesses:[witness(snapshot,fn,contract.name+'.'+signature),
          witness(snapshot,stmt,contract.name+'.'+signature+'.assignment'),
          witness(snapshot,state,contract.name+'.'+lhs)],
      });
    }
  }
  return out;
}

/** General owner-equality guard over an actual state assignment. The
 * security property is unauthorized non-mutation AND authorized write;
 * arbitrary similarly named methods, comments, or unproven guards do not
 * justify an authorization conclusion. */
function sourceOwnerGuardedAssignmentExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const states=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>{
      const type=canonicalAbiType(v.typeName);
      return v.visibility==='public'&&identifier.test(v.name||'')&&!!type&&
        !type.includes('[')&&
        (/^(?:address|bool|u?int(?:[0-9]{1,3})?)$/.test(type)||type.startsWith('('));
    });
  if(states.length<2)return [];
  const ctor=nodes.find(n=>n.type==='FunctionDefinition'&&n.isConstructor&&n.body);
  if(!ctor)return [];
  const initializedBySender=new Set<string>();
  for(const statement of ctor.body.statements||[]){
    const expr=statement.type==='ExpressionStatement'?statement.expression:null;
    if(expr?.type==='BinaryOperation'&&expr.operator==='='&&
      expr.left?.type==='Identifier'&&isMsgSender(expr.right))
      initializedBySender.add(String(expr.left.name));
  }
  const owners=states.filter(v=>v.typeName.name==='address'&&
    initializedBySender.has(v.name)&&!v.expression);
  if(!owners.length)return [];
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,sources,declarations,null);
  let constructorArgs:SoliditySequence['constructorArgs'];
  let constructorValueWei:string|undefined;
  if(setup&&!setup.usesToken&&!setup.initSignature){
    constructorArgs=setup.constructorArgs;
    constructorValueWei=setup.constructorValueWei;
  }else{
    // A custom public administrator (rather than a variable literally named
    // owner) is still source-verifiable when a zero-argument constructor sets
    // it directly from msg.sender. The generic flexible setup resolver only
    // recognizes conventional owner names, so admit this narrower fixture
    // after checking every constructor statement and rejecting opaque effects.
    const ctorParams:any[]=ctor.parameters||[];
    const ctorStatements:any[]=ctor.body.statements||[];
    const hasInitializer=nodes.some(n=>n.type==='FunctionDefinition'&&
      (n.modifiers||[]).some((m:any)=>m.name==='initializer'));
    const safeConstructor=ctorParams.length===0&&!hasInitializer&&
      (ctor.modifiers||[]).length===0&&ctorStatements.every((n:any)=>{
        if(n.type!=='ExpressionStatement')return false;
        const expr=n.expression;
        if(expr?.type!=='BinaryOperation'||expr.operator!=='=')return false;
        if(expr.left?.type!=='Identifier')return false;
        return isMsgSender(expr.right)||
          ['NumberLiteral','BooleanLiteral','StringLiteral','HexLiteral'].includes(expr.right?.type);
      });
    if(!safeConstructor)return [];
    constructorArgs=[];
  }
  const results:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];

  for(const fn of nodes.filter(n=>n.type==='FunctionDefinition'&&n.name===method&&n.body&&
    ['external','public'].includes(n.visibility)&&
    !['view','pure'].includes(n.stateMutability||''))){
    if((fn.modifiers||[]).length)continue;
    const parameters:any[]=fn.parameters||[];
    if(!parameters.length||parameters.length>5)continue;
    const abi=parameters.map(p=>canonicalAbiType(p.typeName));
    if(abi.some(x=>!x)||!declarations.some(d=>
      d.selector===contract.name+'.'+fn.name&&d.operation==='send'&&
      JSON.stringify(d.inputs)===JSON.stringify(abi)))continue;
    const args:SolidityArgValue[]=[],selected=new Map<string,SolidityArgValue>();
    let supported=true;
    for(let i=0;i<abi.length;i++){
      const name=String(parameters[i].name||'');
      const type=abi[i]||'';
      if(!identifier.test(name)){supported=false;break;}
      const value=pickFlexibleArg(type,name);
      if(value===null){supported=false;break;}
      args.push(value);selected.set(name,value);
    }
    if(!supported)continue;
    const statements:any[]=fn.body.statements||[];
    const first=statements[0]?.type==='ExpressionStatement'?
      statements[0].expression:null;
    if(first?.type!=='FunctionCall'||first.expression?.type!=='Identifier'||
      first.expression.name!=='require'||first.arguments?.length<1)continue;
    const condition=first.arguments[0];
    if(condition?.type!=='BinaryOperation'||condition.operator!=='==')continue;
    const ownerRef=isMsgSender(condition.left)?condition.right:
      isMsgSender(condition.right)?condition.left:null;
    if(ownerRef?.type!=='Identifier'||!
      owners.some(owner=>owner.name===ownerRef.name))continue;
    const owner=owners.find(v=>v.name===ownerRef.name)!;
    // A second guard or an opaque helper can invalidate the authorized path.
    // Neither source-inferred call effects nor arbitrary aliases are accepted.
    if(statements.slice(1).some((n:any)=>
      n.type!=='ExpressionStatement'||n.expression?.type!=='BinaryOperation'||
      n.expression.operator!=='='))continue;
    const writes=statements.slice(1).filter((n:any)=>
      n.expression?.left?.type==='Identifier'&&
      n.expression?.right?.type==='Identifier');
    for(const statement of writes){
      const destination=String(statement.expression.left.name||'');
      const sourceParam=String(statement.expression.right.name||'');
      const state=states.find(v=>v.name===destination&&v!==owner&&
        !v.expression&&!initializedBySender.has(v.name));
      const parameter=parameters.find(p=>p.name===sourceParam);
      if(!state||!parameter||!selected.has(sourceParam)||
        canonicalAbiType(state.typeName)!==canonicalAbiType(parameter.typeName))continue;
      if(writes.filter(n=>n.expression.left.name===destination).length!==1)continue;
      const stateCtorWrites=(ctor.body.statements||[]).some((n:any)=>
        n.type==='ExpressionStatement'&&n.expression?.type==='BinaryOperation'&&
        n.expression.left?.type==='Identifier'&&
        n.expression.left.name===destination);
      if(stateCtorWrites)continue;
      const expected=selected.get(sourceParam)!;
      const baseline:SolidityArgValue=abi[parameters.indexOf(parameter)]==='bool'?false:
        abi[parameters.indexOf(parameter)]==='address'?
          '0x0000000000000000000000000000000000000000':'0';
      const signature=canonicalFunctionIdentity(fn);
      const getter=destination+'()';
      const steps:SoliditySequence['steps']=[
        {operation:'call',function:owner.name+'()',args:[],expect:'$account0'},
        {operation:'call',function:getter,args:[],expect:baseline},
        {operation:'send',function:signature,args,sender:1,expectRevert:true},
        {operation:'call',function:getter,args:[],expect:baseline},
        {operation:'send',function:signature,args,sender:0},
        {operation:'call',function:getter,args:[],expect:expected},
      ];
      results.push({
        hypothesis:'Source-owned msg.sender equality rejects nonowner storage mutation and admits the owner exact state assignment',
        property:'source-proof generic owner guard '+contract.name+'.'+signature+':'+destination,
        sequence:{constructorArgs,
          ...(constructorValueWei?{constructorValueWei}:{}),
          steps},
        witnesses:[witness(snapshot,ctor,contract.name+'.constructor'),
          witness(snapshot,owner,contract.name+'.'+owner.name),
          witness(snapshot,fn,contract.name+'.'+signature),
          witness(snapshot,statement,contract.name+'.'+signature+'.assignment'),
          witness(snapshot,state,contract.name+'.'+destination)],
      });
    }
  }
  return results;
}

/** Prove a cross-function mapping write from an acquired exact internal helper
 * and its independently declared public getter. This is a small source-level
 * def/use proof, NOT a heuristic inference from function or variable names.
 * Reads and write keys must be the same mapping lvalue under proven parameter
 * substitution; EVM executes the actual helper bytecode and return assertions. */
function sourceInternalMappingSetterExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const mappingNodes=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      identifier.test(v.name||'')&&v.typeName?.type==='Mapping'&&
      v.typeName?.keyType?.name==='address'&&
      v.typeName?.valueType?.type==='Mapping'&&
      v.typeName?.valueType?.keyType?.name==='address'&&
      /^uint(?:[0-9]{1,3})?$/.test(String(v.typeName?.valueType?.valueType?.name||'')));
  if(!mappingNodes.length)return [];
  const indexPath=(n:any):{name:string;keys:string[]}|null=>{
    if(n?.type==='Identifier'&&identifier.test(n.name||''))
      return {name:n.name,keys:[]};
    if(n?.type!=='IndexAccess')return null;
    const name=n.index?.type==='Identifier'?String(n.index.name||''):
      isMsgSender(n.index)?'msg.sender':'';
    const parent=indexPath(n.base);
    return parent&&(identifier.test(name)||name==='msg.sender')?
      {name:parent.name,keys:[...parent.keys,name]}:null;
  };
  const functions=nodes.filter(n=>n.type==='FunctionDefinition'&&n.name&&n.body);
  const getterCandidates=functions.filter(fn=>
    ['public','external'].includes(fn.visibility)&&
    fn.stateMutability==='view'&&(fn.parameters||[]).length===2&&
    (fn.returnParameters||[]).length===1&&
    (fn.body?.statements||[]).length===1&&
    fn.body.statements[0].type==='ReturnStatement');

  const owner=resolveInheritance(snapshot,contract,sources);
  const setup=resolveFlexibleSetup(snapshot,contract,owner.chain,
    sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];
  const targets=functions.filter(fn=>fn.name===method&&
    ['public','external'].includes(fn.visibility)&&
    !['pure','view'].includes(fn.stateMutability||''));
  for(const fn of targets){
    if((fn.modifiers||[]).length)continue;
    const params:any[]=fn.parameters||[];
    const inputs=params.map(p=>canonicalAbiType(p.typeName));
    if(inputs.length!==2||inputs[0]!=='address'||
      !/^uint(?:[0-9]{1,3})?$/.test(inputs[1]||'')||
      !declarations.some(d=>d.selector===contract.name+'.'+method&&
        d.operation==='send'&&JSON.stringify(d.inputs)===JSON.stringify(inputs)))continue;
    if(!params.every((p:any)=>identifier.test(p.name||'')))continue;
    const statements:any[]=fn.body.statements||[];
    if(statements.length!==2||
      statements[0]?.type!=='ExpressionStatement'||
      statements[0].expression?.type!=='FunctionCall'||
      statements[0].expression.expression?.type!=='Identifier'||
      statements[1]?.type!=='ReturnStatement'||
      statements[1]?.expression?.type!=='BooleanLiteral'||
      statements[1].expression.value!==true)continue;
    const call=statements[0].expression;
    const helperName=String(call.expression.name||'');
    const helperCandidates=functions.filter(h=>h.name===helperName&&
      ['internal','private'].includes(h.visibility)&&
      (h.parameters||[]).length===(call.arguments||[]).length);
    if(helperCandidates.length!==1)continue;
    const helper=helperCandidates[0];
    const helperParams:any[]=helper.parameters||[];
    const bindings=new Map<string,string>();
    let valid=true;
    let incrementalRead:{name:string;keys:string[]}|null=null;
    for(let i=0;i<helperParams.length;i++){
      const argument=call.arguments[i];
      let sourceValue:string|null=null;
      if(argument.type==='Identifier'&&argument.name===params[0].name)
        sourceValue='$account2';
      else if(argument.type==='Identifier'&&argument.name===params[1].name)
        sourceValue='7';
      else if(isMsgSender(argument))
        sourceValue='$account0';
      else if(argument.type==='BinaryOperation'&&argument.operator==='+'&&
        argument.right?.type==='Identifier'&&
        argument.right.name===params[1].name){
        // Exact existing mapping read plus the supplied source amount.
        // The EVM pre-readback must prove the zero baseline before the send.
        incrementalRead=indexPath(argument.left);
        if(incrementalRead)sourceValue='7';
      }
      if(!sourceValue||!identifier.test(helperParams[i].name||'')){
        valid=false;break;
      }
      bindings.set(helperParams[i].name,sourceValue);
    }
    if(!valid)continue;
    const helperStatements:any[]=helper.body.statements||[];
    const assignment=helperStatements.find((n:any)=>n.type==='ExpressionStatement'&&
      n.expression?.type==='BinaryOperation'&&n.expression.operator==='=');
    if(!assignment||helperStatements.some((n:any)=>n!==assignment&&
      n.type!=='EmitStatement'&&!(n.type==='ExpressionStatement'&&
        n.expression?.type==='FunctionCall'&&n.expression.expression?.name==='require')))continue;
    const left=indexPath(assignment.expression.left);
    const rhs=assignment.expression.right;
    if(!left||left.keys.length!==2||rhs?.type!=='Identifier'||
      !mappingNodes.some(m=>m.name===left.name)||
      !bindings.has(rhs.name)||bindings.get(rhs.name)!=='7')continue;
    const resolvedKeys=left.keys.map(name=>bindings.get(name));
    if(resolvedKeys.some(value=>value!=='$account0'&&value!=='$account2')||
      new Set(resolvedKeys).size!==2)continue;
    if(incrementalRead&&(
      incrementalRead.name!==left.name||
      incrementalRead.keys.length!==2||
      incrementalRead.keys[0]!=='msg.sender'||
      incrementalRead.keys[1]!==params[0].name))continue;
    for(const getter of getterCandidates){
      const ret=indexPath(getter.body.statements[0].expression);
      const readerParams:any[]=getter.parameters||[];
      if(!ret||ret.name!==left.name||ret.keys.length!==2||
        ret.keys[0]!==readerParams[0]?.name||
        ret.keys[1]!==readerParams[1]?.name||
        !readerParams.every(p=>canonicalAbiType(p.typeName)==='address')||
        canonicalAbiType(getter.returnParameters[0].typeName)!=='uint256')continue;
      const sig=canonicalFunctionIdentity(fn);
      const getterSig=canonicalFunctionIdentity(getter);
      const stepArgs:SolidityArgValue[]=['$account2','7'];
      const steps:SoliditySequence['steps']=[];
      if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,
        args:setup.initArgs,sender:0,requiredSetup:true});
      steps.push({operation:'call',function:getterSig,
        args:resolvedKeys as string[],expect:'0'});
      steps.push({operation:'send',function:sig,args:stepArgs,sender:0});
      steps.push({operation:'call',function:getterSig,
        args:resolvedKeys as string[],expect:'7'});
      out.push({
        hypothesis:'Source-internal helper writes 7 to the exact private mapping keys and the independent public getter must expose that value',
        property:'source-backed internal setter and public mapping getter '+contract.name+'.'+sig,
        sequence:{constructorArgs:setup.constructorArgs,
          ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
          steps},
        witnesses:[witness(snapshot,fn,contract.name+'.'+sig),
          witness(snapshot,helper,contract.name+'.'+helperName),
          witness(snapshot,getter,contract.name+'.'+getterSig),
          witness(snapshot,mappingNodes.find(m=>m.name===left.name),
            contract.name+'.'+left.name)],
      });
    }
  }
  return out;
}

/** Source-proven onlyOwner direct public mapping-of-struct override.
 * Both ABI return fields, the owner guard and the mined revert are verified. */
function sourceStructOverrideExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  menu:readonly SolidityProbeDeclaration[],sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const ast=parseAstCached(snapshot);
  const owns=(contract.baseContracts||[]).some((b:any)=>b.baseName?.namePath==='Ownable')&&
    (ast.children||[]).some((i:any)=>i.type==='ImportDirective'&&
      i.path==='@openzeppelin/contracts/access/Ownable.sol');
  if(!owns)return [];
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,sources,menu,null);
  if(!setup||setup.usesToken)return [];
  const defs=new Map<string,any>();
  for(const n of nodes)if(n.type==='StructDefinition'&&n.name)defs.set(n.name,n);
  const mappings=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      v.visibility==='public'&&v.typeName?.type==='Mapping'&&identifier.test(v.name||''));
  const escaped=(v:string)=>v.replace(/[.*+?^{}$()|[\]\\]/g,'\\$&');
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];

  for(const fn of nodes.filter(n=>n.type==='FunctionDefinition'&&n.name===method&&n.body&&
    ['public','external'].includes(n.visibility)&&
    (n.modifiers||[]).some((m:any)=>m.name==='onlyOwner'))){
    const params:any[]=fn.parameters||[];
    const types:string[]=params.map((p:any)=>canonicalAbiType(p.typeName)||'');
    if(types.some(t=>!t)||!menu.some(d=>d.operation==='send'&&
      d.selector===contract.name+'.'+method&&
      JSON.stringify(d.inputs)===JSON.stringify(types)))continue;
    const sourceBody=body(snapshot.content,fn);
    for(const variable of mappings){
      let inner:any=variable.typeName;
      const keys:string[]=[],names:string[]=[];
      while(inner?.type==='Mapping'&&keys.length<3){
        const type=canonicalAbiType(inner.keyType);
        if(!type||!['address','uint64','uint256','uint8'].includes(type))break;
        keys.push(type);inner=inner.valueType;
      }
      const name=String(inner?.namePath||'').split('.').pop()||'';
      const struct=defs.get(name),members:any[]=struct?.members||[];
      if(!keys.length||members.length!==2||members[0].typeName?.name!=='bool'||
        !/^uint(?:[0-9]{1,3})?$/.test(String(members[1].typeName?.name||'')))continue;
      let valid=true;
      for(const type of keys){
        const param=params.find((p:any)=>canonicalAbiType(p.typeName)===type&&
          !names.includes(p.name));
        if(!param||!identifier.test(param.name||'')){valid=false;break;}
        names.push(param.name);
      }
      if(!valid)continue;
      const amount=params.find((p:any)=>identifier.test(p.name||'')&&
        /^uint(?:[0-9]{1,3})?$/.test(canonicalAbiType(p.typeName)||'')&&
        !names.includes(p.name));
      if(!amount)continue;
      const lhs=escaped(variable.name)+names.map(n=>
        '\\s*\\[\\s*'+escaped(n)+'\\s*\\]').join('');
      const rhs=escaped(name)+'\\s*\\(\\s*\\{\\s*'+escaped(members[0].name)+
        '\\s*:\\s*true\\s*,\\s*'+escaped(members[1].name)+
        '\\s*:\\s*'+escaped(amount.name)+'\\s*\\}\\s*\\)';
      if(!new RegExp('\\b'+lhs+'\\s*=\\s*'+rhs).test(sourceBody))continue;
      const keyValues=keys.map(type=>type==='address'?'$account2':'1');
      const args:SolidityArgValue[]=[];
      for(let i=0;i<params.length;i++){
        const keyIndex=names.indexOf(params[i].name);
        const v:SolidityArgValue|null=keyIndex>=0?keyValues[keyIndex]:
          params[i].name===amount.name?'7':
          pickFlexibleArg(types[i],params[i].name||'',{ownerAccount:'$account0'});
        if(v===null){valid=false;break;}args.push(v);
      }
      if(!valid)continue;
      const signature=canonicalFunctionIdentity(fn);
      const getter=variable.name+'('+keys.join(',')+')';
      const steps:SoliditySequence['steps']=[];
      if(setup.initSignature)steps.push({operation:'send',function:setup.initSignature,
        args:setup.initArgs,sender:0,requiredSetup:true});
      steps.push({operation:'call',function:'owner()',args:[],expect:'$account0'});
      steps.push({operation:'call',function:getter,args:keyValues,expect:[false,'0']});
      steps.push({operation:'send',function:signature,args,sender:1,expectRevert:true});
      steps.push({operation:'call',function:getter,args:keyValues,expect:[false,'0']});
      steps.push({operation:'send',function:signature,args,sender:0});
      steps.push({operation:'call',function:getter,args:keyValues,expect:[true,'7']});
      out.push({
        hypothesis:'Direct source-owned struct override rejects an unauthorized caller and writes both public struct fields only for the owner',
        property:'owner-gated source struct override '+contract.name+'.'+signature+':'+variable.name,
        sequence:{constructorArgs:setup.constructorArgs,
          ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),steps},
        witnesses:[witness(snapshot,fn,contract.name+'.'+signature),
          witness(snapshot,variable,contract.name+'.'+variable.name),
          witness(snapshot,struct,contract.name+'.'+name)],
      });
    }
  }
  return out;
}

/** Deterministic source-expression oracle for directly executable pure entrypoints.
 * The output is derived only from an acquired expression AST and concrete ABI
 * arguments; arbitrary helper calls, external dependencies, unknown symbols
 * and unreachable/ambiguous branches are never guessed.
 */
function sourcePureExpressionExperiment(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const out:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];

  for(const fn of nodes.filter((n:any)=>n.type==='FunctionDefinition'&&n.body&&
    n.name===method&&n.stateMutability==='pure'&&
    ['public','external'].includes(n.visibility)&&!(n.modifiers||[]).length)){
    const statements:any[]=fn.body.statements||[];
    if(statements.length!==1||statements[0].type!=='ReturnStatement')continue;
    const inputs=(fn.parameters||[]).map((p:any)=>canonicalAbiType(p.typeName));
    const outputs=(fn.returnParameters||[]).map((p:any)=>canonicalAbiType(p.typeName));
    if(inputs.some((t:string|null)=>!t)||outputs.length!==1||!outputs[0]||
      !/^(?:u?int(?:[0-9]{1,3})?|bool)$/.test(outputs[0]))continue;
    if(!declarations.some(d=>d.selector===contract.name+'.'+method&&
      d.operation==='call'&&JSON.stringify(d.inputs)===JSON.stringify(inputs)))continue;
    const params=new Map<string,bigint|boolean>();
    const args:SolidityArgValue[]=[];
    let compatible=true;
    for(let i=0;i<inputs.length;i++){
      const name=String(fn.parameters[i]?.name||'');
      const type=inputs[i]||'';
      if(!identifier.test(name)){compatible=false;break;}
      if(type==='bool'){params.set(name,true);args.push(true);}
      else if(/^u?int(?:[0-9]{1,3})?$/.test(type)){
        params.set(name,7n+BigInt(i));args.push((7+i).toString());
      }else{compatible=false;break;}
    }
    if(!compatible)continue;
    type Scalar=bigint|boolean;
    const evaluate=(n:any,depth=0):Scalar|null=>{
      if(!n||depth>16)return null;
      if(n.type==='NumberLiteral'){
        const raw=String(n.number||'').replace(/_/g,'');
        if(!/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(raw))return null;
        try{return BigInt(raw);}catch{return null;}
      }
      if(n.type==='BooleanLiteral')return n.value===true;
      // Solidity parser represents redundant arithmetic parentheses as
      // one-element TupleExpression nodes. They do not change evaluation.
      if(n.type==='TupleExpression'&&n.components?.length===1)
        return evaluate(n.components[0],depth+1);
      if(n.type==='Identifier')return params.get(String(n.name||''))??null;
      if(n.type==='UnaryOperation'){
        const operand=evaluate(n.subExpression,depth+1);
        if(operand===null)return null;
        if(n.operator==='!'&&typeof operand==='boolean')return !operand;
        if(n.operator==='-'&&typeof operand==='bigint')return -operand;
        if(n.operator==='+'&&typeof operand==='bigint')return operand;
        return null;
      }
      if(n.type==='Conditional'){
        const condition=evaluate(n.condition,depth+1);
        return typeof condition==='boolean'?
          evaluate(condition?n.trueExpression:n.falseExpression,depth+1):null;
      }
      if(n.type!=='BinaryOperation')return null;
      const left=evaluate(n.left,depth+1),right=evaluate(n.right,depth+1);
      if(left===null||right===null)return null;
      if(typeof left==='boolean'&&typeof right==='boolean'){
        if(n.operator==='&&')return left&&right;
        if(n.operator==='||')return left||right;
        if(n.operator==='==')return left===right;
        if(n.operator==='!=')return left!==right;
        return null;
      }
      if(typeof left!=='bigint'||typeof right!=='bigint')return null;
      switch(n.operator){
        case '+':return left+right;
        case '-':return left-right;
        case '*':return left*right;
        case '/':return right!==0n?left/right:null;
        case '%':return right!==0n?left%right:null;
        case '**':return right>=0n&&right<=64n?left**right:null;
        case '==':return left===right;
        case '!=':return left!==right;
        case '>':return left>right;
        case '>=':return left>=right;
        case '<':return left<right;
        case '<=':return left<=right;
        default:return null;
      }
    };
    const answer=evaluate(statements[0].expression);
    if(answer===null)continue;
    const output=outputs[0];
    if(output==='bool'&&typeof answer!=='boolean')continue;
    if(output!=='bool'){
      if(typeof answer!=='bigint')continue;
      const signed=output.startsWith('int');
      const bits=Number(output.replace(/\D/g,''))||256;
      if(bits<8||bits>256||bits%8!==0)continue;
      const lower=signed?-(1n<<BigInt(bits-1)):0n;
      const upper=signed?(1n<<BigInt(bits-1))-1n:(1n<<BigInt(bits))-1n;
      if(answer<lower||answer>upper)continue;
    }
    const setup=resolveFlexibleSetup(snapshot,contract,
      resolveInheritance(snapshot,contract,sources).chain,
      sources,declarations,null);
    if(!setup||setup.usesToken)continue;
    const signature=canonicalFunctionIdentity(fn);
    const steps:SoliditySequence['steps']=[];
    if(setup.initSignature)steps.push({
      operation:'send',function:setup.initSignature,
      args:setup.initArgs,sender:0,requiredSetup:true});
    steps.push({operation:'call',function:signature,args,
      expect:typeof answer==='bigint'?answer.toString():answer});
    out.push({
      hypothesis:'The exact source pure expression of '+contract.name+'.'+signature+
        ' evaluates to '+String(answer)+' for concrete ABI inputs',
      property:'source-exact pure return '+contract.name+'.'+signature,
      sequence:{constructorArgs:setup.constructorArgs,
        ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
        steps},
      witnesses:[witness(snapshot,fn,contract.name+'.'+signature),
        witness(snapshot,statements[0],contract.name+'.'+signature+'.return')],
    });
  }
  return out;
}

/** Two independently source-proven state transitions form an executable
 * conservation property even when the state is private. Every readback must
 * be an acquired exact-return view; do not guess economic intent by names.
 */
function sourcePairedScalarConservationExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  declarations:readonly SolidityProbeDeclaration[],
  sources:ReadonlyMap<string,SourceSnapshot>
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(isTestOrMockPath(snapshot.path)||isAbstractContractNode(contract,
    resolveInheritance(snapshot,contract,sources).chain))return [];
  const nodes:any[]=contract.subNodes||[];
  const stateVars=nodes.filter(n=>n.type==='StateVariableDeclaration')
    .flatMap(n=>n.variables||[]).filter((v:any)=>
      identifier.test(v.name||'')&&!v.expression&&
      v.typeName?.type==='ElementaryTypeName'&&
      /^uint(?:[0-9]{1,3})?$/.test(v.typeName.name||''));
  if(!stateVars.length)return [];
  const observations=extractAccountingObservations(snapshot,contract.name,declarations);
  const setup=resolveFlexibleSetup(snapshot,contract,
    resolveInheritance(snapshot,contract,sources).chain,
    sources,declarations,null);
  if(!setup||setup.usesToken)return [];
  const ctor=nodes.find(n=>n.type==='FunctionDefinition'&&n.isConstructor);
  const init=nodes.find(n=>n.type==='FunctionDefinition'&&
    /^(?:initialize|init)$/.test(n.name||'')&&n.body);
  const entries=nodes.filter(n=>n.type==='FunctionDefinition'&&n.body&&
    n.name&&['public','external'].includes(n.visibility)&&
    !['view','pure'].includes(n.stateMutability||'')&&
    !(n.modifiers||[]).length&&
    (n.parameters||[]).length===1&&
    identifier.test(n.parameters[0]?.name||'')&&
    /^uint(?:[0-9]{1,3})?$/.test(canonicalAbiType(n.parameters[0]?.typeName)||''))
    .filter(n=>declarations.some(d=>d.selector===contract.name+'.'+n.name&&
      d.operation==='send'&&
      JSON.stringify(d.inputs)===JSON.stringify([canonicalAbiType(n.parameters[0].typeName)])))
    .filter(n=>{
      const text=body(snapshot.content,n);
      return !hasAnySourceAuthGuard(n,text)&&
        !/\b(?!msg\b|block\b|abi\b)[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*\s*\(/.test(text)&&
        !/\)\s*\.\s*[A-Za-z_]\w*\s*\(/.test(text);
    });
  if(!entries.some(n=>n.name===method))return [];
  const results:Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}>=[];

  for(const state of stateVars){
    const getter=state.visibility==='public'?state.name+'()':
      observations.find(o=>o.kind==='scalar'&&o.stateVariable===state.name)?.getter;
    if(!getter)continue;
    const mutation=new RegExp('\\b'+state.name+'\\s*(?:\\+?=|-=)');
    if((ctor&&mutation.test(body(snapshot.content,ctor)))||
      (init&&mutation.test(body(snapshot.content,init))))continue;
    const readback=nodes.find(n=>n.type==='FunctionDefinition'&&
      n.name===getter.split('(')[0]&&n.body);
    for(const increase of entries){
      const inParam=increase.parameters[0].name;
      if(!sourceExactAccountingDelta(body(snapshot.content,increase),
        state.name,inParam,'increase'))continue;
      for(const decrease of entries){
        if(increase===decrease||!
          [increase.name,decrease.name].includes(method))continue;
        const outParam=decrease.parameters[0].name;
        if(!sourceExactAccountingDelta(body(snapshot.content,decrease),
          state.name,outParam,'decrease'))continue;
        const inSig=canonicalFunctionIdentity(increase),
          outSig=canonicalFunctionIdentity(decrease);
        const steps:SoliditySequence['steps']=[];
        if(setup.initSignature)steps.push({operation:'send',
          function:setup.initSignature,args:setup.initArgs,sender:0,
          requiredSetup:true});
        steps.push({operation:'call',function:getter,args:[],expect:'0'});
        steps.push({operation:'send',function:inSig,args:['1'],sender:0});
        steps.push({operation:'call',function:getter,args:[],expect:'1'});
        steps.push({operation:'send',function:outSig,args:['1'],sender:0});
        steps.push({operation:'call',function:getter,args:[],expect:'0'});
        results.push({
          hypothesis:'Acquired increase and decrease transitions of '+
            state.name+' must restore the independently observable prestate',
          property:'source-paired scalar conservation '+contract.name+'.'+
            inSig+'->'+outSig+':'+state.name,
          sequence:{constructorArgs:setup.constructorArgs,
            ...(setup.constructorValueWei?{constructorValueWei:setup.constructorValueWei}:{}),
            steps},
          witnesses:[witness(snapshot,increase,contract.name+'.'+inSig),
            witness(snapshot,decrease,contract.name+'.'+outSig),
            witness(snapshot,state,contract.name+'.'+state.name),
            ...(readback?[witness(snapshot,readback,contract.name+'.'+getter)]:[])],
        });
      }
    }
  }
  return results;
}

/** Source-derived CREATE2 clone replay: the acquired Factory source must
 * prove the exact deterministic clone expression, the exact typed initializer
 * and the public prediction helper. We only deploy a real acquired concrete
 * template. Failure to deploy or initialize remains an actual EVM failure;
 * source presence alone cannot certify the clone's behavior.
 */
function sourceFactoryDeterminismExperiments(
  snapshot:SourceSnapshot,contract:any,method:string,
  sources:ReadonlyMap<string,SourceSnapshot>,
  declarations:readonly SolidityProbeDeclaration[]
):Array<{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}> {
  if(contract.name!=='Factory'||isTestOrMockPath(snapshot.path)||!method.startsWith('create'))
    return [];
  const fn=(contract.subNodes||[]).find((n:any)=>n.type==='FunctionDefinition'&&
    n.name===method&&n.body&&['public','external'].includes(n.visibility));
  if(!fn||!fn.parameters||fn.parameters.length<2)return [];
  const params:any[]=fn.parameters;
  if(canonicalAbiType(params[0].typeName)!=='address'||params[0].name!=='template'||
    canonicalAbiType(params[1].typeName)!=='bytes32'||params[1].name!=='salt')
    return [];
  const maybeAbiTypes=params.map((p:any)=>canonicalAbiType(p.typeName));
  const abiTypes=maybeAbiTypes.filter((t):t is string=>t!==null);
  if(abiTypes.length!==params.length||abiTypes.some(t=>!t))return [];
  if(!declarations.some(d=>d.operation==='send'&&
    d.selector==='Factory.'+method&&
    JSON.stringify(d.inputs)===JSON.stringify(abiTypes)))return [];
  const predictor=(contract.subNodes||[]).find((n:any)=>
    n.type==='FunctionDefinition'&&n.name==='predictAddress'&&n.body&&
    ['public','external'].includes(n.visibility)&&
    ['view','pure'].includes(n.stateMutability||''));
  if(!predictor||!declarations.some(d=>d.operation==='call'&&
    d.selector==='Factory.predictAddress'&&
    JSON.stringify(d.inputs)===JSON.stringify(['address','bytes32']))||
    !/\btemplate\s*\.\s*predictDeterministicAddress\s*\(\s*salt\s*\)/.test(
      body(snapshot.content,predictor)))return [];
  const text=body(snapshot.content,fn);
  const m=text.match(/\b([A-Za-z_]\w*)\s+clone\s*=\s*\1\s*\(\s*template\s*\.\s*cloneDeterministic\s*\(\s*salt\s*\)\s*\)/);
  if(!m)return [];
  const templateName=m[1];
  // A type must be imported and genuinely acquired; no guessed template
  // deployment and no substituted mock may stand in for production bytecode.
  const imported=(parseAstCached(snapshot).children||[]).some((n:any)=>
    n.type==='ImportDirective'&&String(n.path||'').endsWith('/'+templateName+'.sol'));
  if(!imported)return [];
  const templates=[...sources.values()].filter(src=>
    src.path.endsWith('/'+templateName+'.sol')&&!isTestOrMockPath(src.path));
  if(templates.length!==1)return [];
  const templateSource=templates[0];
  const templateContract=(parseAstCached(templateSource).children||[]).find((n:any)=>
    n.type==='ContractDefinition'&&n.name===templateName&&
    n.kind!=='interface'&&n.kind!=='library');
  if(!templateContract||isAbstractContractNode(templateContract,
    resolveInheritance(templateSource,templateContract,sources).chain))return [];
  const constructor=(templateContract.subNodes||[]).find((n:any)=>
    n.type==='FunctionDefinition'&&n.isConstructor);
  if(constructor&&(constructor.parameters||[]).length!==0)return [];
  const initMatch=text.match(/\bclone\s*\.\s*initialize\s*\(([^;]*)\)\s*;/);
  if(!initMatch)return [];
  const initializerArgs=initMatch[1].split(',').map(x=>x.trim());
  // The factory itself is the authority for argument forwarding. "msg.sender"
  // is a source-declared address, not an invented extra constructor argument.
  // Other expressions (including struct fields) are refused until separately
  // represented by a real ABI-typed value and proven initialization path.
  if(!initializerArgs.length)return [];
  const initializerTypes:string[]=[];
  for(const expression of initializerArgs){
    if(expression==='msg.sender'){initializerTypes.push('address');continue;}
    if(!identifier.test(expression))return [];
    const parameterIndex=params.findIndex((p:any,i:number)=>
      i>=2&&p.name===expression);
    if(parameterIndex<0||!abiTypes[parameterIndex])return [];
    initializerTypes.push(abiTypes[parameterIndex]);
  }
  const suppliedInit=(templateContract.subNodes||[]).find((n:any)=>
    n.type==='FunctionDefinition'&&n.name==='initialize'&&n.body);
  const directBase=resolveInheritance(templateSource,templateContract,sources).chain;
  const inheritedInit=directBase.flatMap(e=>(e.contract.subNodes||[])
    .filter((n:any)=>n.type==='FunctionDefinition'&&n.name==='initialize'&&n.body)
    .map((node:any)=>({node,source:e.snapshot})));
  const initChoices=suppliedInit?[{node:suppliedInit,source:templateSource}]:inheritedInit;
  if(initChoices.length!==1||JSON.stringify((initChoices[0].node.parameters||[])
    .map((p:any)=>canonicalAbiType(p.typeName)))!==JSON.stringify(initializerTypes))return [];
  // A factory with additional external calls beyond initialization requires
  // a fully resolved fixture; no arbitrary third-party protocol is inferred.
  const rest=text.replace(/\bclone\s*\.\s*initialize\s*\([^;]*\)\s*;/,'')
    .replace(/\bclone\s*\.\s*transferOwnership\s*\(\s*msg\.sender\s*\)\s*;/,'');
  if(/\bclone\s*\.\s*(?:mint|fund|deposit|approve|transferFrom)\s*\(/.test(rest))
    return [];
  // Bind actual acquired transitive constructor and initializer dependencies.
  // In particular, an externally cast address cannot silently become an EOA
  // when the source requires an acquired contract receiver.
  const fixture=resolveSourceFixtureDependencies(templateSource,templateName,
    [...sources.values()]);
  if(fixture.status!=='resolved')return [];
  const tailArgs:SolidityArgValue[]=[];
  for(let i=2;i<params.length;i++){
    const type=abiTypes[i],name=String(params[i].name||'');
    const literal=pickFlexibleArg(type,name);
    if(literal===null)return [];
    const bound=fixture.substitutions[name];
    tailArgs.push(type==='address'&&bound?bound:literal);
  }
  const methodSignature=method+'('+abiTypes.join(',')+')';
  return [ZERO_BYTES32,'0x'+'11'.repeat(32)].map((salt,index)=>{
    const callArgs:SolidityArgValue[]=['$deployment:template',salt,...tailArgs];
    const steps:SoliditySequence['steps']=[
      {operation:'observe',function:'predictAddress(address,bytes32)',
        args:['$deployment:template',salt]},
      {operation:'send',function:methodSignature,args:callArgs,sender:0},
      {operation:'observe',function:'predictAddress(address,bytes32)',
        args:['$deployment:template',salt]},
      {operation:'send',function:methodSignature,args:callArgs,sender:1,expectRevert:true},
      {operation:'observe',function:'predictAddress(address,bytes32)',
        args:['$deployment:template',salt]}
    ];
    return {hypothesis:'An acquired '+templateName+' template deployed by Factory.'+
      method+' must initialize once; an identical deterministic CREATE2 salt cannot initialize a second clone',
      property:'source-proven CREATE2 deterministic clone replay '+method+':'+index,
      sequence:{constructorArgs:[],
        preparation:{deployments:[...fixture.deployments,
          {id:'template',file:templateSource.path,
            contract:templateName,constructorArgs:[]}],
          operations:[...fixture.initializerOperations],checks:[]},steps},
      witnesses:[witness(snapshot,fn,'Factory.'+methodSignature),
        witness(snapshot,predictor,'Factory.predictAddress(address,bytes32)'),
        witness(templateSource,templateContract,templateName),
        witness(initChoices[0].source,initChoices[0].node,
          templateName+'.initialize('+initializerTypes.join(',')+')')]}
  });
}

/** Convert a verified initializer setup into the actual source-declared
 * factory clone pathway when the acquired Factory implementation provides one.
 * No inferred clone behavior, guessed parameter order, arbitrary initializer,
 * or deployment from outside the source manifest is admissible.
 */
function sourceFactoryCloneExperiment(
  candidate:{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]},
  target:SourceSnapshot,contract:any,sources:ReadonlyMap<string,SourceSnapshot>
):typeof candidate {
  const sequence=candidate.sequence;
  if(sequence.factoryClone)return candidate;
  const setupIndex=sequence.steps.findIndex(step=>
    step.operation==='send'&&step.requiredSetup===true&&
    /^initialize\(/.test(step.function)&&!step.deploymentId);
  if(setupIndex<0)return candidate;
  const initStep=sequence.steps[setupIndex];
  if(initStep.operation!=='send')return candidate;
  const init=(contract.subNodes||[]).find((n:any)=>
    n.type==='FunctionDefinition'&&n.name==='initialize'&&n.body&&
    canonicalFunctionIdentity(n)===initStep.function);
  if(!init)return candidate;
  for(const factorySource of sources.values()){
    if(!/(?:^|\/)Factory\.sol$/.test(factorySource.path)||isTestOrMockPath(factorySource.path))
      continue;
    let parsed:any;try{parsed=parseAstCached(factorySource);}catch{continue;}
    const factory=(parsed.children||[]).find((n:any)=>
      n.type==='ContractDefinition'&&n.name==='Factory'&&
      n.kind!=='interface'&&n.kind!=='library');
    if(!factory)continue;
    const create=(factory.subNodes||[]).find((n:any)=>n.type==='FunctionDefinition'&&
      n.name==='create'+contract.name&&n.body&&
      ['external','public'].includes(n.visibility));
    if(!create)continue;
    const params:any[]=create.parameters||[];
    const initParams:any[]=init.parameters||[];
    if(params.length!==initParams.length+2||
      params[0]?.name!=='template'||params[1]?.name!=='salt'||
      canonicalAbiType(params[0]?.typeName)!=='address'||
      canonicalAbiType(params[1]?.typeName)!=='bytes32')continue;
    const factoryTypes=params.map(p=>canonicalAbiType(p.typeName));
    if(factoryTypes.some(t=>!t))continue;
    if(!initParams.every((p,i)=>p.name&&p.name===params[i+2].name&&
      canonicalAbiType(p.typeName)===factoryTypes[i+2]))continue;
    const factoryBody=body(factorySource.content,create);
    // Explicit template.cloneDeterministic(salt) and the exact initializer
    // argument vector must occur in the acquired source.
    if(!/\btemplate\s*\.\s*cloneDeterministic\s*\(\s*salt\s*\)/.test(factoryBody))
      continue;
    const initMatch=factoryBody.match(/\bclone\s*\.\s*initialize\s*\(([\s\S]*?)\)\s*;/);
    if(!initMatch)continue;
    const specifiedArgs=initMatch[1].split(',').map(x=>x.trim());
    if(JSON.stringify(specifiedArgs)!==JSON.stringify(initParams.map(p=>p.name)))
      continue;
    const preparation=sequence.preparation||{deployments:[],operations:[],checks:[]};
    if(preparation.deployments.length>=16)continue;
    const id='sourceFactory';
    if(preparation.deployments.some(d=>d.id===id))continue;
    const cloneMethod=create.name+'('+factoryTypes.join(',')+')';
    const updated:SoliditySequence={
      ...sequence,
      preparation:{deployments:[...preparation.deployments,
        {id,file:factorySource.path,contract:factory.name,constructorArgs:[]}],
        operations:[...preparation.operations],checks:[...preparation.checks]},
      factoryClone:{deploymentId:id,function:cloneMethod,
        args:['$contract',ZERO_BYTES32,...initStep.args],sender:0},
      steps:sequence.steps.filter((_,i)=>i!==setupIndex),
    };
    return {...candidate,sequence:updated,witnesses:[
      ...candidate.witnesses,witness(factorySource,create,'Factory.'+cloneMethod)]};
  }
  return candidate;
}

/** Every acquired preparation node must have a real source witness and an
 * executable predecessor graph. Previously orderPreparation([]) validated no
 * nodes even when the sequence contained deployments and initialization. The
 * executor remains authoritative for actual receipts and ABI compatibility. */
export function sourcePreparationGraph(
  sequence:SoliditySequence,sources:ReadonlyMap<string,SourceSnapshot>,
  target?:SourceSnapshot,contract?:any
):{ok:true;nodes:PreparationPrerequisite[]}|{ok:false;code:string;detail:string}{
  const preparation=sequence.preparation;
  const nodes:PreparationPrerequisite[]=[];
  const dependencies=(value:unknown):string[]=>{
    if(Array.isArray(value))return value.flatMap(dependencies);
    if(typeof value!=='string'||!value.startsWith('$deployment:'))return [];
    return [value.slice('$deployment:'.length)];
  };
  const availableIds=new Set((preparation?.deployments||[]).map(x=>x.id));
  const reject=(detail:string)=>({ok:false as const,code:'INVALID_PREREQUISITE',detail});
  // The schema validates receiver IDs, but arguments and expected readbacks
  // may also carry deployment references. Reject dangling references before
  // constructing source-evidence obligations or executing any transactions.
  for(const [index,step] of sequence.steps.entries()){
    const values=step.operation==='eth_balance'?[step.account]:
      step.operation==='send'||step.operation==='call'||step.operation==='observe'?
        step.operation==='call'?[...step.args,step.expect]:step.args:[];
    for(const ref of values.flatMap(dependencies))
      if(!availableIds.has(ref))
        return reject('Step '+index+' references unacquired deployment: '+ref);
  }
  for(const ref of sequence.constructorArgs.flatMap(dependencies))
    if(!availableIds.has(ref))
      return reject('Target constructor references unacquired deployment: '+ref);
  if(sequence.factoryClone)
    for(const ref of sequence.factoryClone.args.flatMap(dependencies))
      if(!availableIds.has(ref))
        return reject('Source factory arguments reference unacquired deployment: '+ref);
  for(const check of preparation?.checks||[])
    for(const ref of dependencies(check.expect))
      if(!availableIds.has(ref))
        return reject('Preparation readback expects an unacquired deployment: '+ref);
  let executionTargetSource=target;
  let executionTargetContract=contract;
  if(sequence.deployment){
    const requestedPath=sequence.deployment.file;
    const exact=sources.get(requestedPath);
    const suffixMatches=exact?[]:[...sources.values()].filter(source=>
      source.path.endsWith('/'+requestedPath));
    const acquired=exact||(suffixMatches.length===1?suffixMatches[0]:undefined);
    if(!acquired)return reject((suffixMatches.length>1?
      'Execution target source path is ambiguous: ':
      'Execution target source not acquired: ')+sequence.deployment.file);
    let parsed:any;
    try{parsed=parseAstCached(acquired);}
    catch{return reject('Unparseable execution target source: '+sequence.deployment.file);}
    const declared=(parsed.children||[]).find((n:any)=>
      n.type==='ContractDefinition'&&n.name===sequence.deployment!.contract&&
      n.kind!=='interface'&&n.kind!=='library');
    if(!declared)return reject('Execution target contract not declared in acquired source: '+
      sequence.deployment.file+':'+sequence.deployment.contract);
    executionTargetSource=acquired;
    executionTargetContract=declared;
  }
  const appendTarget=():void=>{
    if(!executionTargetSource||!executionTargetContract)return;
    // The target cannot exist before every declared prerequisite deployment,
    // initialization and state readback has completed in the isolated EVM.
    // A source-declared derived execution target is recorded at its actual file.
    nodes.push({id:'target:deploy',kind:'deploy',
      dependsOn:[...new Set([...nodes.map(step=>step.id),
        ...sequence.constructorArgs.flatMap(dependencies).map(id=>'deploy:'+id)])],
      sourceEvidence:[witness(executionTargetSource,executionTargetContract,
        executionTargetContract.name+'.constructor')],
      parameters:{file:executionTargetSource.path,
        contract:sequence.deployment?.contract||executionTargetContract.name,
        constructorArgs:sequence.constructorArgs}});
  };
  if(!preparation){appendTarget();return {ok:true,nodes};}
  const deployments=new Map<string,{source:SourceSnapshot;node:any;position:number}>();
  for(const [position,d] of preparation.deployments.entries()){
    if(deployments.has(d.id))return reject('Duplicate source deployment '+d.id);
    const acquired=sources.get(d.file);
    if(!acquired)return reject('Preparation deployment source not acquired: '+d.file);
    let parsed:any;
    try{parsed=parseAstCached(acquired);}catch{return reject('Unparseable preparation source: '+d.file);}
    const declared=(parsed.children||[]).find((n:any)=>
      n.type==='ContractDefinition'&&n.name===d.contract&&
      n.kind!=='interface'&&n.kind!=='library');
    if(!declared)return reject('Preparation contract not declared in acquired file: '+d.file+':'+d.contract);
    deployments.set(d.id,{source:acquired,node:declared,position});
  }
  for(const [position,d] of preparation.deployments.entries()){
    const entry=deployments.get(d.id)!;
    const predecessors=[...new Set(d.constructorArgs.flatMap(dependencies))];
    if(predecessors.includes(d.id))return reject('Self-referential constructor dependency '+d.id);
    for(const prior of predecessors){
      const dependency=deployments.get(prior);
      if(!dependency||dependency.position>=position)return reject(
        'Constructor dependency not deployed before '+d.id+': '+prior);
    }
    nodes.push({id:'deploy:'+d.id,kind:'deploy',
      dependsOn:predecessors.map(id=>'deploy:'+id),
      sourceEvidence:[witness(entry.source,entry.node,entry.node.name+'.constructor')],
      parameters:{file:d.file,contract:d.contract,constructorArgs:d.constructorArgs}});
  }
  let previousOperation:string|null=null;
  for(const op of preparation.operations){
    const entry=deployments.get(op.deploymentId);
    if(!entry)return reject('Initializer receiver has no acquired deployment: '+op.deploymentId);
    const refs=[...new Set(op.args.flatMap(dependencies))];
    if(refs.some(id=>!deployments.has(id)))return reject('Initializer has unacquired deployment reference: '+op.id);
    const dependsOn=[...new Set(['deploy:'+op.deploymentId,
      ...refs.map(id=>'deploy:'+id),
      ...(previousOperation?[previousOperation]:[])])];
    const fnName=op.function.split('(')[0];
    const declared=(entry.node.subNodes||[]).find((n:any)=>
      n.type==='FunctionDefinition'&&n.name===fnName&&n.body);
    // For inherited ABI, the contract declaration witnesses the receiver,
    // while the actual executor must still prove callable bytecode and receipt.
    const origin=declared||entry.node;
    nodes.push({id:'operation:'+op.id,kind:'initialize',dependsOn,
      sourceEvidence:[witness(entry.source,origin,entry.node.name+'.'+op.function)],
      parameters:{deploymentId:op.deploymentId,signature:op.function,args:op.args}});
    previousOperation='operation:'+op.id;
  }
  for(const check of preparation.checks){
    const entry=deployments.get(check.deploymentId);
    if(!entry)return reject('Readback receiver has no acquired deployment: '+check.deploymentId);
    const refs=[...new Set(check.args.flatMap(dependencies))];
    if(refs.some(id=>!deployments.has(id)))return reject('Readback has unacquired deployment reference: '+check.id);
    nodes.push({id:'check:'+check.id,kind:'assert_state',
      dependsOn:[...new Set(['deploy:'+check.deploymentId,
        ...refs.map(id=>'deploy:'+id),
        ...preparation.operations.map(op=>'operation:'+op.id)])],
      sourceEvidence:[witness(entry.source,entry.node,entry.node.name+'.'+check.function)],
      parameters:{deploymentId:check.deploymentId,signature:check.function,
        args:check.args,expect:check.expect}});
  }
  appendTarget();
  return {ok:true,nodes};
}

function constructSolidityExperimentsCore(input:ConstructionInput):ConstructionResult {
  if(!/^[a-f0-9]{40}$/.test(input.repositoryCommit))
    return {ok:false,code:'INVALID_COMMIT',detail:'Expected a source commit SHA'};
  const indexed=new Map<string,SourceSnapshot>();
  for(const s of input.sources) {
    if(!s.path||s.path.startsWith('/')||s.path.split('/').includes('..')||
      !/^[a-f0-9]{64}$/.test(s.sha256)||hash(s.content)!==s.sha256||
      indexed.has(s.path))
      return {ok:false,code:'SOURCE_IDENTITY_INVALID',detail:s.path};
    indexed.set(s.path,s);
  }
  const target=indexed.get(input.targetPath);
  if(!target)return {ok:false,code:'SOURCE_NOT_ACQUIRED',detail:input.targetPath};
  const separator=input.targetSelector.lastIndexOf('.');
  if(separator<1)return {ok:false,code:'TARGET_INVALID',detail:input.targetSelector};
  const contractName=input.targetSelector.slice(0,separator);
  const rawMethod=input.targetSelector.slice(separator+1);
  const method=rawMethod.split('(')[0];
  let ast:any;
  try{ast=parseAstCached(target);}
  catch{return {ok:false,code:'UNPARSEABLE_SOURCE',detail:input.targetPath};}
  const contract=(ast.children||[]).find((n:any)=>n.type==='ContractDefinition'&&n.name===contractName);
  if(!contract)return {ok:false,code:'TARGET_NOT_DECLARED',detail:input.targetSelector};
  const choices:{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}[]=[];
  if(!input.skipLegacy) {
    // Preserve existing strict role-transition proof as first source of plans.
    const peers=[...indexed.values()].map(s=>({path:s.path,source:s.content}));
    const legacy=sourceGroundedSolidityProbes(target.content,[...input.declarations],
      {path:target.path,peers}).filter(p=>p.selector===input.targetSelector);
    for(const item of legacy)choices.push({hypothesis:item.probe.hypothesis,
      property:'source-proven role mutation',sequence:item.probe.sequence,
      witnesses:[witness(target,contract,input.targetSelector)]});
  }
  const erc721Burn=guardedErc721BurnExperiment(target,contract,method,indexed,input.declarations);
  if(erc721Burn)choices.push(erc721Burn);
  const rotation=guardedOperatorRotationExperiment(target,contract,method,input.declarations);
  if(rotation)choices.push(rotation);
  const funding=sourceBoundedFundingExperiment(target,contract,method,input.declarations);
  if(funding)choices.push(funding);
  const direct=directOwnerExperiment(target,contract,input.declarations,method);
  if(direct)choices.push(direct);
  const inherited=inheritedOwnerExperiment(target,contract,method,input.declarations,indexed);
  if(inherited)choices.push(inherited);
  if(!choices.length) {
    const broadened=broadenedAuthorizationExperiment(target,contract,method,indexed,input.declarations);
    if(broadened)choices.push(broadened);
  }
  if(!choices.length) {
    const initExp=initializeGuardExperiment(target,contract,method,indexed,input.declarations);
    if(initExp)choices.push(initExp);
  }
  if(!choices.length) {
    const authExp=authorityTransferExperiment(target,contract,method,indexed,input.declarations);
    if(authExp)choices.push(authExp);
  }
  if(!choices.length) {
    const privExp=privilegedPrimitiveGuardExperiment(target,contract,method,indexed,input.declarations,input.staticLeads);
    if(privExp)choices.push(privExp);
  }
  if(!choices.length) {
    const reinitExp=reinitOrConstructorTakeoverExperiment(target,contract,method,indexed,input.declarations);
    if(reinitExp)choices.push(reinitExp);
  }
  const replay=sourceInitializerReplayExperiment(target,contract,method,
    indexed,input.declarations);
  if(replay)choices.push(replay);
  for(const clone of sourceFactoryDeterminismExperiments(target,contract,method,
    indexed,input.declarations))choices.push(clone);
  if(!choices.length) {
    const drainOrMintExp=unprotectedFundDrainOrMintExperiment(target,contract,method,indexed,input.declarations);
    if(drainOrMintExp)choices.push(drainOrMintExp);
  }
  for(const scalar of sourceScalarDeltaExperiments(target,contract,method,
    input.declarations,indexed))choices.push(scalar);
  for(const mapping of sourceMappingDeltaExperiments(target,contract,method,
    input.declarations,indexed))choices.push(mapping);
  for(const scalarPure of sourcePureExpressionExperiment(target,contract,method,
    input.declarations,indexed))choices.push(scalarPure);
  for(const internalMapping of sourceInternalMappingSetterExperiments(
    target,contract,method,input.declarations,indexed))choices.push(internalMapping);
  for(const assignment of sourceDirectAssignmentExperiments(target,contract,method,
    input.declarations,indexed))choices.push(assignment);
  for(const guardedWrite of sourceOwnerGuardedAssignmentExperiments(target,contract,method,
    input.declarations,indexed))choices.push(guardedWrite);
  for(const internal of sourceInternalScalarSetterExperiments(target,contract,method,
    input.declarations,indexed))choices.push(internal);
  for(const struct of sourceStructOverrideExperiments(target,contract,method,
    input.declarations,indexed))choices.push(struct);
  for(const pair of sourcePairedScalarConservationExperiments(target,contract,method,
    input.declarations,indexed))choices.push(pair);
  const vestingCreation=groundedVestingCreationExperiment(target,contract,method,input.declarations);
  if(vestingCreation)choices.push(vestingCreation);
  const shareAccounting=groundedShareAccountingExperiment(target,contract,method,input.declarations,indexed);
  if(shareAccounting)choices.push(shareAccounting);
  // 3-stage financial-invariant pipeline: extract -> admit -> construct.
  // Runs alongside authorization probes because accounting conservation is a
  // distinct security property; refuses to fabricate when prerequisites fail.
  let invariantUnresolved: {category: InvariantUnresolvedCategory; reason: string} | null = null;
  let fixtureSearchIncompleteReason:string|null=null;
  const suppliedInvariant = (input.invariants || []).find(
    (inv) => inv.target === input.targetSelector && inv.sourceSha256 === target.sha256,
  );
  if (input.skipFinancialInvariants) {
    // Caller explicitly defers financial-invariant discovery to the ANALYZE stage.
  } else if (suppliedInvariant) {
    const built = constructCoreInvariantExperiment(suppliedInvariant, target, contract, input.declarations, indexed);
    if (built) {
      choices.push(built);
    } else {
      invariantUnresolved = {
        category: 'missing_fixture',
        reason: `Supplied invariant for ${input.targetSelector} failed admission or fixture construction`,
      };
    }
  } else {
    // Every overload is an independent ABI entrypoint. Enumerate candidate
    // companion signatures, then admit only pairs with an actual source and
    // executable typed fixture. No name-only ambiguity or arbitrary first pick.
    const targetVariants=(contract.subNodes||[])
      .filter((fn:any)=>fn.type==='FunctionDefinition'&&fn.name===method&&
        fn.body&&['public','external'].includes(fn.visibility))
      .map(canonicalFunctionIdentity);
    const signatures=targetVariants.length?targetVariants:[undefined];
    const issues:string[]=[];
    // A type's multiple acquired concrete implementations are distinct
    // candidate graphs. Never select an arbitrary first protocol: each
    // graph retains its exact source, ABI and constructor/initializer DAG.
    const fixtureEnumeration=enumerateSourceFixtureDependenciesDetailed(target,contract.name,
      [...indexed.values()],{maxAlternatives:4096,maxSearchNodes:8192});
    const fixtureGraphs=fixtureEnumeration.alternatives;
    const fixtureChoiceSets:Readonly<Record<string,string>|undefined>[]=
      fixtureGraphs.length?fixtureGraphs.map(graph=>graph.implementationChoices):
        fixtureEnumeration.complete?[undefined]:[];
    if(!fixtureEnumeration.complete){
      const unresolved=fixtureEnumeration.unresolvedSelections.slice(0,8).map(item=>
        JSON.stringify(item.selection)+":"+item.missingDependencies.join(","));
      fixtureSearchIncompleteReason=`Source fixture alternatives are incomplete after ${fixtureEnumeration.searchNodes} search nodes; `+
        `${fixtureEnumeration.pendingSelections} selections remain unexplored; `+
        `${fixtureEnumeration.unresolvedSelections.length} branches lack executable fixture graphs`+
        (unresolved.length?` (${unresolved.join("; ")})`:"");
      if(!invariantUnresolved)invariantUnresolved={
        category:'missing_fixture',reason:fixtureSearchIncompleteReason};
    }
    for(const targetSignature of signatures){
      for(const fixtureChoices of fixtureChoiceSets){
        const extracted=extractSourceInvariantDescriptor(target,contract,method,
          input.declarations,indexed,undefined,targetSignature,fixtureChoices);
        const variants=extracted.ok?[extracted]:
          extracted.companionCandidates?.length?
            extracted.companionCandidates.map(companion=>
              extractSourceInvariantDescriptor(target,contract,method,
                input.declarations,indexed,companion,targetSignature,fixtureChoices)):[extracted];
        for(const candidate of variants){
          if(!candidate.ok){
            issues.push((targetSignature||method)+':'+candidate.category+':'+candidate.reason);
            if(!invariantUnresolved)invariantUnresolved={
              category:candidate.category,reason:candidate.reason};
            continue;
          }
          const built=constructCoreInvariantExperiment(candidate.invariant,target,
            contract,input.declarations,indexed);
          if(built)choices.push(built);
          else{
            const reason='Source-witnessed invariant failed typed fixture construction for '+
              (targetSignature||method);
            issues.push(reason);
            if(!invariantUnresolved)invariantUnresolved={
              category:'missing_fixture',reason};
          }
        }
      }
    }
    if(invariantUnresolved&&!choices.length)
      invariantUnresolved.reason=issues.slice(0,18).join('; ').slice(0,1500);
  }

  if (!choices.length) {
    const unresolvedCategory: InvariantUnresolvedCategory =
      invariantUnresolved?.category || 'no_supported_property';
    const isFinancialEntry = /^(?:deposit|withdraw|borrow|repay|mint|burn|redeem|swap|stake|unstake|claim|liquidate|flash|vest|fund|rebalance|harvest|compound)/i.test(input.targetSelector.split('.').pop() || '');
    const prefix = isFinancialEntry
      ? 'Financial entrypoint exists, but no source-derived prestate/assertion invariant could be constructed: '
      : '';
    return {
      ok: false,
      code: 'UNKNOWN_ASSERTION',
      unresolvedCategory,
      detail: invariantUnresolved
        ? `${prefix}[${unresolvedCategory}] ${invariantUnresolved.reason}`
        : `${prefix}No source-grounded security setup and falsifiable assertion for ${input.targetSelector}`,
    };
  }
  const seen=new Set<string>(),out:PreparedSecurityExperiment[]=[];
  const failures:Array<{property:string;code:string;detail:string}>=[];
  for(const original of choices) {
    const c=sourceFactoryCloneExperiment(original,target,contract,indexed);
    const planned=sourcePreparationGraph(c.sequence,indexed,target,contract);
    if(!planned.ok){
      failures.push({property:c.property,code:planned.code,detail:planned.detail});
      continue;
    }
    const graph=orderPreparation(planned.nodes);
    if(!graph.ok){
      failures.push({property:c.property,code:graph.code,detail:graph.detail});
      continue;
    }
    const payload={sourceCommit:input.repositoryCommit,path:input.targetPath,
      selector:input.targetSelector,property:c.property,sequence:c.sequence};
    const id=hash(JSON.stringify(payload));
    if(seen.has(id))continue;seen.add(id);
    out.push({version:1,id,language:'solidity',status:'constructed',
      path:input.targetPath,selector:input.targetSelector,
      hypothesis:c.hypothesis,securityProperty:c.property,witnesses:c.witnesses,
      prerequisites:graph.ordered,sequence:c.sequence});
  }
  const targetIsFinancialEntry=/^(?:deposit|withdraw|borrow|repay|mint|burn|redeem|swap|stake|unstake|claim|liquidate|flash|vest|fund|rebalance|harvest|compound)/i
    .test(input.targetSelector.split('.').pop()||'');
  // A source-specialized property may carry its own complete, source-bound
  // preparation graph (for example xMPH's ERC20Mock seed/deposit/withdraw
  // sequence). In that case unrelated generic fixture alternatives must not
  // suppress the independently executable property. Keep the exception exact
  // to this property; other incomplete financial fixture graphs remain blockers.
  const hasCompleteXmphAccountingFixture=out.some(experiment=>
    experiment.securityProperty==="source-proven zero-reward ERC20 share conservation"&&
    Boolean(experiment.sequence.preparation?.deployments.length&&
      experiment.sequence.preparation.operations.length&&
      experiment.sequence.preparation.checks.length)&&
    ["deposit(uint256)","withdraw(uint256)"].every(signature=>
      experiment.sequence.steps.some(step=>step.operation==="send"&&
        step.function===signature)));
  if(fixtureSearchIncompleteReason&&targetIsFinancialEntry&&
    !hasCompleteXmphAccountingFixture){
    return {ok:false,code:'FIXTURE_ENUMERATION_INCOMPLETE',
      detail:fixtureSearchIncompleteReason,unresolvedCategory:'missing_fixture',
      partialExperiments:out};
  }
  if(failures.length){
    // Preserve *all* source-derived obligations. A constructible property
    // may yield real verifier evidence, but cannot certify an independent
    // property whose transitive prerequisites failed construction.
    return {ok:false,code:failures[0].code,
      detail:failures.map(x=>x.property+":"+x.code+":"+x.detail)
        .slice(0,16).join("; ").slice(0,3000),
      unresolvedCategory:"missing_fixture",partialExperiments:out};
  }
  return {ok:true,experiments:out};
}

/** Bind exact acquired user-defined ABI types for this synchronous planning call.
 * The saved context is restored even when malformed source fails parsing. */
export function constructSolidityExperiments(input:ConstructionInput):ConstructionResult {
  const previous=activeAbiTypeDefinitions;
  try{
    const validSources=Array.isArray(input?.sources)&&input.sources.every(source=>
      source&&typeof source.path==="string"&&typeof source.content==="string"&&
      /^[a-f0-9]{64}$/.test(source.sha256)&&hash(source.content)===source.sha256);
    activeAbiTypeDefinitions=validSources?buildAbiTypeDefinitions(input.sources):new Map();
    return constructSolidityExperimentsCore(input);
  }finally{activeAbiTypeDefinitions=previous;}
}
