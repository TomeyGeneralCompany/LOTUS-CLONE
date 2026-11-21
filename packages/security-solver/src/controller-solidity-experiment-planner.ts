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
import {orderPreparation, type PreparationPrerequisite, type SourceWitness} from './controller-solidity-prerequisites';
import {extractAccountingObservations} from './deterministic/accounting-observations';
import {resolveSourceFixtureDependencies, type PreparedDeployment, type PreparedInitializerOperation} from './deterministic/fixture-dependency-planner';

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
  | {ok:false;code:string;detail:string;unresolvedCategory?:InvariantUnresolvedCategory};

const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
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
  const ownerPath=posix.normalize(posix.join(posix.dirname(snapshot.path),ownerImport.path));
  const peer=sources.get(ownerPath);
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

function canonicalAbiType(typeName:any):string|null {
  if(!typeName)return null;
  if(typeName.type==='ElementaryTypeName'){
    const name=String(typeName.name||'');
    if(name==='address')return 'address';
    if(name==='uint')return 'uint256';
    if(name==='int')return 'int256';
    if(/^(?:u?int[0-9]{0,3}|bool|string|bytes(?:[0-9]{1,2})?)$/.test(name))return name;
    return null;
  }
  if(typeName.type==='UserDefinedTypeName'&&identifier.test(typeName.namePath||'')){
    // Contract/interface parameters compile to ABI type address.
    return 'address';
  }
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
        const resolved=posix.normalize(posix.join(posix.dirname(entry.snapshot.path),p));
        const peer=sources.get(resolved);
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
  if(!['transferOwnership','renounceOwnership','grantRole'].includes(method))return null;
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
    if(!hasAuthorizationGuard(declaredFn.node,setup.kind,chain))return null;
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

function isAbstractContractNode(contract:any,chain:readonly ContractEntry[]=[]):boolean {
  if(!contract||(contract.kind&&contract.kind!=='contract'))return true;
  if((contract.subNodes||[]).some((n:any)=>n.type==='FunctionDefinition'&&!n.body))return true;
  if(chain.length>1){
    const implemented=new Set<string>();
    for(const e of chain){
      for(const n of e.contract.subNodes||[]){
        if(n.type==='FunctionDefinition'&&n.body&&n.name)implemented.add(n.name);
      }
    }
    for(const e of chain){
      for(const n of e.contract.subNodes||[]){
        if(n.type==='FunctionDefinition'&&!n.body&&n.name&&!implemented.has(n.name))return true;
      }
    }
  }
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

function pickFlexibleArg(abiType:string,paramName:string,options:{ownerAccount?:string;tokenRef?:string;amount?:string}={}):SolidityArgValue|null {
  const t=abiType.trim();
  const name=paramName||'';
  if(t==='address'||t==='address payable'){
    if(options.tokenRef && /(?:token|stablecoin|coin|mph|asset|underlying|stake|currency|erc20|want|collateral|reward|base|quote)/i.test(name))
      return options.tokenRef;
    if(options.ownerAccount && /(?:owner|admin|gov|controller|guardian|minter|operator|distributor|beneficiary|treasury|manager|authority|feeTo|recipient|to|user|account|spender)/i.test(name))
      return options.ownerAccount;
    return '$account2';
  }
  if(t==='bool')return false;
  if(t==='string')return 'LOTUS-Test';
  if(/^u?int(?:[0-9]{1,3})?$/.test(t)){
    if(/(?:period|duration|epoch|lock|interval|delay|window|time)/i.test(name))return '86400';
    if(/(?:fee|bps|rate|ratio|percent)/i.test(name))return '100';
    return options.amount ?? '1000';
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
    for(const cp of cParams){
      const abi=canonicalAbiType(cp.typeName);
      if(!abi)return null;
      const tokenRef=mockToken?'$deployment:token':undefined;
      const bound=dependencyBindings[cp.name||''];
      const arg=bound&&abi==='address'?bound:pickFlexibleArg(abi,cp.name||'',{ownerAccount,tokenRef});
      if(arg===null)return null;
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
      const abiTypes:string[]=[];
      let ok=true;
      for(const ip of iParams){
        const abi=canonicalAbiType(ip.typeName);
        if(!abi){ok=false;break;}
        const tokenRef=mockToken?'$deployment:token':undefined;
        const bound=dependencyBindings[ip.name||''];
        const arg=bound&&abi==='address'?bound:pickFlexibleArg(abi,ip.name||'',{ownerAccount,tokenRef});
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
    const payableFundFn=members.find(n=>n.type==='FunctionDefinition'&&['public','external'].includes(n.visibility)&&
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
/** Cycle-safe intra-contract effect closure, from acquired source AST spans. */
function reachableAccountingSource(snapshot:SourceSnapshot,contract:any,seed:any):string {
  const functions=(contract.subNodes||[]).filter((fn:any)=>fn.type==="FunctionDefinition"&&fn.body&&fn.name);
  const byName=new Map<string,any[]>();
  for(const fn of functions){const items=byName.get(fn.name)||[];items.push(fn);byName.set(fn.name,items);}
  const pending=[seed],visited=new Set<any>(),parts:string[]=[];
  while(pending.length&&visited.size<48){
    const fn=pending.shift()!;if(visited.has(fn))continue;visited.add(fn);
    const text=body(snapshot.content,fn);parts.push(text);
    for(const match of text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g))
      for(const next of byName.get(match[1])||[])if(!visited.has(next))pending.push(next);
  }
  return parts.join("\n");
}
function accountingDirections(text:string,state:string):{increase:boolean;decrease:boolean}{
  // Solidity state-variable names are lexical identifiers, not arbitrary regex input.
  if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(state))return {increase:false,decrease:false};
  return {increase:new RegExp("\\b"+state+"\\s*\\+=").test(text),
    decrease:new RegExp("\\b"+state+"\\s*-=").test(text)};
}

export function extractSourceInvariantDescriptor(
  snapshot: SourceSnapshot,
  contract: any,
  method: string,
  declarations: readonly SolidityProbeDeclaration[],
  sources: ReadonlyMap<string, SourceSnapshot>,
  selectedCompanion?:string,
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
  const fns = allNodes.filter(
    (n: any) =>
      n.type === 'FunctionDefinition' &&
      !n.isConstructor &&
      ['public', 'external'].includes(n.visibility) &&
      !['view', 'pure'].includes(n.stateMutability || '') &&
      n.body,
  );
  const accountingStates=allNodes.filter((n:any)=>n.type==='StateVariableDeclaration')
    .flatMap((n:any)=>n.variables||[]).map((v:any)=>String(v.name||''))
    .filter(name=>/^(?:total|balance|deposit|share|reserve|principal|stake|asset|debt)/i.test(name));
  const targetFn = fns.find((n: any) => n.name === method);
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
    const text=reachableAccountingSource(snapshot,contract,fn);
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
  const selected=selectedCompanion?counterparts.filter(x=>x.fn.name===selectedCompanion):counterparts;
  if(selected.length!==1){
    return {ok:false,category:'no_supported_property',
      reason:'Source-backed accounting companion '+
        (counterparts.length?'ambiguous: ':'not established for ')+
        contract.name+'.'+method+': '+counterparts.map(x=>x.fn.name).join(', '),
      witnesses:[witness(snapshot,targetFn,contract.name+'.'+method)],
      companionCandidates:[...new Set(counterparts.map(x=>x.fn.name))]};
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

  const inflowBody = body(snapshot.content, inflowFn);
  const outflowBody = body(snapshot.content, outflowFn);
  const combinedBody = `${inflowBody}\n${outflowBody}`;
  const pairWitnesses: SourceWitness[] = [
    witness(snapshot, inflowFn, `${contract.name}.${inflowFn.name}`),
    witness(snapshot, outflowFn, `${contract.name}.${outflowFn.name}`),
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
  const dependencyPlan=resolveSourceFixtureDependencies(snapshot,contract.name,[...sources.values()]);
  const unresolvedRemaining=unresolvedExt.filter(call=>{
    if(dependencyPlan.status!=="resolved")return true;
    const recv=call.split('.')[0];
    return !Object.prototype.hasOwnProperty.call(dependencyPlan.substitutions,recv);
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
  const accountingStateVars = stateDecls.filter(
    (v: any) => TOTAL_SCALAR_RE.test(v.name) || BALANCE_MAPPING_RE.test(v.name),
  );

  const totalGetterDecl = declarations.find(
    (d) =>
      d.operation === 'call' &&
      d.inputs.length === 0 &&
      d.selector.startsWith(`${contract.name}.`) &&
      TOTAL_SCALAR_RE.test(d.selector.slice(contract.name.length + 1)),
  );
  const balanceGetterDecl = declarations.find(
    (d) =>
      d.operation === 'call' &&
      d.inputs.length === 1 &&
      d.inputs[0] === 'address' &&
      d.selector.startsWith(`${contract.name}.`) &&
      BALANCE_MAPPING_RE.test(d.selector.slice(contract.name.length + 1)),
  );

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

  const inflowDecl = declarations.find(
    (d) => d.operation === 'send' && d.selector === `${contract.name}.${inflowFn.name}`,
  );
  const outflowDecl = declarations.find(
    (d) => d.operation === 'send' && d.selector === `${contract.name}.${outflowFn.name}`,
  );
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
  const inflowParameter=String((inflowFn.parameters||[])[0]?.name||'');
  const outflowParameter=String((outflowFn.parameters||[])[0]?.name||'');
  const inflowEffects=reachableAccountingSource(snapshot,contract,inflowFn);
  const outflowEffects=reachableAccountingSource(snapshot,contract,outflowFn);
  const directlyProven=accountingTarget&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(accountingTarget)&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(inflowParameter)&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(outflowParameter)&&
    new RegExp("\\b"+accountingTarget+"\\s*\\+=\\s*"+inflowParameter+"\\b").test(inflowEffects)&&
    new RegExp("\\b"+accountingTarget+"\\s*-="+ "\\s*"+outflowParameter+"\\b").test(outflowEffects)&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  // A payable deposit and ETH withdrawal can independently establish
  // conservation from the caller balance and the actual transferred value.
  // This detects a missing aggregate-ledger decrement (the BuggyVault case)
  // instead of demanding the correct decrement already exist in the source.
  const matchingBalance=balanceReferenced&&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(balanceVarName)&&
    new RegExp("\\b"+balanceVarName+"\\s*\\[\\s*msg\\.sender\\s*\\]\\s*\\+=\\s*msg\\.value").test(inflowEffects)&&
    new RegExp("\\b"+balanceVarName+"\\s*\\[\\s*msg\\.sender\\s*\\]\\s*-=\\s*"+outflowParameter+"\\b").test(outflowEffects);
  const coupledPayableConservation=totalReferenced&&
    inflowFn.stateMutability==='payable'&&inflowFn.parameters.length===0&&
    outflowFn.parameters.length===1&&/^uint/.test(String(outflowFn.parameters[0]?.typeName?.name||''))&&
    new RegExp("\\b"+totalVarName+"\\s*\\+=\\s*msg\\.value").test(inflowEffects)&&
    matchingBalance&&
    new RegExp("\\bvalue\\s*:\\s*"+outflowParameter+"\\b").test(outflowEffects)&&
    !/\b(?:fee|interest|incomeIndex|rewardUnlock|exchangeRate)\b/i.test(inflowEffects+outflowEffects);
  if(!directlyProven&&!coupledPayableConservation){
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

export function constructSolidityExperiments(input:ConstructionInput):ConstructionResult {
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
  const method=input.targetSelector.slice(separator+1);
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
  if(!choices.length) {
    const drainOrMintExp=unprotectedFundDrainOrMintExperiment(target,contract,method,indexed,input.declarations);
    if(drainOrMintExp)choices.push(drainOrMintExp);
  }
  const vestingCreation=groundedVestingCreationExperiment(target,contract,method,input.declarations);
  if(vestingCreation)choices.push(vestingCreation);
  const shareAccounting=groundedShareAccountingExperiment(target,contract,method,input.declarations,indexed);
  if(shareAccounting)choices.push(shareAccounting);
  // 3-stage financial-invariant pipeline: extract -> admit -> construct.
  // Runs alongside authorization probes because accounting conservation is a
  // distinct security property; refuses to fabricate when prerequisites fail.
  let invariantUnresolved: {category: InvariantUnresolvedCategory; reason: string} | null = null;
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
    const extracted = extractSourceInvariantDescriptor(target, contract, method, input.declarations, indexed);
    if (extracted.ok) {
      const built = constructCoreInvariantExperiment(extracted.invariant, target, contract, input.declarations, indexed);
      if (built) {
        choices.push(built);
      } else {
        invariantUnresolved = {
          category: 'missing_fixture',
          reason: `Extracted invariant for ${input.targetSelector} failed admission or fixture construction`,
        };
      }
    } else if(extracted.companionCandidates && extracted.companionCandidates.length>1){
      // Ambiguous counterparts represent separate source-derived properties,
      // not permission to discard the lead or select an arbitrary first match.
      let constructed=0;
      const issues:string[]=[];
      for(const companion of extracted.companionCandidates){
        const candidate=extractSourceInvariantDescriptor(target,contract,method,
          input.declarations,indexed,companion);
        if(!candidate.ok){issues.push(companion+':'+candidate.reason);continue;}
        const built=constructCoreInvariantExperiment(candidate.invariant,target,contract,
          input.declarations,indexed);
        if(built){choices.push(built);constructed++;}
        else issues.push(companion+':fixture_construction_failed');
      }
      if(!constructed)invariantUnresolved={category:extracted.category,
        reason:issues.join('; ').slice(0,900)};
    } else {
      invariantUnresolved = { category: extracted.category, reason: extracted.reason };
    }
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
  for(const c of choices) {
    const prereqs:PreparationPrerequisite[]=[];
    const graph=orderPreparation(prereqs);
    if(!graph.ok)return {ok:false,code:graph.code,detail:graph.detail};
    const payload={sourceCommit:input.repositoryCommit,path:input.targetPath,
      selector:input.targetSelector,property:c.property,sequence:c.sequence};
    const id=hash(JSON.stringify(payload));
    if(seen.has(id))continue;seen.add(id);
    out.push({version:1,id,language:'solidity',status:'constructed',
      path:input.targetPath,selector:input.targetSelector,
      hypothesis:c.hypothesis,securityProperty:c.property,witnesses:c.witnesses,
      prerequisites:graph.ordered,sequence:c.sequence});
  }
  return {ok:true,experiments:out};
}
