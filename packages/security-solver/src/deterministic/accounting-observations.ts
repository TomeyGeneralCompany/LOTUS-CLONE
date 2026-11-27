/** Source-backed typed accounting observations, never guessed return values. */
import {parse} from "@solidity-parser/parser";
import type {SourceSnapshot} from "../controller-solidity-experiment-planner";
import type {SolidityProbeDeclaration} from "../solidity-probe-inputs";
import {canonicalElementaryAbiType} from "../solidity-abi-types";

export type AccountingObservation =
  | {kind:"scalar";getter:string;sourceWitness:string;stateVariable:string}
  | {kind:"mapping";getter:string;keyType:string;stateVariable:string;sourceWitness:string}
  | {kind:"struct_field";getter:string;keyType:string;fieldName:string;fieldType:string;fieldIndex:number;stateVariable:string;sourceWitness:string}
  | {kind:"collection_length";getter:string;stateVariable:string;sourceWitness:string}
  | {kind:"external_balance";getter:string;keyType:"address";stateVariable:string;sourceWitness:string};

const typeName=(node:any):string=>{
  if(!node)return "";
  if(node.type==="ElementaryTypeName")return String(node.name||"");
  if(node.type==="UserDefinedTypeName")return String(node.namePath||"");
  if(node.type==="ArrayTypeName")return typeName(node.baseTypeName)+"[]";
  if(node.type==="Mapping")return "mapping";
  return "";
};
const simple=(type:string)=>canonicalElementaryAbiType(type)!==null;
const regexEscape=(v:string)=>v.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");

export function extractAccountingObservations(
  snapshot:SourceSnapshot,contractName:string,declarations:readonly SolidityProbeDeclaration[],
):AccountingObservation[]{
  let ast:any;
  try{ast=parse(snapshot.content,{loc:true,tolerant:true}) as any;}catch{return [];}
  const contract=(ast.children||[]).find((node:any)=>node.type==="ContractDefinition"&&node.name===contractName);
  if(!contract)return [];
  const nodes=contract.subNodes||[];
  const topTypes=(ast.children||[]).filter((node:any)=>
    ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(node.type));
  const states=new Map<string,any>();
  const structs=new Map<string,any[]>();
  for(const node of nodes){
    if(node.type==="StateVariableDeclaration")for(const v of node.variables||[]){
      if(v?.name)states.set(v.name,v);
    }
    if(node.type==="StructDefinition")structs.set(node.name,node.members||[]);
  }
  const sourceAbiType=(node:any,seen=new Set<any>()):string|null=>{
    if(!node||seen.has(node))return null;
    seen.add(node);
    if(node.type==="ElementaryTypeName")return canonicalElementaryAbiType(String(node.name||''));
    if(node.type==="ArrayTypeName"){
      const base=sourceAbiType(node.baseTypeName,seen);if(!base)return null;
      const length=node.length?.value===undefined?'':String(node.length.value);
      return length&&/^\d+$/.test(length)?base+'['+length+']':length?null:base+'[]';
    }
    if(node.type!=="UserDefinedTypeName")return null;
    const name=String(node.namePath||'').split('.').pop()||'';
    const declarations=[...nodes,...topTypes].filter((item:any)=>item.name===name&&
      ["StructDefinition","EnumDefinition","UserDefinedValueTypeDefinition","TypeDefinition"].includes(item.type));
    if(declarations.length===1){
      const definition=declarations[0];
      if(definition.type==="EnumDefinition")return (definition.members||[]).length<=256?'uint8':null;
      if(["UserDefinedValueTypeDefinition","TypeDefinition"].includes(definition.type))
        return sourceAbiType(definition.underlyingType||definition.typeName,seen);
      const fields=(definition.members||[]).map((field:any)=>sourceAbiType(field.typeName,new Set(seen)));
      return fields.length&&fields.every(Boolean)?'('+fields.join(',')+')':null;
    }
    const contracts=nodes.filter((item:any)=>item.type==="ContractDefinition"&&item.name===name);
    return contracts.length===1?'address':null;
  };
  const out:AccountingObservation[]=[];
  const seen=new Set<string>();
  const add=(o:AccountingObservation)=>{
    const key=JSON.stringify(o);if(!seen.has(key)){seen.add(key);out.push(o);}
  };
  for(const fn of nodes){
    if(fn.type!=="FunctionDefinition"||!fn.name||!fn.body||!["view","pure"].includes(fn.stateMutability))continue;
    const declaration=declarations.find(d=>d.selector===contractName+"."+fn.name&&d.operation==="call");
    if(!declaration)continue;
    const getter=fn.name+"("+declaration.inputs.join(",")+")";
    const fnLines=snapshot.content.split("\n");
    const line=Math.max(1,fn.loc?.start?.line||1),last=Math.max(line,fn.loc?.end?.line||line);
    const body=fnLines.slice(line-1,last).join("\n");
    const witness=snapshot.path+":"+line+"-"+last+":"+snapshot.sha256;
    const returns=fn.returnParameters||[];
    const resultType=returns.length===1?sourceAbiType(returns[0]?.typeName)||typeName(returns[0]?.typeName):"";
    for(const [name,state] of states){
      if(!new RegExp("\\b"+regexEscape(name)+"\\b").test(body))continue;
      const stateType=state.typeName;
      if(new RegExp("\\b"+regexEscape(name)+"\\s*\\.\\s*length\\b").test(body)&&declaration.inputs.length===0&&simple(resultType)){
        add({kind:"collection_length",getter,stateVariable:name,sourceWitness:witness});
      }
      // Only an exact source-level return of token.balanceOf(caller) is an
      // equivalent public readback. A fee, share-price or event-only wrapper
      // cannot be interpreted as a token balance.
      const tokenType=typeName(stateType);
      const parameter=String(fn.parameters?.[0]?.name||"");
      if(/^(?:I?ERC20|IERC20Upgradeable|ERC20Upgradeable|MockERC20|ERC20Mock)$/.test(tokenType)&&
        declaration.inputs.length===1&&declaration.inputs[0]==="address"&&
        /^[A-Za-z_][A-Za-z0-9_]*$/.test(parameter)&&
        new RegExp("\\breturn\\s+"+regexEscape(name)+
          "\\s*\\.\\s*balanceOf\\s*\\(\\s*"+parameter+"\\s*\\)\\s*;").test(body)){
        add({kind:"external_balance",getter,keyType:"address",stateVariable:name,sourceWitness:witness});
      }
      if(stateType?.type==="Mapping"&&declaration.inputs.length===1){
        const keyType=sourceAbiType(stateType.keyType)||typeName(stateType.keyType);
        if(declaration.inputs[0]===keyType && simple(resultType))
          add({kind:"mapping",getter,keyType,stateVariable:name,sourceWitness:witness});
      }
      if(declaration.inputs.length===0&&simple(resultType)&&stateType?.type==="ElementaryTypeName"&&
         new RegExp("\\breturn\\s+"+regexEscape(name)+"\\s*;").test(body)){
        add({kind:"scalar",getter,stateVariable:name,sourceWitness:witness});
      }
      if(stateType?.type==="ArrayTypeName"&&declaration.inputs.length===1&&
        /^u?int/.test(canonicalElementaryAbiType(declaration.inputs[0])||'')){
        const structName=typeName(stateType.baseTypeName);
        const fields=structs.get(structName)||[];
        if(resultType===structName&&fields.length){
          fields.forEach((field:any,index:number)=>{
            const ft=typeName(field.typeName);
            if(simple(ft))add({kind:"struct_field",getter,keyType:declaration.inputs[0],fieldName:field.name,
              fieldType:ft,fieldIndex:index,stateVariable:name,sourceWitness:witness});
          });
        }
      }
    }
  }
  return out.sort((a,b)=>a.getter.localeCompare(b.getter)||a.kind.localeCompare(b.kind));
}
