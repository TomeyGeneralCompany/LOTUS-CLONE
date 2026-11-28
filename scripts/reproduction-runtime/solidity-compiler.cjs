'use strict';

/** Compile acquired Solidity source groups with the compiler selected from
 * each source's own pragma. This permits authentic preparation dependencies
 * from a different pinned upstream compiler without rewriting their source.
 */
function compileSoliditySourceGroups(sources,resolveCompiler,compilerSettings,
  sequenceMode,importCallback){
  const groups=new Map();
  for(const [file,entry] of Object.entries(sources)){
    const selected=resolveCompiler(entry.content);
    const version=selected.solc.version();
    let group=groups.get(version);
    if(!group){group={solc:selected.solc,evmVersion:selected.evmVersion,sources:{}};
      groups.set(version,group);}
    group.sources[file]=entry;
  }
  if(!groups.size)throw new Error('No acquired Solidity compilation sources');
  const combined={contracts:{},errors:[]};
  for(const group of groups.values()){
    const compile=settings=>JSON.parse(group.solc.compile(JSON.stringify({
      language:'Solidity',sources:group.sources,
      settings:{...settings,evmVersion:group.evmVersion,
        outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.bytecode.linkReferences']}}}
    }),{import:importCallback}));
    let result=compile(compilerSettings);
    let errors=(result.errors||[]).filter(error=>error.severity==='error');
    if(errors.length&&sequenceMode&&!compilerSettings?.optimizer&&
      errors.some(error=>/stack too deep/i.test(String(error.formattedMessage||error.message||'')))){
      result=compile({...compilerSettings,optimizer:{enabled:true,runs:200}});
      errors=(result.errors||[]).filter(error=>error.severity==='error');
    }
    combined.errors.push(...(result.errors||[]));
    for(const [file,contracts] of Object.entries(result.contracts||{}))
      combined.contracts[file]={...(combined.contracts[file]||{}),...contracts};
  }
  return {compiled:combined,compilerGroupCount:groups.size};
}

module.exports={compileSoliditySourceGroups};
