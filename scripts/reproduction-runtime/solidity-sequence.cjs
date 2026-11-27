'use strict';
// Declarative local contract tests. No RPC URL, private key, script or arbitrary calldata input.
function validateSequence(s) {
  const object = (o, required, allowed=required) => {
    if (!o || typeof o !== 'object' || Array.isArray(o) || required.some(k=>!Object.hasOwn(o,k)) ||
        Object.keys(o).some(k=>!allowed.includes(k))) throw new Error('Invalid sequence fields');
  };
  const value = (v, depth=0, budget={nodes:0}) => {
    if(++budget.nodes>256)throw new Error('ABI value exceeds 256 nodes');
    if (typeof v === 'boolean' || typeof v === 'string' && v.length<=2048) return;
    if (Array.isArray(v) && depth<8 && v.length<=32) {v.forEach(x=>value(x,depth+1,budget));return;}
    throw new Error('ABI values must be strings, booleans or bounded arrays; encode integers as strings');
  };
  const args = a => {if(!Array.isArray(a)||a.length>32)throw new Error('Invalid ABI arguments');const budget={nodes:0};a.forEach(v=>value(v,0,budget));};
  const wei = v => {if(v!==undefined && (typeof v!=='string'||!/^(0|[1-9][0-9]{0,29})$/.test(v)))throw new Error('Invalid wei amount');};
  object(s,['constructorArgs','steps'],['constructorArgs','constructorValueWei','steps','deployment','preparation','factoryClone','sourceProperty']);
  if(s.sourceProperty!==undefined){
    const p=s.sourceProperty;
    object(p,['kind','state','method','parameter','amount','direction','sourceSha256'],
      ['kind','state','method','parameter','amount','formula','expectedDelta','direction','sourceSha256']);
    if(p.kind!=='scalar_delta'||p.direction!=='increase'||
      !/^[A-Za-z_]\w*$/.test(p.state)||!/^[A-Za-z_]\w*$/.test(p.parameter)||
      !/^[A-Za-z_]\w*\([A-Za-z0-9_,()[\]]*\)$/.test(p.method)||
      !/^(0|[1-9][0-9]{0,29})$/.test(p.amount)||
      !/^[a-f0-9]{64}$/.test(p.sourceSha256))
      throw new Error('Invalid source-identified scalar obligation');
    if(p.formula!==undefined){
      object(p.formula,['multiplier','divisor']);
      if(!/^[1-9][0-9]{0,9}$/.test(p.formula.multiplier)||
         !/^[1-9][0-9]{0,9}$/.test(p.formula.divisor)||
         typeof p.expectedDelta!=='string'||
         !/^(0|[1-9][0-9]{0,29})$/.test(p.expectedDelta))
        throw new Error('Invalid bounded scalar formula obligation');
    }else if(p.expectedDelta!==undefined)
      throw new Error('Scalar expectedDelta requires a source formula');
  }
  if(s.deployment!==undefined) {
    object(s.deployment,['file','contract']);
    if(typeof s.deployment.file!=='string' || s.deployment.file.length>512 ||
       !/^[A-Za-z0-9_.\/-]+\.sol$/.test(s.deployment.file) ||
       s.deployment.file.startsWith('/') ||
       s.deployment.file.split('/').some(x=>x==='..'||x==='.') ||
       typeof s.deployment.contract!=='string' ||
       !/^[A-Za-z_]\w*$/.test(s.deployment.contract))
      throw new Error('Invalid repository-local derived deployment');
  }
  if(s.preparation!==undefined) {
    const p=s.preparation;
    object(p,['deployments','operations','checks']);
    if(!Array.isArray(p.deployments)||p.deployments.length>16 ||
       !Array.isArray(p.operations)||p.operations.length>24 ||
       !Array.isArray(p.checks)||p.checks.length>16)
      throw new Error('Invalid preparation bounds');
    const ids=new Set(),deployments=new Set();
    const id=v=>typeof v==='string'&&/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(v);
    const method=v=>typeof v==='string'&&/^[A-Za-z_]\w*(?:\([A-Za-z0-9_,()[\]]*\))?$/.test(v);
    for(const d of p.deployments) {
      object(d,['id','file','contract','constructorArgs'],['id','file','contract','constructorArgs','valueWei']);
      if(!id(d.id)||ids.has(d.id)||typeof d.file!=='string' ||
         !/^[A-Za-z0-9_.\/-]+\.sol$/.test(d.file) || d.file.startsWith('/') ||
         d.file.split('/').some(x=>x==='..'||x==='.') ||
         typeof d.contract!=='string'||!/^[A-Za-z_]\w*$/.test(d.contract))
        throw new Error('Invalid preparation deployment');
      ids.add(d.id);deployments.add(d.id);args(d.constructorArgs);wei(d.valueWei);
    }
    for(const step of [...p.operations,...p.checks]) {
      const check=p.checks.includes(step);
      object(step,check?['id','deploymentId','function','args','sender','expect']:
        ['id','deploymentId','function','args','sender'],
        check?['id','deploymentId','function','args','sender','expect']:
        ['id','deploymentId','function','args','sender','valueWei','expectRevert']);
      if(!id(step.id)||ids.has(step.id)||!deployments.has(step.deploymentId) ||
         !method(step.function)||!Number.isInteger(step.sender)||
         step.sender<0||step.sender>2)
        throw new Error('Invalid preparation operation');
      ids.add(step.id);args(step.args);
      if(check)value(step.expect);
      else {wei(step.valueWei);if(step.expectRevert!==undefined&&typeof step.expectRevert!=='boolean')
        throw new Error('Invalid preparation revert expectation');}
    }
  }
  if(s.factoryClone!==undefined){
    const clone=s.factoryClone;
    object(clone,['deploymentId','function','args','sender']);
    if(typeof clone.deploymentId!=='string'||
       !(s.preparation?.deployments||[]).some(d=>d.id===clone.deploymentId)||
       typeof clone.function!=='string'||
       !/^[A-Za-z_][A-Za-z0-9_]*\([A-Za-z0-9_,()[\]]*\)$/.test(clone.function)||
       !Number.isInteger(clone.sender)||clone.sender<0||clone.sender>2)
      throw new Error('Invalid source factory clone reference');
    args(clone.args);
  }
  args(s.constructorArgs);wei(s.constructorValueWei);
  if(JSON.stringify(s).length>16000 || !Array.isArray(s.steps) || !s.steps.length || s.steps.length>16)throw new Error('Invalid sequence length');
  const prepDeployments=new Set((s.preparation?.deployments||[]).map(d=>d.id));
  for(const step of s.steps) {
    if(step?.operation==='eth_balance'){
      object(step,['operation','account']);
      if(typeof step.account!=='string'||!/^(?:\$account[012]|\$contract|\$deployment:[A-Za-z][A-Za-z0-9_-]{0,63})$/.test(step.account))
        throw new Error('Invalid eth_balance account reference');
      if(step.account.startsWith('$deployment:')&&!prepDeployments.has(step.account.slice('$deployment:'.length)))
        throw new Error('Unknown deployment reference '+step.account);
      continue;
    }
    if(step?.operation==='call')object(step,['operation','function','args','expect'],['operation','deploymentId','function','args','expect','sender','expectPath']);
    else if(step?.operation==='observe')object(step,['operation','function','args'],['operation','deploymentId','function','args','sender']);
    else if(step?.operation==='send')object(step,['operation','function','args'],['operation','deploymentId','function','args','sender','valueWei','expectRevert','requiredSetup','expectEvents']);
    else throw new Error('Unknown sequence operation');
    if(step.deploymentId!==undefined && (typeof step.deploymentId!=='string' || !prepDeployments.has(step.deploymentId)))
      throw new Error('Unknown step deploymentId '+String(step.deploymentId));
    if(typeof step.function!=='string'||step.function.length>200||!/^[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z0-9_,()[\]]*\))?$/.test(step.function))throw new Error('Invalid ABI function selector');
    args(step.args);
    if(step.sender!==undefined && (!Number.isInteger(step.sender)||step.sender<0||step.sender>2))throw new Error('Invalid local sender');
    if(step.operation==='call'){
      value(step.expect);
      if(step.expectPath!==undefined && (!Array.isArray(step.expectPath)||step.expectPath.length<1||step.expectPath.length>4||
        step.expectPath.some(v=>!Number.isInteger(v)||v<0||v>31)))throw new Error('Invalid bounded ABI result field path');
    }
    else {wei(step.valueWei);if(step.expectRevert!==undefined&&typeof step.expectRevert!=='boolean')throw new Error('Invalid revert expectation');
      if(step.requiredSetup!==undefined && (step.operation!=='send' || typeof step.requiredSetup!=='boolean' ||
         (step.requiredSetup && step.expectRevert===true)))throw new Error('Invalid required setup flag');
      if(step.expectEvents!==undefined){
        if(step.operation!=='send'||!Array.isArray(step.expectEvents)||step.expectEvents.length>16)
          throw new Error('Invalid event expectations');
        for(const event of step.expectEvents){
          object(event,['signature','args']);
          if(typeof event.signature!=='string'||event.signature.length>200||
             !/^[A-Za-z_][A-Za-z0-9_]*\([A-Za-z0-9_,()[\]]*\)$/.test(event.signature))
            throw new Error('Invalid event signature');
          args(event.args);
        }
      }
    }
  }
  if(!s.steps.some(step=>step.operation==='call'||step.operation==='observe'||step.operation==='eth_balance'))throw new Error('Include a read observation');
  return s;
}
function normalize(v) {
  if(typeof v==='bigint')return v.toString();
  if(Array.isArray(v))return Array.from(v,normalize);
  if(typeof v==='string' && /^0x[0-9a-fA-F]{40}$/.test(v))return v.toLowerCase();
  if(typeof v==='string'||typeof v==='boolean')return v;
  throw new Error('Unsupported ABI result');
}
function receiptEvidence(receipt) {
  return {
    status:Number(receipt.status),
    transactionHash:receipt.hash||receipt.transactionHash||null,
    blockNumber:Number.isSafeInteger(receipt.blockNumber)?receipt.blockNumber:null,
    from:typeof receipt.from==='string'?receipt.from.toLowerCase():null,
    to:typeof receipt.to==='string'?receipt.to.toLowerCase():null,
    contractAddress:typeof receipt.contractAddress==='string'?receipt.contractAddress.toLowerCase():null,
    gasUsed:receipt.gasUsed?.toString?.()||null,
    logs:Array.from(receipt.logs||[],(log,index)=>({
      address:typeof log.address==='string'?log.address.toLowerCase():null,
      topics:Array.from(log.topics||[]),
      data:typeof log.data==='string'?log.data:null,
      index:Number.isSafeInteger(log.index)?log.index:
        Number.isSafeInteger(log.logIndex)?log.logIndex:index,
      transactionHash:log.transactionHash||receipt.hash||null,
      blockNumber:Number.isSafeInteger(log.blockNumber)?log.blockNumber:
        (Number.isSafeInteger(receipt.blockNumber)?receipt.blockNumber:null)
    }))
  };
}
function receiptEvents(contractInterface,receipt) {
  const events=[];
  for(const log of receipt.logs||[]){
    try{
      const parsed=contractInterface.parseLog({topics:log.topics,data:log.data});
      if(parsed)events.push({name:parsed.name,signature:parsed.fragment.format('sighash'),
        address:typeof log.address==='string'?log.address.toLowerCase():null,
        args:normalize(Array.from(parsed.args))});
    }catch{}
  }
  return events;
}
async function runSequence(artifact, sequence, transport, preparationArtifacts={},metadata={}) {
  validateSequence(sequence);
  const {BrowserProvider, ContractFactory, Contract}=require('ethers');
  const {createHash}=require('node:crypto');
  if(!artifact?.evm?.bytecode?.object)
    throw new Error('A deployable contract with compiler bytecode is required');
  const provider=new BrowserProvider(transport,undefined,{cacheTimeout:-1,pollingInterval:10});
  let runtimePhase='fixture_preparation';
  let runtimeStepIndex=null;
  const receiptHistory=[];
  const recordReceipt=(phase,action,receipt)=>receiptHistory.push({phase,action,receipt:receiptEvidence(receipt)});
  const diagnosticError=(error)=>{
    const cause=error instanceof Error?error:new Error(String(error));
    const receipt=cause.receipt||null;
    const status=receipt?.status;
    const phase=runtimePhase;
    const classification=phase==='target_deployment'?'target_deployment_failed':
      phase==='fixture_initialization'?'preparation_initialization_failed':
      phase==='fixture_deployment'?'preparation_deployment_failed':
      phase==='fixture_preparation'?'preparation_precondition_failed':
      phase==='target_action'?'target_execution_failed':'runtime_execution_failed';
    cause.phase=phase;cause.classification=cause.classification||classification;
    cause.diagnostics={
      experimentId:metadata.experimentId||null,fixtureId:metadata.fixtureId||null,
      sourceSha256:metadata.sourceSha256||null,file:metadata.file||null,
      selector:metadata.selector||null,selectedFile:metadata.selectedFile||null,
      contractName:metadata.contractName||null,compilerVersion:metadata.compilerVersion||null,
      evmVersion:metadata.evmVersion||null,cacheHit:metadata.cacheHit??null,
      bytecodeSha256:metadata.bytecodeSha256||null,
      abiSha256:metadata.abiSha256||null,
      preparationAbiSha256:metadata.preparationAbiSha256||{},
      constructorTypes:metadata.constructorTypes||[],stepIndex:runtimeStepIndex,
      receiptStatus:typeof status==='number'?status:null,
      receiptTo:receipt?.to??null,
      transactionHash:receipt?.hash||null,
      gasUsed:receipt?.gasUsed?.toString?.()||null,
      receipt:receipt?receiptEvidence(receipt):undefined,
      receiptHistory
    };
    return cause;
  };
  try {
    const signers=await Promise.all([0,1,2].map(i=>provider.getSigner(i)));
    const accounts=await Promise.all(signers.map(s=>s.getAddress()));
    let address;
    const deployed=new Map();
    const setupSteps=[];
    const linkedLibraries=new Map();
    const linking=new Set();
    const deployableArtifact=async(sourceFile,contractName,compiledArtifact)=>{
      const bytecode=compiledArtifact?.evm?.bytecode?.object;
      if(typeof bytecode!=='string'||!bytecode.length)
        throw new Error('Missing compiler bytecode for '+sourceFile+':'+contractName);
      const references=compiledArtifact.evm.bytecode.linkReferences||{};
      let linkedBytecode=bytecode;
      for(const [libraryFile,libraries] of Object.entries(references)){
        for(const [libraryName,locations] of Object.entries(libraries||{})){
          const key=libraryFile+':'+libraryName;
          let libraryAddress=linkedLibraries.get(key);
          if(!libraryAddress){
            if(linking.has(key))throw new Error('Circular Solidity library link: '+key);
            const libraryArtifact=preparationArtifacts[libraryFile]?.[libraryName];
            if(!libraryArtifact)throw new Error('Compiler library artifact unavailable: '+key);
            linking.add(key);
            try {
              const linkedLibrary=await deployableArtifact(libraryFile,libraryName,libraryArtifact);
              const library=await new ContractFactory(linkedLibrary.abi,
                linkedLibrary.evm.bytecode.object,signers[0]).deploy({gasLimit:10000000});
              const receipt=await library.deploymentTransaction().wait();
              if(receipt)recordReceipt(runtimePhase,'deploy-library:'+key,receipt);
              if(!receipt||receipt.status!==1)throw new Error('Solidity library deployment failed: '+key);
              libraryAddress=(await library.getAddress()).toLowerCase();
              linkedLibraries.set(key,libraryAddress);
              setupSteps.push({operation:'setup',function:'deploy-library:'+key,
                sender:0,passed:true,gasUsed:receipt.gasUsed.toString(),
                receipt:receiptEvidence(receipt),
                purpose:'link compiler-declared source library '+libraryAddress});
            } finally {linking.delete(key);}
          }
          for(const location of locations){
            const start=location.start*2;
            const length=location.length*2;
            if(location.length!==20||start<0||start+length>linkedBytecode.length)
              throw new Error('Unsupported compiler library link location: '+key);
            const replacement=libraryAddress.slice(2).padStart(length,'0');
            linkedBytecode=linkedBytecode.slice(0,start)+replacement+
              linkedBytecode.slice(start+length);
          }
        }
      }
      if(!/^[0-9a-fA-F]+$/.test(linkedBytecode))
        throw new Error('Unresolved compiler library link in '+sourceFile+':'+contractName);
      return {...compiledArtifact,evm:{...compiledArtifact.evm,
        bytecode:{...compiledArtifact.evm.bytecode,object:linkedBytecode}}};
    };
    let lastObservation = null;
    const resolve = v => {
      if(Array.isArray(v))return v.map(resolve);
      if(typeof v==='string'){
        const observedReference=/^\$lastObservation:([0-9]+(?:\.[0-9]+)*)$/.exec(v);
        if(observedReference){
          if(lastObservation===null)throw new Error('Dynamic observation reference has no preceding observe step');
          let value=lastObservation;
          for(const segment of observedReference[1].split('.')){
            const index=Number(segment);
            if(!Array.isArray(value)||index>=value.length)
              throw new Error('Dynamic observation reference path is outside the observed value');
            value=value[index];
          }
          if(value===null||value===undefined)throw new Error('Dynamic observation reference resolved to no value');
          return value;
        }
      }
      if(typeof v==='string' && /^\$account[012]$/.test(v))return accounts[Number(v.at(-1))];
      if(typeof v==='string'&&/^\$deployment:[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(v)){
        const item=deployed.get(v.slice('$deployment:'.length));
        if(!item)throw new Error('Unresolved earlier deployment '+v);
        return item.address;
      }
      if(v==='$contract') {if(!address)throw new Error('$contract is unavailable in constructor arguments');return address;}
      if(typeof v==='string' && v.startsWith('$'))throw new Error('Unknown local address reference');
      return v;
    };
    // Preparation runs only in this isolated EVM. Each deployment and setup
    // operation is source-declared and evidence-checked before the main probe.
    const preparation=sequence.preparation;
    if(preparation) {
      for(const d of preparation.deployments) {
        runtimePhase='fixture_deployment';
        const depArtifact=preparationArtifacts[d.file]?.[d.contract];
        if(!depArtifact?.evm?.bytecode?.object)
          throw new Error('Missing preparation contract '+d.file+':'+d.contract);
        const linkedDependency=await deployableArtifact(d.file,d.contract,depArtifact);
        const dep=await new ContractFactory(linkedDependency.abi,linkedDependency.evm.bytecode.object,signers[0])
          .deploy(...d.constructorArgs.map(resolve),{value:d.valueWei||'0',gasLimit:10000000});
        const receipt=await dep.deploymentTransaction().wait();
        if(receipt)recordReceipt(runtimePhase,'deploy:'+d.id,receipt);
        if(receipt?.status!==1)throw new Error('Preparation deployment failed: '+d.id);
        const depAddress=await dep.getAddress();
        deployed.set(d.id,{contract:dep,address:depAddress,receipt});
        setupSteps.push({operation:'setup',function:'deploy:'+d.file+':'+d.contract,
          sender:0,passed:true,gasUsed:receipt.gasUsed.toString(),
          receipt:receiptEvidence(receipt),purpose:'prepare '+d.id});
      }
      for(const op of preparation.operations) {
        runtimePhase='fixture_initialization';
        const item=deployed.get(op.deploymentId);
        const fn=item.contract.connect(signers[op.sender]).getFunction(op.function);
        const fragment=fn.fragment;
        if(!['payable','nonpayable'].includes(fragment.stateMutability))
          throw new Error('Preparation operation must change state: '+op.id);
        const values=op.args.map(resolve);
        item.contract.interface.encodeFunctionData(fragment,values);
        if(fragment.stateMutability!=='payable'&&BigInt(op.valueWei||'0')!==0n)
          throw new Error('Nonpayable preparation operation: '+op.id);
        let receipt;
        try {const tx=await fn.send(...values,{value:op.valueWei||'0',gasLimit:2000000});receipt=await tx.wait();}
        catch(error) {if(error.receipt?.status!==0)throw error;receipt=error.receipt;}
        if(receipt)recordReceipt(runtimePhase,'preparation:'+op.id,receipt);
        if(!receipt||![0,1].includes(receipt.status))
          throw new Error('Preparation missing transaction receipt: '+op.id);
        const actualReverted=receipt.status===0;
        setupSteps.push({operation:'setup',function:fragment.format('sighash'),
          sender:op.sender,gasUsed:receipt.gasUsed.toString(),
          passed:actualReverted===!!op.expectRevert,receipt:receiptEvidence(receipt),
          purpose:'preparation operation '+op.id});
        if(actualReverted!==!!op.expectRevert)
          throw new Error('Preparation transaction expectation failed: '+op.id);
      }
      for(const check of preparation.checks) {
        runtimePhase='fixture_precondition_check';
        const item=deployed.get(check.deploymentId);
        const fn=item.contract.connect(signers[check.sender]).getFunction(check.function);
        if(!['view','pure'].includes(fn.fragment.stateMutability))
          throw new Error('Preparation check must be read-only: '+check.id);
        const result=await fn.staticCallResult(...check.args.map(resolve),{gasLimit:1000000});
        const actual=normalize(fn.fragment.outputs.length===1?result[0]:result);
        const expected=normalize(resolve(check.expect));
        if(JSON.stringify(actual)!==JSON.stringify(expected))
          throw new Error('Preparation check failed: '+check.id);
      }
    }
    runtimePhase='target_deployment';
    const linkedTarget=await deployableArtifact(metadata.selectedFile||metadata.file||'<target>',
      metadata.contractName||'<target>',artifact);
    const latestBlock=await provider.getBlock('latest');
    const deployGasLimit=latestBlock?.gasLimit && latestBlock.gasLimit > 12000000n
      ? (latestBlock.gasLimit * 9n) / 10n
      : 10000000n;
    let contract=await new ContractFactory(linkedTarget.abi,linkedTarget.evm.bytecode.object,signers[0])
      .deploy(...sequence.constructorArgs.map(resolve),{value:sequence.constructorValueWei||'0',gasLimit:deployGasLimit});
    const deployment=await contract.deploymentTransaction().wait();
    if(deployment)recordReceipt(runtimePhase,'target-deployment',deployment);
    if(!deployment || deployment.status!==1)throw new Error('Constructor deployment failed');
    address=await contract.getAddress();
    // Source-defined 88mph Factory creates deterministic EIP-1167 clones of
    // this deployed template. The actual factory implementation is compiled
    // from acquired repository source, executed in this isolated local EVM.
    // Never interpret the template constructor as initializing clone storage.
    if(sequence.factoryClone){
      runtimePhase='fixture_initialization';
      const call=sequence.factoryClone;
      const factory=deployed.get(call.deploymentId)?.contract;
      if(!factory)throw new Error('Acquired source factory is not deployed');
      const fn=factory.connect(signers[call.sender]).getFunction(call.function);
      if(!['payable','nonpayable'].includes(fn.fragment.stateMutability))
        throw new Error('Factory clone must be a source-declared transaction');
      const values=call.args.map(resolve);
      factory.interface.encodeFunctionData(fn.fragment,values);
      const predicted=await fn.staticCall(...values,{gasLimit:deployGasLimit});
      if(typeof predicted!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(predicted)||
        predicted.toLowerCase()===address.toLowerCase())
        throw new Error('Factory returned no independently deployed clone address');
      const tx=await fn.send(...values,{gasLimit:deployGasLimit});
      const cloneReceipt=await tx.wait();
      if(cloneReceipt)recordReceipt(runtimePhase,'factory-clone:'+call.deploymentId,cloneReceipt);
      if(!cloneReceipt||cloneReceipt.status!==1)
        throw new Error('Factory clone creation or initialization failed');
      const code=await provider.getCode(predicted);
      if(!/^0x[0-9a-fA-F]+$/.test(code)||code.length<=4)
        throw new Error('Factory predicted clone has no executable EVM bytecode');
      const cloneDigest=createHash('sha256').update(Buffer.from(code.slice(2),'hex')).digest('hex');
      setupSteps.push({operation:'setup',function:'factoryClone:'+fn.fragment.format('sighash'),
        sender:call.sender,gasUsed:cloneReceipt.gasUsed.toString(),passed:true,
        receipt:receiptEvidence(cloneReceipt),purpose:'acquired factory '+call.deploymentId+' created clone '+predicted.toLowerCase()+
          ' with runtime code sha256 '+cloneDigest});
      address=predicted;
      contract=new Contract(address,linkedTarget.abi,signers[0]);
    }
    runtimePhase='target_action';
    const steps=[...setupSteps];
    // Only the explicitly generated ERC1155 test harness gets automatic setup.
    // These are actual mined transactions, recorded separately from the probe.
    const harness = artifact.abi.some(x=>x.type==='function' && x.name==='tomeyMint') &&
      artifact.abi.some(x=>x.type==='function' && x.name==='tomeyMintBatch');
    const prepared = new Set();
    async function prepareTransfer(step) {
      if(!harness || step.operation!=='send' || step.expectRevert===true)return;
      const name=step.function.split('(')[0];
      if(!['safeTransferFrom','safeBatchTransferFrom'].includes(name))return;
      const values=step.args.map(resolve);
      const [from,to]=values;
      if(typeof from!=='string' || !accounts.some(a=>a.toLowerCase()===from.toLowerCase()) ||
         typeof to!=='string' || /^0x0{40}$/i.test(to))return;
      const ownerIndex=accounts.findIndex(a=>a.toLowerCase()===from.toLowerCase());
      const sender=step.sender??0;
      const idList=name==='safeTransferFrom'?[values[2]]:values[2];
      const amountList=name==='safeTransferFrom'?[values[3]]:values[3];
      if(!Array.isArray(idList)||!Array.isArray(amountList)||idList.length!==amountList.length||
         !idList.length||idList.length>32)return;
      const pairs=idList.map((id,i)=>[String(id),String(amountList[i])]);
      if(pairs.some(([id,amount])=>!/^(0|[1-9][0-9]{0,77})$/.test(id) ||
         !/^(0|[1-9][0-9]{0,77})$/.test(amount)))return;
      const key=JSON.stringify([from,pairs]);
      if(!prepared.has(key)){
        const mint=contract.getFunction('tomeyMintBatch(address,uint256[],uint256[])');
        const tx=await mint.send(from,pairs.map(p=>p[0]),pairs.map(p=>p[1]),{gasLimit:2000000});
        const receipt=await tx.wait();
        if(receipt)recordReceipt(runtimePhase,'erc1155-mint-setup',receipt);
        if(receipt?.status!==1)throw new Error('ERC1155 harness mint setup failed');
        steps.push({operation:'setup',function:'tomeyMintBatch(address,uint256[],uint256[])',
          sender:0,passed:true,gasUsed:receipt.gasUsed.toString(),receipt:receiptEvidence(receipt),
          purpose:'fund transfer prerequisites'});
        prepared.add(key);
      }
      if(ownerIndex!==sender){
        const approved=await contract.getFunction('isApprovedForAll(address,address)')
          .staticCall(from,accounts[sender]);
        if(!approved){
          const tx=await contract.connect(signers[ownerIndex])
            .getFunction('setApprovalForAll(address,bool)').send(accounts[sender],true,{gasLimit:2000000});
          const receipt=await tx.wait();
          if(receipt)recordReceipt(runtimePhase,'erc1155-approval-setup',receipt);
          if(receipt?.status!==1)throw new Error('ERC1155 harness approval setup failed');
          steps.push({operation:'setup',function:'setApprovalForAll(address,bool)',
            sender:ownerIndex,passed:true,gasUsed:receipt.gasUsed.toString(),
            receipt:receiptEvidence(receipt),purpose:'authorize transfer sender'});
        }
      }
    }
    let stepIndex=0;
    for(const step of sequence.steps) {
      runtimeStepIndex=stepIndex++;runtimePhase=step.requiredSetup?'fixture_initialization':'target_action';
      if(step.operation==='eth_balance') {
        const targetAddr=resolve(step.account);
        const bal=await provider.getBalance(targetAddr);
        steps.push({operation:'eth_balance',target:step.account,address:String(targetAddr).toLowerCase(),
          balanceWei:bal.toString(),passed:true});
        continue;
      }
      if(!step.deploymentId)await prepareTransfer(step);
      const targetContract=step.deploymentId ? deployed.get(step.deploymentId).contract : contract;
      const depMeta=step.deploymentId ? {deploymentId:step.deploymentId} : {};
      const fn=targetContract.connect(signers[step.sender??0]).getFunction(step.function);
      const fragment=fn.fragment;
      const args=step.args.map(resolve);
      // Encode first: ABI/selector/setup failures must not count as expected reverts.
      targetContract.interface.encodeFunctionData(fragment,args);
      if(step.operation==='call' || step.operation==='observe') {
        if(!['view','pure'].includes(fragment.stateMutability))throw new Error('call requires a view/pure function');
        const result=await fn.staticCallResult(...args,{gasLimit:1000000});
        const observed=normalize(fragment.outputs.length===1?result[0]:result);
        let actual=observed;
        if(step.operation==='call' && step.expectPath){
          for(const pos of step.expectPath){
            if(!Array.isArray(actual)||pos>=actual.length)throw new Error('Observed ABI tuple/array field not present');
            actual=actual[pos];
          }
        }
        if(step.operation==='call') {
          const expected=normalize(resolve(step.expect));
          steps.push({operation:'call',...depMeta,function:fragment.format('sighash'),sender:step.sender??0,
            actual,expected,...(step.expectPath?{expectPath:step.expectPath}:{}),passed:JSON.stringify(actual)===JSON.stringify(expected)});
        } else {
          lastObservation=observed;
          steps.push({operation:'observe',...depMeta,function:fragment.format('sighash'),
            sender:step.sender??0,args:normalize(args),actual:observed});
        }
      } else {
        if(!['nonpayable','payable'].includes(fragment.stateMutability))throw new Error('send requires a state-changing function');
        const expectedEvents=step.expectEvents||[];
        const expectedEventFragments=expectedEvents.map(event=>{
          let eventFragment;
          try{eventFragment=targetContract.interface.getEvent(event.signature);}catch{}
          if(!eventFragment)throw new Error('Event is not declared in the compiled acquired-source ABI: '+event.signature);
          return eventFragment;
        });
        if(fragment.stateMutability!=='payable' && BigInt(step.valueWei||'0')!==0n)throw new Error('Nonpayable function cannot receive value');
        let receipt;
        try {const tx=await fn.send(...args,{value:step.valueWei||'0',gasLimit:2000000});receipt=await tx.wait();}
        catch(error) {
          // Only a mined EVM revert is a revert observation, not a transport/ABI error.
          if(error.receipt?.status!==0)throw error;
          receipt=error.receipt;
        }
        if(receipt)recordReceipt(runtimePhase,'target-send:'+fragment.format('sighash'),receipt);
        if(!receipt || ![0,1].includes(receipt.status))throw new Error('No transaction receipt');
        if(receipt.status===0 && receipt.gasUsed>=2000000n)throw new Error('Transaction exhausted its gas limit');
        const reverted=receipt.status===0;
        const actualEvents=receiptEvents(targetContract.interface,receipt);
        const checkedEvents=expectedEvents.map((expected,index)=>{
          const expectedArgs=normalize(resolve(expected.args));
          const actual=actualEvents.find(event=>event.signature===expectedEventFragments[index].format('sighash')&&
            JSON.stringify(event.args)===JSON.stringify(expectedArgs));
          return {signature:expectedEventFragments[index].format('sighash'),
            expected:expectedArgs,observed:actual?.args??null,passed:!!actual};
        });
        const eventsPassed=checkedEvents.every(event=>event.passed);
        // Preserve raw receipt logs for independent review; display fitting
        // must never become the canonical evidence record.
        steps.push({operation:'send',...depMeta,function:fragment.format('sighash'),sender:step.sender??0,
          args:normalize(args),
          valueWei:step.valueWei||'0',reverted,gasUsed:receipt.gasUsed.toString(),
          receipt:receiptEvidence(receipt),actualEvents,expectedEvents:checkedEvents,
          eventsPassed,passed:reverted===!!step.expectRevert&&eventsPassed});
        if(step.requiredSetup && reverted)
          throw new Error('PREPARATION_INITIALIZATION_FAILED: required successful setup '+fragment.format('sighash')+' reverted; security experiment not executed');
      }
    }
    const observations={contract:address.toLowerCase(),accounts:accounts.map(a=>a.toLowerCase()),
      deploymentGasUsed:deployment.gasUsed.toString(),deploymentReceipt:receiptEvidence(deployment),steps,
      diagnostics:{experimentId:metadata.experimentId||null,fixtureId:metadata.fixtureId||null,
        sourceSha256:metadata.sourceSha256||null,bytecodeSha256:metadata.bytecodeSha256||null,
        compilerVersion:metadata.compilerVersion||null,evmVersion:metadata.evmVersion||null,
        selectedFile:metadata.selectedFile||null,contractName:metadata.contractName||null,
        constructorTypes:metadata.constructorTypes||[],
        abiSha256:metadata.abiSha256||null,
        preparationAbiSha256:metadata.preparationAbiSha256||{}}};
    if(JSON.stringify(observations).length>1024*1024)throw new Error('Sequence evidence exceeds 1MB; refusing to truncate verifier receipts');
    return observations;
  } catch(error) {throw diagnosticError(error);}
  finally {provider.destroy();}
}
module.exports={validateSequence,runSequence};
