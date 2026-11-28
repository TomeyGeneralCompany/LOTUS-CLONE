import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {indexedEntryRoutes} from '../packages/security-solver/src/controller-indexed-route';

const root=await mkdtemp(join(tmpdir(),'lotus-graph-regression-'));
try{
 for(const language of ['python','javascript','java'] as const){
   const c=generateCrucible({language,seed:'source-route-graph-verification-20261106'});
   const eligible:string[]=[];
   for(const [path,body] of Object.entries(c.files)){
     if(!/\.(?:py|cjs|java)$/.test(path))continue;
     const target='source-1/'+path,full=join(root,target);
     await mkdir(dirname(full),{recursive:true});await writeFile(full,body);eligible.push(target);
   }
   const routes=await indexedEntryRoutes(root,eligible);
   const expected=c.privateAnswerKey.defects.map(x=>'source-1/'+x.entryPath);
   for(const path of expected)assert.ok(routes.some(r=>r.entry===path),
     language+': source graph must traverse actual multi-hop service calls from '+path);
   assert.ok(routes.every(r=>r.chain.every(p=>eligible.includes(p))));
   assert.ok(routes.every(r=>r.kind==='source_hypothesis'));
   // A safe or negative-control route is still a valid source-navigation
   // hypothesis. Only a real sandboxed entry probe may classify its behavior.
   const protectedNode='source-1/'+c.privateAnswerKey.negativeControls[0].affectedPaths[0];
   assert.ok(routes.every(r=>r.kind==='source_hypothesis'));
   assert.ok(protectedNode.startsWith('source-1/'));
   console.log(language+': complete 2000-source entry-to-service route discovery PASSED; routes='+routes.length);
 }

 const deepRoot=join(root,'deep'),deepEligible:string[]=[];
 const gateway='source-1/app/handler.py';
 const gatewayFull=join(deepRoot,gateway);
 await mkdir(dirname(gatewayFull),{recursive:true});
 await writeFile(gatewayFull,
   'from app.module0 import transform\n'+
   'def handle(request):\n    if request.args:\n        return transform(request.args, 14)\n');
 deepEligible.push(gateway);
 for(let index=0;index<15;index++){
   const path=`source-1/app/module${index}.py`,full=join(deepRoot,path);
   await mkdir(dirname(full),{recursive:true});
   const body=index===14
     ? 'def transform(value, remaining):\n    return project(value)\ndef project(value):\n    return "<p>" + value + "</p>"\n'
     : `from app.module${index+1} import transform as next_transform\ndef transform(value, remaining):\n    return next_transform(value, remaining - 1)\n`;
   await writeFile(full,body);deepEligible.push(path);
 }
 const deepRoutes=await indexedEntryRoutes(deepRoot,deepEligible);
 const deepRoute=deepRoutes.find(route=>route.entry===gateway);
 assert.ok(deepRoute,'controller must retain a complete acquired route deeper than twelve hops');
 assert.equal(deepRoute.chain.length,15,'deep route must include every acquired transformation module');
}finally{await rm(root,{recursive:true,force:true});}
