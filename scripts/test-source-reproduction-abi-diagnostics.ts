import assert from "node:assert/strict";
import {fixtureDiagnosticsSchema,sequenceObservations,resultSchema} from "../packages/security-solver/src/source-reproduction";

const fingerprint="a".repeat(64),dependency="b".repeat(64);
const receipt={status:1,transactionHash:"0xabc",blockNumber:12,from:"0x0000000000000000000000000000000000000002",
  to:"0x0000000000000000000000000000000000000001",contractAddress:null,gasUsed:"45000",
  logs:[{address:"0x0000000000000000000000000000000000000001",topics:["0x"+"1".repeat(64)],
    data:"0x00",index:0,transactionHash:"0xabc",blockNumber:12}]};
const eventStep={operation:"send",function:"settle()",sender:0,valueWei:"0",reverted:false,gasUsed:"45000",
  passed:true,receipt,actualEvents:[{name:"Settled",signature:"Settled()",address:"0x0000000000000000000000000000000000000001",args:[]}],
  expectedEvents:[{signature:"Settled()",expected:[],observed:[],passed:true}],eventsPassed:true};
const diagnostics={
  experimentId:fingerprint,
  fixtureId:dependency,
  sourceSha256:fingerprint,
  file:"contracts/Settlement.sol",
  selector:"Settlement.settle",
  selectedFile:"contracts/Settlement.sol",
  contractName:"Settlement",
  compilerVersion:"0.8.28",
  evmVersion:"shanghai",
  cacheHit:false,
  bytecodeSha256:dependency,
  abiSha256:fingerprint,
  preparationAbiSha256:{token:dependency,market:fingerprint},
  constructorTypes:["address"],
  stepIndex:null,receiptStatus:null,receiptTo:null,
  transactionHash:null,gasUsed:null,receipt,
};
assert.deepEqual(fixtureDiagnosticsSchema.parse(diagnostics),diagnostics,
  "Authenticated ABI and dependency ABI digests from actual Solidity runtime must survive validation");
assert.ok(sequenceObservations.safeParse({
  contract:"0x0000000000000000000000000000000000000001",
  accounts:Array(3).fill("0x0000000000000000000000000000000000000002"),
  deploymentGasUsed:"70000",
  diagnostics,
  steps:[{operation:"call",function:"balance()",sender:0,actual:"1",expected:"1",passed:true},eventStep],
}).success,"Full runtime observation with compiler ABI certificates must parse");
const validResponse={
  status:"behavior_observed",behavior_observed:true,
  source_sha256:fingerprint,kind:"solidity_sequence",
  diagnostics,
  observations:{
    contract:"0x0000000000000000000000000000000000000001",
    accounts:Array(3).fill("0x0000000000000000000000000000000000000002"),
    deploymentGasUsed:"70000",diagnostics,
    steps:[{operation:"call",function:"balance()",sender:0,actual:"1",expected:"1",passed:true},eventStep],
  }
};
assert.ok(resultSchema.safeParse(validResponse).success,
  "Entire real verifier result, not just nested diagnostics, must survive contract validation");
assert.equal(resultSchema.safeParse({
  ...validResponse,observations:{...validResponse.observations,
    diagnostics:{...diagnostics,abiSha256:"untrusted"}}
}).success,false,"Invalid ABI evidence must be rejected in full verifier result");
for(const bad of [
  {...diagnostics,abiSha256:"pretend"},
  {...diagnostics,preparationAbiSha256:{token:"fake"}},
  {...diagnostics,preparationAbiSha256:{"":fingerprint}},
  {...diagnostics,preparationAbiSha256:{token:42}},
  {...diagnostics,unverified:"an assertion invented by the model"},
]){
  assert.equal(fixtureDiagnosticsSchema.safeParse(bad).success,false,
    "Invalid ABI certificates and unknown runtime fields must fail closed");
}
assert.equal(fixtureDiagnosticsSchema.safeParse({...diagnostics,receipt:{...receipt,unexpected:true}}).success,false,
  "Receipt evidence must be fully typed and reject unknown fields");
assert.equal(sequenceObservations.safeParse({
  contract:"0x0000000000000000000000000000000000000001",
  accounts:Array(3).fill("0x0000000000000000000000000000000000000002"),
  deploymentGasUsed:"70000",diagnostics,
  steps:[{operation:"call",function:"balance()",sender:0,actual:"1",expected:"1",passed:true}],
}).success,true,"Legacy persisted observations without optional receipt fields remain readable");
console.log("SOURCE_REPRODUCTION_ABI_DIAGNOSTICS_VALIDATED");
