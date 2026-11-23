import assert from "node:assert/strict";
import {fixtureDiagnosticsSchema,sequenceObservations} from "../packages/security-solver/src/source-reproduction";

const fingerprint="a".repeat(64),dependency="b".repeat(64);
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
  transactionHash:null,gasUsed:null,
};
assert.deepEqual(fixtureDiagnosticsSchema.parse(diagnostics),diagnostics,
  "Authenticated ABI and dependency ABI digests from actual Solidity runtime must survive validation");
assert.ok(sequenceObservations.safeParse({
  contract:"0x0000000000000000000000000000000000000001",
  accounts:Array(3).fill("0x0000000000000000000000000000000000000002"),
  deploymentGasUsed:"70000",
  diagnostics,
  steps:[{operation:"call",function:"balance()",sender:0,actual:"1",expected:"1",passed:true}],
}).success,"Full runtime observation with compiler ABI certificates must parse");
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
console.log("SOURCE_REPRODUCTION_ABI_DIAGNOSTICS_VALIDATED");
