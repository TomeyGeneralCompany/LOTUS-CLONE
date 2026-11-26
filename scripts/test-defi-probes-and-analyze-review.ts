import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { soliditySequenceSchema } from "../packages/security-solver/src/solidity-sequence";
import { normalizeSolidityPreparationPaths } from "../packages/security-solver/src/source-reproduction";
import {
  controllerGroundedSolidityOptions,
  prioritizeSolidityStagedPlans,
  runLocalAudit,
  sanitizeOllamaFormatSchema,
  solidityProbeBasePriority,
} from "../packages/security-solver/src/local-ollama-runner";
import { decodeAuditAction } from "../packages/security-solver/src/local-audit-protocol";
import { runEvidenceOnlyReview } from "../packages/security-solver/src/evidence-only-review";
import { rankSolidityStaticTargets } from "../packages/security-solver/src/local-static-leads";
import { constructSolidityExperiments, accountingTransitionPatterns } from "../packages/security-solver/src/controller-solidity-experiment-planner";

import {reconcileHuntReason,type HuntCoverageLedger} from '../packages/security-solver/src/local-program-flow';

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// Real-world regression: dynamic Solidity accounting regexes must compile and
// match real push/pop and struct field updates, including escaped identifiers.
{
  const patterns=accountingTransitionPatterns('deposits','amount');
  assert.ok(patterns.push.test('deposits.push(value)'));
  assert.ok(patterns.pop.test('deposits.pop()'));
  assert.ok(patterns.fieldDecrement.test('deposits[0].amount -= 400'));
  assert.equal(patterns.push.test('depositsXpush(value)'),false);
  assert.equal(patterns.pop.test('other.pop()'),false);
  const escaped=accountingTransitionPatterns('deposits$','amount+fee');
  assert.ok(escaped.push.test('deposits$.push(value)'));
  assert.ok(escaped.fieldDecrement.test('deposits$[0].amount+fee -= 1'));
}

// #227 field evidence: 31 guarded negatives, 13 observation-only, 12
// incomplete/failed; 56 selected, no observed positive. A model's reversed
// word-order blanket-negative claim must not change any ledger disposition.
{
 const ledger:HuntCoverageLedger={
   sourceIndexed:91,sourceRead:91,leadsSelected:6,leadsAssessedByModel:0,
   leadsDeferred:0,leadsBlocked:0,experimentsSelected:56,experimentsExecuted:44,
   supportedNegative:31,observationOnly:13,fixtureFailed:12,unsupported:0,
   positiveObserved:0,verifiedFindings:0,unresolved:0,
   sourceCoverage:'complete',analysisCoverage:'partial',experimentCoverage:'partial'
 };
 const actual='The controller has observed behavior_not_observed status for all candidate functions.';
 const checked=reconcileHuntReason(actual,ledger);
 assert.deepEqual(checked.contradictions,['blanket_negative_contradicts_partial_experiment_ledger']);
 assert.match(checked.reason,/31 source-supported negative experiments/);
 assert.match(checked.reason,/13 observation-only/);
 assert.match(checked.reason,/12 failed\/incomplete fixtures/);
 assert.match(checked.reason,/Model analysis partial/i);
 assert.doesNotMatch(checked.reason,/negative status for all candidate functions/i);
 assert.equal(reconcileHuntReason('31 supported negatives and 25 unresolved or inconclusive executions.',ledger).contradictions.length,0);
}


// 1. Validate soliditySequenceSchema eth_balance and deploymentId extensions
{
  const valid = soliditySequenceSchema.safeParse({
    constructorArgs: [],
    preparation: {
      deployments: [{ id: "token", file: "contracts/mocks/ERC20Mock.sol", contract: "ERC20Mock", constructorArgs: [] }],
      operations: [],
      checks: [],
    },
    steps: [
      { operation: "eth_balance", account: "$contract" },
      { operation: "send", deploymentId: "token", function: "mint(address,uint256)", args: ["$contract", "1000"], sender: 0 },
      { operation: "observe", deploymentId: "token", function: "balanceOf(address)", args: ["$contract"], sender: 0 },
      { operation: "send", function: "rescue(address,address,uint256)", args: ["$deployment:token", "$account1", "1000"], sender: 1 },
      { operation: "eth_balance", account: "$account1" },
    ],
  });
  assert.ok(valid.success, "Valid eth_balance + deploymentId sequence should parse");
  const requiredSetup = soliditySequenceSchema.safeParse({
    constructorArgs: [],steps:[
      {operation:"send",function:"initialize()",args:[],sender:0,requiredSetup:true},
      {operation:"observe",function:"owner()",args:[]}
    ]
  });
  assert.ok(requiredSetup.success, "A required successful initializer must be accepted");
  const contradictorySetup = soliditySequenceSchema.safeParse({
    constructorArgs: [],steps:[
      {operation:"send",function:"initialize()",args:[],sender:0,requiredSetup:true,expectRevert:true},
      {operation:"observe",function:"owner()",args:[]}
    ]
  });
  assert.ok(!contradictorySetup.success, "Setup cannot require both success and revert");

  const invalidRef = soliditySequenceSchema.safeParse({
    constructorArgs: [],
    steps: [
      { operation: "send", function: "rescue(address)", args: ["$deployment:missing"], sender: 1 },
    ],
  });
  assert.ok(!invalidRef.success, "Undeclared $deployment: reference must be rejected");
}

// Regression: workspace source-1/... paths must become /repo-relative sources
// without making any neighboring repository or host path accessible.
{
  const tmp=await mkdtemp(join(tmpdir(),"lotus-fixture-path-"));
  try {
    const workspace=join(tmp,"workspace");
    const repository=join(workspace,"source-1");
    await mkdir(join(repository,"contracts"),{recursive:true});
    await writeFile(join(repository,"contracts","MockToken.sol"),"contract MockToken {}");
    await mkdir(join(workspace,"source-2"),{recursive:true});
    await writeFile(join(workspace,"source-2","Secret.sol"),"contract Secret {}");
    const sequence=soliditySequenceSchema.parse({
      constructorArgs:[],
      preparation:{deployments:[{
        id:"token",file:"source-1/contracts/MockToken.sol",
        contract:"MockToken",constructorArgs:[]
      }],operations:[],checks:[]},
      steps:[{operation:"send",function:"deposit()",args:[]},
        {operation:"observe",function:"owner()",args:[]}]
    });
    const normalized=await normalizeSolidityPreparationPaths(workspace,repository,sequence);
    assert.equal(normalized.preparation?.deployments[0].file,"contracts/MockToken.sol");
    assert.equal(sequence.preparation?.deployments[0].file,"source-1/contracts/MockToken.sol",
      "Preflight must not mutate the controller's original evidence");
    await assert.rejects(normalizeSolidityPreparationPaths(workspace,repository,{
      ...sequence,preparation:{...sequence.preparation!,
        deployments:[{...sequence.preparation!.deployments[0],file:"source-2/Secret.sol"}]}
    }),/outside selected Solidity repository/);
  } finally {await rm(tmp,{recursive:true,force:true});}
}

// 2. Test DeFi planner patterns & null commit compatibility
{
  const reinitSource = `pragma solidity 0.8.4;
contract VaultInit {
  address public owner;
  address public treasury;
  uint256 public fee;
  function initialize(address _owner, address _treasury, uint256 _fee) external {
    owner = _owner; treasury = _treasury; fee = _fee;
  }
}`;
  const mockSource = `pragma solidity 0.8.4;
contract ERC20Mock {
  mapping(address => uint256) public balanceOf;
  uint256 public totalSupply;
  function mint(address to, uint256 amt) public {
    totalSupply += amt; balanceOf[to] += amt;
  }
}`;
  const minterSource = `pragma solidity 0.8.4;
contract RealMinter {
  mapping(address => uint256) public balanceOf;
  uint256 public totalSupply;
  function mint(address to, uint256 amt) external {
    totalSupply += amt; balanceOf[to] += amt;
  }
  function deposit(uint256 amt) external {
    balanceOf[msg.sender] += amt;
  }
}`;
  const snap = [
    { path: "source-1/contracts/VaultInit.sol", content: reinitSource, sha256: sha(reinitSource) },
    { path: "source-1/contracts/mocks/ERC20Mock.sol", content: mockSource, sha256: sha(mockSource) },
    { path: "source-1/contracts/RealMinter.sol", content: minterSource, sha256: sha(minterSource) },
  ];
  const initOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/VaultInit.sol",
    reinitSource,
    [
      { selector: "VaultInit.owner", operation: "call", inputs: [] },
      { selector: "VaultInit.initialize", operation: "send", inputs: ["address", "address", "uint256"] },
    ],
    snap,
    "a".repeat(40),
  );
  assert.ok(initOpts.some(o => o.selector === "VaultInit.initialize"), "Multi-arg initialize probe should be planned");
  assert.equal(
    controllerGroundedSolidityOptions("source-1/contracts/VaultInit.sol", reinitSource, [
      { selector: "VaultInit.owner", operation: "call", inputs: [] },
      { selector: "VaultInit.initialize", operation: "send", inputs: ["address", "address", "uint256"] },
    ], snap, null).length,
    0,
    "Null commit must disable new scenario construction"
  );

  const mockOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/mocks/ERC20Mock.sol",
    mockSource,
    [{ selector: "ERC20Mock.mint", operation: "send", inputs: ["address", "uint256"] }],
    snap,
    "a".repeat(40),
  );
  assert.equal(mockOpts.length, 0, "Mock file unguarded minting must never be queued");

  const minterOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/RealMinter.sol",
    minterSource,
    [
      { selector: "RealMinter.balanceOf", operation: "call", inputs: ["address"] },
      { selector: "RealMinter.totalSupply", operation: "call", inputs: [] },
      { selector: "RealMinter.mint", operation: "send", inputs: ["address", "uint256"] },
      { selector: "RealMinter.deposit", operation: "send", inputs: ["uint256"] },
    ],
    snap,
    "a".repeat(40),
  );
  assert.ok(minterOpts.some(o => o.selector === "RealMinter.mint"), "Non-mock unguarded mint must be queued");
  assert.ok(minterOpts.some(o => o.selector === "RealMinter.deposit"), "Core DeFi deposit entrypoint must be queued");
  const selectedDeposit = minterOpts.find(o => o.selector === "RealMinter.deposit")!;
  assert.match(selectedDeposit.probe.hypothesis, /Unauthorized caller/,
    "A source-backed unauthorized-mint hypothesis must outrank an exploratory fallback");

  // A plain entrypoint with no grounded security assertion must remain exploratory.
  const plainSource = `pragma solidity 0.8.4;
contract PlainVault {
  function deposit(uint256 amount) external {}
}`;
  const plainPath = "source-1/contracts/PlainVault.sol";
  const plainOpts = controllerGroundedSolidityOptions(
    plainPath,
    plainSource,
    [{ selector: "PlainVault.deposit", operation: "send", inputs: ["uint256"] }],
    [{ path: plainPath, content: plainSource, sha256: sha(plainSource) }],
    "a".repeat(40),
  );
  assert.equal(plainOpts.some(o => o.selector === "PlainVault.deposit"), false,
    "A plain deposit without a source-derived security assertion must not become an executable experiment");
  const plainConstruction = constructSolidityExperiments({
    repositoryCommit: "a".repeat(40),
    targetPath: plainPath,
    targetSelector: "PlainVault.deposit",
    sources: [{ path: plainPath, content: plainSource, sha256: sha(plainSource) }],
    declarations: [{ selector: "PlainVault.deposit", operation: "send", inputs: ["uint256"] }],
  });
  assert.equal(plainConstruction.ok, false,
    "The source-backed planner must retain plain deposit as a lead instead of inventing an invariant");
  if (!plainConstruction.ok) {
    assert.equal(plainConstruction.code, "UNKNOWN_ASSERTION");
    assert.match(plainConstruction.detail, /Financial entrypoint exists/);
    assert.match(plainConstruction.detail, /no source-derived prestate/);
  }
}

// 3. Queue prioritization & Tier-4 setter cap (>16 items, max 3 Tier-4 per path)
{
  const items = [
    ...Array.from({ length: 16 }, (_, i) => ({
      id: `setter-${i}`,
      plan: { path: "source-1/contracts/Config.sol", query: `Config.set${i}`, hypothesis: `source-proven owner-gated state transition ${i}` },
    })),
    {
      id: "defi-deposit",
      plan: { path: "source-1/contracts/Vault.sol", query: "Vault.deposit", hypothesis: "core DeFi entrypoint state check" },
    },
    {
      id: "eth-extract",
      plan: { path: "source-1/contracts/Vault.sol", query: "Vault.sweep", hypothesis: "unauthorized ETH extraction guard" },
    },
  ];
  const leads = [{ path: "source-1/contracts/Vault.sol", line: 10, rule: "solidity-eth-transfer", message: "eth", severity: "WARNING" }];
  const prioritized = prioritizeSolidityStagedPlans(items, leads);
  assert.equal(prioritized.selected[0].id, "eth-extract", "Tier 1 extraction probe must be first");
  assert.equal(prioritized.selected[1].id, "defi-deposit", "Tier 2 core DeFi probe must precede setters");
  assert.equal(prioritized.droppedTier4Count, 0, "Round 3 must not discard valid low-priority experiments");
  assert.equal(prioritized.selected.length, items.length,
    "Priority must order all valid options without discarding any");
  assert.equal(new Set(prioritized.selected.map(item=>item.id)).size, items.length,
    "Each valid option must be retained exactly once");
}

// 4. Protocol decodeAuditAction in ANALYZE stage
{
  const decoded = decodeAuditAction(
    JSON.stringify({
      action: "discover_experiment",
      file: "source-1/contracts/Vault.sol",
      function: "Vault.deposit",
      kind: "solidity_sequence",
      sequence: { constructorArgs: [], steps: [{ operation: "send", function: "deposit(uint256)", args: ["10"], sender: 1 }] },
    }),
    true,
    true,
  );
  assert.equal(decoded.path, "source-1/contracts/Vault.sol");
  assert.equal(decoded.query, "Vault.deposit");
  assert.equal(decoded.answer, "solidity_sequence");
  assert.throws(() => decodeAuditAction(JSON.stringify({ action: "discover_experiment", path: "", query: "", answer: "" }), true, false));
}

// 5. rankSolidityStaticTargets with limit 24
{
  const targets = rankSolidityStaticTargets([
    "source-1/contracts/mocks/Fake.sol",
    "source-1/vendor/Lib.sol",
    "source-1/contracts/DInterest.sol",
    "source-1/contracts/MPHMinter.sol",
  ], "source-1", 24);
  assert.deepEqual(targets, ["contracts/DInterest.sol", "contracts/MPHMinter.sol"]);
}

// 6. A legacy model endpoint cannot reactivate Qwen in LOTUS-CLONE.
// End-to-end deterministic ANALYZE, EXPERIMENT, REVIEW and source inventory
// are exercised by scripts/test-deterministic-lotus.ts and
// scripts/test-deterministic-full-inventory.ts, without any model server.
{
  const { resolveLocalModelAdapter } = await import("../packages/security-solver/src/deterministic");
  assert.equal(resolveLocalModelAdapter({AUTOHACK_OLLAMA_URL:"http://127.0.0.1:11434/api/chat"}),"deterministic");
  assert.throws(() => resolveLocalModelAdapter({LOCAL_MODEL_ADAPTER:"qwen-agent"}),/LOTUS_MODEL_REMOVED/);
}

// 7. Regression tests for #232: GBNF schema sanitization, hypothesis priority tiers, .isContract() binding, Echidna/Dummy exclusions
{
  const sanitized = sanitizeOllamaFormatSchema({
    type: "object",
    additionalProperties: false,
    properties: {
      leadId: { type: "string", pattern: "^[a-f0-9]{64}$" },
      reason: { type: "string", minLength: 20, maxLength: 600 },
      findings: { type: "array", maxItems: 0 },
    },
    required: ["findings", "reason"],
  });
  assert.equal(sanitized.properties.leadId.pattern, undefined);
  assert.equal(sanitized.properties.reason.minLength, undefined);
  assert.equal(sanitized.properties.reason.maxLength, undefined);
  assert.equal(sanitized.properties.findings.maxItems, 0);
  assert.deepEqual(sanitized.required, ["findings", "reason"]);

  assert.equal(solidityProbeBasePriority("Unauthorized caller must not mint NFTs via NFT.mint; authorized owner may."), 100);
  assert.equal(solidityProbeBasePriority("Unauthorized caller ($account1) must not extract ETH from Vault via sweep."), 100);
  assert.equal(solidityProbeBasePriority("Unauthorized caller must not re-initialize Market.initialize once initialized; initial owner authority must remain deployer ($account0)."), 40);
  assert.equal(solidityProbeBasePriority("Non-owner must not pause MPHConverter via MPHConverter.pause; owner may."), 40);
  assert.equal(solidityProbeBasePriority("Unauthorized caller must not transfer Vault ownership via transferOwnership."), 40);
  assert.equal(solidityProbeBasePriority("Unauthorized caller must not update fee via FeeModel.setFee; authorized owner may."), 10);

  const ranked = rankSolidityStaticTargets([
    "source-1/contracts/EchidnaDepositWithdrawTest.sol",
    "source-1/contracts/rewards/DummyMPHMinter.sol",
    "source-1/contracts/echidna/Harness.sol",
    "source-1/contracts/VaultTests.sol",
    "source-1/contracts/DInterest.sol",
  ], "source-1");
  assert.deepEqual(ranked, ["contracts/DInterest.sol"], "Echidna, Dummy, and *Test(s) Solidity files must be excluded");

  const marketSource = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;
library AddressUpgradeable { function isContract(address account) internal view returns (bool) { return account.code.length > 0; } }
abstract contract OwnableUpgradeable {
  address private _owner;
  modifier onlyOwner() { require(msg.sender == _owner, "owner"); _; }
  function __Ownable_init() internal { _owner = msg.sender; }
  function owner() public view returns (address) { return _owner; }
}
contract MarketWithContractGuards is OwnableUpgradeable {
  using AddressUpgradeable for address;
  address public cToken;
  address public rewards;
  address public stablecoin;
  bool private initialized;
  modifier initializer() { require(!initialized, "init"); initialized = true; _; }
  function initialize(address _cToken, address _rewards, address _stablecoin) external initializer {
    __Ownable_init();
    require(_cToken.isContract() && _stablecoin.isContract() && _rewards != address(0), "invalid");
    cToken = _cToken;
    rewards = _rewards;
    stablecoin = _stablecoin;
  }
  function setRewards(address _rewards) external onlyOwner {
    require(_rewards != address(0), "zero");
    rewards = _rewards;
  }
}
`;
  const marketPlan = constructSolidityExperiments({
    repositoryCommit: "0123456789abcdef0123456789abcdef01234567",
    targetPath: "source-1/contracts/MarketWithContractGuards.sol",
    targetSelector: "MarketWithContractGuards.setRewards",
    sources: [{ path: "source-1/contracts/MarketWithContractGuards.sol", content: marketSource, sha256: sha(marketSource) }],
    declarations: [
      { selector: "MarketWithContractGuards.initialize", operation: "send", inputs: ["address", "address", "address"] },
      { selector: "MarketWithContractGuards.setRewards", operation: "send", inputs: ["address"] },
      { selector: "MarketWithContractGuards.owner", operation: "call", inputs: [] },
      { selector: "MarketWithContractGuards.rewards", operation: "call", inputs: [] },
    ],
  });
  assert.equal(marketPlan.ok, true, "MarketWithContractGuards plan must succeed");
  if (marketPlan.ok) {
    const initStep = marketPlan.experiments[0].sequence.steps.find(step => step.operation === "send" && step.function.startsWith("initialize("));
    assert.ok(initStep, "Plan must include initialize setup step");
    assert.deepEqual(initStep.args, ["$contract", "$account2", "$contract"], ".isContract() initialize params must resolve to $contract");
  }
}

// Approved financial-property regression: the construction gate must build
// source-grounded share and vesting tests without admitting guessed properties.
{
  const tokenSource='pragma solidity 0.8.4; contract ERC20Mock { mapping(address=>uint256) public balanceOf; function mint(address to,uint256 amount) public {balanceOf[to]+=amount;} function approve(address,uint256) external returns(bool) { return true; } }';
  const tokenPath='source-1/contracts/mocks/ERC20Mock.sol';
  const shareSource=`pragma solidity 0.8.4;
contract xMPH is ERC20Upgradeable, AccessControlUpgradeable {
 uint256 public constant MIN_AMOUNT=10**9;
 function initialize(address _mph,uint256 rewardUnlockPeriod,address distributor) external {}
 function getPricePerFullShare() public view returns(uint256) {
   if (_lastRewardAmount == 0) {return mphBalance.div(totalShares);} return 0;
 }
 function deposit(uint256 _mphAmount) external returns(uint256 shareAmount) {
   return _deposit(_mphAmount);
 }
 function _deposit(uint256 _mphAmount) internal returns(uint256 shareAmount) {
   shareAmount = _mphAmount.div(getPricePerFullShare());
   _mint(msg.sender, shareAmount);
   mph.safeTransferFrom(msg.sender,address(this),_mphAmount);
 }
 function withdraw(uint256 _shareAmount) external returns(uint256 mphAmount) {
   return _withdraw(_shareAmount);
 }
 function _withdraw(uint256 _shareAmount) internal returns(uint256 mphAmount) {
   require(totalSupply() >= _shareAmount + MIN_AMOUNT);
   mphAmount = _shareAmount.mul(getPricePerFullShare());
   _burn(msg.sender,_shareAmount);
   mph.safeTransfer(msg.sender,mphAmount);
 }
 function initSeed() internal { _deposit(MIN_AMOUNT); }
}`;
  const sharePath='source-1/contracts/rewards/xMPH.sol';
  const sharePlan=constructSolidityExperiments({
    repositoryCommit:'a'.repeat(40),targetPath:sharePath,targetSelector:'xMPH.withdraw',
    sources:[{path:sharePath,content:shareSource,sha256:sha(shareSource)},
      {path:tokenPath,content:tokenSource,sha256:sha(tokenSource)}],
    declarations:[
      {selector:'xMPH.initialize',operation:'send',inputs:['address','uint256','address']},
      {selector:'xMPH.deposit',operation:'send',inputs:['uint256']},
      {selector:'xMPH.withdraw',operation:'send',inputs:['uint256']},
    ],
  });
  assert.equal(sharePlan.ok,true,'Source-backed zero-reward shares must yield an executable plan');
  if(sharePlan.ok){
    const plan=sharePlan.experiments.find(p=>p.securityProperty.includes('share conservation'));
    assert.ok(plan,'Source-proven share test must survive normal planner admission');
    assert.ok(plan.sequence.preparation?.operations.some(x=>x.id==='mintSeedAndDeposit'));
    assert.ok(plan.sequence.steps.some(x=>x.operation==='call'&&x.function==='totalSupply()'));
  }
  const unprovedSource=shareSource.replace('_burn(msg.sender,_shareAmount);','');
  const unproved=constructSolidityExperiments({
    repositoryCommit:'a'.repeat(40),targetPath:sharePath,targetSelector:'xMPH.withdraw',
    sources:[{path:sharePath,content:unprovedSource,sha256:sha(unprovedSource)},
      {path:tokenPath,content:tokenSource,sha256:sha(tokenSource)}],
    declarations:[{selector:'xMPH.withdraw',operation:'send',inputs:['uint256']},
      {selector:'xMPH.deposit',operation:'send',inputs:['uint256']},
      {selector:'xMPH.initialize',operation:'send',inputs:['address','uint256','address']}],
  });
  assert.equal(unproved.ok,false,'Do not guess share conservation after removing burn witness');
  const vestSource=`pragma solidity 0.8.4;
contract Vesting02 is ERC721URIStorageUpgradeable, BoringOwnable {
 uint64[] public vestList;address public mphMinter;
 mapping(address=>mapping(uint64=>uint64)) public depositIDToVestID;
 function initialize(address _token,string calldata tokenName,string calldata tokenSymbol) external {}
 function setMPHMinter(address value) external {mphMinter=value;}
 function createVestForDeposit(address to,address pool,uint64 depositID,uint256 rate) external returns(uint64 vestID){
   require(address(msg.sender) == address(mphMinter));
   vestList.push(1);
   vestID = uint64(vestList.length);
   depositIDToVestID[pool][depositID] = vestID;
   _safeMint(to, vestID);
 }
 function numVests() external view returns(uint256){return vestList.length;}
}`;
  const vestPath='source-1/contracts/rewards/Vesting02.sol';
  const vest=constructSolidityExperiments({
    repositoryCommit:'a'.repeat(40),targetPath:vestPath,targetSelector:'Vesting02.createVestForDeposit',
    sources:[{path:vestPath,content:vestSource,sha256:sha(vestSource)}],
    declarations:[
      {selector:'Vesting02.initialize',operation:'send',inputs:['address','string','string']},
      {selector:'Vesting02.setMPHMinter',operation:'send',inputs:['address']},
      {selector:'Vesting02.createVestForDeposit',operation:'send',inputs:['address','address','uint64','uint256']},
      {selector:'Vesting02.numVests',operation:'call',inputs:[]}],
  });
  assert.equal(vest.ok,true,'Vesting creation must be admitted by source effects, not name lists');
  if(vest.ok)assert.ok(vest.experiments.some(p=>p.securityProperty.includes('vest creation')));
}

// A source with two valid outflows must produce two separate financial
// properties rather than a guessed first companion or a discarded lead.
{
  const multiSource=`pragma solidity ^0.8.0;
contract Finance {
 uint256 public totalDeposits;
 function deposit(uint256 amount) external {totalDeposits += amount;}
 function withdraw(uint256 amount) external {totalDeposits -= amount;}
 function redeem(uint256 amount) external {totalDeposits -= amount;}
}`;
  const path='source-1/contracts/Finance.sol';
  const multi=constructSolidityExperiments({
    repositoryCommit:'a'.repeat(40),targetPath:path,targetSelector:'Finance.deposit',
    sources:[{path,content:multiSource,sha256:sha(multiSource)}],
    declarations:[
      {selector:'Finance.totalDeposits',operation:'call',inputs:[]},
      {selector:'Finance.deposit',operation:'send',inputs:['uint256']},
      {selector:'Finance.withdraw',operation:'send',inputs:['uint256']},
      {selector:'Finance.redeem',operation:'send',inputs:['uint256']}],
  });
  assert.equal(multi.ok,true,'Ambiguous source-backed companion set must remain constructible');
  if(multi.ok){
    const pairs=multi.experiments.filter(x=>x.securityProperty.startsWith('financial '));
    assert.equal(pairs.length,2);
    assert.equal(new Set(pairs.map(x=>x.id)).size,2,'Each distinct proven counterpart requires its own experiment ID');
  }
}

console.log("DeFi probes, security classification, ANALYZE window & REVIEW anti-bias tests PASSED");
