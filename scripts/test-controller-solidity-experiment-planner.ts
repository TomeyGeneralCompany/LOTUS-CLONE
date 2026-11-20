import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {constructSolidityExperiments} from '../packages/security-solver/src/controller-solidity-experiment-planner';
const content=`pragma solidity ^0.8.20;
contract Vault {
  address public owner;
  uint256 public reserve;
  constructor() { owner = msg.sender; }
  function setReserve(uint256 value) external {
    require(msg.sender == owner, "owner only");
    reserve = value;
  }
}`;
const input={
 repositoryCommit:'f'.repeat(40),targetPath:'contracts/Vault.sol',
 targetSelector:'Vault.setReserve',
 sources:[{path:'contracts/Vault.sol',sha256:createHash('sha256').update(content).digest('hex'),content}],
 declarations:[
 {selector:'Vault.setReserve',operation:'send' as const,inputs:['uint256']},
 {selector:'Vault.reserve',operation:'call' as const,inputs:[]},
 {selector:'Vault.owner',operation:'call' as const,inputs:[]}
 ]};
const a=constructSolidityExperiments(input);
assert.equal(a.ok,true,JSON.stringify(a));
if(a.ok){
 assert.ok(a.experiments.length>0);
 assert.ok(a.experiments.every(x=>x.sequence.steps.length===6));
 assert.deepEqual(a,constructSolidityExperiments(input),'Construction must be deterministic');
}
const changed={...input,sources:[{...input.sources[0],content:content+'\n'}]};
assert.deepEqual(constructSolidityExperiments(changed).ok,false,'Source hash must match bytes');
const unguarded={...input,sources:[{...input.sources[0],
 content:content.replace('require(msg.sender == owner, "owner only");','')}]};
unguarded.sources[0].sha256=createHash('sha256').update(unguarded.sources[0].content).digest('hex');
assert.equal(constructSolidityExperiments(unguarded).ok,false,'No authorization proof, no scenario');

// Regression derived from the 88mphV3 run's actual Vesting02 / BoringOwnable
// initialization, owner guard and MPHMinter setter. Standalone; no reader.
const ownable='pragma solidity 0.8.4; contract BoringOwnable {'+
  'address private _owner;'+
  'function __Ownable_init() internal { _owner = msg.sender; }'+
  'function owner() external view returns(address){return _owner;}'+
  'modifier onlyOwner(){require(msg.sender == _owner, "Ownable: caller is not the owner");_;}'+
  '}';
const vesting='pragma solidity 0.8.4; import {BoringOwnable} from "../libs/BoringOwnable.sol";'+
  'interface IERC20 {} interface MPHMinter {} contract Vesting02 is BoringOwnable {'+
  'IERC20 public token; MPHMinter public mphMinter;'+
  'function initialize(address _token,string calldata tokenName,string calldata tokenSymbol) external initializer {'+
  '__Ownable_init(); __ERC721_init(tokenName, tokenSymbol); token = IERC20(_token); }'+
  'function setMPHMinter(address newValue) external onlyOwner {'+
  'require(newValue != address(0),"Vesting02: 0 address");'+
  'mphMinter = MPHMinter(newValue); emit ESetMPHMinter(newValue); }'+
  'event ESetMPHMinter(address newValue); }';
const vestingInput={
 repositoryCommit:'f'.repeat(40),
 targetPath:'contracts/rewards/Vesting02.sol',
 targetSelector:'Vesting02.setMPHMinter',
 sources:[
  {path:'contracts/rewards/Vesting02.sol',sha256:createHash('sha256').update(vesting).digest('hex'),content:vesting},
  {path:'contracts/libs/BoringOwnable.sol',sha256:createHash('sha256').update(ownable).digest('hex'),content:ownable}
 ],
 declarations:[{selector:'Vesting02.setMPHMinter',operation:'send' as const,inputs:['address']}]
};
const inheritedResult=constructSolidityExperiments(vestingInput);
assert.equal(inheritedResult.ok,true,JSON.stringify(inheritedResult));
if(inheritedResult.ok) {
 assert.equal(inheritedResult.experiments.length,1);
 assert.equal(inheritedResult.experiments[0].sequence.steps.length,7);
 assert.equal(inheritedResult.experiments[0].witnesses.length,6);
}

// Broadened ANALYZE regressions: OwnableUpgradeable, PausableUpgradeable,
// AccessControlUpgradeable, ERC20/ERC721 minting, explicit view getters,
// multi-hop local inheritance, and strict rejection of unsafe initializers.
const nftSrc = `pragma solidity 0.8.4;
import {ERC721URIStorageUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
contract NFT is ERC721URIStorageUpgradeable, OwnableUpgradeable {
  string internal _contractURI;
  function initialize(string calldata n, string calldata s) external initializer {
    __Ownable_init();
    __ERC721_init(n, s);
  }
  function contractURI() external view returns (string memory) { return _contractURI; }
  function setContractURI(string calldata newURI) external onlyOwner { _contractURI = newURI; }
  function mint(address to, uint256 tokenId) external onlyOwner { _safeMint(to, tokenId); }
}`;
const nftSha = createHash('sha256').update(nftSrc).digest('hex');
const nftUriRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/tokens/NFT.sol',
  targetSelector: 'NFT.setContractURI',
  sources: [{path: 'contracts/tokens/NFT.sol', sha256: nftSha, content: nftSrc}],
  declarations: [{selector: 'NFT.setContractURI', operation: 'send', inputs: ['string calldata']}]
});
assert.equal(nftUriRes.ok, true, JSON.stringify(nftUriRes));
if (nftUriRes.ok) {
  assert.equal(nftUriRes.experiments[0].sequence.steps[0].function, 'initialize(string,string)');
  assert.equal(nftUriRes.experiments[0].sequence.steps[3].function, 'setContractURI(string)');
  assert.equal(nftUriRes.experiments[0].sequence.steps[3].expectRevert, true);
}
const nftMintRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/tokens/NFT.sol',
  targetSelector: 'NFT.mint',
  sources: [{path: 'contracts/tokens/NFT.sol', sha256: nftSha, content: nftSrc}],
  declarations: [{selector: 'NFT.mint', operation: 'send', inputs: ['address', 'uint256']}]
});
assert.equal(nftMintRes.ok, true, JSON.stringify(nftMintRes));
if (nftMintRes.ok) {
  assert.equal(nftMintRes.experiments[0].sequence.steps.at(-1)?.function, 'ownerOf(uint256)');
}

const converterSrc = `pragma solidity 0.8.4;
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
interface MPHMinter {}
contract MPHConverter is PausableUpgradeable, OwnableUpgradeable {
  MPHMinter public mphMinter;
  mapping(address => bool) public isWhitelistedForeignToken;
  function initialize(MPHMinter _mphMinter) external initializer {
    __Pausable_init();
    __Ownable_init();
    mphMinter = _mphMinter;
  }
  function pause() external onlyOwner { _pause(); }
  function unpause() external onlyOwner { _unpause(); }
  function setForeignTokenWhitelist(IERC20 foreignToken, bool isWhitelisted) external onlyOwner {
    isWhitelistedForeignToken[address(foreignToken)] = isWhitelisted;
  }
}`;
const convSha = createHash('sha256').update(converterSrc).digest('hex');
for (const sel of ['MPHConverter.pause', 'MPHConverter.unpause', 'MPHConverter.setForeignTokenWhitelist']) {
  const res = constructSolidityExperiments({
    repositoryCommit: 'f'.repeat(40),
    targetPath: 'contracts/rewards/MPHConverter.sol',
    targetSelector: sel,
    sources: [{path: 'contracts/rewards/MPHConverter.sol', sha256: convSha, content: converterSrc}],
    declarations: [{selector: sel, operation: 'send', inputs: []}]
  });
  assert.equal(res.ok, true, sel + ': ' + JSON.stringify(res));
}

const minterSrc = `pragma solidity 0.8.4;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
contract MPHMinter is AccessControlUpgradeable {
  uint256 internal constant PRECISION = 10**18;
  address public govTreasury;
  address public vesting02;
  uint256 public devRewardMultiplier;
  function __MPHMinter_init(address _govTreasury, address _vesting02, uint256 _dev) internal initializer {
    __AccessControl_init();
    __MPHMinter_init_unchained(_govTreasury, _vesting02, _dev);
  }
  function __MPHMinter_init_unchained(address _govTreasury, address _vesting02, uint256 _dev) internal initializer {
    _setupRole(DEFAULT_ADMIN_ROLE, _govTreasury);
    govTreasury = _govTreasury;
    vesting02 = _vesting02;
    devRewardMultiplier = _dev;
  }
  function initialize(address _govTreasury, address _vesting02, uint256 _dev) external initializer {
    __MPHMinter_init(_govTreasury, _vesting02, _dev);
  }
  function setGovTreasury(address newValue) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(newValue != address(0), "0");
    govTreasury = newValue;
  }
  function setDevRewardMultiplier(uint256 newMultiplier) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(newMultiplier <= PRECISION, "bad");
    devRewardMultiplier = newMultiplier;
  }
  function setVesting02(address newValue) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(newValue.isContract(), "not contract");
    vesting02 = newValue;
  }
}`;
const minterSha = createHash('sha256').update(minterSrc).digest('hex');
const govRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/rewards/MPHMinter.sol',
  targetSelector: 'MPHMinter.setGovTreasury',
  sources: [{path: 'contracts/rewards/MPHMinter.sol', sha256: minterSha, content: minterSrc}],
  declarations: [{selector: 'MPHMinter.setGovTreasury', operation: 'send', inputs: ['address']}]
});
assert.equal(govRes.ok, true, JSON.stringify(govRes));
if (govRes.ok) {
  assert.deepEqual(govRes.experiments[0].sequence.steps[0].args, ['$account0', '$account2', '0']);
  assert.equal(govRes.experiments[0].sequence.steps[1].function, 'hasRole(bytes32,address)');
}
const vestSetRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/rewards/MPHMinter.sol',
  targetSelector: 'MPHMinter.setVesting02',
  sources: [{path: 'contracts/rewards/MPHMinter.sol', sha256: minterSha, content: minterSrc}],
  declarations: [{selector: 'MPHMinter.setVesting02', operation: 'send', inputs: ['address']}]
});
assert.equal(vestSetRes.ok, true, JSON.stringify(vestSetRes));
if (vestSetRes.ok) {
  assert.deepEqual(vestSetRes.experiments[0].sequence.steps[3].args, ['$contract']);
}

// Negative control: initializer calling external contract via helper must be rejected.
const unsafeInitSrc = `pragma solidity 0.8.4;
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
interface IERC20 { function transferFrom(address,address,uint256) external; }
contract UnsafeToken is OwnableUpgradeable {
  IERC20 public token;
  uint256 public fee;
  function initialize(address _token) external initializer {
    __Ownable_init();
    token = IERC20(_token);
    _pull();
  }
  function _pull() internal { token.transferFrom(msg.sender, address(this), 1); }
  function setFee(uint256 v) external onlyOwner { fee = v; }
}`;
const unsafeSha = createHash('sha256').update(unsafeInitSrc).digest('hex');
assert.equal(constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/UnsafeToken.sol',
  targetSelector: 'UnsafeToken.setFee',
  sources: [{path: 'contracts/UnsafeToken.sol', sha256: unsafeSha, content: unsafeInitSrc}],
  declarations: [{selector: 'UnsafeToken.setFee', operation: 'send', inputs: ['uint256']}]
}).ok, false, 'Initializer with unverified helper / external call must be rejected');

// Negative control: untrusted external base import must be rejected.
const untrustedBaseSrc = `pragma solidity 0.8.4;
import {OwnableUpgradeable} from "@untrusted/FakeOwnable.sol";
contract FakeVault is OwnableUpgradeable {
  uint256 public fee;
  function initialize() external initializer { __Ownable_init(); }
  function setFee(uint256 v) external onlyOwner { fee = v; }
}`;
const untrustedSha = createHash('sha256').update(untrustedBaseSrc).digest('hex');
assert.equal(constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/FakeVault.sol',
  targetSelector: 'FakeVault.setFee',
  sources: [{path: 'contracts/FakeVault.sol', sha256: untrustedSha, content: untrustedBaseSrc}],
  declarations: [{selector: 'FakeVault.setFee', operation: 'send', inputs: ['uint256']}]
}).ok, false, 'Untrusted external Ownable import must be rejected');

// Non-setter A1: initialize() re-initialization guard (initializer present)
const reinitSrc = `pragma solidity 0.8.4;
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
contract ReinitVault is OwnableUpgradeable {
  function initialize() external initializer { __Ownable_init(); }
  function transferOwnership(address newOwner) public override onlyOwner {}
}`;
const reinitSha = createHash('sha256').update(reinitSrc).digest('hex');
const reinitRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/ReinitVault.sol',
  targetSelector: 'ReinitVault.initialize',
  sources: [{path: 'contracts/ReinitVault.sol', sha256: reinitSha, content: reinitSrc}],
  declarations: [
    {selector: 'ReinitVault.initialize', operation: 'send', inputs: []},
    {selector: 'ReinitVault.owner', operation: 'call', inputs: []},
    {selector: 'ReinitVault.transferOwnership', operation: 'send', inputs: ['address']},
  ]
});
assert.equal(reinitRes.ok, true, 'initialize() re-init guard must construct');
if (reinitRes.ok) {
  assert.equal(reinitRes.experiments[0].sequence.steps[0].function, 'initialize()');
  assert.equal(reinitRes.experiments[0].sequence.steps[2].sender, 1);
  assert.equal(reinitRes.experiments[0].sequence.steps[2].expectRevert, true);
}

// Non-setter A2: initialize() missing initializer modifier still constructs bounded check
const missingInitModSrc = `pragma solidity 0.8.4;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
contract OpenInit is AccessControlUpgradeable {
  function initialize(address admin) external { _setupRole(DEFAULT_ADMIN_ROLE, admin); }
}`;
const missingInitSha = createHash('sha256').update(missingInitModSrc).digest('hex');
const missingInitRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/OpenInit.sol',
  targetSelector: 'OpenInit.initialize',
  sources: [{path: 'contracts/OpenInit.sol', sha256: missingInitSha, content: missingInitModSrc}],
  declarations: [
    {selector: 'OpenInit.initialize', operation: 'send', inputs: ['address']},
    {selector: 'OpenInit.hasRole', operation: 'call', inputs: ['bytes32', 'address']},
  ]
});
assert.equal(missingInitRes.ok, true, 'missing-initializer initialize(address) must construct');
if (missingInitRes.ok) {
  assert.deepEqual(missingInitRes.experiments[0].sequence.steps[0].args, ['$account0']);
  assert.deepEqual(missingInitRes.experiments[0].sequence.steps[2].args, ['$account1']);
  assert.equal(missingInitRes.experiments[0].sequence.steps[2].expectRevert, true);
}

// Non-setter B: authority transfer (BoringOwnable.transferOwnership, OZ transferOwnership, renounceOwnership, grantRole)
const boringTransferLib = ownable.replace(
  'modifier onlyOwner',
  'function transferOwnership(address newOwner, bool direct, bool renounce) public onlyOwner {} modifier onlyOwner'
);
const transferBoringRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: vestingInput.targetPath,
  targetSelector: 'Vesting02.transferOwnership',
  sources: [
    vestingInput.sources[0],
    {path: 'contracts/libs/BoringOwnable.sol', sha256: createHash('sha256').update(boringTransferLib).digest('hex'), content: boringTransferLib},
  ],
  declarations: [
    {selector: 'Vesting02.initialize', operation: 'send', inputs: ['address', 'string', 'string']},
    {selector: 'Vesting02.transferOwnership', operation: 'send', inputs: ['address', 'bool', 'bool']},
    {selector: 'Vesting02.owner', operation: 'call', inputs: []},
  ]
});
assert.equal(transferBoringRes.ok, true, 'BoringOwnable transferOwnership must construct');
if (transferBoringRes.ok) {
  const sends = transferBoringRes.experiments[0].sequence.steps.filter(s => s.operation === 'send');
  assert.equal(sends.length, 3);
  assert.equal(sends[1].sender, 1);
  assert.equal(sends[1].expectRevert, true);
}

const ozOwnableSrc = `pragma solidity 0.8.4;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
contract OwnableVault is Ownable {
  function ping() external onlyOwner {}
}`;
const ozOwnableSha = createHash('sha256').update(ozOwnableSrc).digest('hex');
const ozRenounceRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/OwnableVault.sol',
  targetSelector: 'OwnableVault.renounceOwnership',
  sources: [{path: 'contracts/OwnableVault.sol', sha256: ozOwnableSha, content: ozOwnableSrc}],
  declarations: [
    {selector: 'OwnableVault.renounceOwnership', operation: 'send', inputs: []},
    {selector: 'OwnableVault.transferOwnership', operation: 'send', inputs: ['address']},
    {selector: 'OwnableVault.owner', operation: 'call', inputs: []},
  ]
});
assert.equal(ozRenounceRes.ok, true, 'OZ renounceOwnership must construct');
const ozGrantRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/rewards/MPHMinter.sol',
  targetSelector: 'MPHMinter.grantRole',
  sources: [{path: 'contracts/rewards/MPHMinter.sol', sha256: minterSha, content: minterSrc}],
  declarations: [
    {selector: 'MPHMinter.initialize', operation: 'send', inputs: ['address', 'address', 'uint256']},
    {selector: 'MPHMinter.grantRole', operation: 'send', inputs: ['bytes32', 'address']},
    {selector: 'MPHMinter.hasRole', operation: 'call', inputs: ['bytes32', 'address']},
  ]
});
assert.equal(ozGrantRes.ok, true, 'AccessControl grantRole must construct');

// Non-setter C: dangerous primitive (tx.origin / selfdestruct / delegatecall) + staticLeads hint
const dangerSrc = `pragma solidity 0.8.4;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
contract DangerVault is Ownable {
  function destroy(address payable to) external onlyOwner {
    selfdestruct(to);
  }
  function txOriginAction() external {
    require(tx.origin == owner(), "not origin");
  }
  function hashOnly(bytes memory b) external pure returns (bytes32) {
    return keccak256(abi.encodePacked(b));
  }
}`;
const dangerSha = createHash('sha256').update(dangerSrc).digest('hex');
const dangerDecls = [
  {selector: 'DangerVault.destroy', operation: 'send' as const, inputs: ['address']},
  {selector: 'DangerVault.txOriginAction', operation: 'send' as const, inputs: []},
  {selector: 'DangerVault.hashOnly', operation: 'call' as const, inputs: ['bytes']},
  {selector: 'DangerVault.owner', operation: 'call' as const, inputs: []},
];
const destroyRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/DangerVault.sol',
  targetSelector: 'DangerVault.destroy',
  sources: [{path: 'contracts/DangerVault.sol', sha256: dangerSha, content: dangerSrc}],
  declarations: dangerDecls,
  staticLeads: [{path: 'contracts/DangerVault.sol', line: 5, rule: 'solidity-selfdestruct', message: 'Inspect selfdestruct'}]
});
assert.equal(destroyRes.ok, true, 'Guarded selfdestruct must construct bounded auth test');
const txOriginRes = constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/DangerVault.sol',
  targetSelector: 'DangerVault.txOriginAction',
  sources: [{path: 'contracts/DangerVault.sol', sha256: dangerSha, content: dangerSrc}],
  declarations: dangerDecls,
  staticLeads: [{path: 'contracts/DangerVault.sol', line: 8, rule: 'solidity-tx-origin-auth', message: 'Inspect tx.origin'}]
});
assert.equal(txOriginRes.ok, true, 'tx.origin check must construct bounded auth test');

// Negative control: unguarded ABI-packed helper with static lead must still return ok=false
const unguardedHashSrc = `pragma solidity 0.8.4;
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
contract SafePack is Ownable {
  uint256 public nonce;
  function bump(bytes memory b) external { nonce = uint256(keccak256(abi.encodePacked(b))); }
}`;
const unguardedHashSha = createHash('sha256').update(unguardedHashSrc).digest('hex');
assert.equal(constructSolidityExperiments({
  repositoryCommit: 'f'.repeat(40),
  targetPath: 'contracts/SafePack.sol',
  targetSelector: 'SafePack.bump',
  sources: [{path: 'contracts/SafePack.sol', sha256: unguardedHashSha, content: unguardedHashSrc}],
  declarations: [
    {selector: 'SafePack.bump', operation: 'send', inputs: ['bytes']},
    {selector: 'SafePack.owner', operation: 'call', inputs: []},
  ],
  staticLeads: [{path: 'contracts/SafePack.sol', line: 5, rule: 'solidity-abi-encode-packed-hash', message: 'Inspect abi.encodePacked'}]
}).ok, false, 'Non-dangerous static lead on unguarded function must not fabricate auth experiment');


// --- 3-stage Financial-Invariant Pipeline & Negative Controls ---

// 1. ETH deposit -> withdraw accounting defect (BuggyAccountingVault vs FixedAccountingVault)
const buggyVaultSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract BuggyAccountingVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}`;
const fixedVaultSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FixedAccountingVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}`;
for (const [name, code] of [['BuggyAccountingVault', buggyVaultSrc], ['FixedAccountingVault', fixedVaultSrc]] as const) {
  const vaultSha = createHash('sha256').update(code).digest('hex');
  const vaultDecls = [
    {selector: `${name}.deposit`, operation: 'send' as const, inputs: []},
    {selector: `${name}.withdraw`, operation: 'send' as const, inputs: ['uint256']},
    {selector: `${name}.totalDeposits`, operation: 'call' as const, inputs: []},
    {selector: `${name}.balances`, operation: 'call' as const, inputs: ['address']},
  ];
  const res = constructSolidityExperiments({
    repositoryCommit: 'e'.repeat(40),
    targetPath: `contracts/${name}.sol`,
    targetSelector: `${name}.withdraw`,
    sources: [{path: `contracts/${name}.sol`, sha256: vaultSha, content: code}],
    declarations: vaultDecls,
  });
  assert.equal(res.ok, true, `${name}.withdraw must construct financial conservation experiment`);
  if (res.ok) {
    const invExp = res.experiments.find((e) => e.securityProperty.includes('conservation'));
    assert.ok(invExp, `${name}.withdraw must include conservation experiment`);
    assert.ok(invExp!.witnesses.length >= 2, 'Conservation experiment must cite both deposit and withdraw witnesses');
    const stepFns = invExp!.sequence.steps.map((s) => ('function' in s ? s.function : s.operation));
    assert.ok(stepFns.includes('deposit()'), 'Sequence must call deposit()');
    assert.ok(stepFns.includes('withdraw(uint256)'), 'Sequence must call withdraw(uint256)');
    assert.ok(
      invExp!.sequence.steps.some((s) => s.operation === 'call' && s.function === 'totalDeposits()' && s.expect === '600'),
      'Sequence must assert totalDeposits() == 600 after deposit(1000) -> withdraw(400)',
    );
  }
}

// 2. Internal ledger deposit(uint256) -> withdraw(uint256) conservation
const internalLedgerSrc = `pragma solidity ^0.8.20;
contract InternalLedgerVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
}`;
const internalLedgerRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: 'contracts/InternalLedgerVault.sol',
  targetSelector: 'InternalLedgerVault.withdraw',
  sources: [{path: 'contracts/InternalLedgerVault.sol', sha256: createHash('sha256').update(internalLedgerSrc).digest('hex'), content: internalLedgerSrc}],
  declarations: [
    {selector: 'InternalLedgerVault.deposit', operation: 'send', inputs: ['uint256']},
    {selector: 'InternalLedgerVault.withdraw', operation: 'send', inputs: ['uint256']},
    {selector: 'InternalLedgerVault.totalDeposits', operation: 'call', inputs: []},
    {selector: 'InternalLedgerVault.balances', operation: 'call', inputs: ['address']},
  ],
});
assert.equal(internalLedgerRes.ok, true, 'Internal ledger deposit/withdraw must construct conservation invariant');

// 3. Mint/burn totalSupply conservation
const mintBurnSrc = `pragma solidity ^0.8.20;
contract MintBurnVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    function burn(address from, uint256 amount) external {
        require(balanceOf[from] >= amount, "insufficient");
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}`;
const mintBurnRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: 'contracts/MintBurnVault.sol',
  targetSelector: 'MintBurnVault.burn',
  sources: [{path: 'contracts/MintBurnVault.sol', sha256: createHash('sha256').update(mintBurnSrc).digest('hex'), content: mintBurnSrc}],
  declarations: [
    {selector: 'MintBurnVault.mint', operation: 'send', inputs: ['address', 'uint256']},
    {selector: 'MintBurnVault.burn', operation: 'send', inputs: ['address', 'uint256']},
    {selector: 'MintBurnVault.totalSupply', operation: 'call', inputs: []},
    {selector: 'MintBurnVault.balanceOf', operation: 'call', inputs: ['address']},
  ],
});
assert.equal(mintBurnRes.ok, true, 'Mint/burn conservation invariant must construct');

// 4. Negative control: private state without public getters -> UNKNOWN_ASSERTION(missing_observable_state)
const privateVaultSrc = `pragma solidity ^0.8.20;
contract PrivateAccountingVault {
    mapping(address => uint256) private balances;
    uint256 private totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }
}`;
const privateVaultRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: 'contracts/PrivateAccountingVault.sol',
  targetSelector: 'PrivateAccountingVault.deposit',
  sources: [{path: 'contracts/PrivateAccountingVault.sol', sha256: createHash('sha256').update(privateVaultSrc).digest('hex'), content: privateVaultSrc}],
  declarations: [
    {selector: 'PrivateAccountingVault.deposit', operation: 'send', inputs: []},
    {selector: 'PrivateAccountingVault.withdraw', operation: 'send', inputs: ['uint256']},
  ],
});
assert.equal(privateVaultRes.ok, false, 'Private accounting state with no observable getter must refuse to fabricate');
if (!privateVaultRes.ok) {
  assert.equal(privateVaultRes.code, 'UNKNOWN_ASSERTION');
  assert.equal(privateVaultRes.unresolvedCategory, 'missing_observable_state');
}

// 5. Negative control: unresolvable external dependency -> UNKNOWN_ASSERTION, zero fabricated experiments
const oracleVaultSrc = `pragma solidity ^0.8.20;
interface IExternalBook { function credit(address u, uint256 a) external; function debit(address u, uint256 a) external; }
contract ExternalOracleVault {
    IExternalBook public book;
    uint256 public totalDeposits;
    constructor(address _book) { book = IExternalBook(_book); }
    function deposit(uint256 amount) external {
        book.credit(msg.sender, amount);
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        book.debit(msg.sender, amount);
        totalDeposits -= amount;
    }
}`;
const oracleVaultRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: 'contracts/ExternalOracleVault.sol',
  targetSelector: 'ExternalOracleVault.withdraw',
  sources: [{path: 'contracts/ExternalOracleVault.sol', sha256: createHash('sha256').update(oracleVaultSrc).digest('hex'), content: oracleVaultSrc}],
  declarations: [
    {selector: 'ExternalOracleVault.deposit', operation: 'send', inputs: ['uint256']},
    {selector: 'ExternalOracleVault.withdraw', operation: 'send', inputs: ['uint256']},
    {selector: 'ExternalOracleVault.totalDeposits', operation: 'call', inputs: []},
  ],
});
assert.equal(oracleVaultRes.ok, false, 'External unresolved dependency must refuse to fabricate experiment');
if (!oracleVaultRes.ok) {
  assert.equal(oracleVaultRes.code, 'UNKNOWN_ASSERTION');
  assert.ok(
    oracleVaultRes.unresolvedCategory === 'unresolved_dependency' ||
      oracleVaultRes.unresolvedCategory === 'missing_fixture',
    `Expected unresolved_dependency or missing_fixture, got ${oracleVaultRes.unresolvedCategory}`,
  );
}

// 6. Acquired-source ERC20 vault multi-contract fixture construction (erc20_deposit_withdraw)
const mockErc20Src = `pragma solidity ^0.8.20;
contract ERC20Mock {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        require(allowance[from][msg.sender] >= amount, "allow");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}`;
const erc20VaultSrc = `pragma solidity ^0.8.20;
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}
contract CoreERC20Vault {
    IERC20 public stablecoin;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    constructor(address _stablecoin) { stablecoin = IERC20(_stablecoin); }
    function deposit(uint256 amount) external {
        require(stablecoin.transferFrom(msg.sender, address(this), amount), "tf");
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
        // Intentional accounting bug: totalDeposits not decremented!
        require(stablecoin.transfer(msg.sender, amount), "t");
    }
}`;
const mockErc20Snap = {
  path: 'contracts/mocks/ERC20Mock.sol',
  sha256: createHash('sha256').update(mockErc20Src).digest('hex'),
  content: mockErc20Src,
};
const erc20VaultSnap = {
  path: 'contracts/CoreERC20Vault.sol',
  sha256: createHash('sha256').update(erc20VaultSrc).digest('hex'),
  content: erc20VaultSrc,
};
const erc20VaultRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: erc20VaultSnap.path,
  targetSelector: 'CoreERC20Vault.withdraw',
  sources: [erc20VaultSnap, mockErc20Snap],
  declarations: [
    {selector: 'CoreERC20Vault.deposit', operation: 'send', inputs: ['uint256']},
    {selector: 'CoreERC20Vault.withdraw', operation: 'send', inputs: ['uint256']},
    {selector: 'CoreERC20Vault.totalDeposits', operation: 'call', inputs: []},
    {selector: 'CoreERC20Vault.balances', operation: 'call', inputs: ['address']},
  ],
});
assert.equal(erc20VaultRes.ok, true, 'Acquired-source ERC20 vault with MockERC20 must construct multi-contract fixture');
if (erc20VaultRes.ok) {
  const exp = erc20VaultRes.experiments.find((e) => e.securityProperty.includes('conservation'));
  assert.ok(exp, 'Expected conservation invariant experiment for CoreERC20Vault');
  assert.equal(exp!.sequence.preparation?.deployments?.[0]?.id, 'token');
  assert.equal(exp!.sequence.preparation?.deployments?.[0]?.file, mockErc20Snap.path);
  assert.deepEqual(exp!.sequence.constructorArgs, ['$deployment:token']);
  assert.ok(
    exp!.sequence.steps.some((s: any) => s.deploymentId === 'token' && s.function === 'mint(address,uint256)'),
    'ERC20 fixture must mint tokens on $deployment:token',
  );
  assert.ok(
    exp!.sequence.steps.some((s: any) => s.deploymentId === 'token' && s.function === 'approve(address,uint256)'),
    'ERC20 fixture must approve $contract on $deployment:token',
  );
  assert.ok(
    exp!.sequence.steps.some((s: any) => s.operation === 'call' && s.function === 'totalDeposits()' && s.expect === '600'),
    'ERC20 conservation experiment must assert post-withdraw totalDeposits == 600',
  );
}

// 7. Off-repo external market adapter (BenqiERC20Market) MUST still refuse even when ERC20Mock is present
const benqiSrc = `pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); function transfer(address t, uint256 a) external returns (bool); }
interface ICERC20 { function mint(uint256 a) external returns (uint256); function redeemUnderlying(uint256 a) external returns (uint256); }
interface IComptroller { function claimComp(address holder) external; }
contract BenqiERC20Market {
    IERC20 public stablecoin;
    ICERC20 public cToken;
    IComptroller public comptroller;
    uint256 public totalDeposits;
    constructor(address _stablecoin, address _cToken, address _comptroller) {
        stablecoin = IERC20(_stablecoin);
        cToken = ICERC20(_cToken);
        comptroller = IComptroller(_comptroller);
    }
    function deposit(uint256 amount) external {
        stablecoin.transferFrom(msg.sender, address(this), amount);
        cToken.mint(amount);
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        cToken.redeemUnderlying(amount);
        comptroller.claimComp(address(this));
        stablecoin.transfer(msg.sender, amount);
        totalDeposits -= amount;
    }
}`;
const benqiSnap = {
  path: 'contracts/models/moneymarket/benqi/BenqiERC20Market.sol',
  sha256: createHash('sha256').update(benqiSrc).digest('hex'),
  content: benqiSrc,
};
const benqiRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: benqiSnap.path,
  targetSelector: 'BenqiERC20Market.deposit',
  sources: [benqiSnap, mockErc20Snap],
  declarations: [
    {selector: 'BenqiERC20Market.deposit', operation: 'send', inputs: ['uint256']},
    {selector: 'BenqiERC20Market.withdraw', operation: 'send', inputs: ['uint256']},
    {selector: 'BenqiERC20Market.totalDeposits', operation: 'call', inputs: []},
  ],
});
assert.equal(benqiRes.ok, false, 'External Benqi market adapter with ICERC20/IComptroller must refuse');
if (!benqiRes.ok) {
  assert.equal(benqiRes.code, 'UNKNOWN_ASSERTION');
  assert.equal(benqiRes.unresolvedCategory, 'unresolved_dependency');
}

// 8. Abstract contract with acquired concrete subclass reports subclass hint cleanly
const abstractMarketSrc = `pragma solidity ^0.8.20;
abstract contract YVaultMarket {
    uint256 public totalDeposits;
    function deposit(uint256 amount) external virtual;
    function withdraw(uint256 amount) external { totalDeposits -= amount; }
}`;
const concreteMarketSrc = `pragma solidity ^0.8.20;
contract YVaultMarketV2 is YVaultMarket {
    function deposit(uint256 amount) external override { totalDeposits += amount; }
}`;
const abstractSnap = {
  path: 'contracts/models/moneymarket/yvault/YVaultMarket.sol',
  sha256: createHash('sha256').update(abstractMarketSrc).digest('hex'),
  content: abstractMarketSrc,
};
const concreteSnap = {
  path: 'contracts/models/moneymarket/yvault/YVaultMarketV2.sol',
  sha256: createHash('sha256').update(concreteMarketSrc).digest('hex'),
  content: concreteMarketSrc,
};
const abstractRes = constructSolidityExperiments({
  repositoryCommit: 'e'.repeat(40),
  targetPath: abstractSnap.path,
  targetSelector: 'YVaultMarket.withdraw',
  sources: [abstractSnap, concreteSnap],
  declarations: [
    {selector: 'YVaultMarket.withdraw', operation: 'send', inputs: ['uint256']},
    {selector: 'YVaultMarket.totalDeposits', operation: 'call', inputs: []},
  ],
});
assert.equal(abstractRes.ok, false, 'Abstract contract must refuse direct instantiation');
if (!abstractRes.ok) {
  assert.equal(abstractRes.code, 'UNKNOWN_ASSERTION');
  assert.equal(abstractRes.unresolvedCategory, 'missing_fixture');
  assert.match(abstractRes.detail, /YVaultMarketV2/, 'Abstract contract refusal must report acquired concrete subclass');
}

console.log('Standalone experiment construction passed');
