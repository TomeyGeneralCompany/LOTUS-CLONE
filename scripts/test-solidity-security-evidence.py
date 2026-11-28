#!/usr/bin/env python3
"""Offline tests for multi-class Solidity security evidence, compile caching, and pragma selection."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from solidity_security_evidence import (security_behavior_observed, security_experiment_disposition,
    _dynamic_observation_arguments_match, _asserted_dynamic_position_withdrawal_negative)  # noqa: E402

repro_spec = importlib.util.spec_from_file_location('source_repro', SCRIPTS_DIR / 'source-reproduction.py')
repro_mod = importlib.util.module_from_spec(repro_spec)
repro_spec.loader.exec_module(repro_mod)

static_spec = importlib.util.spec_from_file_location('source_static', SCRIPTS_DIR / 'source-static.py')
static_mod = importlib.util.module_from_spec(static_spec)
static_spec.loader.exec_module(static_mod)


ACCOUNTS = [
    "0x" + "11" * 20,
    "0x" + "22" * 20,
    "0x" + "33" * 20,
]
CONTRACT_ADDR = "0x" + "44" * 20


class SoliditySecurityEvidenceTests(unittest.TestCase):
    def test_dynamic_withdrawal_argument_must_match_prior_struct_observation(self):
        requested=[
            {"operation":"observe","function":"getDeposit(uint64)","args":["1"]},
            {"operation":"send","function":"withdraw(uint64,uint256,bool)",
             "args":["1","$lastObservation:0",True]},
        ]
        actual=[
            {"operation":"observe","function":"getDeposit(uint64)","args":["1"],
             "actual":["1087","87000000000000000"]},
            {"operation":"send","function":"withdraw(uint64,uint256,bool)",
             "args":["1","1087",True]},
        ]
        self.assertTrue(_dynamic_observation_arguments_match(requested,actual))
        tampered=[dict(actual[0]),dict(actual[1],args=["1","1088",True])]
        self.assertFalse(_dynamic_observation_arguments_match(requested,tampered))
        missing=[dict(actual[0]),{"operation":"send","args":["1",True]}]
        self.assertFalse(_dynamic_observation_arguments_match(requested,missing))
        out_of_range=[dict(requested[0]),dict(requested[1],args=["1","$lastObservation:8",True])]
        self.assertFalse(_dynamic_observation_arguments_match(out_of_range,actual))

    def test_dynamic_position_lifecycle_requires_source_and_two_final_readbacks(self):
        source=("contract Vault { struct Deposit { uint256 virtualTokenTotalSupply; } "
                "function getDeposit(uint64 depositID) external view returns(Deposit memory) "
                "{ return deposits[depositID - 1]; } "
                "function deposit(uint256 depositAmount,uint64) external "
                "{ totalDeposit += depositAmount; } "
                "function withdraw(uint64 depositID,uint256 virtualTokenAmount,bool) external "
                "{ if(virtualTokenAmount > virtualTokenTotalSupply) "
                "{ virtualTokenAmount = virtualTokenTotalSupply; } "
                "totalDeposit -= depositAmount; "
                "_getDeposit(depositID).virtualTokenTotalSupply -= virtualTokenAmount; } }")
        requested=[
            {"operation":"call","function":"totalDeposit()","expect":"0"},
            {"operation":"send","function":"deposit(uint256,uint64)"},
            {"operation":"call","function":"totalDeposit()","expect":"1000"},
            {"operation":"observe","function":"getDeposit(uint64)","args":["1"]},
            {"operation":"send","function":"withdraw(uint64,uint256,bool)",
             "args":["1","$lastObservation:0",True]},
            {"operation":"call","function":"getDeposit(uint64)","expectPath":[0]},
            {"operation":"call","function":"totalDeposit()","expect":"0"},
        ]
        actual=[
            {"operation":"call","actual":"0","passed":True},
            {"operation":"send","args":["1000","2000000000"],"passed":True},
            {"operation":"call","actual":"1000","passed":True},
            {"operation":"observe","args":["1"],"actual":["1000"]},
            {"operation":"send","args":["1","1000",True],"passed":True},
            {"operation":"call","actual":"0","passed":True},
            {"operation":"call","actual":"0","passed":True},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            source_path=Path(tmp)/"Vault.sol"
            source_path.write_text(source,encoding="utf8")
            result=_asserted_dynamic_position_withdrawal_negative(source_path,requested,actual)
            self.assertIsNotNone(result)
            bad=actual[:-1]+[dict(actual[-1],actual="1",passed=False)]
            self.assertIsNone(_asserted_dynamic_position_withdrawal_negative(
                source_path,requested,bad))

    def test_imported_inherited_method_requires_acquired_executable_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            src=root/"contracts"
            src.mkdir()
            abstract=src/"Rescuable.sol"
            abstract.write_text(
                "pragma solidity ^0.8.4; abstract contract Rescuable { "
                "function rescue(uint256 amount) external virtual { require(amount>0); } }")
            concrete=src/"Wallet.sol"
            concrete.write_text(
                'pragma solidity ^0.8.4; import "./Rescuable.sol"; '
                'contract Wallet is Rescuable { }')
            allowed,why=repro_mod.execution_capability(
                root,"contracts/Wallet.sol","Wallet.rescue","solidity_sequence")
            self.assertTrue(allowed,why)
            interface=src/"IAccount.sol"
            interface.write_text(
                "pragma solidity ^0.8.4; interface IAccount { "
                "function rescue(uint256 amount) external; }")
            fake=src/"Fake.sol"
            fake.write_text(
                'pragma solidity ^0.8.4; import "./IAccount.sol"; '
                'contract Fake is IAccount { }')
            allowed,_=repro_mod.execution_capability(
                root,"contracts/Fake.sol","Fake.rescue","solidity_sequence")
            self.assertFalse(allowed,
                "An imported ABI interface must not become an invented executable experiment")

    def test_reinit_takeover_positive_and_single_init_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "contracts" / "Vault.sol"
            vault.parent.mkdir(parents=True)
            vault.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Vault {\n"
                "  address public owner;\n"
                "  function initialize(address _owner, uint256 _fee) external {\n"
                "    owner = _owner;\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            steps_takeover = [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[1], "passed": False},
            ]
            ok, cls, _ = security_behavior_observed(
                root, vault, "Vault.initialize", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_takeover}
            )
            self.assertTrue(ok)
            self.assertEqual(cls, "reinit_or_constructor_takeover")

            # Upgradeable proxy guarded on 2nd init: $account1 reverts, owner remains $account0
            steps_guarded = [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 1, "reverted": True, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
            ]
            ok2, cls2, _ = security_behavior_observed(
                root, vault, "Vault.initialize", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded}
            )
            self.assertFalse(ok2)
            self.assertIsNone(cls2)
            # An explicit, fully asserted denied unauthorized transition is a
            # genuine negative outcome, not an unclassified observation.
            guarded_spec = {"sequence": {"steps": [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0},
                {"operation": "call", "function": "owner()"},
                {"operation": "send", "function": "initialize(address,uint256)",
                 "sender": 1, "expectRevert": True},
                {"operation": "call", "function": "owner()"},
            ]}}
            status, category, reason = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded},
                guarded_spec,
            )
            self.assertEqual(status, "behavior_not_observed")
            self.assertEqual(category, "guarded_negative")
            self.assertIn("unchanged", reason)

            # No explicit falsification or a failed assertion remains inconclusive.
            status_unproven, _, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded},
            )
            self.assertEqual(status_unproven, "observation_only")
            failing = [dict(step) for step in steps_guarded]
            failing[-1]["passed"] = False
            status_failed, _, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": failing},
                guarded_spec,
            )
            self.assertEqual(status_failed, "observation_only")
            status_positive, classification_positive, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_takeover},
                guarded_spec,
            )
            self.assertEqual(status_positive, "behavior_observed")
            self.assertEqual(classification_positive, "reinit_or_constructor_takeover")

    def test_eth_and_erc20_extraction_and_guard_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            treasury = root / "contracts" / "Treasury.sol"
            treasury.parent.mkdir(parents=True)
            treasury.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Treasury {\n"
                "  address public owner;\n"
                "  constructor() { owner = msg.sender; }\n"
                "  function sweepETH(address payable to) external {\n"
                "    to.transfer(address(this).balance);\n"
                "  }\n"
                "  function rescueToken(address token, address to, uint256 amt) external {\n"
                "    IERC20(token).transfer(to, amt);\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            eth_steps = [
                {"operation": "eth_balance", "account": "$contract", "address": CONTRACT_ADDR, "balanceWei": "1000000000000000000"},
                {"operation": "eth_balance", "account": "$account1", "address": ACCOUNTS[1], "balanceWei": "500000000000000000"},
                {"operation": "send", "function": "sweepETH(address)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "eth_balance", "account": "$contract", "address": CONTRACT_ADDR, "balanceWei": "0"},
                {"operation": "eth_balance", "account": "$account1", "address": ACCOUNTS[1], "balanceWei": "1500000000000000000"},
            ]
            ok_eth, cls_eth, _ = security_behavior_observed(
                root, treasury, "Treasury.sweepETH", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": eth_steps}
            )
            self.assertTrue(ok_eth)
            self.assertEqual(cls_eth, "unauthorized_value_extraction")

            erc20_steps = [
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "1000", "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "send", "function": "rescueToken(address,address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "1000", "passed": True},
            ]
            ok_erc, cls_erc, _ = security_behavior_observed(
                root, treasury, "Treasury.rescueToken", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": erc20_steps}
            )
            self.assertTrue(ok_erc)
            self.assertEqual(cls_erc, "unauthorized_value_extraction")

            # Source guard blocks classification even on unexpected trace
            treasury.write_text(
                treasury.read_text(encoding="utf8").replace(
                    "function sweepETH(address payable to) external {",
                    "function sweepETH(address payable to) external { require(msg.sender == owner);",
                ),
                encoding="utf8",
            )
            ok_guarded, _, _ = security_behavior_observed(
                root, treasury, "Treasury.sweepETH", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": eth_steps}
            )
            self.assertFalse(ok_guarded)

    def test_non_mock_mint_vs_mock_exclusion_and_primitives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tok = root / "contracts" / "Token.sol"
            tok.parent.mkdir(parents=True)
            tok.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Token {\n"
                "  uint256 public totalSupply;\n"
                "  mapping(address => uint256) public balanceOf;\n"
                "  function mint(address to, uint256 amount) external {\n"
                "    totalSupply += amount; balanceOf[to] += amount;\n"
                "  }\n"
                "  function exec(address target, bytes calldata data) external {\n"
                "    target.delegatecall(data);\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            mint_steps = [
                {"operation": "call", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "call", "function": "totalSupply()", "sender": 0, "actual": "0", "passed": True},
                {"operation": "send", "function": "mint(address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "balanceOf(address)", "sender": 0, "actual": "500", "passed": True},
                {"operation": "call", "function": "totalSupply()", "sender": 0, "actual": "500", "passed": True},
            ]
            ok_mint, cls_mint, _ = security_behavior_observed(
                root, tok, "Token.mint", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": mint_steps}
            )
            self.assertTrue(ok_mint)
            self.assertEqual(cls_mint, "unauthorized_value_extraction")

            # Mock path must never be flagged for unguarded minting
            mock = root / "contracts" / "mocks" / "ERC20Mock.sol"
            mock.parent.mkdir(parents=True)
            mock.write_text(tok.read_text(encoding="utf8"), encoding="utf8")
            ok_mock, _, _ = security_behavior_observed(
                root, mock, "Token.mint", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": mint_steps}
            )
            self.assertFalse(ok_mock)

            # Unguarded delegatecall primitive
            prim_steps = [
                {"operation": "send", "function": "exec(address,bytes)", "sender": 1, "reverted": False, "passed": True},
            ]
            ok_prim, cls_prim, _ = security_behavior_observed(
                root, tok, "Token.exec", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": prim_steps}
            )
            self.assertTrue(ok_prim)
            self.assertEqual(cls_prim, "unguarded_dangerous_primitive")

    def test_expected_mismatch_alone_never_classifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pool = root / "contracts" / "Pool.sol"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Pool {\n"
                "  uint256 public totalDeposited;\n"
                "  function deposit(uint256 amt) external { totalDeposited += amt; }\n"
                "}\n",
                encoding="utf8",
            )
            steps = [
                {"operation": "send", "function": "deposit(uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "totalDeposited()", "sender": 0, "actual": "7", "expected": "99", "passed": False},
            ]
            ok, cls, _ = security_behavior_observed(
                root, pool, "Pool.deposit", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps}
            )
            self.assertFalse(ok)
            self.assertIsNone(cls)

    def test_88mph_asserted_financial_and_vesting_negative_vs_observation(self):
        """Preserve actual verification semantics for the three laptop observations."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            share = root / "contracts" / "rewards" / "xMPH.sol"
            share.parent.mkdir(parents=True)
            share.write_text(
                "contract xMPH {\n"
                " function deposit(uint256 amount) external {}\n"
                " function withdraw(uint256 amount) external {}\n"
                "}\n", encoding="utf8")
            def call(fn, val, dep=None):
                step={"operation":"call","function":fn,"sender":0,
                      "actual":str(val),"expected":str(val),"passed":True}
                if dep:step["deploymentId"]=dep
                return step
            steps=[
                call("totalSupply()",1000000000),
                call("balanceOf(address)",1000000000,"token"),
                {"operation":"send","function":"deposit(uint256)","sender":0,
                 "reverted":False,"passed":True},
                call("totalSupply()",1000001000),
                call("balanceOf(address)",1000001000,"token"),
                {"operation":"send","function":"withdraw(uint256)","sender":0,
                 "reverted":False,"passed":True},
                call("totalSupply()",1000000600),
                call("balanceOf(address)",1000000600,"token"),
            ]
            request=[{"operation":step["operation"],"function":step["function"],
                      **({"deploymentId":step["deploymentId"]} if "deploymentId" in step else {}),
                      **({"args":["$contract"]} if step["function"]=="balanceOf(address)" else {"args":[]}),
                      **({"sender":step["sender"]} if step["operation"]=="send" else
                         {"expect":step["expected"]})}
                     for step in steps]
            evidence={"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":steps}
            for method in ("deposit","withdraw"):
                result=security_experiment_disposition(root,share,"xMPH."+method,evidence,
                                                        {"sequence":{"steps":request}})
                self.assertEqual(result[0],"behavior_not_observed")
                self.assertEqual(result[1],"share_accounting_negative")
            incorrect=[dict(step) for step in steps]
            incorrect[-1]["passed"]=False
            neg=security_experiment_disposition(root,share,"xMPH.withdraw",
                {**evidence,"steps":incorrect},{"sequence":{"steps":request}})
            self.assertEqual(neg[0],"observation_only")
            missing_setup=[dict(step) for step in steps]
            missing_setup[1]["actual"]="invalid"
            self.assertEqual(security_experiment_disposition(root,share,"xMPH.deposit",
                {**evidence,"steps":missing_setup},{"sequence":{"steps":request}})[0],
                "observation_only")
            vest=root / "contracts" / "rewards" / "Vesting02.sol"
            vest.write_text(
                "contract Vesting02 {\n"
                " function createVestForDeposit(address to,address pool,uint64 id,uint256 rate) external {}\n"
                "}\n", encoding="utf8")
            veststeps=[
                call("numVests()",0),
                {"operation":"send","function":"createVestForDeposit(address,address,uint64,uint256)",
                 "sender":0,"reverted":True,"passed":True},
                call("numVests()",0),
                {"operation":"send","function":"createVestForDeposit(address,address,uint64,uint256)",
                 "sender":1,"reverted":False,"passed":True},
                call("numVests()",1),
                call("depositIDToVestID(address,uint64)",1),
                call("ownerOf(uint256)",ACCOUNTS[2]),
            ]
            vestreq=[{"operation":step["operation"],"function":step["function"],
                      **({"sender":step["sender"],"expectRevert":step["reverted"]}
                         if step["operation"]=="send" else {"expect":step["expected"]})}
                     for step in veststeps]
            vestout=security_experiment_disposition(root,vest,"Vesting02.createVestForDeposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":veststeps},
                {"sequence":{"steps":vestreq}})
            self.assertEqual(vestout[0],"behavior_not_observed")
            self.assertEqual(vestout[1],"vest_creation_negative")
            # Exact laptop evidence: the verifier resolved $account2 into the
            # third EVM signer. A placeholder is not a failed ownership assertion.
            vest_with_setup=[
                {"operation":"send","function":"initialize(address,string,string)",
                 "sender":0,"reverted":False,"passed":True},
                {"operation":"send","function":"setMPHMinter(address)",
                 "sender":0,"reverted":False,"passed":True},
                *veststeps,
            ]
            vest_source_requests=[
                {"operation":"send","function":"initialize(address,string,string)",
                 "sender":0},
                {"operation":"send","function":"setMPHMinter(address)",
                 "sender":0},
                *vestreq,
            ]
            vest_source_requests[-1]["expect"]="$account2"
            observed=security_experiment_disposition(root,vest,
                "Vesting02.createVestForDeposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":vest_with_setup},
                {"sequence":{"steps":vest_source_requests}})
            self.assertEqual(observed[0],"behavior_not_observed",
                "The exact 9-step laptop trace had all nine asserted steps pass")
            self.assertEqual(observed[1],"vest_creation_negative")
            wrong_owner=[dict(x) for x in vest_with_setup]
            wrong_owner[-1]["actual"]=ACCOUNTS[1]
            wrong_owner[-1]["passed"]=False
            wrong=security_experiment_disposition(root,vest,
                "Vesting02.createVestForDeposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":wrong_owner},
                {"sequence":{"steps":vest_source_requests}})
            self.assertEqual(wrong[0],"observation_only",
                "An actual failed ownership assertion must not certify a negative")
            vestmissing=veststeps[:-1]
            self.assertEqual(security_experiment_disposition(root,vest,
                "Vesting02.createVestForDeposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":vestmissing},
                {"sequence":{"steps":vestreq}})[0],"observation_only")

    def test_xmph_reward_unlock_uses_observed_local_evm_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/"contracts"/"rewards"/"xMPH.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "contract xMPH is ERC20Upgradeable, AccessControlUpgradeable {\n"
                "uint256 public constant MIN_AMOUNT=10**9;\n"
                "uint256 internal constant MAX_REWARD_UNLOCK_PERIOD=365 days;\n"
                "uint256 public rewardUnlockPeriod; uint256 public currentUnlockEndTimestamp;\n"
                "uint256 public lastRewardTimestamp; uint256 public lastRewardAmount;\n"
                "function initialize(address _mph,uint256 _rewardUnlockPeriod,address _distributor) external { "
                "_setupRole(DISTRIBUTOR_ROLE,msg.sender); _deposit(MIN_AMOUNT); }\n"
                "function distributeReward(uint256 rewardAmount) external { require(hasRole(DISTRIBUTOR_ROLE,msg.sender)); "
                "mph.safeTransferFrom(msg.sender,address(this),rewardAmount); "
                "currentUnlockEndTimestamp=block.timestamp+rewardUnlockPeriod; "
                "lastRewardTimestamp=block.timestamp; lastRewardAmount=rewardAmount; emit DistributeReward(rewardAmount); }\n"
                "function deposit(uint256 _mphAmount) external returns(uint256 shareAmount) { "
                "shareAmount=_mphAmount.div(getPricePerFullShare()); _mint(msg.sender,shareAmount); "
                "mph.safeTransferFrom(msg.sender,address(this),_mphAmount); }\n"
                "function withdraw(uint256 _shareAmount) external returns(uint256 mphAmount) { "
                "require(totalSupply() >= _shareAmount + MIN_AMOUNT); "
                "mphAmount=_shareAmount.mul(getPricePerFullShare()); _burn(msg.sender,_shareAmount); "
                "mph.safeTransfer(msg.sender,mphAmount); }\n"
                "function getPricePerFullShare() external view returns(uint256) { uint256 lockedRewardAmount="
                "(_lastRewardAmount*(_currentUnlockEndTimestamp-block.timestamp))/"
                "(_currentUnlockEndTimestamp-_lastRewardTimestamp); return (mphBalance-lockedRewardAmount).div(totalShares); }\n"
                "}",encoding="utf8")
            req=[
                {"operation":"send","function":"approve(address,uint256)","sender":0},
                {"operation":"send","function":"initialize(address,uint256,address)",
                 "args":["$deployment:token","86400","$account0"],"sender":0},
                {"operation":"call","deploymentId":"token","function":"balanceOf(address)","args":["$contract"],"expect":"1000000000"},
                {"operation":"send","function":"distributeReward(uint256)","args":["1000000000"],"sender":2,"expectRevert":True},
                {"operation":"call","deploymentId":"token","function":"balanceOf(address)","args":["$contract"],"expect":"1000000000"},
                {"operation":"send","function":"distributeReward(uint256)","args":["1000000000"],"sender":0},
                {"operation":"call","function":"getPricePerFullShare()","expect":"1000000000000000000"},
                {"operation":"advance_time","seconds":"43200"},
                {"operation":"observe","function":"getPricePerFullShare()","args":[]},
                {"operation":"advance_time","seconds":"43200"},
                {"operation":"call","function":"getPricePerFullShare()","expect":"2000000000000000000"},
                {"operation":"send","function":"deposit(uint256)","args":["1000"],"sender":0},
                {"operation":"call","function":"getPricePerFullShare()","expect":"2000000000000000000"},
                {"operation":"send","function":"withdraw(uint256)","args":["400"],"sender":0},
                {"operation":"call","deploymentId":"token","function":"balanceOf(address)","args":["$account0"],"expect":"999999800"},
                {"operation":"call","deploymentId":"token","function":"balanceOf(address)","args":["$contract"],"expect":"2000000200"},
            ]
            first_elapsed=43201
            locked=1000000000*(86400-first_elapsed)//86400
            midpoint=str((2000000000-locked)*10**18//1000000000)
            actual=[]
            local_time=1577836800
            for i,step in enumerate(req):
                item={"operation":step["operation"],"passed":True}
                if step["operation"]=="call": item["actual"]=step["expect"]
                if step["operation"]=="observe": item["actual"]=midpoint
                if step["operation"]=="send":
                    item.update({"reverted":step.get("expectRevert",False),"args":step.get("args",[])})
                    if step["function"]=="distributeReward(uint256)" and step["sender"]==0:
                        item.update({"eventsPassed":True,"expectedEvents":[
                            {"signature":"DistributeReward(uint256)","passed":True}]})
                if step["operation"]=="advance_time":
                    item.update({"fromTimestamp":str(local_time),"toTimestamp":str(local_time+43201),
                                 "elapsedSeconds":"43201"})
                    local_time+=43201
                actual.append(item)
            result=security_experiment_disposition(root,source,"xMPH.distributeReward",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":actual},
                {"sequence":{"steps":req}})
            self.assertEqual(result[0],"behavior_not_observed")
            self.assertEqual(result[1],"source_xmph_reward_unlock_negative")
            bad_time=[dict(item) for item in actual]
            bad_time[8]=dict(actual[8],actual="1500000000000000000")
            self.assertEqual(security_experiment_disposition(root,source,"xMPH.distributeReward",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":bad_time},
                {"sequence":{"steps":req}})[0],"observation_only")

    def test_general_source_scalar_conservation_is_independently_proven(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/"contracts"/"Ledger.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Ledger {\n"
                "uint256 public reserve;\n"
                "function accrue(uint256 amount) external { reserve += amount; }\n"
                "}\n",encoding="utf8")
            sha=hashlib.sha256(source.read_bytes()).hexdigest()
            before={"operation":"call","function":"reserve()",
                    "sender":0,"actual":"0","expected":"0","passed":True}
            tx={"operation":"send","function":"accrue(uint256)",
                "sender":0,"reverted":False,"passed":True}
            after={"operation":"call","function":"reserve()",
                   "sender":0,"actual":"1000","expected":"1000","passed":True}
            requested=[
                {"operation":"call","function":"reserve()","args":[],"expect":"0"},
                {"operation":"send","function":"accrue(uint256)","args":["1000"],"sender":0},
                {"operation":"call","function":"reserve()","args":[],"expect":"1000"},
            ]
            prop={"kind":"scalar_delta","state":"reserve","method":"accrue(uint256)",
                  "parameter":"amount","amount":"1000","direction":"increase",
                  "sourceSha256":sha}
            spec={"sequence":{"constructorArgs":[],"steps":requested,"sourceProperty":prop}}
            evidence={"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,
                      "steps":[before,tx,after]}
            certified=security_experiment_disposition(root,source,"Ledger.accrue",
                evidence,spec)
            self.assertEqual(certified[0],"behavior_not_observed")
            self.assertEqual(certified[1],"source_scalar_delta_negative")
            wrong_state=dict(after,actual="999",passed=False)
            result=security_experiment_disposition(root,source,"Ledger.accrue",
                {**evidence,"steps":[before,tx,wrong_state]},spec)
            self.assertEqual(result[0],"observation_only")
            stale_spec={"sequence":{**spec["sequence"],
                "sourceProperty":{**prop,"sourceSha256":"0"*64}}}
            self.assertEqual(security_experiment_disposition(
                root,source,"Ledger.accrue",evidence,stale_spec)[0],"observation_only")
            unrelated={"sequence":{**spec["sequence"],
                "sourceProperty":{**prop,"method":"accrue(uint8)"}}}
            self.assertEqual(security_experiment_disposition(
                root,source,"Ledger.accrue",evidence,unrelated)[0],"observation_only")

    def test_source_scalar_delta_binds_nonfinal_amount_and_typed_arguments(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/"TypedLedger.sol"
            source.write_text("""pragma solidity ^0.8.20;
contract TypedLedger {
uint256 public totalDeposits;
function deposit(uint256 amount) external { totalDeposits+=amount; }
function deposit(uint64 maturityTimestamp,uint256 wad,bool enabled) external {
require(maturityTimestamp>block.timestamp);
enabled;
totalDeposits+=wad;
}
}
""",encoding="utf8")
            sha=hashlib.sha256(source.read_bytes()).hexdigest()
            requested=[
                {"operation":"call","function":"totalDeposits()","args":[],"expect":"0"},
                {"operation":"send","function":"deposit(uint64,uint256,bool)",
                 "args":["2000000000","1000",False],"sender":0},
                {"operation":"call","function":"totalDeposits()","args":[],"expect":"1000"},
            ]
            actual=[
                {"operation":"call","actual":"0","passed":True},
                {"operation":"send","reverted":False,"passed":True},
                {"operation":"call","actual":"1000","passed":True},
            ]
            prop={"kind":"scalar_delta","state":"totalDeposits",
                  "method":"deposit(uint64,uint256,bool)","parameter":"wad",
                  "amount":"1000","direction":"increase","sourceSha256":sha}
            spec={"sequence":{"constructorArgs":[],"steps":requested,
                              "sourceProperty":prop}}
            result=security_experiment_disposition(root,source,"TypedLedger.deposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":actual},spec)
            self.assertEqual(result[0],"behavior_not_observed")
            self.assertEqual(result[1],"source_scalar_delta_negative")
            wrong_args=[dict(step) for step in requested]
            wrong_args[1]=dict(wrong_args[1],args=["2000000000","1",False])
            wrong_spec={"sequence":{"constructorArgs":[],"steps":wrong_args,
                                    "sourceProperty":prop}}
            self.assertEqual(security_experiment_disposition(
                root,source,"TypedLedger.deposit",{"accounts":ACCOUNTS,
                "contract":CONTRACT_ADDR,"steps":actual},wrong_spec)[0],
                "observation_only")

    def test_source_scalar_delta_accepts_exact_private_state_getter(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/"PrivateScalar.sol"
            source.write_text("""pragma solidity ^0.8.20;
contract PrivateScalar {
uint256 private held;
function observedAmount() external view returns(uint256) { return held; }
function accrue(uint256 value) external { held+=value; }
}
""",encoding="utf8")
            sha=hashlib.sha256(source.read_bytes()).hexdigest()
            requested=[
                {"operation":"call","function":"observedAmount()","args":[],"expect":"0"},
                {"operation":"send","function":"accrue(uint256)","args":["1000"],"sender":0},
                {"operation":"call","function":"observedAmount()","args":[],"expect":"1000"},
            ]
            actual=[
                {"operation":"call","actual":"0","passed":True},
                {"operation":"send","reverted":False,"passed":True},
                {"operation":"call","actual":"1000","passed":True},
            ]
            prop={"kind":"scalar_delta","state":"held","method":"accrue(uint256)",
                  "parameter":"value","amount":"1000","direction":"increase",
                  "sourceSha256":sha}
            spec={"sequence":{"constructorArgs":[],"steps":requested,
                              "sourceProperty":prop}}
            result=security_experiment_disposition(root,source,"PrivateScalar.accrue",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":actual},spec)
            self.assertEqual(result[0],"behavior_not_observed")
            self.assertEqual(result[1],"source_scalar_delta_negative")

    def test_source_scalar_delta_verifies_literal_fee_formula(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/"FeeLedger.sol"
            source.write_text("""pragma solidity ^0.8.20;
contract FeeLedger {
uint256 public fees;
function deposit(uint256 amount) external { fees += amount * 100 / 10000; }
}
""",encoding="utf8")
            sha=hashlib.sha256(source.read_bytes()).hexdigest()
            requested=[
                {"operation":"call","function":"fees()","args":[],"expect":"0"},
                {"operation":"send","function":"deposit(uint256)",
                 "args":["10001"],"sender":0},
                {"operation":"call","function":"fees()","args":[],"expect":"100"},
            ]
            actual=[
                {"operation":"call","actual":"0","passed":True},
                {"operation":"send","reverted":False,"passed":True},
                {"operation":"call","actual":"100","passed":True},
            ]
            prop={"kind":"scalar_delta","state":"fees",
                  "method":"deposit(uint256)","parameter":"amount",
                  "amount":"10001","formula":{"multiplier":"100",
                  "divisor":"10000"},"expectedDelta":"100",
                  "direction":"increase","sourceSha256":sha}
            spec={"sequence":{"constructorArgs":[],"steps":requested,
                              "sourceProperty":prop}}
            result=security_experiment_disposition(root,source,"FeeLedger.deposit",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":actual},spec)
            self.assertEqual(result[0],"behavior_not_observed")
            self.assertEqual(result[1],"source_scalar_delta_negative")
            wrong_formula={**prop,"expectedDelta":"101"}
            wrong_spec={"sequence":{"constructorArgs":[],"steps":requested,
                                    "sourceProperty":wrong_formula}}
            self.assertEqual(security_experiment_disposition(
                root,source,"FeeLedger.deposit",{"accounts":ACCOUNTS,
                "contract":CONTRACT_ADDR,"steps":actual},wrong_spec)[0],
                "observation_only")

    def test_bounded_funding_source_and_state_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            src=root/"contracts"/"settlement"/"SettlementVault.sol"
            src.parent.mkdir(parents=True)
            src.write_text("""contract SettlementVault {
mapping(address=>uint256) public credit;
uint256 public totalCredit;
function fund(address recipient,uint256 amount) external {
uint256 v=amount.bounded(type(uint128).max);
credit[recipient]+=v;totalCredit+=v;}
}
""",encoding="utf8")
            def read(fn,actual,args=None):
                return {"operation":"call","function":fn,"sender":0,"actual":str(actual),
                        "passed":True}
            steps=[read("credit(address)",0),read("totalCredit()",0),
                   {"operation":"send","function":"fund(address,uint256)",
                    "sender":0,"reverted":False,"passed":True},
                   read("credit(address)",1000),read("totalCredit()",1000)]
            req=[{"operation":step["operation"],"function":step["function"],
                  **({"expect":step["actual"]} if step["operation"]=="call" else {"sender":0})}
                 for step in steps]
            result=security_experiment_disposition(root,src,"SettlementVault.fund",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":steps},
                {"sequence":{"steps":req}})
            self.assertEqual(result[0],"behavior_not_observed")
            self.assertEqual(result[1],"bounded_credit_negative")
            wrong=[dict(step) for step in steps]
            wrong[-1]["actual"]="999"
            self.assertEqual(security_experiment_disposition(root,src,"SettlementVault.fund",
                {"accounts":ACCOUNTS,"contract":CONTRACT_ADDR,"steps":wrong},
                {"sequence":{"steps":req}})[0],"observation_only")

    def test_compile_cache_path_and_pragma_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            cache_dir = Path(tmp) / "cache"
            root.mkdir()
            sol = root / "Vault.sol"
            sol.write_text("pragma solidity 0.8.4; contract Vault {}", encoding="utf8")
            spec = {"file": "Vault.sol", "function": "Vault.deposit", "compilerSettings": {}, "remappings": []}

            prev = os.environ.get("TOMEY_SOLC_CACHE")
            try:
                os.environ["TOMEY_SOLC_CACHE"] = str(cache_dir)
                p1 = repro_mod.solidity_compile_cache_path(root, spec)
                self.assertIsNotNone(p1)
                self.assertEqual(p1.parent, cache_dir)
                sol.write_text("pragma solidity 0.8.4; contract Vault { uint256 x; }", encoding="utf8")
                p2 = repro_mod.solidity_compile_cache_path(root, spec)
                self.assertNotEqual(p1, p2)
                os.environ["TOMEY_SOLC_CACHE"] = "0"
                self.assertIsNone(repro_mod.solidity_compile_cache_path(root, spec))
            finally:
                if prev is None:
                    os.environ.pop("TOMEY_SOLC_CACHE", None)
                else:
                    os.environ["TOMEY_SOLC_CACHE"] = prev

        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.8.4;"), "solc_0_8_4")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.8.0;"), "solc_0_8_4")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.5.16;"), "solc_0_5")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.6.12;"), "solc_0_6")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.7.6;"), "solc_0_7")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.8.24;"), "solc")


if __name__ == "__main__":
    unittest.main()
