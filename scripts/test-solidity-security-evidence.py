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

from solidity_security_evidence import security_behavior_observed, security_experiment_disposition  # noqa: E402

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
