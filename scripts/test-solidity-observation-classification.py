#!/usr/bin/env python3
"""No EVM/network needed: classify recorded transactions, not guessed output."""
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('lotus_source_reproduction',Path(__file__).with_name('source-reproduction.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
evaluate=module.observed_non_deployer_state_transition
before={'operation':'observe','function':'operator()','sender':0,'actual':'0x0000000000000000000000000000000000000001'}
send={'operation':'send','function':'rotateOperator(address)','sender':1,'reverted':False,'passed':True}
after={**before,'actual':'0x0000000000000000000000000000000000000002'}
assert evaluate([before,send,after])
assert evaluate([before,{**send,'passed':False},after]), 'successful role transfer disproving revert must be preserved'
assert not evaluate([before,{**send,'reverted':True},after]), 'reverted send cannot establish state mutation'
assert not evaluate([before,{**send,'sender':0},after]), 'deployer action does not prove cross-account mutation'
assert not evaluate([before,send,before]), 'no state change cannot be a positive behavior'
assert not evaluate([before,send,{**after,'function':'administrator()'}]), 'unrelated getter cannot prove the send effect'
assert not evaluate([before,send,{**after,'sender':2}]), 'different getter caller context is not comparable'
assert not evaluate([before,{'operation':'call','function':'value()','passed':False},after])
# A source-authenticated getter, actual EVM write, and exact parameter match
# are independently sufficient for a bounded property test. This does not
# assert the absence of vulnerabilities or bypass security review.
import tempfile
from solidity_security_evidence import (
    _source_witnessed_direct_assignment_negative,
    security_experiment_disposition,
)
with tempfile.TemporaryDirectory() as td:
    path=Path(td)/"Authority.sol"
    src="""pragma solidity ^0.8.20;
contract Authority {
 address public operator;
 constructor(){operator=msg.sender;}
 function rotateOperator(address next) external {
   require(next!=address(0),"zero"); operator=next;
 }
}"""
    path.write_text(src)
    account0="0x0000000000000000000000000000000000000001"
    account1="0x0000000000000000000000000000000000000002"
    account2="0x0000000000000000000000000000000000000003"
    requested=[
        {"operation":"observe","function":"operator()","args":[]},
        {"operation":"send","function":"rotateOperator(address)",
         "args":["$account2"],"sender":0},
        {"operation":"call","function":"operator()","args":[],"expect":"$account2"},
    ]
    actual=[
        {"operation":"observe","function":"operator()","actual":account0},
        {"operation":"send","function":"rotateOperator(address)","sender":0,
         "passed":True,"reverted":False},
        {"operation":"call","function":"operator()","actual":account2,"passed":True},
    ]
    accounts=[account0,account1,account2]
    witnessed=_source_witnessed_direct_assignment_negative(
        path,"Authority.rotateOperator",requested,actual,accounts)
    assert witnessed and witnessed[0]=="source_direct_assignment_negative", witnessed
    classification=security_experiment_disposition(
        Path(td),path,"Authority.rotateOperator",
        {"steps":actual,"accounts":accounts},
        {"sequence":{"steps":requested}})
    assert classification[0]=="behavior_not_observed",classification
    assert _source_witnessed_direct_assignment_negative(
        path,"Authority.rotateOperator",requested,
        [*actual[:2],{**actual[2],"actual":account1}],accounts) is None
    assert _source_witnessed_direct_assignment_negative(
        path,"Authority.rotateOperator",requested,
        [*actual[:1],{**actual[1],"reverted":True,"passed":False},actual[2]],accounts) is None
    path.write_text(src.replace("operator=next;","operator=msg.sender;"))
    assert _source_witnessed_direct_assignment_negative(
        path,"Authority.rotateOperator",requested,actual,accounts) is None
    path.write_text(src.replace("address public operator;",
                                "address private operator;"))
    assert _source_witnessed_direct_assignment_negative(
        path,"Authority.rotateOperator",requested,actual,accounts) is None

print('Solidity non-deployer state-transition classifier PASSED')
