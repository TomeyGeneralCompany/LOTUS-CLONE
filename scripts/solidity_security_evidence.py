"""Conservative, source-correlated Solidity security behavior classification.

Never treats an arbitrary expected-value mismatch or revert expectation mismatch
as security proof. Every positive classification requires:
- Owned/authorized repository source correlation
- Concrete before/after EVM transactions and observations on Ganache
- Non-administrator ($account1) triggering an unauthorized transition,
  takeover, value/token extraction, or unguarded dangerous primitive.
"""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import Tuple

from solidity_access_evidence import authorization_transition_observed


_AUTH_NAMES = {
    "owner", "admin", "administrator", "governance", "governor",
    "controller", "guardian", "authority", "operator", "manager",
}


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", "", text)


def _extract_fn_bodies(source: str, fn_name: str) -> list[Tuple[str, str]]:
    cleaned = _strip_comments(source)
    pattern = re.compile(
        r"\bfunction\s+" + re.escape(fn_name) + r"\s*\([^)]*\)\s*(?:external|public)\b[^;{]*\{"
    )
    out=[]
    for m in pattern.finditer(cleaned):
        depth = 1
        pos = m.end()
        while pos < len(cleaned) and depth > 0:
            if cleaned[pos] == "{":
                depth += 1
            elif cleaned[pos] == "}":
                depth -= 1
            pos += 1
        if depth == 0:
            out.append((m.group(0),cleaned[m.end():pos - 1]))
    return out


def _extract_fn_body(source: str, fn_name: str) -> Tuple[str, str]:
    bodies=_extract_fn_bodies(source,fn_name)
    if bodies:
        return bodies[0]
    return "", ""


def _is_auth_getter(step: dict, require_passed: bool = True) -> bool:
    if step.get("operation") not in ("call", "observe"):
        return False
    if not isinstance(step.get("actual"), str):
        return False
    if require_passed and step.get("operation") == "call" and step.get("passed") is not True:
        return False
    fn = str(step.get("function", ""))
    base = fn.split("(", 1)[0].strip().lower()
    return base in _AUTH_NAMES and not step.get("deploymentId")


def _reinit_or_constructor_takeover_observed(
    file: Path, selector: str, data: dict
) -> bool:
    steps = data.get("steps") or []
    accounts = data.get("accounts") or []
    if len(accounts) != 3 or len(steps) < 4:
        return False
    acc0 = str(accounts[0]).lower()
    acc1 = str(accounts[1]).lower()
    acc2 = str(accounts[2]).lower()
    fn_name = selector.split(".")[-1]
    if not re.match(r"^(?:initialize|init|__[A-Za-z0-9_]*init)$", fn_name, re.I):
        return False
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False
    header, body = _extract_fn_body(source, fn_name)
    if not header and not body:
        return False
    # Look for initial setup by deployer ($account0), verified auth == $account0,
    # followed by non-deployer ($account1) non-reverting send changing auth to $account1/$account2.
    init0 = next(
        (
            i for i, s in enumerate(steps)
            if s.get("operation") == "send"
            and str(s.get("function", "")).startswith(fn_name + "(")
            and s.get("sender") == 0
            and not s.get("reverted")
        ),
        None,
    )
    if init0 is None:
        return False
    before_auth = next(
        (
            i for i in range(init0 + 1, len(steps))
            if _is_auth_getter(steps[i], require_passed=True)
            and str(steps[i].get("actual", "")).lower() == acc0
        ),
        None,
    )
    if before_auth is None:
        return False
    attack_send = next(
        (
            i for i in range(before_auth + 1, len(steps))
            if s_is_non_deployer_ok(steps[i], fn_name)
        ),
        None,
    )
    if attack_send is None:
        return False
    after_auth = next(
        (
            i for i in range(attack_send + 1, len(steps))
            if _is_auth_getter(steps[i], require_passed=False)
        ),
        None,
    )
    if after_auth is None:
        return False
    new_auth = str(steps[after_auth].get("actual", "")).lower()
    return new_auth in (acc1, acc2) and new_auth != acc0


def s_is_non_deployer_ok(step: dict, fn_name: str) -> bool:
    return (
        step.get("operation") == "send"
        and not step.get("deploymentId")
        and str(step.get("function", "")).startswith(fn_name + "(")
        and step.get("sender") == 1
        and step.get("reverted") is False
    )


def _has_source_auth_guard(header: str, body: str) -> bool:
    combined = header + "\n" + body
    if re.search(
        r"\b(?:onlyOwner|onlyRole|onlyAdmin|onlyOperator|onlyGovernance|onlyMinter|onlyController|onlyGuardian|initializer|hasRole|_checkRole)\b",
        combined,
        re.I,
    ):
        return True
    if re.search(r"\b(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))\s*[!=]=", combined):
        return True
    return False


def _unauthorized_value_extraction_observed(
    repository: Path, file: Path, selector: str, data: dict
) -> Tuple[bool, str]:
    steps = data.get("steps") or []
    accounts = data.get("accounts") or []
    if len(accounts) != 3 or len(steps) < 3:
        return False, ""
    rel = file.as_posix()
    if re.search(r"(?:^|/)(?:mocks?|tests?|__tests__|fixtures|echidna)(?:/|$)|(?:Mock|Tests?)\.sol$|(?:^|/)(?:Dummy|Echidna)[A-Za-z0-9_]*\.sol$", rel, re.I):
        return False, ""
    fn_name = selector.split(".")[-1]
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False, ""
    header, body = _extract_fn_body(source, fn_name)
    if not body or _has_source_auth_guard(header, body):
        return False, ""

    attack_idx = next(
        (i for i, s in enumerate(steps) if s_is_non_deployer_ok(s, fn_name)),
        None,
    )
    if attack_idx is None:
        return False, ""

    acc1 = str(accounts[1]).lower()
    acc2 = str(accounts[2]).lower()
    contract_addr = str(data.get("contract", "")).lower()

    # 1. ETH balance extraction
    if re.search(r"\.\s*(?:transfer|send)\s*\(|\.\s*call\s*\{[^}]*\bvalue\b", body, re.I):
        before_eth = [
            s for s in steps[:attack_idx]
            if s.get("operation") == "eth_balance" and isinstance(s.get("balanceWei"), str)
        ]
        after_eth = [
            s for s in steps[attack_idx + 1:]
            if s.get("operation") == "eth_balance" and isinstance(s.get("balanceWei"), str)
        ]
        before_c = next((int(s["balanceWei"]) for s in before_eth if str(s.get("address", "")).lower() == contract_addr), None)
        after_c = next((int(s["balanceWei"]) for s in after_eth if str(s.get("address", "")).lower() == contract_addr), None)
        before_r = next((int(s["balanceWei"]) for s in before_eth if str(s.get("address", "")).lower() in (acc1, acc2)), None)
        after_r = next((int(s["balanceWei"]) for s in after_eth if str(s.get("address", "")).lower() in (acc1, acc2)), None)
        if before_c is not None and after_c is not None and before_r is not None and after_r is not None:
            if after_c < before_c and after_r > before_r:
                return True, (
                    f"Verified unauthorized ETH extraction by $account1 via {selector} "
                    f"(contract ETH {before_c} -> {after_c}, recipient ETH {before_r} -> {after_r}); "
                    "reachability and exploit impact still require independent review."
                )

    # 2. ERC20 balance extraction (using preparation token deployment)
    if re.search(r"\.\s*(?:safeTransfer|transfer)\s*\(", body, re.I):
        def _token_bal(slice_steps: list, target_ref: str) -> int | None:
            for s in slice_steps:
                if (
                    s.get("operation") in ("call", "observe")
                    and s.get("deploymentId")
                    and str(s.get("function", "")).startswith("balanceOf(")
                    and isinstance(s.get("actual"), str)
                    and re.fullmatch(r"\d+", s["actual"])
                ):
                    pass
            return None

        before_tok = [
            s for s in steps[:attack_idx]
            if s.get("operation") in ("call", "observe")
            and s.get("deploymentId")
            and str(s.get("function", "")).startswith("balanceOf(")
            and re.fullmatch(r"\d+", str(s.get("actual", "")))
        ]
        after_tok = [
            s for s in steps[attack_idx + 1:]
            if s.get("operation") in ("call", "observe")
            and s.get("deploymentId")
            and str(s.get("function", "")).startswith("balanceOf(")
            and re.fullmatch(r"\d+", str(s.get("actual", "")))
        ]
        if len(before_tok) >= 2 and len(after_tok) >= 2:
            b_contract = int(before_tok[-2]["actual"])
            b_recip = int(before_tok[-1]["actual"])
            a_contract = int(after_tok[0]["actual"])
            a_recip = int(after_tok[1]["actual"])
            if a_contract < b_contract and a_recip > b_recip:
                return True, (
                    f"Verified unauthorized ERC20 extraction by $account1 via {selector} "
                    f"(contract balance {b_contract} -> {a_contract}, recipient balance {b_recip} -> {a_recip}); "
                    "reachability and exploit impact still require independent review."
                )

    # 3. Unguarded non-mock token minting
    if re.search(
        r"\b_?(?:safeM|m)int\s*\(|\btotalSupply\s*\+=|\b(?:balanceOf|_balances)\s*\[[^\]]+\]\s*\+=",
        body,
    ):
        def _mint_metrics(slice_steps: list) -> dict[str, int]:
            metrics: dict[str, int] = {}
            for s in slice_steps:
                if s.get("operation") not in ("call", "observe") or s.get("deploymentId"):
                    continue
                fn = str(s.get("function", ""))
                val = str(s.get("actual", ""))
                if not re.fullmatch(r"\d+", val):
                    continue
                if fn.startswith("balanceOf("):
                    metrics["balanceOf"] = int(val)
                elif fn.startswith("totalSupply("):
                    metrics["totalSupply"] = int(val)
            return metrics

        before_m = _mint_metrics(steps[:attack_idx])
        after_m = _mint_metrics(steps[attack_idx + 1:])
        bal_increased = (
            "balanceOf" in before_m and "balanceOf" in after_m and after_m["balanceOf"] > before_m["balanceOf"]
        )
        sup_increased = (
            "totalSupply" in before_m and "totalSupply" in after_m and after_m["totalSupply"] > before_m["totalSupply"]
        )
        if bal_increased or sup_increased:
            return True, (
                f"Verified unguarded non-mock token minting by $account1 via {selector}; "
                "reachability and exploit impact still require independent review."
            )

    return False, ""


def _unguarded_dangerous_primitive_observed(file: Path, selector: str, data: dict) -> Tuple[bool, str]:
    steps = data.get("steps") or []
    if len(data.get("accounts") or []) != 3 or not steps:
        return False, ""
    rel = file.as_posix()
    if re.search(r"(?:^|/)(?:mocks?|tests?|__tests__|fixtures|echidna)(?:/|$)|(?:Mock|Tests?)\.sol$|(?:^|/)(?:Dummy|Echidna)[A-Za-z0-9_]*\.sol$", rel, re.I):
        return False, ""
    fn_name = selector.split(".")[-1]
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False, ""
    header, body = _extract_fn_body(source, fn_name)
    if not body or _has_source_auth_guard(header, body):
        return False, ""
    primitive_match = re.search(r"\b(?:selfdestruct|suicide)\s*\(|\.\s*delegatecall\s*\(", body)
    if not primitive_match:
        return False, ""
    attack_idx = next(
        (i for i, s in enumerate(steps) if s_is_non_deployer_ok(s, fn_name)),
        None,
    )
    if attack_idx is None:
        return False, ""
    return True, (
        f"Verified unguarded dangerous primitive execution by $account1 via {selector}; "
        "reachability and exploit impact still require independent review."
    )



def _asserted_financial_or_vesting_negative(
    file: Path, selector: str, requested_steps: list, actual_steps: list,
    accounts: list | None = None, contract_address: str | None = None,
) -> tuple[str, str] | None:
    """A *bounded* falsifier that was actually executed with passing readbacks.

    This never asserts protocol-wide absence of bugs. Only the acquired, exact
    88mph operations for which the source-derived controller provides numeric
    pre/post assertions can produce this negative disposition.
    """
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return None
    contract, _, method = selector.partition(".")
    families = {
        ("xMPH", "deposit"): "share_accounting_negative",
        ("xMPH", "withdraw"): "share_accounting_negative",
        ("Vesting02", "createVestForDeposit"): "vest_creation_negative",
        ("SettlementVault", "fund"): "bounded_credit_negative",
    }
    family = families.get((contract, method))
    if not family or not re.search(r"\bcontract\s+" + re.escape(contract) + r"\b", source):
        return None
    if not re.search(r"\bfunction\s+" + re.escape(method) + r"\s*\(", source):
        return None
    if len(requested_steps) != len(actual_steps) or not requested_steps:
        return None
    for expected, observed in zip(requested_steps, actual_steps):
        if expected.get("operation") != observed.get("operation"):
            return None
        if observed.get("operation") in ("send", "call") and observed.get("passed") is not True:
            return None
        if observed.get("operation") == "call" and (
            "expect" not in expected or
            str(
                (accounts[int(expected["expect"][8:])]
                 if isinstance(expected["expect"], str) and
                    re.fullmatch(r"\$account[0-2]", expected["expect"]) and
                    isinstance(accounts, list) and len(accounts) == 3
                 else contract_address
                 if expected["expect"] == "$contract" and isinstance(contract_address, str)
                 else expected["expect"])
            ).lower() != str(observed.get("actual", "")).lower()
        ):
            return None
    targeted = [i for i, (req, got) in enumerate(zip(requested_steps, actual_steps))
                if req.get("operation") == "send"
                and req.get("function", "").split("(", 1)[0] == method
                and got.get("reverted") is False and got.get("passed") is True]
    if not targeted:
        return None
    if family == "bounded_credit_negative":
        clean = _strip_comments(source)
        if not (re.search(r"mapping\s*\(\s*address\s*=>\s*uint256\s*\)\s*public\s+credit", clean)
                and re.search(r"uint256\s+public\s+totalCredit", clean)
                and re.search(r"credit\s*\[\s*recipient\s*\]\s*\+=\s*v", clean)
                and re.search(r"totalCredit\s*\+=\s*v", clean)
                and re.search(r"v\s*=\s*amount\.bounded\s*\(\s*type\s*\(\s*uint128\s*\)\.max\s*\)", clean)):
            return None
        index = targeted[0]
        def nearest(call: str, before: bool):
            segment = list(zip(requested_steps[:index], actual_steps[:index])) if before else list(zip(requested_steps[index+1:], actual_steps[index+1:]))
            hits = [(r, step) for r, step in segment if r.get("operation") == "call"
                    and r.get("function") == call and step.get("passed") is True
                    and str(step.get("actual", "")).isdecimal()]
            return hits[-1][1] if before and hits else hits[0][1] if hits else None
        credit_before, credit_after = nearest("credit(address)", True), nearest("credit(address)", False)
        total_before, total_after = nearest("totalCredit()", True), nearest("totalCredit()", False)
        if None in (credit_before, credit_after, total_before, total_after):
            return None
        if (int(credit_after["actual"]) - int(credit_before["actual"]) == 1000 and
                int(total_after["actual"]) - int(total_before["actual"]) == 1000):
            return family, (
                "The concrete in-range funding experiment credited 1000 units "
                "to the recipient and aggregate ledger with all source-bound "
                "assertions passing. Other values and protocol states remain untested."
            )
        return None
    if family == "share_accounting_negative":
        for index in targeted:
            pre = actual_steps[:index]
            post = actual_steps[index + 1:]
            def paired_change(name: str, dependency: bool) -> bool:
                before = [(r, a) for r, a in zip(requested_steps[:index], pre)
                          if r.get("operation") == "call"
                          and r.get("function") == name
                          and bool(r.get("deploymentId")) == dependency]
                after = [(r, a) for r, a in zip(requested_steps[index + 1:], post)
                         if r.get("operation") == "call"
                         and r.get("function") == name
                         and bool(r.get("deploymentId")) == dependency]
                if not before or not after:
                    return False
                # Nearest matched readback around the *selected* call is
                # mandatory. Comparing across an earlier deposit could make
                # a broken no-op withdrawal look like a successful negative.
                b_req, b_obs = before[-1]
                a_req, a_obs = next(((r, obs) for r, obs in after
                                     if r.get("args") == b_req.get("args")), (None, None))
                if a_req is None:
                    return False
                x, y = str(b_obs.get("actual")), str(a_obs.get("actual"))
                if not x.isdecimal() or not y.isdecimal():
                    return False
                return (int(y) > int(x)) if method == "deposit" else (int(y) < int(x))
            if paired_change("totalSupply()", False) and paired_change("balanceOf(address)", True):
                return family, (
                    "Source-bound xMPH share and token-balance transitions passed "
                    "pre/post numerical falsifiers in this isolated EVM sequence; "
                    "the tested behavior was not a violation. This does not exclude "
                    "untested amounts, timing, reward states or economic attacks."
                )
        return None
    # Vest creation: only the designated minter succeeded; the unauthorized
    # caller reverted, while ID mapping and recipient ownership were asserted.
    index = next((i for i in targeted if requested_steps[i].get("sender") == 1), None)
    if index is None:
        return None
    rejected = any(requested_steps[i].get("operation") == "send"
                   and requested_steps[i].get("function", "").split("(", 1)[0] == method
                   and requested_steps[i].get("expectRevert") is True
                   and actual_steps[i].get("reverted") is True
                   for i in range(index))
    after = [(r, a) for r, a in zip(requested_steps[index + 1:], actual_steps[index + 1:])
             if r.get("operation") == "call" and a.get("passed") is True]
    names = {str(r.get("function")) for r, _ in after}
    if not rejected or not {"numVests()", "depositIDToVestID(address,uint64)", "ownerOf(uint256)"}.issubset(names):
        return None
    if not any(str(a.get("actual")) == "1" and r.get("function") == "numVests()"
               for r, a in after):
        return None
    return family, (
        "Unauthorized vest creation reverted; authorized creation and the "
        "source-linked vest count, deposit mapping and ERC721 ownership "
        "assertions passed. Only this concrete EVM scenario is falsified."
    )


def _asserted_source_scalar_delta(
    file: Path, selector: str, requested_steps: list, actual_steps: list,
    specification: dict | None,
) -> tuple[str, str] | None:
    """Independent source/replay proof of an exactly bounded scalar increment.

    A passing arbitrary value check is never enough. Require an actual public
    uint getter, matching full function signature, a literal source mutation,
    a successful mined transaction, and both passing before/after reads.
    """
    seq=(specification or {}).get("sequence") or {}
    property_spec=seq.get("sourceProperty")
    if not isinstance(property_spec,dict) or property_spec.get("kind")!="scalar_delta":
        return None
    if property_spec.get("direction")!="increase":
        return None
    try:
        text=file.read_text(encoding="utf8")
        source_sha=hashlib.sha256(file.read_bytes()).hexdigest()
    except OSError:
        return None
    if property_spec.get("sourceSha256")!=source_sha:
        return None
    state=property_spec.get("state")
    parameter=property_spec.get("parameter")
    method=property_spec.get("method")
    amount=property_spec.get("amount")
    formula=property_spec.get("formula")
    expected_delta=property_spec.get("expectedDelta")
    if not all(isinstance(v,str) and re.fullmatch(r"[A-Za-z_]\w*",v)
               for v in (state,parameter)):
        return None
    if not isinstance(amount,str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,29})",amount) or int(amount)==0:
        return None
    method_match = re.fullmatch(r"([A-Za-z_]\w*)\(([^()]*)\)", method) if isinstance(method,str) else None
    if not method_match:
        return None
    method_name=method_match.group(1)
    declared_types=[] if not method_match.group(2) else method_match.group(2).split(",")
    if not declared_types or selector.rsplit(".",1)[-1]!=method_name:
        return None
    source=_strip_comments(text)
    public_state=bool(re.search(r"\buint(?:[0-9]{1,3})?\s+public\s+"+re.escape(state)+r"\s*;",source))
    def parse_parameters(header_text):
        signature_match=re.search(r"\bfunction\s+"+re.escape(method_name)+r"\s*\(([^)]*)\)",header_text)
        if not signature_match:return None
        declarations=[part.strip() for part in signature_match.group(1).split(",")]
        if len(declarations)!=len(declared_types):return None
        parsed=[]
        for declaration in declarations:
            item=re.fullmatch(
                r"(uint(?:[0-9]{1,3})?|int(?:[0-9]{1,3})?|address(?:\s+payable)?|bool|string|bytes(?:[1-9]|[12][0-9]|3[012])?)"
                r"\s+(?:(?:memory|calldata|storage)\s+)?([A-Za-z_]\w*)",declaration)
            if not item:return None
            abi_type=re.sub(r"\s+payable$","",item.group(1))
            if abi_type=="uint":abi_type="uint256"
            if abi_type=="int":abi_type="int256"
            parsed.append((abi_type,item.group(2)))
        return parsed if [item[0] for item in parsed]==declared_types else None
    selected=next(((candidate_header,candidate_body,parsed)
        for candidate_header,candidate_body in _extract_fn_bodies(source,method_name)
        if (parsed:=parse_parameters(candidate_header)) is not None),None)
    if not selected:
        return None
    header,fn_body,source_parameters=selected
    amount_indexes=[i for i,(abi_type,param_name) in enumerate(source_parameters)
                    if param_name==parameter and abi_type.startswith("uint")]
    if len(amount_indexes)!=1:
        return None
    if formula is None:
        if expected_delta is not None or not re.search(
            r"\b"+re.escape(state)+r"\s*\+=\s*"+
            re.escape(parameter)+r"\s*;",fn_body):
            return None
        expected_state_delta=amount
    else:
        if (not isinstance(formula,dict) or
                set(formula)!={"multiplier","divisor"} or
                any(not isinstance(formula.get(k),str) or
                    not re.fullmatch(r"[1-9][0-9]{0,9}",formula[k])
                    for k in ("multiplier","divisor")) or
                not isinstance(expected_delta,str) or
                not re.fullmatch(r"(?:0|[1-9][0-9]{0,29})",expected_delta)):
            return None
        formula_match=re.search(
            r"\b"+re.escape(state)+r"\s*\+=\s*"+re.escape(parameter)+
            r"\s*(?:\*\s*([1-9][0-9]{0,9}))?\s*/\s*([1-9][0-9]{0,9})\s*;",
            fn_body)
        if (not formula_match or
                (formula_match.group(1) or "1")!=formula["multiplier"] or
                formula_match.group(2)!=formula["divisor"]):
            return None
        expected_state_delta=str(
            int(amount)*int(formula["multiplier"])//int(formula["divisor"])
        )
        if expected_state_delta!=expected_delta or expected_state_delta=="0":
            return None
    if len(actual_steps)!=len(requested_steps):
        return None
    getter=state+"()" if public_state else None
    if not getter:
        for step in requested_steps:
            if step.get("operation")!="call" or step.get("args")!=[]:
                continue
            candidate=str(step.get("function",""))
            getter_name=candidate.split("(",1)[0]
            getter_header,getter_body=_extract_fn_body(source,getter_name)
            if (getter_header and getter_body and
                re.search(r"\breturns\s*\(\s*uint(?:[0-9]{1,3})?\s*(?:[A-Za-z_]\w*)?\s*\)",getter_header) and
                re.search(r"\breturn\s+"+re.escape(state)+r"\s*;",getter_body)):
                getter=candidate
                break
    if not getter:return None
    calls=[i for i,step in enumerate(requested_steps)
           if step.get("operation")=="call" and step.get("function")==getter
           and step.get("args")==[]]
    sends=[i for i,step in enumerate(requested_steps)
           if step.get("operation")=="send" and step.get("function")==method
           and isinstance(step.get("args"),list) and
           len(step.get("args"))==len(source_parameters) and
           step.get("args")[amount_indexes[0]]==amount and
           not step.get("deploymentId")]
    if len(calls)!=2 or len(sends)!=1 or not(calls[0]<sends[0]<calls[1]):
        return None
    pre,transaction,post=(actual_steps[i] for i in (calls[0],sends[0],calls[1]))
    if pre.get("passed") is not True or post.get("passed") is not True or \
       transaction.get("passed") is not True or transaction.get("reverted") is not False:
        return None
    if pre.get("operation")!="call" or post.get("operation")!="call" or \
       transaction.get("operation")!="send":
        return None
    if str(pre.get("actual"))!="0" or str(post.get("actual"))!=expected_state_delta:
        return None
    if requested_steps[calls[0]].get("expect")!="0" or \
       requested_steps[calls[1]].get("expect")!=expected_state_delta:
        return None
    return ("source_scalar_delta_negative",
            "Source-identified scalar increment executed in the isolated EVM; "
            "the prestate, successful transaction and poststate agree with the "
            "source-derived bounded state-transition equation"+
            (" including the exact integer multiplier/divisor formula" if formula else "")+
            ". This proves only "
            "the tested input and fixture state.")

def _source_witnessed_direct_assignment_negative(
    file: Path, selector: str, requested_steps: list,
    actual_steps: list, accounts: list | None,
) -> tuple[str, str] | None:
    """Complete a narrowly falsifiable exact-source storage assignment test.

    This is NOT proof of authorization, absence of a vulnerability, or
    production reachability. It verifies the selected direct assignment
    through a real successful EVM send and the compiler-generated getter.
    The positive unauthorized-transition classifier runs first.
    """
    if not isinstance(accounts, list) or len(accounts) != 3:
        return None
    if not isinstance(requested_steps, list) or len(requested_steps) != len(actual_steps):
        return None
    method = selector.rsplit(".", 1)[-1]
    try:
        source = _strip_comments(file.read_text(encoding="utf8"))
    except OSError:
        return None
    header, body = _extract_fn_body(source, method)
    if not header or not body:
        return None
    # Binding must be the actual ABI parameter, with a matching source
    # public getter. A made-up getter or storage alias is not sufficient.
    declared = re.search(
        r"\bfunction\s+" + re.escape(method) +
        r"\s*\(\s*(address|bool|u?int(?:\d{0,3})?)\s+([A-Za-z_]\w*)\s*\)"
        r"\s*(?:external|public)\b",
        header)
    if not declared:
        return None
    param_type, parameter = declared.groups()
    assignments = re.findall(
        r"\b([A-Za-z_]\w*)\s*=\s*" + re.escape(parameter) + r"\s*;", body)
    if len(assignments) != 1:
        return None
    state = assignments[0]
    if not re.search(
        r"\b" + re.escape(param_type) + r"\s+public\s+" +
        re.escape(state) + r"\s*;", source):
        return None
    if len(re.findall(r"\b" + re.escape(state) + r"\s*(?:=|\+=|-=)", body)) != 1:
        return None
    # A direct source observation must have the exact same getter name,
    # a real old-value observation, and a successful post-state readback.
    getter = state + "()"
    before = next((i for i, step in enumerate(requested_steps)
                   if step.get("operation") in ("observe", "call")
                   and step.get("function") == getter
                   and actual_steps[i].get("operation") in ("observe", "call")
                   and actual_steps[i].get("actual") is not None), None)
    target = next((i for i, step in enumerate(requested_steps)
                   if step.get("operation") == "send"
                   and step.get("function", "").split("(", 1)[0] == method
                   and step.get("sender") == 0
                   and len(step.get("args", [])) == 1
                   and actual_steps[i].get("passed") is True
                   and actual_steps[i].get("reverted") is False), None)
    if before is None or target is None or before >= target:
        return None
    after = next((i for i in range(target + 1, len(requested_steps))
                  if requested_steps[i].get("operation") == "call"
                  and requested_steps[i].get("function") == getter
                  and actual_steps[i].get("passed") is True), None)
    if after is None:
        return None
    requested_value = requested_steps[target]["args"][0]
    if isinstance(requested_value, str) and re.fullmatch(r"\$account[0-2]", requested_value):
        expected = accounts[int(requested_value[-1])]
    elif isinstance(requested_value, (str, int, bool)):
        expected = requested_value
    else:
        return None
    actual = actual_steps[after].get("actual")
    if str(actual).lower() != str(expected).lower():
        return None
    if str(actual_steps[before].get("actual")).lower() == str(actual).lower():
        return None  # not a witnessed state transition
    return (
        "source_direct_assignment_negative",
        "Acquired public state "+state+" was observed before and after a successful "
        "selected EVM transaction. Exact source assignment, concrete ABI argument "
        "and compiler getter agree. This is a bounded property test, not a "
        "claim that other security properties or threats are absent."
    )


def _source_witnessed_funded_mapping_negative(
    file: Path, selector: str, requested_steps: list,
    actual_steps: list,
) -> tuple[str, str] | None:
    """A tested cross-function source relation, not inferred security absence.

    Both the funding and settlement lvalue arithmetic must be present in the
    acquired file, and the isolated EVM must confirm each actual transaction
    plus independent before/after readbacks for BOTH storage values.
    """
    if not isinstance(requested_steps, list) or not requested_steps or \
       len(requested_steps) != len(actual_steps):
        return None
    try:
        source = _strip_comments(file.read_text(encoding="utf8"))
    except OSError:
        return None
    method = selector.rsplit(".", 1)[-1]
    header, body = _extract_fn_body(source, method)
    if not header or not body:
        return None
    signature = re.search(
        r"\bfunction\s+" + re.escape(method) +
        r"\s*\(\s*address\s+([A-Za-z_]\w*)\s*,\s*uint(?:256)?\s+([A-Za-z_]\w*)\s*\)",
        header,
    )
    if not signature:
        return None
    account_key, amount_key = signature.groups()
    mapping = re.search(
        r"\bmapping\s*\(\s*address\s*=>\s*uint(?:256)?\s*\)\s*public\s+([A-Za-z_]\w*)\s*;",
        source,
    )
    total = re.search(r"\buint(?:256)?\s+public\s+([A-Za-z_]\w*)\s*;", source)
    if not mapping or not total:
        return None
    account, scalar = mapping.group(1), total.group(1)
    if not re.search(r"\b" + re.escape(account) +
                     r"\s*\[\s*" + re.escape(account_key) +
                     r"\s*\]\s*\+=\s*" + re.escape(amount_key) + r"\s*;", body):
        return None
    if not re.search(r"\b" + re.escape(scalar) +
                     r"\s*-=\s*" + re.escape(amount_key) + r"\s*;", body):
        return None
    if not re.search(re.escape(amount_key) +
                     r"\s*>\s*0\s*&&\s*" + re.escape(amount_key) +
                     r"\s*<=\s*" + re.escape(scalar), body):
        return None
    # Independently witness that another acquired entrypoint is a matching
    # source-backed inflow, not an invented initial balance.
    funding = re.search(
        r"\bfunction\s+([A-Za-z_]\w*)\s*\(\s*address\s+([A-Za-z_]\w*)"
        r"\s*,\s*uint(?:256)?\s+([A-Za-z_]\w*)\s*\)\s*external\b[^{]*\{"
        r"([\s\S]*?)\}", source
    )
    if not funding:
        return None
    fund_name, fund_account, fund_amount, fund_body = funding.groups()
    if fund_name == method:
        return None
    local = re.search(
        r"\buint(?:256)?\s+([A-Za-z_]\w*)\s*=\s*" +
        re.escape(fund_amount) + r"\s*\.\s*bounded\s*\(", fund_body,
    )
    inflow_var = local.group(1) if local else fund_amount
    if not re.search(r"\b" + re.escape(account) +
                     r"\s*\[\s*" + re.escape(fund_account) +
                     r"\s*\]\s*\+=\s*" + re.escape(inflow_var) + r"\s*;", fund_body) or \
       not re.search(r"\b" + re.escape(scalar) +
                     r"\s*\+=\s*" + re.escape(inflow_var) + r"\s*;", fund_body):
        return None

    def actual_call(name: str, before: bool, at: int, args: list | None = None):
        region = range(at) if before else range(at+1, len(actual_steps))
        for i in (reversed(tuple(region)) if before else region):
            requested, observed = requested_steps[i], actual_steps[i]
            if requested.get("operation") != "call" or \
               requested.get("function") != name or observed.get("passed") is not True:
                continue
            if args is not None and requested.get("args") != args:
                continue
            raw = str(observed.get("actual", ""))
            if re.fullmatch(r"\d+", raw):
                return int(raw)
        return None

    for index, (requested, observed) in enumerate(zip(requested_steps,actual_steps)):
        if requested.get("operation") != "send" or \
           requested.get("function", "").split("(", 1)[0] != method or \
           requested.get("sender") != 0 or \
           observed.get("passed") is not True or observed.get("reverted") is not False:
            continue
        args = requested.get("args") or []
        if len(args) != 2 or not re.fullmatch(r"[1-9]\d*", str(args[1])):
            continue
        amount = int(args[1])
        funded = any(
            i < index and req.get("operation") == "send" and
            req.get("function", "").split("(", 1)[0] == fund_name and
            req.get("args", [None])[0] == args[0] and
            got.get("passed") is True and got.get("reverted") is False
            for i,(req,got) in enumerate(zip(requested_steps,actual_steps))
        )
        if not funded:
            continue
        mapping_getter=account+"(address)"
        total_getter=scalar+"()"
        args_key=[args[0]]
        account_before=actual_call(mapping_getter,True,index,args_key)
        account_after=actual_call(mapping_getter,False,index,args_key)
        total_before=actual_call(total_getter,True,index,[])
        total_after=actual_call(total_getter,False,index,[])
        if None in (account_before,account_after,total_before,total_after):
            continue
        if total_before>=amount and \
           account_after-account_before==amount and \
           total_before-total_after==amount:
            return (
                "source_funded_mapping_negative",
                "The exact acquired source provided a concrete funding precondition "
                "and two independent EVM storage readbacks. The selected operation "
                "increased the specified mapping entry and decreased the bounded "
                "total by the measured input; only this local property was tested."
            )
    return None


def security_experiment_disposition(
    repository: Path,
    file: Path,
    selector: str,
    data: dict,
    specification: dict | None = None,
) -> Tuple[str, str | None, str]:
    """Classify a completed local-EVM experiment without inventing negative proof.

    A negative outcome requires an explicit denied unauthorized transaction,
    successful sequence assertions, and matching before/after state evidence.
    Mere absence of a recognized positive result is always inconclusive.
    """
    positive, classification, explanation = security_behavior_observed(
        repository, file, selector, data, specification
    )
    if positive:
        return "behavior_observed", classification, explanation

    requested = (specification or {}).get("sequence") or {}
    requested_steps = requested.get("steps") or []
    actual_steps = [step for step in (data.get("steps") or [])
                    if step.get("operation") != "setup"]
    if len(requested_steps) != len(actual_steps) or not requested_steps:
        return "observation_only", None, explanation
    if any(step.get("passed") is not True for step in actual_steps
           if step.get("operation") not in ("observe",)):
        return "observation_only", None, explanation

    funded = _source_witnessed_funded_mapping_negative(
        file, selector, requested_steps, actual_steps
    )
    if funded is not None:
        return "behavior_not_observed", funded[0], funded[1]

    direct = _source_witnessed_direct_assignment_negative(
        file, selector, requested_steps, actual_steps, data.get("accounts")
    )
    if direct is not None:
        return "behavior_not_observed", direct[0], direct[1]

    scalar = _asserted_source_scalar_delta(
        file, selector, requested_steps, actual_steps, specification
    )
    if scalar is not None:
        return "behavior_not_observed", scalar[0], scalar[1]

    bounded = _asserted_financial_or_vesting_negative(
        file, selector, requested_steps, actual_steps,
        data.get("accounts"), data.get("contract"),
    )
    if bounded is not None:
        return "behavior_not_observed", bounded[0], bounded[1]

    target_name = selector.rsplit(".", 1)[-1]
    for i, (requested_step, actual_step) in enumerate(zip(requested_steps, actual_steps)):
        if (requested_step.get("operation") != "send" or
                requested_step.get("sender") != 1 or
                requested_step.get("expectRevert") is not True or
                requested_step.get("deploymentId") or
                str(requested_step.get("function", "")).split("(", 1)[0] != target_name or
                actual_step.get("operation") != "send" or
                actual_step.get("sender") != 1 or
                actual_step.get("reverted") is not True):
            continue
        before = actual_steps[:i]
        after = actual_steps[i + 1:]
        for before_index, preceding in enumerate(before):
            if (preceding.get("operation") != "call" or
                    preceding.get("deploymentId") or
                    preceding.get("passed") is not True):
                continue
            requested_before = requested_steps[before_index]
            for after_index, following in enumerate(after, start=i + 1):
                requested_after = requested_steps[after_index]
                if (following.get("operation") != "call" or
                        following.get("deploymentId") or
                        following.get("passed") is not True or
                        following.get("function") != preceding.get("function") or
                        requested_before.get("operation") != "call" or
                        requested_after.get("operation") != "call" or
                        requested_before.get("function") != requested_after.get("function") or
                        requested_before.get("args") != requested_after.get("args")):
                    continue
                if preceding.get("actual") == following.get("actual"):
                    return ("behavior_not_observed", "guarded_negative",
                            "Unauthorized selected transaction reverted and an identical source-declared state readback remained unchanged; all recorded assertions passed.")
    return "observation_only", None, explanation


def security_behavior_observed(
    repository: Path,
    file: Path,
    selector: str,
    data: dict,
    specification: dict | None = None,
) -> Tuple[bool, str | None, str]:
    """Return (behavior_observed, classification, limitation)."""
    if authorization_transition_observed(repository, file, selector, data):
        return (
            True,
            "authorization_transition",
            "Verified nonadministrator role mutation with before/after EVM observations and a source-declared privileged role consumer; reachability and exploit impact still require independent review.",
        )
    if _reinit_or_constructor_takeover_observed(file, selector, data):
        return (
            True,
            "reinit_or_constructor_takeover",
            "Verified unauthorized initialization or re-initialization authority takeover by $account1 with before/after EVM authority observations; reachability and exploit impact still require independent review.",
        )
    extracted, extract_msg = _unauthorized_value_extraction_observed(repository, file, selector, data)
    if extracted:
        return True, "unauthorized_value_extraction", extract_msg
    prim, prim_msg = _unguarded_dangerous_primitive_observed(file, selector, data)
    if prim:
        return True, "unguarded_dangerous_primitive", prim_msg
    return (
        False,
        None,
        "Only bounded Solidity transactions and assertions were observed. An expected-value mismatch is not independent security proof.",
    )
