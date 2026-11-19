#!/usr/bin/env python3
"""Z3 (MIT) SMT constraint feasibility solver for LOTUS guard & invariant checks."""
import ast
import json
import sys
from typing import Any, Dict, List

try:
    import z3
except Exception as exc:
    print(json.dumps({"error": f"z3_unavailable: {exc}", "status": "unavailable"}))
    sys.exit(2)


def normalize_expr(expr: str) -> str:
    return (
        expr.replace("&&", " and ")
        .replace("||", " or ")
        .replace("!==", "!=")
        .replace("===", "==")
        .replace("!", " not ")
        .replace(" not =", "!=")
    )


def translate_ast(node: ast.AST, env: Dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return translate_ast(node.body, env)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return z3.BoolVal(node.value)
        if isinstance(node.value, int):
            return z3.IntVal(node.value)
        raise ValueError(f"Unsupported constant: {node.value!r}")
    if isinstance(node, ast.Name):
        name = node.id
        if name in ("true", "True"):
            return z3.BoolVal(True)
        if name in ("false", "False"):
            return z3.BoolVal(False)
        if name not in env:
            env[name] = z3.Int(name)
        return env[name]
    if isinstance(node, ast.Attribute):
        # e.g. msg.sender -> msg_sender
        parts: List[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        name = "_".join(reversed(parts))
        if name not in env:
            env[name] = z3.Int(name)
        return env[name]
    if isinstance(node, ast.UnaryOp):
        operand = translate_ast(node.operand, env)
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return operand
        if isinstance(node.op, ast.Not):
            return z3.Not(operand if z3.is_bool(operand) else operand != 0)
        raise ValueError(f"Unsupported unary op: {type(node.op).__name__}")
    if isinstance(node, ast.BinOp):
        left = translate_ast(node.left, env)
        right = translate_ast(node.right, env)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, (ast.Div, ast.FloorDiv)):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        raise ValueError(f"Unsupported binop: {type(node.op).__name__}")
    if isinstance(node, ast.BoolOp):
        vals = [translate_ast(v, env) for v in node.values]
        bool_vals = [v if z3.is_bool(v) else (v != 0) for v in vals]
        if isinstance(node.op, ast.And):
            return z3.And(*bool_vals)
        if isinstance(node.op, ast.Or):
            return z3.Or(*bool_vals)
        raise ValueError(f"Unsupported boolop: {type(node.op).__name__}")
    if isinstance(node, ast.Compare):
        left = translate_ast(node.left, env)
        clauses = []
        for op, comp in zip(node.ops, node.comparators):
            right = translate_ast(comp, env)
            if isinstance(op, ast.Eq):
                clauses.append(left == right)
            elif isinstance(op, ast.NotEq):
                clauses.append(left != right)
            elif isinstance(op, ast.Lt):
                clauses.append(left < right)
            elif isinstance(op, ast.LtE):
                clauses.append(left <= right)
            elif isinstance(op, ast.Gt):
                clauses.append(left > right)
            elif isinstance(op, ast.GtE):
                clauses.append(left >= right)
            else:
                raise ValueError(f"Unsupported comparison: {type(op).__name__}")
            left = right
        return z3.And(*clauses) if len(clauses) > 1 else clauses[0]
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")


def solve_query(query: Dict[str, Any]) -> Dict[str, Any]:
    solver = z3.Solver()
    solver.set("timeout", int(query.get("timeoutMs", 3000)))

    smtlib2 = query.get("smtlib2")
    if isinstance(smtlib2, str) and smtlib2.strip():
        try:
            solver.from_string(smtlib2)
        except Exception as exc:
            return {"status": "error", "error": str(exc), "model": {}}
    else:
        env: Dict[str, Any] = {}
        for var_name, var_type in (query.get("variables") or {}).items():
            if var_type == "bool":
                env[var_name] = z3.Bool(var_name)
            elif var_type == "uint256":
                v = z3.Int(var_name)
                env[var_name] = v
                solver.add(v >= 0, v < (1 << 256))
            else:
                env[var_name] = z3.Int(var_name)

        parsed = 0
        errors: List[str] = []
        for raw_expr in query.get("constraints") or []:
            try:
                tree = ast.parse(normalize_expr(str(raw_expr)), mode="eval")
                formula = translate_ast(tree, env)
                solver.add(formula if z3.is_bool(formula) else (formula != 0))
                parsed += 1
            except Exception as exc:
                errors.append(f"{raw_expr}: {exc}")

        if parsed == 0 and errors:
            return {"status": "error", "error": "; ".join(errors), "model": {}, "constraintsParsed": 0}

    res = solver.check()
    if res == z3.sat:
        m = solver.model()
        out_model: Dict[str, Any] = {}
        for decl in m.decls():
            val = m[decl]
            s = str(val)
            if s in ("True", "False"):
                out_model[decl.name()] = (s == "True")
            else:
                try:
                    out_model[decl.name()] = int(s)
                except ValueError:
                    out_model[decl.name()] = s
        return {"status": "sat", "model": out_model, "z3Version": z3.get_version_string()}
    if res == z3.unsat:
        return {"status": "unsat", "model": {}, "z3Version": z3.get_version_string()}
    return {"status": "unknown", "model": {}, "z3Version": z3.get_version_string()}


def main() -> None:
    payload = json.loads(sys.stdin.read() or "{}")
    if "queries" in payload and isinstance(payload["queries"], list):
        results = [solve_query(q) for q in payload["queries"]]
        print(json.dumps({"adapter": "z3", "z3Version": z3.get_version_string(), "results": results}))
    else:
        res = solve_query(payload)
        res["adapter"] = "z3"
        print(json.dumps(res))


if __name__ == "__main__":
    main()
