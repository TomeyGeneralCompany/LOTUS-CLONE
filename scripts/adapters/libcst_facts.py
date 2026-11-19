#!/usr/bin/env python3
"""LibCST (MIT) Python structural CST facts extractor for LOTUS ProgramFacts IR."""
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional

try:
    import libcst as cst
    from libcst.metadata import MetadataWrapper, PositionProvider
except Exception as exc:
    print(json.dumps({"error": f"libcst_unavailable: {exc}", "symbols": [], "facts": [], "edges": []}))
    sys.exit(2)


AUTH_DECORATOR_TOKENS = (
    "login_required",
    "permission_required",
    "requires_auth",
    "require_auth",
    "admin_required",
    "authenticated",
    "roles_required",
    "jwt_required",
)

ROUTE_DECORATOR_TOKENS = (
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "api_view",
)

DANGEROUS_SINKS = {
    "eval": ("dangerous_sink", "Dynamic eval() execution"),
    "exec": ("dangerous_sink", "Dynamic exec() execution"),
    "os.system": ("dangerous_sink", "OS command execution via os.system"),
    "os.popen": ("dangerous_sink", "OS command execution via os.popen"),
    "subprocess.Popen": ("dangerous_sink", "Subprocess command execution"),
    "subprocess.run": ("dangerous_sink", "Subprocess command execution"),
    "subprocess.call": ("dangerous_sink", "Subprocess command execution"),
    "subprocess.check_output": ("dangerous_sink", "Subprocess command execution"),
    "pickle.loads": ("dangerous_sink", "Unsafe pickle deserialization"),
    "pickle.load": ("dangerous_sink", "Unsafe pickle deserialization"),
    "yaml.load": ("dangerous_sink", "Potential unsafe yaml.load deserialization"),
    "marshal.loads": ("dangerous_sink", "Unsafe marshal deserialization"),
    "render_template_string": ("dangerous_sink", "Server-side template injection sink"),
    "mark_safe": ("dangerous_sink", "Unescaped HTML mark_safe sink"),
    "Markup": ("dangerous_sink", "Unescaped HTML Markup sink"),
    "execute": ("dangerous_sink", "Database SQL execute sink"),
    "executemany": ("dangerous_sink", "Database SQL executemany sink"),
    "raw": ("dangerous_sink", "Raw SQL query sink"),
}


def stable_id(parts: List[Any]) -> str:
    h = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return h[:20]


def dotted_name(node: cst.CSTNode) -> str:
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        left = dotted_name(node.value)
        return f"{left}.{node.attr.value}" if left else node.attr.value
    return ""


class LibCSTFactsVisitor(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, path: str):
        self.path = path
        self.symbols: List[Dict[str, Any]] = []
        self.facts: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.class_stack: List[str] = []
        self.func_stack: List[Dict[str, Any]] = []

    def _line(self, node: cst.CSTNode) -> int:
        try:
            pos = self.get_metadata(PositionProvider, node)
            return int(pos.start.line)
        except Exception:
            return 1

    def _end_line(self, node: cst.CSTNode) -> int:
        try:
            pos = self.get_metadata(PositionProvider, node)
            return int(pos.end.line)
        except Exception:
            return self._line(node)

    def _qual(self, name: str) -> str:
        return ".".join(self.class_stack + [name]) if self.class_stack else name

    def visit_ClassDef(self, node: cst.ClassDef) -> Optional[bool]:
        cname = node.name.value
        qname = self._qual(cname)
        line = self._line(node)
        self.symbols.append({
            "id": stable_id(["libcst", "sym", self.path, qname, line]),
            "name": cname,
            "qualifiedName": qname,
            "kind": "class",
            "language": "python",
            "file": self.path,
            "line": line,
            "endLine": self._end_line(node),
            "modifiers": [],
        })
        self.class_stack.append(cname)
        return True

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        if self.class_stack:
            self.class_stack.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> Optional[bool]:
        fname = node.name.value
        qname = self._qual(fname)
        line = self._line(node)
        end_line = self._end_line(node)
        sym_id = stable_id(["libcst", "sym", self.path, qname, line])
        decorators: List[str] = []
        has_auth = False
        is_route = False
        for dec in node.decorators:
            dec_expr = dec.decorator.func if isinstance(dec.decorator, cst.Call) else dec.decorator
            dname = dotted_name(dec_expr)
            if dname:
                decorators.append(dname)
                low = dname.lower()
                if any(tok in low for tok in AUTH_DECORATOR_TOKENS):
                    has_auth = True
                if any(low.endswith("." + tok) or low == tok for tok in ROUTE_DECORATOR_TOKENS):
                    is_route = True

        self.symbols.append({
            "id": sym_id,
            "name": fname,
            "qualifiedName": qname,
            "kind": "method" if self.class_stack else "function",
            "language": "python",
            "file": self.path,
            "line": line,
            "endLine": end_line,
            "visibility": "private" if fname.startswith("_") and not fname.startswith("__") else "public",
            "modifiers": decorators,
        })

        if is_route or not fname.startswith("_"):
            self.facts.append({
                "id": stable_id(["libcst", "entry", self.path, qname, line]),
                "kind": "entry_point",
                "adapter": "libcst",
                "file": self.path,
                "line": line,
                "symbol": qname,
                "summary": f"Python {'route ' if is_route else ''}entrypoint {qname}",
                "confidence": 0.9 if is_route else 0.72,
                "attributes": {"decorators": decorators, "isRoute": is_route},
            })

        if has_auth:
            self.facts.append({
                "id": stable_id(["libcst", "auth", self.path, qname, line]),
                "kind": "auth_guard",
                "adapter": "libcst",
                "file": self.path,
                "line": line,
                "symbol": qname,
                "summary": f"Decorator auth guard on {qname}: {', '.join(decorators)}",
                "confidence": 0.92,
                "attributes": {"decorators": decorators},
            })

        self.func_stack.append({"id": sym_id, "qname": qname})
        return True

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        if self.func_stack:
            self.func_stack.pop()

    def visit_If(self, node: cst.If) -> Optional[bool]:
        if not self.func_stack:
            return True
        code = cst.Module([]).code_for_node(node.test)
        low = code.lower()
        if any(tok in low for tok in ("is_authenticated", "is_admin", "is_superuser", "has_perm", "current_user", "role ==", "role !=")):
            cur = self.func_stack[-1]
            line = self._line(node)
            self.facts.append({
                "id": stable_id(["libcst", "if_auth", self.path, cur["qname"], line]),
                "kind": "auth_guard",
                "adapter": "libcst",
                "file": self.path,
                "line": line,
                "symbol": cur["qname"],
                "summary": f"Inline auth check in {cur['qname']}: {code[:120]}",
                "confidence": 0.85,
                "attributes": {"condition": code[:160]},
            })
        return True

    def visit_Call(self, node: cst.Call) -> Optional[bool]:
        callee = dotted_name(node.func)
        if not callee:
            return True
        line = self._line(node)
        cur_sym = self.func_stack[-1]["qname"] if self.func_stack else "<module>"
        cur_id = self.func_stack[-1]["id"] if self.func_stack else stable_id(["libcst", "mod", self.path])

        self.edges.append({
            "kind": "calls",
            "from": cur_id,
            "to": callee,
            "file": self.path,
            "line": line,
        })

        leaf = callee.split(".")[-1]
        sink_info = DANGEROUS_SINKS.get(callee) or DANGEROUS_SINKS.get(leaf)
        if sink_info:
            # Check for yaml.load(..., Loader=SafeLoader) mitigation
            if callee == "yaml.load":
                args_code = ",".join(cst.Module([]).code_for_node(a) for a in node.args)
                if "SafeLoader" in args_code or "CSafeLoader" in args_code:
                    return True
            # Check for subprocess with shell=True vs safe list
            attrs: Dict[str, Any] = {"callee": callee}
            if callee.startswith("subprocess."):
                args_code = ",".join(cst.Module([]).code_for_node(a) for a in node.args)
                attrs["shellTrue"] = "shell=True" in args_code.replace(" ", "")
            self.facts.append({
                "id": stable_id(["libcst", "sink", self.path, cur_sym, callee, line]),
                "kind": sink_info[0],
                "adapter": "libcst",
                "file": self.path,
                "line": line,
                "symbol": cur_sym,
                "summary": f"{sink_info[1]} ({callee}) in {cur_sym}",
                "confidence": 0.9 if attrs.get("shellTrue") or callee in ("eval", "exec", "os.system", "pickle.loads", "render_template_string", "mark_safe") else 0.78,
                "attributes": attrs,
            })
        return True


def main() -> None:
    payload = json.loads(sys.stdin.read() or "{}")
    sources = payload.get("sources", [])
    symbols: List[Dict[str, Any]] = []
    facts: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    errors: List[str] = []

    for src in sources:
        path = str(src.get("path", ""))
        content = str(src.get("content", ""))
        if not path.endswith(".py"):
            continue
        try:
            tree = cst.parse_module(content)
            wrapper = MetadataWrapper(tree)
            visitor = LibCSTFactsVisitor(path)
            wrapper.visit(visitor)
            symbols.extend(visitor.symbols)
            facts.extend(visitor.facts)
            edges.extend(visitor.edges)
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    print(json.dumps({"adapter": "libcst", "symbols": symbols, "facts": facts, "edges": edges, "errors": errors}))


if __name__ == "__main__":
    main()
