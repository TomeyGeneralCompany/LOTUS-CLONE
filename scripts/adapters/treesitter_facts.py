#!/usr/bin/env python3
"""Tree-sitter (MIT) multi-language CST structural facts extractor for LOTUS."""
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    from tree_sitter import Language, Parser
except Exception as exc:
    print(json.dumps({"error": f"tree_sitter_unavailable: {exc}", "symbols": [], "facts": [], "edges": []}))
    sys.exit(2)


def load_language(lang_name: str) -> Optional[Language]:
    try:
        if lang_name == "python":
            import tree_sitter_python as tsp
            return Language(tsp.language())
        if lang_name == "javascript":
            import tree_sitter_javascript as tsj
            return Language(tsj.language())
        if lang_name == "java":
            import tree_sitter_java as tsjava
            return Language(tsjava.language())
    except Exception:
        return None
    return None


def stable_id(parts: List[Any]) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:20]


def detect_lang(path: str) -> Optional[str]:
    low = path.lower()
    if low.endswith(".py"):
        return "python"
    if low.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")):
        return "javascript"
    if low.endswith(".java"):
        return "java"
    return None


SINK_KEYWORDS = (
    "eval", "exec", "execSync", "spawn", "system", "popen", "innerHTML",
    "dangerouslySetInnerHTML", "executeQuery", "ProcessBuilder", "readObject",
    "pickle", "render_template_string", "mark_safe", "DocumentBuilderFactory",
)

AUTH_KEYWORDS = (
    "isAdmin", "is_admin", "is_authenticated", "requireAuth", "login_required",
    "PreAuthorize", "Secured", "RolesAllowed", "verifyJwt", "hasRole", "onlyOwner",
)


def extract_tree(path: str, lang_name: str, content: str, language: Language) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    parser = Parser(language)
    raw = content.encode("utf-8", errors="replace")
    tree = parser.parse(raw)
    symbols: List[Dict[str, Any]] = []
    facts: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def text_of(node) -> str:
        return raw[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def walk(node, scope_stack: List[Tuple[str, str]]) -> None:
        ntype = node.type
        pushed = False

        if ntype in ("class_definition", "class_declaration", "interface_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                cname = text_of(name_node)
                line = node.start_point[0] + 1
                sid = stable_id(["ts", "class", path, cname, line])
                symbols.append({
                    "id": sid,
                    "name": cname,
                    "qualifiedName": cname,
                    "kind": "class",
                    "language": lang_name,
                    "file": path,
                    "line": line,
                    "endLine": node.end_point[0] + 1,
                    "modifiers": [],
                })
                scope_stack.append((sid, cname))
                pushed = True

        elif ntype in ("function_definition", "function_declaration", "method_declaration", "method_definition"):
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                fname = text_of(name_node)
                qname = ".".join([s[1] for s in scope_stack] + [fname]) if scope_stack else fname
                line = node.start_point[0] + 1
                sid = stable_id(["ts", "fn", path, qname, line])
                symbols.append({
                    "id": sid,
                    "name": fname,
                    "qualifiedName": qname,
                    "kind": "method" if scope_stack else "function",
                    "language": lang_name,
                    "file": path,
                    "line": line,
                    "endLine": node.end_point[0] + 1,
                    "modifiers": [],
                })
                facts.append({
                    "id": stable_id(["ts", "entry", path, qname, line]),
                    "kind": "entry_point",
                    "adapter": "tree-sitter",
                    "file": path,
                    "line": line,
                    "symbol": qname,
                    "summary": f"Tree-sitter ({lang_name}) symbol {qname}",
                    "confidence": 0.78,
                    "attributes": {"nodeType": ntype, "language": lang_name},
                })
                scope_stack.append((sid, qname))
                pushed = True

        elif ntype in ("call", "call_expression", "method_invocation"):
            fn_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            callee = text_of(fn_node)[:100] if fn_node is not None else text_of(node)[:80]
            line = node.start_point[0] + 1
            cur_id = scope_stack[-1][0] if scope_stack else stable_id(["ts", "file", path])
            cur_sym = scope_stack[-1][1] if scope_stack else "<module>"
            edges.append({
                "kind": "calls",
                "from": cur_id,
                "to": callee,
                "file": path,
                "line": line,
            })
            if any(k in callee for k in SINK_KEYWORDS):
                facts.append({
                    "id": stable_id(["ts", "sink", path, cur_sym, callee, line]),
                    "kind": "dangerous_sink",
                    "adapter": "tree-sitter",
                    "file": path,
                    "line": line,
                    "symbol": cur_sym,
                    "summary": f"Tree-sitter call sink {callee} in {cur_sym}",
                    "confidence": 0.8,
                    "attributes": {"callee": callee, "language": lang_name},
                })
            if any(k in callee for k in AUTH_KEYWORDS):
                facts.append({
                    "id": stable_id(["ts", "auth", path, cur_sym, callee, line]),
                    "kind": "auth_guard",
                    "adapter": "tree-sitter",
                    "file": path,
                    "line": line,
                    "symbol": cur_sym,
                    "summary": f"Tree-sitter auth guard {callee} in {cur_sym}",
                    "confidence": 0.82,
                    "attributes": {"callee": callee, "language": lang_name},
                })

        elif ntype in ("annotation", "marker_annotation", "decorator"):
            txt = text_of(node)
            line = node.start_point[0] + 1
            cur_sym = scope_stack[-1][1] if scope_stack else "<module>"
            if any(k in txt for k in AUTH_KEYWORDS):
                facts.append({
                    "id": stable_id(["ts", "ann_auth", path, cur_sym, line]),
                    "kind": "auth_guard",
                    "adapter": "tree-sitter",
                    "file": path,
                    "line": line,
                    "symbol": cur_sym,
                    "summary": f"Tree-sitter auth annotation {txt[:100]}",
                    "confidence": 0.88,
                    "attributes": {"annotation": txt[:120]},
                })

        for child in node.children:
            walk(child, scope_stack)

        if pushed:
            scope_stack.pop()

    walk(tree.root_node, [])
    return symbols, facts, edges


def main() -> None:
    payload = json.loads(sys.stdin.read() or "{}")
    sources = payload.get("sources", [])
    symbols: List[Dict[str, Any]] = []
    facts: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    loaded: Dict[str, Optional[Language]] = {}
    supported_langs: List[str] = []

    for lang_name in ("python", "javascript", "java"):
        loaded[lang_name] = load_language(lang_name)
        if loaded[lang_name] is not None:
            supported_langs.append(lang_name)

    for src in sources:
        path = str(src.get("path", ""))
        content = str(src.get("content", ""))
        lang_name = detect_lang(path)
        if not lang_name or loaded.get(lang_name) is None:
            continue
        s, f, e = extract_tree(path, lang_name, content, loaded[lang_name])
        symbols.extend(s)
        facts.extend(f)
        edges.extend(e)

    print(json.dumps({
        "adapter": "tree-sitter",
        "supportedLanguages": supported_langs,
        "symbols": symbols,
        "facts": facts,
        "edges": edges,
    }))


if __name__ == "__main__":
    main()
