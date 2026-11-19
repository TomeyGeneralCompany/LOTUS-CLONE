/**
 * Babel Parser (@babel/parser, MIT) JavaScript/TypeScript AST adapter.
 *
 * Replaces regex-based JS/TS structural extraction with real AST traversal for
 * JS, JSX, ESM, CJS, and TypeScript sources: extracts exported/route functions,
 * auth guards, HTML/SQL/command/path/deserialization sinks, and call edges.
 */
import { createHash } from "node:crypto";
import { parse } from "@babel/parser";
import type {
  AdapterExtractionInput,
  AdapterExtractionResult,
  ProgramEdge,
  ProgramFact,
  ProgramFactKind,
  ProgramFactsAdapter,
  ProgramSymbol,
  FactSeverity,
} from "../program-facts";

function stableId(parts: readonly (string | number | undefined)[]): string {
  return createHash("sha256").update(parts.map((p) => String(p ?? "")).join("|")).digest("hex").slice(0, 20);
}

function isJsTsPath(filePath: string): boolean {
  return /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(filePath);
}

function memberChain(node: any): string {
  if (!node || typeof node !== "object") return "";
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "ThisExpression") return "this";
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    const obj = memberChain(node.object);
    const prop = node.computed
      ? node.property?.type === "StringLiteral"
        ? node.property.value
        : ""
      : node.property?.name || "";
    return obj && prop ? `${obj}.${prop}` : obj || prop;
  }
  return "";
}

const AUTH_IDENT_RE = /(?:isAdmin|isAuthenticated|requireAuth|ensureAuth|verifyJwt|verifyToken|checkAuth|hasRole|authorize|rbac|canAccess)/i;

function classifySink(callee: string): { kind: ProgramFactKind; severity: FactSeverity; label: string } | null {
  const leaf = callee.split(".").pop() || callee;
  if (callee === "eval" || callee === "Function" || callee === "vm.runInNewContext" || callee === "vm.runInThisContext") {
    return { kind: "sink_command", severity: "critical", label: `Dynamic JS code execution (${callee})` };
  }
  if (/(?:^|\.)(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(callee)) {
    return { kind: "sink_command", severity: "critical", label: `Child process command execution (${callee})` };
  }
  if (/(?:^|\.)(?:query|execute|raw|unsafe|prepare)$/.test(callee) && /(?:db|sql|pool|client|conn|knex|prisma|sequelize|mysql|pg|sqlite)/i.test(callee)) {
    return { kind: "sink_sql", severity: "high", label: `Database SQL execution (${callee})` };
  }
  if (/(?:^|\.)(?:send|end|write|render|html|insertAdjacentHTML)$/.test(callee) && /(?:res|reply|response|document|el|element|dom)/i.test(callee)) {
    return { kind: "sink_html", severity: "high", label: `HTML/HTTP response sink (${callee})` };
  }
  if (/(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|unlink|unlinkSync)$/.test(callee)) {
    return { kind: "sink_path", severity: "high", label: `Filesystem path sink (${callee})` };
  }
  if (leaf === "unserialize" || callee === "yaml.load" || callee === "serialize.unserialize") {
    return { kind: "sink_deserialization", severity: "high", label: `Deserialization sink (${callee})` };
  }
  return null;
}

function extractParamNames(params: any[] | undefined): string[] {
  if (!Array.isArray(params)) return [];
  return params.map((p) => {
    if (!p) return "arg";
    if (p.type === "Identifier") return p.name;
    if (p.type === "AssignmentPattern" && p.left?.type === "Identifier") return p.left.name;
    if (p.type === "RestElement" && p.argument?.type === "Identifier") return `...${p.argument.name}`;
    return "param";
  });
}

export const babelAstFactsAdapter: ProgramFactsAdapter = {
  name: "babel-parser",
  languages: ["javascript"],
  license: "MIT",
  role: "JavaScript/TypeScript AST symbol, auth-guard, sink, and call-edge extraction via @babel/parser",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const symbols: ProgramSymbol[] = [];
    const facts: ProgramFact[] = [];
    const edges: ProgramEdge[] = [];

    for (const src of input.sources) {
      if (!isJsTsPath(src.path)) continue;
      let ast: any;
      try {
        ast = parse(src.content, {
          sourceType: "unambiguous",
          errorRecovery: true,
          plugins: [
            "typescript",
            "jsx",
            "decorators-legacy",
          ],
        });
      } catch {
        continue;
      }

      const scopeStack: Array<{ id: string; qname: string }> = [];

      const recordFunction = (name: string, node: any, kind: "function" | "method", isExported: boolean) => {
        const line = node.loc?.start?.line ?? 1;
        const endLine = node.loc?.end?.line ?? line;
        const parent = scopeStack.length > 0 ? scopeStack[scopeStack.length - 1].qname : undefined;
        const qname = parent ? `${parent}.${name}` : name;
        const id = stableId(["babel", "sym", src.path, qname, line]);
        symbols.push({
          id,
          language: "javascript",
          file: src.path,
          line,
          endLine,
          kind,
          name,
          qualifiedName: qname,
          parent,
          visibility: isExported ? "public" : "internal",
          modifiers: isExported ? ["export"] : [],
          params: extractParamNames(node.params),
        });
        facts.push({
          id: stableId(["babel", "entry", src.path, qname, line]),
          kind: "entry_point",
          language: "javascript",
          file: src.path,
          line,
          symbol: qname,
          severity: "info",
          adapter: "babel-parser",
          detail: `JS/TS ${isExported ? "exported " : ""}${kind} ${qname}(${extractParamNames(node.params).join(", ")})`,
          metadata: { exported: isExported, async: Boolean(node.async) },
        });
        return { id, qname };
      };

      const visit = (node: any, isExported = false): void => {
        if (!node || typeof node !== "object") return;
        if (Array.isArray(node)) {
          for (const item of node) visit(item, false);
          return;
        }
        const type = node.type;
        if (typeof type !== "string") return;

        let pushed = false;

        if (type === "ExportNamedDeclaration" || type === "ExportDefaultDeclaration") {
          visit(node.declaration, true);
          return;
        }

        if (type === "ClassDeclaration" || type === "ClassExpression") {
          const cname = node.id?.name || "AnonymousClass";
          const line = node.loc?.start?.line ?? 1;
          const id = stableId(["babel", "class", src.path, cname, line]);
          symbols.push({
            id,
            language: "javascript",
            file: src.path,
            line,
            endLine: node.loc?.end?.line ?? line,
            kind: "class",
            name: cname,
            qualifiedName: cname,
            visibility: isExported ? "public" : "internal",
            modifiers: isExported ? ["export"] : [],
            params: [],
          });
          scopeStack.push({ id, qname: cname });
          pushed = true;
        } else if (type === "FunctionDeclaration" && node.id?.name) {
          scopeStack.push(recordFunction(node.id.name, node, "function", isExported));
          pushed = true;
        } else if (type === "ClassMethod" || type === "ObjectMethod") {
          const mname = node.key?.name || node.key?.value;
          if (mname && mname !== "constructor") {
            scopeStack.push(recordFunction(String(mname), node, "method", true));
            pushed = true;
          }
        } else if (
          type === "VariableDeclarator" &&
          node.id?.type === "Identifier" &&
          (node.init?.type === "ArrowFunctionExpression" || node.init?.type === "FunctionExpression")
        ) {
          scopeStack.push(recordFunction(node.id.name, node.init, "function", isExported));
          visit(node.init.body, false);
          scopeStack.pop();
          return;
        } else if (
          type === "AssignmentExpression" &&
          node.left?.type === "MemberExpression" &&
          (memberChain(node.left).startsWith("exports.") || memberChain(node.left).startsWith("module.exports"))
        ) {
          const leftChain = memberChain(node.left);
          const exportedName = leftChain.split(".").pop() || "default";
          if (node.right?.type === "ArrowFunctionExpression" || node.right?.type === "FunctionExpression") {
            scopeStack.push(recordFunction(exportedName, node.right, "function", true));
            visit(node.right.body, false);
            scopeStack.pop();
            return;
          }
        }

        // Assignment to innerHTML / outerHTML / __proto__
        if (type === "AssignmentExpression" && node.left?.type === "MemberExpression") {
          const lhs = memberChain(node.left);
          const line = node.loc?.start?.line ?? 1;
          const curSym = scopeStack[scopeStack.length - 1]?.qname;
          if (/\.(?:innerHTML|outerHTML)$/.test(lhs)) {
            facts.push({
              id: stableId(["babel", "innerHTML", src.path, curSym, line]),
              kind: "sink_html",
              language: "javascript",
              file: src.path,
              line,
              symbol: curSym,
              severity: "high",
              adapter: "babel-parser",
              detail: `Unsanitized DOM HTML assignment (${lhs})`,
            });
          }
        }

        // JSX dangerouslySetInnerHTML
        if (type === "JSXAttribute" && node.name?.name === "dangerouslySetInnerHTML") {
          const line = node.loc?.start?.line ?? 1;
          const curSym = scopeStack[scopeStack.length - 1]?.qname;
          facts.push({
            id: stableId(["babel", "jsx_html", src.path, curSym, line]),
            kind: "sink_html",
            language: "javascript",
            file: src.path,
            line,
            symbol: curSym,
            severity: "high",
            adapter: "babel-parser",
            detail: "React dangerouslySetInnerHTML attribute",
          });
        }

        // Template literal containing raw HTML tags returned from a function
        if (type === "TemplateLiteral" && Array.isArray(node.expressions) && node.expressions.length > 0) {
          const rawQuasis = (node.quasis || []).map((q: any) => q.value?.raw || "").join("");
          if (/<[a-z][a-z0-9-]*(?:\s|>)/i.test(rawQuasis)) {
            const line = node.loc?.start?.line ?? 1;
            const curSym = scopeStack[scopeStack.length - 1]?.qname;
            facts.push({
              id: stableId(["babel", "tpl_html", src.path, curSym, line]),
              kind: "sink_html",
              language: "javascript",
              file: src.path,
              line,
              symbol: curSym,
              severity: "medium",
              adapter: "babel-parser",
              detail: `Template literal interpolates dynamic expression into HTML in ${curSym || "<module>"}`,
            });
          }
        }

        // Call expressions & new Function(...)
        if (type === "CallExpression" || type === "OptionalCallExpression" || type === "NewExpression") {
          const callee = memberChain(node.callee);
          const line = node.loc?.start?.line ?? 1;
          const curScope = scopeStack[scopeStack.length - 1];
          if (callee) {
            edges.push({
              kind: "calls",
              from: curScope?.id || stableId(["babel", "mod", src.path]),
              to: callee,
              file: src.path,
              line,
            });
            // Express/Fastify HTTP route registration: app.get('/path', handler)
            if (/^(?:app|router|server|fastify)\.(?:get|post|put|delete|patch|use)$/i.test(callee)) {
              const routeArg = node.arguments?.[0]?.type === "StringLiteral" ? node.arguments[0].value : "<dynamic>";
              facts.push({
                id: stableId(["babel", "route", src.path, callee, routeArg, line]),
                kind: "entry_point",
                language: "javascript",
                file: src.path,
                line,
                symbol: curScope?.qname || `${callee}(${routeArg})`,
                severity: "info",
                adapter: "babel-parser",
                detail: `HTTP route handler ${callee}("${routeArg}")`,
                metadata: { route: routeArg, callee },
              });
            }
            if (AUTH_IDENT_RE.test(callee)) {
              facts.push({
                id: stableId(["babel", "auth_call", src.path, curScope?.qname, callee, line]),
                kind: "auth_guard",
                language: "javascript",
                file: src.path,
                line,
                symbol: curScope?.qname,
                severity: "info",
                adapter: "babel-parser",
                detail: `Authorization check call ${callee}()`,
              });
            }
            const sink = classifySink(callee);
            if (sink) {
              facts.push({
                id: stableId(["babel", "sink", src.path, curScope?.qname, callee, line]),
                kind: sink.kind,
                language: "javascript",
                file: src.path,
                line,
                symbol: curScope?.qname,
                severity: sink.severity,
                adapter: "babel-parser",
                detail: sink.label,
                metadata: { callee },
              });
            }
          }
        }

        // If-statement auth checks (e.g. if (!req.user?.isAdmin) return 403)
        if (type === "IfStatement" && node.test) {
          const testChain = memberChain(node.test.argument || node.test.left || node.test);
          if (AUTH_IDENT_RE.test(testChain) || /(?:req\.user|session\.user|role)/i.test(testChain)) {
            const line = node.loc?.start?.line ?? 1;
            const curSym = scopeStack[scopeStack.length - 1]?.qname;
            facts.push({
              id: stableId(["babel", "auth_if", src.path, curSym, line]),
              kind: "auth_guard",
              language: "javascript",
              file: src.path,
              line,
              symbol: curSym,
              severity: "info",
              adapter: "babel-parser",
              detail: `Conditional authorization guard on ${testChain}`,
            });
          }
        }

        for (const [k, v] of Object.entries(node)) {
          if (k === "loc" || k === "start" || k === "end" || k === "tokens" || k === "comments") continue;
          if (v && typeof v === "object") {
            visit(v, false);
          }
        }

        if (pushed) scopeStack.pop();
      };

      visit(ast.program, false);
    }

    return { symbols, facts, edges };
  },
};
