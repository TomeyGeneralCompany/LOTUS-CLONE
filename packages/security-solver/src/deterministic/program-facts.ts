/**
 * Common Program-Facts Representation (IR) and Pluggable Analyzer Adapter Interface.
 *
 * All static analyzers, parsers, CPG builders, symbolic engines, and fuzzers
 * normalize their outputs into ProgramFactsGraph so the Hypothesis Engine and
 * Deterministic Analysis/Review Driver remain tool- and language-agnostic.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseSolidity } from "@solidity-parser/parser";
import { babelAstFactsAdapter } from "./adapters/babel-adapter";
import { libCstFactsAdapter, isLibCstAvailable } from "./adapters/libcst-adapter";
import { treeSitterFactsAdapter, isTreeSitterAvailable } from "./adapters/treesitter-adapter";
import { javaParserFactsAdapter, isJavaParserAvailable } from "./adapters/javaparser-adapter";
import { isMythrilAvailable } from "./adapters/mythril-adapter";
import { isJoernAvailable } from "./adapters/joern-adapter";
import type { SourceSnapshot, StaticLeadHint } from "../controller-solidity-experiment-planner";

export type FactLanguage = "solidity" | "javascript" | "python" | "java" | "unknown";

export type ProgramSymbolKind =
  | "contract"
  | "class"
  | "interface"
  | "library"
  | "function"
  | "method"
  | "modifier"
  | "state_var";

export interface ProgramSymbol {
  id: string;
  language: FactLanguage;
  file: string;
  line: number;
  endLine?: number;
  kind: ProgramSymbolKind;
  name: string;
  qualifiedName: string;
  parent?: string;
  visibility?: string;
  mutability?: string;
  modifiers: string[];
  params: string[];
  returnType?: string;
}

export type ProgramFactKind =
  | "entry_point"
  | "auth_guard"
  | "unguarded_mutation"
  | "state_write"
  | "value_transfer"
  | "mint_or_burn"
  | "privileged_primitive"
  | "initializer"
  | "sink_html"
  | "sink_path"
  | "sink_command"
  | "sink_sql"
  | "sink_deserialization"
  | "static_finding"
  | "constraint_guard"
  | "property_counterexample"
  | "symbolic_finding"
  | "taint_flow"
  | "smt_unsat_guard"
  | "smt_sat_witness"
  | "foundry_invariant_violated"
  | "foundry_property_held";

export type FactSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface ProgramFact {
  id: string;
  kind: ProgramFactKind;
  language: FactLanguage;
  file: string;
  line: number;
  symbol?: string;
  severity: FactSeverity;
  adapter: string;
  detail: string;
  metadata?: Record<string, unknown>;
}

export type ProgramEdgeKind = "calls" | "inherits" | "imports" | "writes_state" | "guards" | "dataflow";

export interface ProgramEdge {
  from: string;
  to: string;
  kind: ProgramEdgeKind;
  file: string;
  line: number;
}

export interface AdapterExtractionInput {
  sources: readonly SourceSnapshot[];
  staticLeads?: readonly StaticLeadHint[];
}

export interface AdapterExtractionResult {
  symbols: ProgramSymbol[];
  facts: ProgramFact[];
  edges: ProgramEdge[];
}

export interface ProgramFactsAdapter {
  readonly name: string;
  readonly languages: readonly FactLanguage[];
  readonly license: string;
  readonly role: string;
  extract(input: AdapterExtractionInput): AdapterExtractionResult;
}

export interface ProgramFactsGraph {
  generatedAt: string;
  languages: FactLanguage[];
  filesIndexed: number;
  adaptersUsed: string[];
  symbols: ProgramSymbol[];
  facts: ProgramFact[];
  edges: ProgramEdge[];
  byFile: ReadonlyMap<string, { symbols: ProgramSymbol[]; facts: ProgramFact[] }>;
  bySymbol: ReadonlyMap<string, ProgramFact[]>;
}

export interface ExternalToolAdapterSpec {
  id: string;
  name: string;
  role: string;
  license: string;
  languages: readonly FactLanguage[];
  status: "integrated" | "planned_adapter";
  probeCommand?: readonly string[];
  probeNodeModule?: string;
}

export const EXTERNAL_ADAPTER_CATALOG: readonly ExternalToolAdapterSpec[] = [
  { id: "semgrep", name: "Semgrep", role: "Pattern & rule static lead scanning", license: "LGPL-2.1", languages: ["solidity", "javascript", "python", "java"], status: "integrated", probeCommand: ["semgrep", "--version"] },
  { id: "slither", name: "Slither", role: "Bounded Solidity static & dataflow analysis", license: "AGPL-3.0", languages: ["solidity"], status: "integrated", probeCommand: ["slither", "--version"] },
  { id: "solidity-parser", name: "@solidity-parser/parser", role: "Solidity AST & symbol/guard extraction", license: "MIT", languages: ["solidity"], status: "integrated", probeNodeModule: "@solidity-parser/parser" },
  { id: "babel-parser", name: "@babel/parser", role: "JavaScript/TypeScript AST extraction", license: "MIT", languages: ["javascript"], status: "integrated", probeNodeModule: "@babel/parser" },
  { id: "fast-check", name: "fast-check", role: "JavaScript/TypeScript property-based testing", license: "MIT", languages: ["javascript"], status: "integrated", probeNodeModule: "fast-check" },
  { id: "libcst", name: "LibCST", role: "Python concrete syntax tree analysis", license: "MIT", languages: ["python"], status: "integrated", probeCommand: ["python3", "-c", "import libcst"] },
  { id: "tree-sitter", name: "Tree-sitter", role: "Structural multi-language CST/AST analysis", license: "MIT", languages: ["solidity", "javascript", "python", "java"], status: "integrated", probeCommand: ["python3", "-c", "import tree_sitter"] },
  { id: "z3", name: "Z3", role: "SMT constraint solving for path & invariant feasibility", license: "MIT", languages: ["solidity", "javascript", "python", "java"], status: "integrated", probeCommand: ["python3", "-c", "import z3"] },
  { id: "foundry", name: "Foundry (forge)", role: "Solidity stateful fuzzing & invariant testing", license: "MIT/Apache-2.0", languages: ["solidity"], status: "integrated", probeCommand: ["forge", "--version"] },
  { id: "javaparser", name: "JavaParser", role: "Java AST parsing & symbol resolution", license: "Apache-2.0", languages: ["java"], status: "integrated", probeCommand: ["java", "-version"] },
  { id: "mythril", name: "Mythril", role: "EVM bytecode symbolic execution", license: "MIT", languages: ["solidity"], status: "integrated", probeCommand: ["myth", "version"] },
  { id: "joern", name: "Joern", role: "Code property graphs & interprocedural taint", license: "Apache-2.0", languages: ["javascript", "python", "java"], status: "integrated", probeCommand: ["joern-parse", "--help"] },
];

export interface AdapterAvailability {
  id: string;
  name: string;
  role: string;
  license: string;
  status: "integrated" | "planned_adapter";
  availableOnHost: boolean;
}

export function detectAvailableAdapters(): AdapterAvailability[] {
  return EXTERNAL_ADAPTER_CATALOG.map((spec) => {
    let availableOnHost = false;
    if (spec.id === "javaparser") {
      availableOnHost = isJavaParserAvailable();
    } else if (spec.id === "mythril") {
      availableOnHost = isMythrilAvailable();
    } else if (spec.id === "joern") {
      availableOnHost = isJoernAvailable();
    } else if (spec.probeCommand) {
      try {
        execFileSync(spec.probeCommand[0], spec.probeCommand.slice(1), {
          stdio: "ignore",
          timeout: 2500,
        });
        availableOnHost = true;
      } catch {
        availableOnHost = false;
      }
    } else if (spec.probeNodeModule) {
      const root = process.env.PROJECT_ROOT || process.cwd();
      availableOnHost =
        spec.id === "solidity-parser" ||
        existsSync(join(root, "node_modules", ...spec.probeNodeModule.split("/")));
    }
    return {
      id: spec.id,
      name: spec.name,
      role: spec.role,
      license: spec.license,
      status: spec.status,
      availableOnHost,
    };
  });
}

export function detectLanguage(filePath: string): FactLanguage {
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".sol")) return "solidity";
  if (/\.(?:js|mjs|cjs|ts|tsx|jsx)$/.test(lower)) return "javascript";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".java")) return "java";
  return "unknown";
}

function stableId(parts: readonly (string | number | undefined)[]): string {
  return createHash("sha256")
    .update(parts.map((p) => String(p ?? "")).join("|"))
    .digest("hex")
    .slice(0, 24);
}

const AUTH_MODIFIER_RE = /\b(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyMinter|onlyController|onlyGuardian|onlyManager|onlyOperator|onlyAuthorized|auth|requiresAuth|restricted|onlyPool|onlyFactory|onlyKeeper)\b/i;
const INIT_MODIFIER_RE = /\b(?:initializer|reinitializer|onlyInitializing)\b/i;
const INLINE_AUTH_GUARD_RE = /\b(?:msg\.sender\s*==|hasRole\s*\(|_checkRole\s*\(|_checkOwner\s*\(|owner\s*\(\s*\)\s*==|==\s*owner\b|==\s*_owner\b|==\s*admin\b|==\s*governance\b)/i;

function walkAst(node: any, visit: (n: any) => void, depth = 0): void {
  if (!node || typeof node !== "object" || depth > 48) return;
  if (Array.isArray(node)) {
    for (const item of node) walkAst(item, visit, depth + 1);
    return;
  }
  visit(node);
  for (const [k, v] of Object.entries(node)) {
    if (k === "loc" || k === "range") continue;
    walkAst(v, visit, depth + 1);
  }
}

export const solidityAstFactsAdapter: ProgramFactsAdapter = {
  name: "solidity-ast",
  languages: ["solidity"],
  license: "MIT",
  role: "AST extraction for Solidity contracts, auth guards, state writes, transfers, and privileged primitives",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const symbols: ProgramSymbol[] = [];
    const facts: ProgramFact[] = [];
    const edges: ProgramEdge[] = [];

    for (const src of input.sources) {
      if (detectLanguage(src.path) !== "solidity") continue;
      let ast: any;
      try {
        ast = parseSolidity(src.content, { loc: true, range: true, tolerant: true });
      } catch {
        continue;
      }
      const lines = src.content.split("\n");
      for (const node of ast.children || []) {
        if (node.type === "ImportDirective" && typeof node.path === "string") {
          edges.push({
            from: src.path,
            to: node.path,
            kind: "imports",
            file: src.path,
            line: node.loc?.start?.line ?? 1,
          });
          continue;
        }
        if (node.type !== "ContractDefinition" || !node.name) continue;
        const contractName: string = node.name;
        const contractLine: number = node.loc?.start?.line ?? 1;
        const kind: ProgramSymbolKind =
          node.kind === "interface" ? "interface" : node.kind === "library" ? "library" : "contract";
        symbols.push({
          id: stableId(["sym", src.path, contractName]),
          language: "solidity",
          file: src.path,
          line: contractLine,
          endLine: node.loc?.end?.line,
          kind,
          name: contractName,
          qualifiedName: contractName,
          modifiers: [],
          params: [],
        });

        for (const base of node.baseContracts || []) {
          const baseName = base?.baseName?.namePath;
          if (baseName) {
            edges.push({
              from: contractName,
              to: baseName,
              kind: "inherits",
              file: src.path,
              line: base.loc?.start?.line ?? contractLine,
            });
          }
        }

        const stateVars = new Set<string>();
        for (const sub of node.subNodes || []) {
          if (sub.type === "StateVariableDeclaration") {
            for (const v of sub.variables || []) {
              if (!v?.name) continue;
              stateVars.add(v.name);
              symbols.push({
                id: stableId(["sym", src.path, contractName, v.name, sub.loc?.start?.line]),
                language: "solidity",
                file: src.path,
                line: sub.loc?.start?.line ?? contractLine,
                kind: "state_var",
                name: v.name,
                qualifiedName: `${contractName}.${v.name}`,
                parent: contractName,
                visibility: v.visibility || "internal",
                modifiers: [],
                params: [],
              });
            }
          }
        }

        if (kind !== "contract") continue;

        for (const sub of node.subNodes || []) {
          if (sub.type !== "FunctionDefinition" || !sub.body) continue;
          const fnName: string = sub.isConstructor ? "constructor" : sub.isReceiveEther ? "receive" : sub.isFallback ? "fallback" : (sub.name || "");
          if (!fnName) continue;
          const visibility: string = sub.visibility || "public";
          const mutability: string = sub.stateMutability || "";
          const fnLine: number = sub.loc?.start?.line ?? contractLine;
          const endLine: number = sub.loc?.end?.line ?? fnLine;
          const modifiers: string[] = (sub.modifiers || []).map((m: any) => String(m?.name || "")).filter(Boolean);
          const params: string[] = (sub.parameters || []).map((p: any) => String(p?.name || p?.typeName?.name || "arg"));
          const qualifiedName = `${contractName}.${fnName}`;

          symbols.push({
            id: stableId(["sym", src.path, qualifiedName, fnLine]),
            language: "solidity",
            file: src.path,
            line: fnLine,
            endLine,
            kind: "function",
            name: fnName,
            qualifiedName,
            parent: contractName,
            visibility,
            mutability,
            modifiers,
            params,
          });

          const isEntry = !sub.isConstructor && (visibility === "public" || visibility === "external") && mutability !== "view" && mutability !== "pure";
          if (!isEntry) continue;

          facts.push({
            id: stableId(["fact", "entry_point", src.path, qualifiedName, fnLine]),
            kind: "entry_point",
            language: "solidity",
            file: src.path,
            line: fnLine,
            symbol: qualifiedName,
            severity: "info",
            adapter: "solidity-ast",
            detail: `${visibility} state-changing Solidity entrypoint ${qualifiedName}`,
            metadata: { visibility, mutability, modifiers },
          });

          const fnSource = lines.slice(Math.max(0, fnLine - 1), Math.min(lines.length, endLine)).join("\n");
          const hasAuthModifier = modifiers.some((m) => AUTH_MODIFIER_RE.test(m));
          const hasInitModifier = modifiers.some((m) => INIT_MODIFIER_RE.test(m));
          const hasInlineAuth = INLINE_AUTH_GUARD_RE.test(fnSource);
          const isAuthGuarded = hasAuthModifier || hasInlineAuth;

          if (isAuthGuarded) {
            facts.push({
              id: stableId(["fact", "auth_guard", src.path, qualifiedName, fnLine]),
              kind: "auth_guard",
              language: "solidity",
              file: src.path,
              line: fnLine,
              symbol: qualifiedName,
              severity: "info",
              adapter: "solidity-ast",
              detail: hasAuthModifier
                ? `Authorization modifier(s): ${modifiers.filter((m) => AUTH_MODIFIER_RE.test(m)).join(", ")}`
                : `Inline caller authorization check detected in ${qualifiedName}`,
              metadata: { modifiers, hasInlineAuth },
            });
          }

          if (/^(?:initialize|init|__[A-Za-z0-9_]+_init)$/i.test(fnName)) {
            facts.push({
              id: stableId(["fact", "initializer", src.path, qualifiedName, fnLine]),
              kind: "initializer",
              language: "solidity",
              file: src.path,
              line: fnLine,
              symbol: qualifiedName,
              severity: hasInitModifier || isAuthGuarded ? "low" : "high",
              adapter: "solidity-ast",
              detail: hasInitModifier || isAuthGuarded
                ? `Guarded initializer ${qualifiedName} (${modifiers.join(", ") || "inline check"})`
                : `Initializer ${qualifiedName} lacks initializer/reinitializer or explicit caller guard`,
              metadata: { hasInitModifier, isAuthGuarded, modifiers },
            });
          }

          const writtenVars = new Set<string>();
          let hasValueTransfer = false;
          let hasMintOrBurn = false;
          let hasPrivilegedPrimitive = false;
          let hasConstraintGuard = false;
          let transferLine = fnLine;
          let mintLine = fnLine;
          let privLine = fnLine;

          walkAst(sub.body, (n: any) => {
            const line = n?.loc?.start?.line ?? fnLine;
            if (n.type === "BinaryOperation" && ["=", "+=", "-=", "*=", "/="].includes(n.operator)) {
              let lhs = n.left;
              while (lhs && (lhs.type === "IndexAccess" || lhs.type === "MemberAccess")) {
                lhs = lhs.base ?? lhs.expression;
              }
              if (lhs?.type === "Identifier" && stateVars.has(lhs.name)) {
                writtenVars.add(lhs.name);
                edges.push({ from: qualifiedName, to: `${contractName}.${lhs.name}`, kind: "writes_state", file: src.path, line });
              }
            }
            if (n.type === "FunctionCall") {
              const expr = n.expression;
              const callee =
                expr?.type === "Identifier" ? expr.name
                : expr?.type === "MemberAccess" ? expr.memberName
                : expr?.type === "NameValueExpression" && expr.expression?.type === "MemberAccess" ? expr.expression.memberName
                : "";
              if (callee) {
                edges.push({ from: qualifiedName, to: callee, kind: "calls", file: src.path, line });
              }
              if (callee === "delegatecall" || callee === "selfdestruct" || callee === "suicide") {
                hasPrivilegedPrimitive = true;
                privLine = line;
              } else if (/^(?:transfer|transferFrom|safeTransfer|safeTransferFrom|send|sendValue|withdraw|sweep|rescue)$/i.test(callee) ||
                         (callee === "call" && expr?.type === "NameValueExpression")) {
                hasValueTransfer = true;
                transferLine = line;
              } else if (/^(?:_?mint|_?burn|_?safeMint)$/i.test(callee)) {
                hasMintOrBurn = true;
                mintLine = line;
              } else if (callee === "require" || callee === "isContract") {
                hasConstraintGuard = true;
              }
            }
          });

          if (writtenVars.size > 0) {
            facts.push({
              id: stableId(["fact", "state_write", src.path, qualifiedName, fnLine]),
              kind: "state_write",
              language: "solidity",
              file: src.path,
              line: fnLine,
              symbol: qualifiedName,
              severity: "info",
              adapter: "solidity-ast",
              detail: `${qualifiedName} writes state variable(s): ${[...writtenVars].sort().join(", ")}`,
              metadata: { variables: [...writtenVars].sort(), isAuthGuarded },
            });
            if (!isAuthGuarded && !hasInitModifier) {
              facts.push({
                id: stableId(["fact", "unguarded_mutation", src.path, qualifiedName, fnLine]),
                kind: "unguarded_mutation",
                language: "solidity",
                file: src.path,
                line: fnLine,
                symbol: qualifiedName,
                severity: "medium",
                adapter: "solidity-ast",
                detail: `${qualifiedName} mutates state (${[...writtenVars].sort().join(", ")}) without an explicit auth modifier or inline sender check`,
                metadata: { variables: [...writtenVars].sort() },
              });
            }
          }

          if (hasPrivilegedPrimitive) {
            facts.push({
              id: stableId(["fact", "privileged_primitive", src.path, qualifiedName, privLine]),
              kind: "privileged_primitive",
              language: "solidity",
              file: src.path,
              line: privLine,
              symbol: qualifiedName,
              severity: isAuthGuarded ? "medium" : "critical",
              adapter: "solidity-ast",
              detail: `${qualifiedName} invokes delegatecall/selfdestruct (${isAuthGuarded ? "auth-guarded" : "unguarded"})`,
              metadata: { isAuthGuarded },
            });
          }

          if (hasValueTransfer) {
            facts.push({
              id: stableId(["fact", "value_transfer", src.path, qualifiedName, transferLine]),
              kind: "value_transfer",
              language: "solidity",
              file: src.path,
              line: transferLine,
              symbol: qualifiedName,
              severity: isAuthGuarded ? "low" : "high",
              adapter: "solidity-ast",
              detail: `${qualifiedName} transfers ETH/tokens (${isAuthGuarded ? "auth-guarded" : "no explicit auth guard"})`,
              metadata: { isAuthGuarded },
            });
          }

          if (hasMintOrBurn) {
            facts.push({
              id: stableId(["fact", "mint_or_burn", src.path, qualifiedName, mintLine]),
              kind: "mint_or_burn",
              language: "solidity",
              file: src.path,
              line: mintLine,
              symbol: qualifiedName,
              severity: isAuthGuarded ? "low" : "critical",
              adapter: "solidity-ast",
              detail: `${qualifiedName} performs mint/burn operation (${isAuthGuarded ? "auth-guarded" : "no explicit auth guard"})`,
              metadata: { isAuthGuarded },
            });
          }

          if (hasConstraintGuard) {
            facts.push({
              id: stableId(["fact", "constraint_guard", src.path, qualifiedName, fnLine]),
              kind: "constraint_guard",
              language: "solidity",
              file: src.path,
              line: fnLine,
              symbol: qualifiedName,
              severity: "info",
              adapter: "solidity-ast",
              detail: `${qualifiedName} enforces runtime require/isContract precondition(s)`,
            });
          }
        }
      }
    }

    return { symbols, facts, edges };
  },
};

function scanLineSinks(
  src: SourceSnapshot,
  language: FactLanguage,
  adapter: string,
  fnRe: RegExp,
  sinkRules: ReadonlyArray<{ kind: ProgramFactKind; severity: FactSeverity; re: RegExp; label: string }>,
  guardRe: RegExp,
): AdapterExtractionResult {
  const symbols: ProgramSymbol[] = [];
  const facts: ProgramFact[] = [];
  const edges: ProgramEdge[] = [];
  const lines = src.content.split("\n");
  let currentSymbol = "";

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i];
    const fnMatch = fnRe.exec(line);
    if (fnMatch) {
      const fnName = fnMatch[1] || fnMatch[2] || "";
      if (fnName && !/^(?:if|for|while|switch|catch|return)$/.test(fnName)) {
        currentSymbol = fnName;
        symbols.push({
          id: stableId(["sym", src.path, fnName, lineNo]),
          language,
          file: src.path,
          line: lineNo,
          kind: "function",
          name: fnName,
          qualifiedName: fnName,
          modifiers: [],
          params: [],
        });
        facts.push({
          id: stableId(["fact", "entry_point", src.path, fnName, lineNo]),
          kind: "entry_point",
          language,
          file: src.path,
          line: lineNo,
          symbol: fnName,
          severity: "info",
          adapter,
          detail: `${language} callable symbol ${fnName}`,
        });
      }
    }
    if (guardRe.test(line)) {
      facts.push({
        id: stableId(["fact", "auth_guard", src.path, currentSymbol, lineNo]),
        kind: "auth_guard",
        language,
        file: src.path,
        line: lineNo,
        symbol: currentSymbol || undefined,
        severity: "info",
        adapter,
        detail: `Guard/sanitization pattern detected: ${line.trim().slice(0, 120)}`,
      });
    }
    for (const rule of sinkRules) {
      if (rule.re.test(line)) {
        facts.push({
          id: stableId(["fact", rule.kind, src.path, currentSymbol, lineNo, rule.label]),
          kind: rule.kind,
          language,
          file: src.path,
          line: lineNo,
          symbol: currentSymbol || undefined,
          severity: rule.severity,
          adapter,
          detail: `${rule.label} at ${src.path}:${lineNo}`,
          metadata: { snippet: line.trim().slice(0, 160) },
        });
      }
    }
  }
  return { symbols, facts, edges };
}

export const javascriptStructuralFactsAdapter: ProgramFactsAdapter = {
  name: "javascript-structural",
  languages: ["javascript"],
  license: "MIT",
  role: "Structural JS/TS entrypoint and sink extractor (upgradable via Babel Parser / Tree-sitter)",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const out: AdapterExtractionResult = { symbols: [], facts: [], edges: [] };
    const fnRe = /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)/;
    const guardRe = /\b(?:escapeHtml|sanitizeHtml|DOMPurify|encodeURIComponent|startsWith\s*\(\s*base|isAuthorized|requireAuth)\b/i;
    const rules = [
      { kind: "sink_html" as const, severity: "high" as const, re: /(?:innerHTML|outerHTML|document\.write|res\.send\s*\(|['"`]<(?:div|p|span|html|body|section|article|h[1-6]|li|a|script)\b)/i, label: "HTML markup construction/sink" },
      { kind: "sink_path" as const, severity: "high" as const, re: /\b(?:path\.join|path\.resolve|readFileSync|readFile|createReadStream|sendFile)\s*\(/, label: "Filesystem path construction/access sink" },
      { kind: "sink_command" as const, severity: "critical" as const, re: /\b(?:child_process|execSync|execFile|spawnSync|\beval\s*\(|new\s+Function\s*\()/, label: "Command or dynamic code execution sink" },
      { kind: "sink_sql" as const, severity: "high" as const, re: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\$\{/i, label: "Interpolated SQL query sink" },
    ];
    for (const src of input.sources) {
      if (detectLanguage(src.path) !== "javascript") continue;
      const r = scanLineSinks(src, "javascript", "javascript-structural", fnRe, rules, guardRe);
      out.symbols.push(...r.symbols);
      out.facts.push(...r.facts);
      out.edges.push(...r.edges);
    }
    return out;
  },
};

export const pythonStructuralFactsAdapter: ProgramFactsAdapter = {
  name: "python-structural",
  languages: ["python"],
  license: "MIT",
  role: "Structural Python entrypoint and sink extractor (upgradable via LibCST / Tree-sitter)",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const out: AdapterExtractionResult = { symbols: [], facts: [], edges: [] };
    const fnRe = /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/;
    const guardRe = /\b(?:html\.escape|markupsafe\.escape|bleach\.clean|login_required|permission_required|is_relative_to|commonpath)\b/i;
    const rules = [
      { kind: "sink_html" as const, severity: "high" as const, re: /(?:render_template_string|Markup\s*\(|f["']<(?:div|p|span|html|body|section|h[1-6]|li)\b)/i, label: "Python HTML markup sink" },
      { kind: "sink_path" as const, severity: "high" as const, re: /\b(?:os\.path\.join|Path\s*\([^)]*\)\s*\/|open\s*\(|send_file\s*\()/, label: "Python path construction/access sink" },
      { kind: "sink_command" as const, severity: "critical" as const, re: /\b(?:os\.system|subprocess\.(?:Popen|run|call|check_output)|eval\s*\(|exec\s*\()/, label: "Python command/code execution sink" },
      { kind: "sink_deserialization" as const, severity: "critical" as const, re: /\b(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads)\b/, label: "Unsafe Python deserialization sink" },
    ];
    for (const src of input.sources) {
      if (detectLanguage(src.path) !== "python") continue;
      const r = scanLineSinks(src, "python", "python-structural", fnRe, rules, guardRe);
      out.symbols.push(...r.symbols);
      out.facts.push(...r.facts);
      out.edges.push(...r.edges);
    }
    return out;
  },
};

export const javaStructuralFactsAdapter: ProgramFactsAdapter = {
  name: "java-structural",
  languages: ["java"],
  license: "Apache-2.0",
  role: "Structural Java entrypoint and sink extractor (upgradable via JavaParser / Tree-sitter)",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const out: AdapterExtractionResult = { symbols: [], facts: [], edges: [] };
    const fnRe = /^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\(/;
    const guardRe = /\b(?:HtmlUtils\.htmlEscape|StringEscapeUtils|@PreAuthorize|@Secured|normalize\(\)\.startsWith)\b/;
    const rules = [
      { kind: "sink_html" as const, severity: "high" as const, re: /(?:text\/html|"<(?:div|p|span|html|body|section|h[1-6]|li)\b|getWriter\s*\(\s*\)\.(?:write|print))/i, label: "Java HTML output sink" },
      { kind: "sink_path" as const, severity: "high" as const, re: /\b(?:Paths\.get|Path\.of|new\s+File\s*\(|Files\.read(?:String|AllBytes))\b/, label: "Java filesystem path sink" },
      { kind: "sink_command" as const, severity: "critical" as const, re: /\b(?:Runtime\.getRuntime\s*\(\s*\)\.exec|new\s+ProcessBuilder\s*\()/, label: "Java OS command execution sink" },
      { kind: "sink_deserialization" as const, severity: "critical" as const, re: /\b(?:new\s+ObjectInputStream|readObject\s*\()/, label: "Java deserialization sink" },
      { kind: "sink_sql" as const, severity: "high" as const, re: /\b(?:createStatement|executeQuery\s*\([^)]*\+)/, label: "Java concatenated SQL sink" },
    ];
    for (const src of input.sources) {
      if (detectLanguage(src.path) !== "java") continue;
      const r = scanLineSinks(src, "java", "java-structural", fnRe, rules, guardRe);
      out.symbols.push(...r.symbols);
      out.facts.push(...r.facts);
      out.edges.push(...r.edges);
    }
    return out;
  },
};

export const staticLeadsFactsAdapter: ProgramFactsAdapter = {
  name: "static-leads",
  languages: ["solidity", "javascript", "python", "java"],
  license: "MIT",
  role: "Normalizes Semgrep and Slither static scanner leads into common ProgramFacts",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const facts: ProgramFact[] = [];
    for (const lead of input.staticLeads || []) {
      const lang = detectLanguage(lead.path);
      const sevRaw = String(lead.severity || "WARNING").toLowerCase();
      const severity: FactSeverity =
        sevRaw === "high" || sevRaw === "error" || sevRaw === "critical" ? "high"
        : sevRaw === "medium" || sevRaw === "warning" ? "medium"
        : "low";
      facts.push({
        id: stableId(["fact", "static_finding", lead.path, lead.line, lead.rule]),
        kind: "static_finding",
        language: lang,
        file: lead.path,
        line: lead.line,
        severity,
        adapter: lead.engine ? `static-${lead.engine}` : "static-leads",
        detail: `[${lead.rule}] ${lead.message}`,
        metadata: { rule: lead.rule, engine: lead.engine || "static", rawSeverity: lead.severity || "WARNING" },
      });
    }
    return { symbols: [], facts, edges: [] };
  },
};

export const DEFAULT_FACTS_ADAPTERS: readonly ProgramFactsAdapter[] = [
  solidityAstFactsAdapter,
  babelAstFactsAdapter,
  javascriptStructuralFactsAdapter,
  pythonStructuralFactsAdapter,
  javaStructuralFactsAdapter,
  staticLeadsFactsAdapter,
];

let cachedHostAdapters: readonly ProgramFactsAdapter[] | null = null;

/**
 * Returns DEFAULT_FACTS_ADAPTERS enriched with all host-available external AST/CST
 * adapters (LibCST, Tree-sitter, JavaParser). Probing is cached per process.
 */
export function createHostFactsAdapters(forceRefresh = false): readonly ProgramFactsAdapter[] {
  if (!forceRefresh && cachedHostAdapters) return cachedHostAdapters;
  const list: ProgramFactsAdapter[] = [
    solidityAstFactsAdapter,
    babelAstFactsAdapter,
    staticLeadsFactsAdapter,
  ];
  if (isLibCstAvailable()) list.push(libCstFactsAdapter);
  if (isJavaParserAvailable()) list.push(javaParserFactsAdapter);
  if (isTreeSitterAvailable()) list.push(treeSitterFactsAdapter);
  list.push(javascriptStructuralFactsAdapter, pythonStructuralFactsAdapter, javaStructuralFactsAdapter);
  cachedHostAdapters = list;
  return list;
}

export function buildProgramFactsGraph(
  input: AdapterExtractionInput,
  adapters: readonly ProgramFactsAdapter[] = DEFAULT_FACTS_ADAPTERS,
): ProgramFactsGraph {
  const symbols: ProgramSymbol[] = [];
  const facts: ProgramFact[] = [];
  const edges: ProgramEdge[] = [];
  const adaptersUsed: string[] = [];
  const seenSymbols = new Set<string>();
  const seenFacts = new Set<string>();

  for (const adapter of adapters) {
    const res = adapter.extract(input);
    if (res.symbols.length || res.facts.length || res.edges.length) {
      adaptersUsed.push(adapter.name);
    }
    for (const sym of res.symbols) {
      if (!seenSymbols.has(sym.id)) {
        seenSymbols.add(sym.id);
        symbols.push(sym);
      }
    }
    for (const fact of res.facts) {
      if (!seenFacts.has(fact.id)) {
        seenFacts.add(fact.id);
        facts.push(fact);
      }
    }
    edges.push(...res.edges);
  }

  // Link static_finding facts to their nearest enclosing symbol in the same file
  const symbolsByFile = new Map<string, ProgramSymbol[]>();
  for (const sym of symbols) {
    let list = symbolsByFile.get(sym.file);
    if (!list) {
      list = [];
      symbolsByFile.set(sym.file, list);
    }
    list.push(sym);
  }
  for (const fact of facts) {
    if (fact.symbol) continue;
    const candidates = (symbolsByFile.get(fact.file) || []).filter(
      (s) => (s.kind === "function" || s.kind === "method") && s.line <= fact.line && (!s.endLine || s.endLine >= fact.line),
    );
    if (candidates.length) {
      candidates.sort((a, b) => b.line - a.line);
      fact.symbol = candidates[0].qualifiedName;
    }
  }

  const byFile = new Map<string, { symbols: ProgramSymbol[]; facts: ProgramFact[] }>();
  for (const sym of symbols) {
    let bucket = byFile.get(sym.file);
    if (!bucket) {
      bucket = { symbols: [], facts: [] };
      byFile.set(sym.file, bucket);
    }
    bucket.symbols.push(sym);
  }
  for (const fact of facts) {
    let bucket = byFile.get(fact.file);
    if (!bucket) {
      bucket = { symbols: [], facts: [] };
      byFile.set(fact.file, bucket);
    }
    bucket.facts.push(fact);
  }

  const bySymbol = new Map<string, ProgramFact[]>();
  for (const fact of facts) {
    if (!fact.symbol) continue;
    let list = bySymbol.get(fact.symbol);
    if (!list) {
      list = [];
      bySymbol.set(fact.symbol, list);
    }
    list.push(fact);
  }

  const languages = [...new Set(input.sources.map((s) => detectLanguage(s.path)).filter((l) => l !== "unknown"))];
  return {
    generatedAt: new Date().toISOString(),
    languages,
    filesIndexed: input.sources.length,
    adaptersUsed,
    symbols,
    facts,
    edges,
    byFile,
    bySymbol,
  };
}
