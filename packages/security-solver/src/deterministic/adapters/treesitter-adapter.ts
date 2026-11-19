/**
 * Tree-sitter (MIT) multi-language CST structural facts adapter.
 *
 * Bridges to scripts/adapters/treesitter_facts.py (tree-sitter + Python/JS/Java
 * grammars) for error-tolerant multi-language symbol, sink, guard, and call extraction.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
  AdapterExtractionInput,
  AdapterExtractionResult,
  FactLanguage,
  FactSeverity,
  ProgramEdge,
  ProgramFact,
  ProgramFactKind,
  ProgramFactsAdapter,
  ProgramSymbol,
} from "../program-facts";

function findScriptPath(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/adapters/treesitter_facts.py"),
    resolve(process.cwd(), "../../scripts/adapters/treesitter_facts.py"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function mapTreeSitterFact(rawKind: string, detail: string): { kind: ProgramFactKind; severity: FactSeverity } {
  if (rawKind === "entry_point") return { kind: "entry_point", severity: "info" };
  if (rawKind === "auth_guard") return { kind: "auth_guard", severity: "info" };
  const low = detail.toLowerCase();
  if (low.includes("innerhtml") || low.includes("mark_safe") || low.includes("render_template_string")) {
    return { kind: "sink_html", severity: "high" };
  }
  if (low.includes("executequery") || low.includes("sql")) return { kind: "sink_sql", severity: "high" };
  if (low.includes("readobject") || low.includes("pickle")) return { kind: "sink_deserialization", severity: "high" };
  return { kind: "sink_command", severity: "high" };
}

export function isTreeSitterAvailable(): boolean {
  try {
    execFileSync("python3", ["-c", "import tree_sitter"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

export const treeSitterFactsAdapter: ProgramFactsAdapter = {
  name: "tree-sitter",
  languages: ["python", "javascript", "java"],
  license: "MIT",
  role: "Error-tolerant multi-language CST structural symbol, guard, and sink extraction via Tree-sitter",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const supported = input.sources.filter((s) => /\.(?:py|[cm]?js|jsx|[cm]?ts|tsx|java)$/i.test(s.path));
    if (supported.length === 0) return { symbols: [], facts: [], edges: [] };
    const script = findScriptPath();
    if (!script) return { symbols: [], facts: [], edges: [] };

    try {
      const stdout = execFileSync("python3", [script], {
        input: JSON.stringify({ sources: supported.map((s) => ({ path: s.path, content: s.content })) }),
        encoding: "utf8",
        timeout: 15_000,
        maxBuffer: 16 * 1024 * 1024,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const parsed = JSON.parse(stdout || "{}");
      const symbols: ProgramSymbol[] = (parsed.symbols || []).map((s: any) => ({
        id: String(s.id),
        language: (s.language || "unknown") as FactLanguage,
        file: String(s.file),
        line: Number(s.line || 1),
        endLine: s.endLine ? Number(s.endLine) : undefined,
        kind: s.kind === "class" ? "class" : s.kind === "method" ? "method" : "function",
        name: String(s.name),
        qualifiedName: String(s.qualifiedName || s.name),
        modifiers: Array.isArray(s.modifiers) ? s.modifiers.map(String) : [],
        params: [],
      }));
      const facts: ProgramFact[] = (parsed.facts || []).map((f: any) => {
        const detail = String(f.summary || f.detail || "");
        const mapped = mapTreeSitterFact(String(f.kind || ""), detail);
        const lang = (f.attributes?.language || "unknown") as FactLanguage;
        return {
          id: String(f.id),
          kind: mapped.kind,
          language: lang,
          file: String(f.file),
          line: Number(f.line || 1),
          symbol: f.symbol ? String(f.symbol) : undefined,
          severity: mapped.severity,
          adapter: "tree-sitter",
          detail,
          metadata: f.attributes && typeof f.attributes === "object" ? f.attributes : undefined,
        };
      });
      const edges: ProgramEdge[] = (parsed.edges || []).map((e: any) => ({
        from: String(e.from),
        to: String(e.to),
        kind: "calls",
        file: String(e.file),
        line: Number(e.line || 1),
      }));
      return { symbols, facts, edges };
    } catch {
      return { symbols: [], facts: [], edges: [] };
    }
  },
};
