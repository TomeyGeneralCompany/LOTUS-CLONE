/**
 * LibCST (MIT) Python concrete syntax tree facts adapter.
 *
 * Bridges to scripts/adapters/libcst_facts.py when Python + libcst are available
 * on the host, normalizing Python classes, functions, decorators, auth guards,
 * dangerous sinks, and call edges into LOTUS ProgramFactsGraph.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
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

function findScriptPath(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/adapters/libcst_facts.py"),
    resolve(process.cwd(), "../../scripts/adapters/libcst_facts.py"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function mapLibcstFactKind(rawKind: string, detail: string): { kind: ProgramFactKind; severity: FactSeverity } {
  if (rawKind === "entry_point") return { kind: "entry_point", severity: "info" };
  if (rawKind === "auth_guard") return { kind: "auth_guard", severity: "info" };
  const low = detail.toLowerCase();
  if (low.includes("sql") || low.includes("execute")) return { kind: "sink_sql", severity: "high" };
  if (low.includes("pickle") || low.includes("yaml") || low.includes("marshal") || low.includes("deserializ")) {
    return { kind: "sink_deserialization", severity: "high" };
  }
  if (low.includes("html") || low.includes("template") || low.includes("mark_safe") || low.includes("markup")) {
    return { kind: "sink_html", severity: "high" };
  }
  return { kind: "sink_command", severity: "critical" };
}

export function isLibCstAvailable(): boolean {
  try {
    execFileSync("python3", ["-c", "import libcst"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

export const libCstFactsAdapter: ProgramFactsAdapter = {
  name: "libcst",
  languages: ["python"],
  license: "MIT",
  role: "Python concrete syntax tree symbol, decorator, auth-guard, and sink extraction via LibCST",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const pySources = input.sources.filter((s) => /\.py$/i.test(s.path));
    if (pySources.length === 0) return { symbols: [], facts: [], edges: [] };
    const script = findScriptPath();
    if (!script) return { symbols: [], facts: [], edges: [] };

    try {
      const stdout = execFileSync("python3", [script], {
        input: JSON.stringify({ sources: pySources.map((s) => ({ path: s.path, content: s.content })) }),
        encoding: "utf8",
        timeout: 15_000,
        maxBuffer: 16 * 1024 * 1024,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const parsed = JSON.parse(stdout || "{}");
      const symbols: ProgramSymbol[] = (parsed.symbols || []).map((s: any) => ({
        id: String(s.id),
        language: "python",
        file: String(s.file),
        line: Number(s.line || 1),
        endLine: s.endLine ? Number(s.endLine) : undefined,
        kind: s.kind === "class" ? "class" : s.kind === "method" ? "method" : "function",
        name: String(s.name),
        qualifiedName: String(s.qualifiedName || s.name),
        visibility: s.visibility,
        modifiers: Array.isArray(s.modifiers) ? s.modifiers.map(String) : [],
        params: [],
      }));
      const facts: ProgramFact[] = (parsed.facts || []).map((f: any) => {
        const detail = String(f.summary || f.detail || "");
        const mapped = mapLibcstFactKind(String(f.kind || ""), detail);
        return {
          id: String(f.id),
          kind: mapped.kind,
          language: "python",
          file: String(f.file),
          line: Number(f.line || 1),
          symbol: f.symbol ? String(f.symbol) : undefined,
          severity: mapped.severity,
          adapter: "libcst",
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
