/**
 * JavaParser (Apache-2.0) Java AST & symbol extraction adapter.
 *
 * Invokes scripts/adapters/JavaParserFacts.java with com.github.javaparser:javaparser-core
 * jar (located via JAVAPARSER_JAR, .lotus-tools/javaparser-core.jar, or
 * /tmp/lotus-tools/javaparser-core.jar) and normalizes Java classes, methods,
 * Spring/JAX-RS annotations, auth guards, dangerous sinks, and call edges.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import type {
  AdapterExtractionInput,
  AdapterExtractionResult,
  FactSeverity,
  ProgramEdge,
  ProgramFact,
  ProgramFactKind,
  ProgramFactsAdapter,
  ProgramSymbol,
} from "../program-facts";

export function findJavaParserJar(): string | null {
  const candidates = [
    process.env.JAVAPARSER_JAR?.trim(),
    join(process.cwd(), ".lotus-tools/javaparser-core.jar"),
    "/tmp/lotus-tools/javaparser-core.jar",
    "/opt/lotus-tools/javaparser-core.jar",
  ].filter((x): x is string => Boolean(x));
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function findJavaScriptPath(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/adapters/JavaParserFacts.java"),
    resolve(process.cwd(), "../../scripts/adapters/JavaParserFacts.java"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

export function isJavaParserAvailable(): boolean {
  if (!findJavaParserJar() || !findJavaScriptPath()) return false;
  try {
    execFileSync("java", ["-version"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

function mapJavaParserFact(rawKind: string, detail: string): { kind: ProgramFactKind; severity: FactSeverity } {
  if (rawKind === "entry_point") return { kind: "entry_point", severity: "info" };
  if (rawKind === "auth_guard") return { kind: "auth_guard", severity: "info" };
  const low = detail.toLowerCase();
  if (low.includes("sql") || low.includes("executequery") || low.includes("executeupdate")) {
    return { kind: "sink_sql", severity: "high" };
  }
  if (low.includes("deserializ") || low.includes("readobject") || low.includes("objectinputstream")) {
    return { kind: "sink_deserialization", severity: "critical" };
  }
  if (low.includes("filesystem") || low.includes("readstring")) {
    return { kind: "sink_path", severity: "high" };
  }
  return { kind: "sink_command", severity: "critical" };
}

export const javaParserFactsAdapter: ProgramFactsAdapter = {
  name: "javaparser",
  languages: ["java"],
  license: "Apache-2.0",
  role: "Java AST parsing, annotation auth-guard detection, and sink/call extraction via JavaParser",
  extract(input: AdapterExtractionInput): AdapterExtractionResult {
    const javaSources = input.sources.filter((s) => /\.java$/i.test(s.path));
    if (javaSources.length === 0) return { symbols: [], facts: [], edges: [] };
    const jar = findJavaParserJar();
    const javaSrc = findJavaScriptPath();
    if (!jar || !javaSrc) return { symbols: [], facts: [], edges: [] };

    const tmp = mkdtempSync(join(tmpdir(), "lotus-javaparser-"));
    try {
      const args: string[] = ["-cp", jar, javaSrc];
      javaSources.forEach((src, idx) => {
        const diskPath = join(tmp, `${idx}-${basename(src.path).replace(/[^A-Za-z0-9_.-]/g, "_")}`);
        writeFileSync(diskPath, src.content, "utf8");
        args.push(src.path, diskPath);
      });

      const stdout = execFileSync("java", args, {
        encoding: "utf8",
        timeout: 20_000,
        maxBuffer: 16 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
      });
      const parsed = JSON.parse(stdout || "{}");
      const symbols: ProgramSymbol[] = (parsed.symbols || []).map((s: any) => ({
        id: String(s.id),
        language: "java",
        file: String(s.file),
        line: Number(s.line || 1),
        endLine: s.endLine ? Number(s.endLine) : undefined,
        kind: s.kind === "class" ? "class" : "method",
        name: String(s.name),
        qualifiedName: String(s.qualifiedName || s.name),
        visibility: s.visibility,
        modifiers: Array.isArray(s.modifiers) ? s.modifiers.map(String) : [],
        params: [],
      }));
      const facts: ProgramFact[] = (parsed.facts || []).map((f: any) => {
        const detail = String(f.summary || f.detail || "");
        const mapped = mapJavaParserFact(String(f.kind || ""), detail);
        return {
          id: String(f.id),
          kind: mapped.kind,
          language: "java",
          file: String(f.file),
          line: Number(f.line || 1),
          symbol: f.symbol ? String(f.symbol) : undefined,
          severity: mapped.severity,
          adapter: "javaparser",
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
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  },
};
