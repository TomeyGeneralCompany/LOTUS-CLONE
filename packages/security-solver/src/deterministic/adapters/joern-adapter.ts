/**
 * Joern (Apache-2.0) Code Property Graph (CPG) & interprocedural taint adapter.
 *
 * Runs `joern-parse` + `joern --script scripts/adapters/joern_cpg_facts.sc` when
 * Joern CLI is available on the host (PATH or JOERN_HOME), and normalizes CPG
 * methods, dangerous call sinks, and interprocedural parameter-to-sink dataflows
 * into LOTUS ProgramFacts (`taint_flow`) and ProgramEdges (`dataflow`).
 */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type {
  AdapterExtractionInput,
  AdapterExtractionResult,
  FactLanguage,
  ProgramEdge,
  ProgramFact,
  ProgramSymbol,
} from "../program-facts";

function joernBin(name: "joern" | "joern-parse"): string {
  const home = process.env.JOERN_HOME?.trim();
  if (home) {
    const candidate = join(home, name);
    if (existsSync(candidate)) return candidate;
  }
  return name;
}

function findJoernScript(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/adapters/joern_cpg_facts.sc"),
    resolve(process.cwd(), "../../scripts/adapters/joern_cpg_facts.sc"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

export function isJoernAvailable(): boolean {
  try {
    execFileSync(joernBin("joern-parse"), ["--help"], { stdio: "ignore", timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}

function detectLang(path: string): FactLanguage {
  const low = path.toLowerCase();
  if (low.endsWith(".py")) return "python";
  if (low.endsWith(".java")) return "java";
  if (/\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/.test(low)) return "javascript";
  return "unknown";
}

export function parseJoernCpgJson(rawJson: string): AdapterExtractionResult {
  const symbols: ProgramSymbol[] = [];
  const facts: ProgramFact[] = [];
  const edges: ProgramEdge[] = [];

  let parsed: any;
  try {
    parsed = JSON.parse(rawJson || "{}");
  } catch {
    return { symbols, facts, edges };
  }

  for (const m of parsed.methods || []) {
    const file = String(m.file || "");
    const name = String(m.name || "");
    if (!name || name.startsWith("<")) continue;
    const line = Number(m.line || 1);
    const qname = String(m.qualifiedName || name);
    symbols.push({
      id: createHash("sha256").update(`joern|sym|${file}|${qname}|${line}`).digest("hex").slice(0, 20),
      language: detectLang(file),
      file,
      line,
      kind: "method",
      name,
      qualifiedName: qname,
      modifiers: [],
      params: [],
    });
  }

  for (const s of parsed.sinks || []) {
    const file = String(s.file || "");
    const line = Number(s.line || 1);
    const name = String(s.name || "");
    const method = String(s.method || "");
    facts.push({
      id: createHash("sha256").update(`joern|sink|${file}|${line}|${name}|${method}`).digest("hex").slice(0, 20),
      kind: "sink_command",
      language: detectLang(file),
      file,
      line,
      symbol: method || undefined,
      severity: "high",
      adapter: "joern",
      detail: `Joern CPG sink call ${name} (${String(s.code || "").slice(0, 100)})`,
      metadata: { callee: name, code: s.code },
    });
  }

  for (const f of parsed.flows || []) {
    const srcFile = String(f.sourceFile || "");
    const dstFile = String(f.sinkFile || srcFile);
    const srcLine = Number(f.sourceLine || 1);
    const dstLine = Number(f.sinkLine || 1);
    const srcCode = String(f.sourceCode || "");
    const dstCode = String(f.sinkCode || "");
    const steps = Number(f.steps || 2);
    const flowId = createHash("sha256")
      .update(`joern|flow|${srcFile}:${srcLine}|${dstFile}:${dstLine}|${dstCode}`)
      .digest("hex")
      .slice(0, 20);
    facts.push({
      id: flowId,
      kind: "taint_flow",
      language: detectLang(dstFile),
      file: dstFile,
      line: dstLine,
      severity: "critical",
      adapter: "joern",
      detail: `Joern CPG taint flow (${steps} hops): ${srcFile}:${srcLine} (${srcCode.slice(0, 60)}) -> ${dstFile}:${dstLine} (${dstCode.slice(0, 80)})`,
      metadata: { sourceFile: srcFile, sourceLine: srcLine, sourceCode: srcCode, sinkCode: dstCode, steps },
    });
    edges.push({
      from: `${srcFile}:${srcLine}:${srcCode.slice(0, 40)}`,
      to: `${dstFile}:${dstLine}:${dstCode.slice(0, 40)}`,
      kind: "dataflow",
      file: dstFile,
      line: dstLine,
    });
  }

  return { symbols, facts, edges };
}

export interface JoernRunResult extends AdapterExtractionResult {
  adapter: "joern";
  status: "completed" | "unavailable" | "error";
  error?: string;
}

export function runJoernCpgAnalysis(input: AdapterExtractionInput, timeoutMs = 120_000): JoernRunResult {
  const supported = input.sources.filter((s) => /\.(?:java|py|[cm]?js|ts)$/i.test(s.path));
  if (supported.length === 0 || !isJoernAvailable()) {
    return { adapter: "joern", status: "unavailable", symbols: [], facts: [], edges: [] };
  }
  const script = findJoernScript();
  if (!script) {
    return { adapter: "joern", status: "unavailable", symbols: [], facts: [], edges: [] };
  }

  const tmp = mkdtempSync(join(tmpdir(), "lotus-joern-"));
  try {
    const srcRoot = join(tmp, "src");
    for (const s of supported) {
      const rel = s.path.replace(/^\/+/, "").replace(/\.\./g, "_");
      const full = join(srcRoot, rel);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, s.content, "utf8");
    }

    const cpgPath = join(tmp, "cpg.bin");
    const outPath = join(tmp, "joern-facts.json");

    const parseProc = spawnSync(joernBin("joern-parse"), [srcRoot, "--output", cpgPath], {
      encoding: "utf8",
      timeout: Math.floor(timeoutMs / 2),
      maxBuffer: 16 * 1024 * 1024,
    });
    if (parseProc.status !== 0 || !existsSync(cpgPath)) {
      return {
        adapter: "joern",
        status: "error",
        symbols: [],
        facts: [],
        edges: [],
        error: (parseProc.stderr || parseProc.stdout || `joern-parse exited ${parseProc.status}`).slice(0, 600),
      };
    }

    const queryProc = spawnSync(
      joernBin("joern"),
      ["--script", script, "--param", `cpgFile=${cpgPath}`, "--param", `outFile=${outPath}`],
      {
        encoding: "utf8",
        timeout: Math.floor(timeoutMs / 2),
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    if (!existsSync(outPath)) {
      return {
        adapter: "joern",
        status: "error",
        symbols: [],
        facts: [],
        edges: [],
        error: (queryProc.stderr || queryProc.stdout || `joern query exited ${queryProc.status}`).slice(0, 600),
      };
    }

    const raw = readFileSync(outPath, "utf8");
    const extracted = parseJoernCpgJson(raw);
    return {
      adapter: "joern",
      status: "completed",
      ...extracted,
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
