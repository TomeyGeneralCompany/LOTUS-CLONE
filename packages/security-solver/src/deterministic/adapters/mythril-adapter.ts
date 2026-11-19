/**
 * Mythril (MIT) EVM bytecode symbolic analysis adapter.
 *
 * Invokes `myth analyze <file> -o json` with bounded execution timeout and
 * symbolic depth when Mythril is installed on the host, and normalizes SWC
 * issues + transaction sequences into LOTUS ProgramFacts (`symbolic_finding`).
 */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { FactSeverity, ProgramFact } from "../program-facts";

export interface MythrilAnalysisRequest {
  file: string;
  contractSource: string;
  solv?: string;
  executionTimeoutSec?: number;
  maxDepth?: number;
  timeoutMs?: number;
}

export interface MythrilAnalysisResult {
  adapter: "mythril";
  status: "completed" | "unavailable" | "error";
  issuesCount: number;
  facts: ProgramFact[];
  error?: string;
}

function mythBinary(): string {
  return process.env.MYTHRIL_BIN?.trim() || "myth";
}

export function isMythrilAvailable(): boolean {
  try {
    execFileSync(mythBinary(), ["version"], { stdio: "ignore", timeout: 8000 });
    return true;
  } catch {
    return false;
  }
}

function mapMythrilSeverity(raw: unknown): FactSeverity {
  const s = String(raw || "medium").toLowerCase();
  if (s === "high" || s === "critical") return "high";
  if (s === "low") return "low";
  return "medium";
}

export function parseMythrilJsonOutput(rawJson: string, logicalFile: string): ProgramFact[] {
  const facts: ProgramFact[] = [];
  const trimmed = rawJson.trim();
  const idx = trimmed.indexOf("{");
  if (idx < 0) return facts;

  let parsed: any;
  try {
    parsed = JSON.parse(trimmed.slice(idx));
  } catch {
    return facts;
  }

  const issues = Array.isArray(parsed?.issues) ? parsed.issues : [];
  for (const issue of issues) {
    const swcId = String(issue["swc-id"] || issue.swcID || "SWC-000");
    const title = String(issue.title || "Mythril symbolic issue");
    const line = Number(issue.lineno || 1);
    const fnName = typeof issue.function === "string" ? issue.function : undefined;
    const contract = typeof issue.contract === "string" ? issue.contract : undefined;
    const symbol = contract && fnName ? `${contract}.${fnName}` : fnName || contract;
    facts.push({
      id: createHash("sha256")
        .update(`mythril|${logicalFile}|${swcId}|${line}|${symbol || ""}|${title}`)
        .digest("hex")
        .slice(0, 20),
      kind: "symbolic_finding",
      language: "solidity",
      file: logicalFile,
      line,
      symbol,
      severity: mapMythrilSeverity(issue.severity),
      adapter: "mythril",
      detail: `Mythril [SWC-${swcId.replace(/^SWC-/i, "")}] ${title}${symbol ? ` in ${symbol}` : ""}`,
      metadata: {
        swcId: `SWC-${swcId.replace(/^SWC-/i, "")}`,
        title,
        contract,
        function: fnName,
        address: issue.address,
        txSequence: issue.tx_sequence,
      },
    });
  }
  return facts;
}

export function runMythrilSymbolicAnalysis(req: MythrilAnalysisRequest): MythrilAnalysisResult {
  if (!isMythrilAvailable()) {
    return { adapter: "mythril", status: "unavailable", issuesCount: 0, facts: [] };
  }

  const tmp = mkdtempSync(join(tmpdir(), "lotus-mythril-"));
  try {
    const solPath = join(tmp, basename(req.file).replace(/[^A-Za-z0-9_.-]/g, "_"));
    writeFileSync(solPath, req.contractSource, "utf8");

    const args = [
      "analyze",
      solPath,
      "-o",
      "json",
      "--execution-timeout",
      String(Math.max(5, Math.min(req.executionTimeoutSec ?? 25, 120))),
      "--max-depth",
      String(Math.max(4, Math.min(req.maxDepth ?? 16, 64))),
    ];
    if (req.solv) {
      args.push("--solv", req.solv);
    }

    const proc = spawnSync(mythBinary(), args, {
      encoding: "utf8",
      timeout: req.timeoutMs ?? 90_000,
      maxBuffer: 16 * 1024 * 1024,
    });

    const facts = parseMythrilJsonOutput(proc.stdout || "", req.file);
    if (facts.length === 0 && proc.status !== 0 && !(proc.stdout || "").includes('"issues"')) {
      return {
        adapter: "mythril",
        status: "error",
        issuesCount: 0,
        facts: [],
        error: (proc.stderr || proc.stdout || `myth exited ${proc.status}`).slice(0, 600),
      };
    }

    return {
      adapter: "mythril",
      status: "completed",
      issuesCount: facts.length,
      facts,
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
