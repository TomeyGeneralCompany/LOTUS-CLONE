/**
 * fast-check (MIT) JavaScript/TypeScript property-based security testing adapter.
 *
 * SECURITY ISOLATION BOUNDARY:
 * Never evaluates untrusted JavaScript in-process or via Node's `node:vm`
 * (which is explicitly not a security isolation boundary).
 *
 * `fast-check` generates security-weighted candidate inputs in the trusted
 * controller and delegates ALL untrusted source execution to LOTUS's existing
 * `bubblewrap` (`bwrap --unshare-all --cap-drop ALL --clearenv` + rlimits)
 * isolated reproduction runner (`scripts/source-reproduction.py`,
 * kind=`javascript_property_batch`), or an explicit caller-supplied isolated
 * evaluator callback. Fails closed (`blocked_no_sandbox`) if no isolated
 * execution boundary is available.
 */
import { createHash, randomBytes } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import fc from "fast-check";
import type { ProgramFact } from "../program-facts";

export type FastCheckSecurityProperty =
  | "no_raw_html_reflection"
  | "no_path_traversal"
  | "no_prototype_pollution"
  | "no_unhandled_exception";

export interface IsolatedJsBatchObservation {
  input: string;
  ok: boolean;
  output?: string;
  error?: string;
  protoPolluted?: boolean;
}

export interface IsolatedJsBatchResponse {
  status: "completed" | "blocked_no_sandbox" | "error";
  isolation: string;
  results: IsolatedJsBatchObservation[];
  error?: string;
}

export type IsolatedJsBatchEvaluator = (req: {
  file: string;
  symbol: string;
  sourceCode: string;
  repositoryDir?: string;
  property: FastCheckSecurityProperty;
  inputs: readonly string[];
  timeoutMs: number;
}) => IsolatedJsBatchResponse;

export interface FastCheckProbeRequest {
  file: string;
  symbol: string;
  sourceCode: string;
  /** Optional pre-existing authorized repository root containing `file`. */
  repositoryDir?: string;
  property: FastCheckSecurityProperty;
  numRuns?: number;
  seed?: number;
  timeoutMs?: number;
  /** Optional isolated evaluator hook (must execute inside a real isolation boundary). */
  isolatedEvaluator?: IsolatedJsBatchEvaluator;
}

export interface FastCheckProbeResult {
  adapter: "fast-check";
  status: "counterexample_found" | "property_held" | "blocked_no_sandbox" | "error";
  isolation: string;
  property: FastCheckSecurityProperty;
  numRuns: number;
  seed: number;
  counterexample?: string;
  detail: string;
  fact?: ProgramFact;
}

const SECURITY_SEEDS: Record<FastCheckSecurityProperty, readonly string[]> = {
  no_raw_html_reflection: [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "'><iframe src=javascript:alert(1)>",
  ],
  no_path_traversal: [
    "../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "/etc/shadow",
    "foo/../../secret.txt",
  ],
  no_prototype_pollution: ["__proto__", "constructor", "prototype"],
  no_unhandled_exception: [
    "",
    "\x00",
    "a".repeat(256),
    "{\"__proto__\":{\"polluted\":true}}",
  ],
};

function findSourceReproductionScript(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/source-reproduction.py"),
    resolve(process.cwd(), "../../scripts/source-reproduction.py"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

export function isIsolatedJsSandboxAvailable(): boolean {
  if (!findSourceReproductionScript()) return false;
  try {
    execFileSync("bwrap", ["--version"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

function evaluateViaBwrapReproduction(req: {
  file: string;
  symbol: string;
  sourceCode: string;
  repositoryDir?: string;
  property: FastCheckSecurityProperty;
  inputs: readonly string[];
  timeoutMs: number;
}): IsolatedJsBatchResponse {
  const script = findSourceReproductionScript();
  if (!script) {
    return {
      status: "blocked_no_sandbox",
      isolation: "none",
      results: [],
      error: "scripts/source-reproduction.py not found",
    };
  }
  try {
    execFileSync("bwrap", ["--version"], { stdio: "ignore", timeout: 4000 });
  } catch {
    return {
      status: "blocked_no_sandbox",
      isolation: "none",
      results: [],
      error: "bubblewrap (bwrap) isolated reproduction sandbox unavailable; untrusted JS execution refused",
    };
  }

  const tmp = mkdtempSync(join(tmpdir(), "lotus-fc-bwrap-"));
  try {
    let repoDir = req.repositoryDir;
    let relFile = req.file.replace(/^\/+/, "");
    if (!repoDir) {
      repoDir = join(tmp, "repo");
      if (!/\.(?:js|mjs|cjs)$/.test(relFile)) {
        relFile = relFile.replace(/\.[^.]+$/, "") + ".mjs";
      }
      const targetFull = join(repoDir, relFile);
      mkdirSync(dirname(targetFull), { recursive: true });
      // Write ES module directly for Node's native import inside bwrap (no eval / no vm).
      writeFileSync(targetFull, req.sourceCode, "utf8");
      if (relFile.endsWith(".js")) {
        writeFileSync(join(repoDir, "package.json"), JSON.stringify({ type: "module" }), "utf8");
      }
    }

    const specPath = join(tmp, "spec.json");
    const spec = {
      file: relFile,
      function: req.symbol,
      kind: "javascript_property_batch",
      property: req.property,
      nonce: randomBytes(16).toString("hex"),
      inputs: req.inputs.slice(0, 64),
    };
    writeFileSync(specPath, JSON.stringify(spec), "utf8");

    const proc = spawnSync("python3", [script, "--repository", repoDir, "--spec", specPath], {
      encoding: "utf8",
      timeout: Math.max(10_000, req.timeoutMs),
      maxBuffer: 8 * 1024 * 1024,
    });

    const raw = (proc.stdout || "").trim();
    const jsonStart = raw.indexOf("{");
    if (jsonStart < 0) {
      return {
        status: "error",
        isolation: "bwrap_source_reproduction",
        results: [],
        error: (proc.stderr || raw || `source-reproduction exited ${proc.status}`).slice(0, 500),
      };
    }

    const parsed = JSON.parse(raw.slice(jsonStart));
    if (parsed.status === "blocked_no_sandbox") {
      return {
        status: "blocked_no_sandbox",
        isolation: "none",
        results: [],
        error: parsed.detail || "bwrap sandbox unavailable",
      };
    }
    const obsResults = parsed?.observations?.results;
    if (!Array.isArray(obsResults)) {
      return {
        status: "error",
        isolation: "bwrap_source_reproduction",
        results: [],
        error: parsed.detail || `Unexpected isolated probe status: ${parsed.status}`,
      };
    }
    return {
      status: "completed",
      isolation: "bwrap_source_reproduction",
      results: obsResults as IsolatedJsBatchObservation[],
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function violatesProperty(
  property: FastCheckSecurityProperty,
  obs: IsolatedJsBatchObservation,
): boolean {
  if (property === "no_raw_html_reflection") {
    if (!obs.ok) return false;
    const input = obs.input;
    const out = obs.output ?? "";
    const hasDangerousMarkup =
      /<[a-z]/i.test(input) &&
      (input.includes("<script") ||
        input.includes("onerror=") ||
        input.includes("onload=") ||
        input.includes("<iframe"));
    return hasDangerousMarkup && out.includes(input);
  }
  if (property === "no_path_traversal") {
    if (!obs.ok) return false;
    const input = obs.input;
    const out = obs.output ?? "";
    return (
      (input.includes("..") || input.startsWith("/etc/")) &&
      (out.includes("..") || out.startsWith("/etc/"))
    );
  }
  if (property === "no_prototype_pollution") {
    return obs.protoPolluted === true;
  }
  // no_unhandled_exception
  return !obs.ok;
}

function shrinkCandidates(failingInput: string): string[] {
  const candidates: string[] = [];
  if (failingInput.length <= 2) return candidates;
  const mid = Math.floor(failingInput.length / 2);
  candidates.push(failingInput.slice(0, mid));
  candidates.push(failingInput.slice(mid));
  if (failingInput.trim() !== failingInput && failingInput.trim().length > 0) {
    candidates.push(failingInput.trim());
  }
  return [...new Set(candidates.filter((c) => c.length > 0 && c.length < failingInput.length))];
}

export function runFastCheckJsProbe(req: FastCheckProbeRequest): FastCheckProbeResult {
  const numRuns = Math.max(8, Math.min(req.numRuns ?? 40, 64));
  const seed = req.seed ?? 133742;
  const timeoutMs = req.timeoutMs ?? 20_000;
  const evaluator = req.isolatedEvaluator ?? evaluateViaBwrapReproduction;

  const securityArb = fc.oneof(
    { weight: 3, arbitrary: fc.constantFrom(...SECURITY_SEEDS[req.property]) },
    { weight: 2, arbitrary: fc.string({ minLength: 0, maxLength: 64 }) },
  );

  // Generate deterministic corpus via fast-check in the trusted parent controller,
  // ensuring all security seeds are always covered plus fast-check random samples.
  const sampled = fc.sample(securityArb, { numRuns, seed });
  const uniqueInputs = [...new Set([...SECURITY_SEEDS[req.property], ...sampled])].slice(0, 64);

  const batchRes = evaluator({
    file: req.file,
    symbol: req.symbol,
    sourceCode: req.sourceCode,
    repositoryDir: req.repositoryDir,
    property: req.property,
    inputs: uniqueInputs,
    timeoutMs,
  });

  if (batchRes.status === "blocked_no_sandbox") {
    return {
      adapter: "fast-check",
      status: "blocked_no_sandbox",
      isolation: batchRes.isolation,
      property: req.property,
      numRuns: 0,
      seed,
      detail: batchRes.error || "Isolated reproduction sandbox unavailable",
    };
  }

  if (batchRes.status !== "completed") {
    return {
      adapter: "fast-check",
      status: "error",
      isolation: batchRes.isolation,
      property: req.property,
      numRuns: 0,
      seed,
      detail: batchRes.error || "Isolated JavaScript property batch failed",
    };
  }

  const firstFailure = batchRes.results.find((obs) => violatesProperty(req.property, obs));
  if (!firstFailure) {
    return {
      adapter: "fast-check",
      status: "property_held",
      isolation: batchRes.isolation,
      property: req.property,
      numRuns: batchRes.results.length,
      seed,
      detail: `fast-check property ${req.property} held for ${req.symbol} across ${batchRes.results.length} isolated runs (${batchRes.isolation}, seed=${seed})`,
    };
  }

  // Deterministic bounded shrinking inside the same isolated boundary
  let minimal = firstFailure.input;
  let shrinks = 0;
  for (let round = 0; round < 3; round++) {
    const smaller = shrinkCandidates(minimal);
    if (!smaller.length) break;
    const shrinkRes = evaluator({
      file: req.file,
      symbol: req.symbol,
      sourceCode: req.sourceCode,
      repositoryDir: req.repositoryDir,
      property: req.property,
      inputs: smaller,
      timeoutMs,
    });
    if (shrinkRes.status !== "completed") break;
    const hit = shrinkRes.results.find((obs) => violatesProperty(req.property, obs));
    if (!hit) break;
    minimal = hit.input;
    shrinks++;
  }

  const detail = `fast-check (${batchRes.isolation}) violated ${req.property} on ${req.symbol} with counterexample ${JSON.stringify(minimal)} (seed=${seed}, runs=${batchRes.results.length})`;
  const fact: ProgramFact = {
    id: createHash("sha256")
      .update(`fc|${req.file}|${req.symbol}|${req.property}|${minimal}`)
      .digest("hex")
      .slice(0, 20),
    kind: "property_counterexample",
    language: "javascript",
    file: req.file,
    line: 1,
    symbol: req.symbol,
    severity: "high",
    adapter: "fast-check",
    detail,
    metadata: {
      property: req.property,
      counterexample: minimal,
      isolation: batchRes.isolation,
      seed,
      numRuns: batchRes.results.length,
      numShrinks: shrinks,
    },
  };

  return {
    adapter: "fast-check",
    status: "counterexample_found",
    isolation: batchRes.isolation,
    property: req.property,
    numRuns: batchRes.results.length,
    seed,
    counterexample: minimal,
    detail,
    fact,
  };
}
