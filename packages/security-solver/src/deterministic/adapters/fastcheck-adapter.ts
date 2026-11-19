/**
 * fast-check (MIT) JavaScript/TypeScript property-based security testing adapter.
 *
 * Exercises JS target functions inside a bounded VM sandbox using fast-check
 * shrinking arbitraries weighted with security payloads (XSS markup, command
 * metacharacters, path traversal, prototype pollution keys) and emits minimal
 * counterexamples as ProgramFacts.
 */
import { createHash } from "node:crypto";
import vm from "node:vm";
import fc from "fast-check";
import type { ProgramFact } from "../program-facts";

export type FastCheckSecurityProperty =
  | "no_raw_html_reflection"
  | "no_path_traversal"
  | "no_prototype_pollution"
  | "no_unhandled_exception";

export interface FastCheckProbeRequest {
  file: string;
  symbol: string;
  sourceCode: string;
  property: FastCheckSecurityProperty;
  numRuns?: number;
  seed?: number;
  timeoutMs?: number;
}

export interface FastCheckProbeResult {
  adapter: "fast-check";
  status: "counterexample_found" | "property_held" | "error";
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
  no_prototype_pollution: [
    "__proto__",
    "constructor",
    "prototype",
  ],
  no_unhandled_exception: [
    "",
    "\x00",
    "a".repeat(512),
    "{\"__proto__\":{\"polluted\":true}}",
  ],
};

function loadSandboxedFunction(sourceCode: string, symbol: string, timeoutMs: number): (...args: any[]) => any {
  const exportsObj: Record<string, any> = {};
  const moduleObj = { exports: exportsObj };
  const sandbox: Record<string, any> = {
    module: moduleObj,
    exports: exportsObj,
    console: { log: () => {}, warn: () => {}, error: () => {} },
    URL,
    URLSearchParams,
    encodeURIComponent,
    decodeURIComponent,
  };
  const ctx = vm.createContext(sandbox);
  // Strip ESM `export ` keywords so simple ESM modules run cleanly in CJS vm sandbox.
  const normalized = sourceCode
    .replace(/\bexport\s+default\s+/g, "module.exports.default = ")
    .replace(/\bexport\s+(?=(?:async\s+)?function\s+([A-Za-z0-9_$]+))/g, "")
    .replace(/\bexport\s+(?=const\s+|let\s+|var\s+)/g, "");
  const wrapped = `${normalized}\n;if (typeof ${symbol} === "function") { module.exports["${symbol}"] = ${symbol}; }`;
  const script = new vm.Script(wrapped);
  script.runInContext(ctx, { timeout: timeoutMs });
  const target =
    typeof moduleObj.exports === "function"
      ? moduleObj.exports
      : moduleObj.exports?.[symbol] ?? moduleObj.exports?.default;
  if (typeof target !== "function") {
    throw new Error(`Exported JS function "${symbol}" not found in sandbox`);
  }
  return target;
}

export function runFastCheckJsProbe(req: FastCheckProbeRequest): FastCheckProbeResult {
  const numRuns = Math.max(10, Math.min(req.numRuns ?? 60, 250));
  const seed = req.seed ?? 133742;
  const timeoutMs = req.timeoutMs ?? 1500;

  let fn: (...args: any[]) => any;
  try {
    fn = loadSandboxedFunction(req.sourceCode, req.symbol, timeoutMs);
  } catch (err) {
    return {
      adapter: "fast-check",
      status: "error",
      property: req.property,
      numRuns: 0,
      seed,
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  const securityArb = fc.oneof(
    { weight: 3, arbitrary: fc.constantFrom(...SECURITY_SEEDS[req.property]) },
    { weight: 2, arbitrary: fc.string({ minLength: 0, maxLength: 64 }) },
  );

  const checkResult = fc.check(
    fc.property(securityArb, (input: string) => {
      if (req.property === "no_raw_html_reflection") {
        const out = String(fn(input) ?? "");
        const hasDangerousInput = /<[a-z]/i.test(input) && (input.includes("<script") || input.includes("onerror=") || input.includes("onload=") || input.includes("<iframe"));
        if (hasDangerousInput && out.includes(input)) {
          return false;
        }
        return true;
      }
      if (req.property === "no_path_traversal") {
        const out = String(fn(input) ?? "");
        if ((input.includes("..") || input.startsWith("/etc/")) && (out.includes("..") || out.startsWith("/etc/"))) {
          return false;
        }
        return true;
      }
      if (req.property === "no_prototype_pollution") {
        const target: Record<string, any> = {};
        const payload = JSON.parse(`{"${input}":{"lotusPolluted":true}}`);
        fn(target, payload);
        const polluted = ({} as any).lotusPolluted === true || (Object.prototype as any).lotusPolluted === true;
        if (polluted) {
          delete (Object.prototype as any).lotusPolluted;
          return false;
        }
        return true;
      }
      // no_unhandled_exception
      fn(input);
      return true;
    }),
    { numRuns, seed },
  );

  if (checkResult.failed) {
    const shrunk = Array.isArray(checkResult.counterexample)
      ? String(checkResult.counterexample[0] ?? "")
      : "";
    const detail = `fast-check violated ${req.property} on ${req.symbol} with counterexample ${JSON.stringify(shrunk)} (seed=${seed}, runs=${checkResult.numRuns})`;
    const fact: ProgramFact = {
      id: createHash("sha256").update(`fc|${req.file}|${req.symbol}|${req.property}|${shrunk}`).digest("hex").slice(0, 20),
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
        counterexample: shrunk,
        seed,
        numRuns: checkResult.numRuns,
        numShrinks: checkResult.numShrinks,
      },
    };
    return {
      adapter: "fast-check",
      status: "counterexample_found",
      property: req.property,
      numRuns: checkResult.numRuns,
      seed,
      counterexample: shrunk,
      detail,
      fact,
    };
  }

  return {
    adapter: "fast-check",
    status: "property_held",
    property: req.property,
    numRuns: checkResult.numRuns,
    seed,
    detail: `fast-check property ${req.property} held for ${req.symbol} across ${checkResult.numRuns} runs (seed=${seed})`,
  };
}
