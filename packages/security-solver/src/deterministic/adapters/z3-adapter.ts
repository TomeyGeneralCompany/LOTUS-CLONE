/**
 * Z3 (MIT) SMT constraint solving adapter.
 *
 * Checks path, guard, and arithmetic invariant feasibility via z3-solver
 * (scripts/adapters/z3_feasibility.py) or the native `z3` CLI for SMT-LIB2,
 * producing `smt_unsat_guard` facts (proving dead/unreachable exploit paths)
 * and `smt_sat_witness` facts (concrete satisfying inputs for probes/fuzzers).
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { FactLanguage, ProgramFact } from "../program-facts";

export interface Z3FeasibilityQuery {
  constraints?: readonly string[];
  variables?: Record<string, "int" | "uint256" | "bool">;
  smtlib2?: string;
  timeoutMs?: number;
}

export interface Z3FeasibilityResult {
  adapter: "z3";
  status: "sat" | "unsat" | "unknown" | "unavailable" | "error";
  model: Record<string, number | boolean | string>;
  z3Version?: string;
  error?: string;
}

function findScriptPath(): string | null {
  const candidates = [
    join(process.cwd(), "scripts/adapters/z3_feasibility.py"),
    resolve(process.cwd(), "../../scripts/adapters/z3_feasibility.py"),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

export function isZ3Available(): boolean {
  try {
    execFileSync("python3", ["-c", "import z3"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    try {
      execFileSync("z3", ["--version"], { stdio: "ignore", timeout: 4000 });
      return true;
    } catch {
      return false;
    }
  }
}

export function solveConstraintsWithZ3(query: Z3FeasibilityQuery): Z3FeasibilityResult {
  const script = findScriptPath();
  if (script) {
    try {
      const stdout = execFileSync("python3", [script], {
        input: JSON.stringify(query),
        encoding: "utf8",
        timeout: (query.timeoutMs ?? 3000) + 5000,
        stdio: ["pipe", "pipe", "ignore"],
      });
      const parsed = JSON.parse(stdout || "{}");
      return {
        adapter: "z3",
        status: parsed.status || "unknown",
        model: parsed.model || {},
        z3Version: parsed.z3Version,
        error: parsed.error,
      };
    } catch {
      // Fall through to native z3 binary if smtlib2 was provided
    }
  }

  if (query.smtlib2) {
    try {
      const stdout = execFileSync("z3", ["-in"], {
        input: `${query.smtlib2}\n(check-sat)\n`,
        encoding: "utf8",
        timeout: (query.timeoutMs ?? 3000) + 2000,
        stdio: ["pipe", "pipe", "ignore"],
      }).trim();
      const firstLine = stdout.split(/\r?\n/)[0]?.trim();
      if (firstLine === "sat" || firstLine === "unsat" || firstLine === "unknown") {
        return { adapter: "z3", status: firstLine, model: {} };
      }
    } catch {
      // unavailable
    }
  }

  return { adapter: "z3", status: "unavailable", model: {} };
}

export function checkGuardFeasibilityFact(input: {
  file: string;
  line: number;
  language: FactLanguage;
  symbol?: string;
  constraints: readonly string[];
  variables?: Record<string, "int" | "uint256" | "bool">;
}): ProgramFact | null {
  const res = solveConstraintsWithZ3({
    constraints: input.constraints,
    variables: input.variables,
  });
  if (res.status === "unsat") {
    return {
      id: createHash("sha256")
        .update(`z3|unsat|${input.file}|${input.line}|${input.constraints.join("&")}`)
        .digest("hex")
        .slice(0, 20),
      kind: "smt_unsat_guard",
      language: input.language,
      file: input.file,
      line: input.line,
      symbol: input.symbol,
      severity: "info",
      adapter: "z3",
      detail: `Z3 proved guard constraints UNSAT (unreachable): ${input.constraints.join(" && ")}`,
      metadata: { constraints: input.constraints, z3Version: res.z3Version },
    };
  }
  if (res.status === "sat") {
    return {
      id: createHash("sha256")
        .update(`z3|sat|${input.file}|${input.line}|${input.constraints.join("&")}`)
        .digest("hex")
        .slice(0, 20),
      kind: "smt_sat_witness",
      language: input.language,
      file: input.file,
      line: input.line,
      symbol: input.symbol,
      severity: "medium",
      adapter: "z3",
      detail: `Z3 SAT witness for [${input.constraints.join(" && ")}]: ${JSON.stringify(res.model)}`,
      metadata: { constraints: input.constraints, model: res.model, z3Version: res.z3Version },
    };
  }
  return null;
}
