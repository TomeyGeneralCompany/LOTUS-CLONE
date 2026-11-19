/**
 * Foundry (forge, MIT/Apache-2.0) Solidity stateful fuzzing & invariant testing adapter.
 *
 * Synthesizes an isolated temporary Foundry workspace (zero network dependencies —
 * uses Foundry's built-in Vm cheatcode precompile at 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D),
 * executes `forge test --json --fuzz-runs <N>`, and normalizes results into LOTUS ProgramFacts.
 */
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { ProgramFact } from "../program-facts";

export interface FoundryProbeRequest {
  file: string;
  contractSource: string;
  contractFileName?: string;
  testContractSource: string;
  fuzzRuns?: number;
  solcVersion?: string;
  timeoutMs?: number;
}

export interface FoundryTestCaseResult {
  name: string;
  status: "Success" | "Failure" | "Skipped";
  reason?: string | null;
  counterexample?: unknown;
  gasUsed?: number;
}

export interface FoundryProbeResult {
  adapter: "foundry";
  status: "completed" | "unavailable" | "error";
  passedCount: number;
  failedCount: number;
  tests: FoundryTestCaseResult[];
  facts: ProgramFact[];
  error?: string;
}

const VM_CHEATCODE_INTERFACE = `// SPDX-License-Identifier: MIT
pragma solidity >=0.6.0 <0.9.0;

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function deal(address who, uint256 newBalance) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes calldata) external;
    function assume(bool) external;
}
`;

export function isFoundryAvailable(): boolean {
  try {
    execFileSync("forge", ["--version"], { stdio: "ignore", timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

export function parseForgeJsonOutput(rawJson: string, logicalFile: string): {
  tests: FoundryTestCaseResult[];
  facts: ProgramFact[];
} {
  const tests: FoundryTestCaseResult[] = [];
  const facts: ProgramFact[] = [];
  const trimmed = rawJson.trim();
  const jsonStart = trimmed.indexOf("{");
  if (jsonStart < 0) return { tests, facts };

  let parsed: Record<string, any>;
  try {
    parsed = JSON.parse(trimmed.slice(jsonStart));
  } catch {
    return { tests, facts };
  }

  for (const [suiteKey, suiteVal] of Object.entries(parsed)) {
    const testResults = (suiteVal as any)?.test_results;
    if (!testResults || typeof testResults !== "object") continue;
    for (const [testName, entry] of Object.entries<any>(testResults)) {
      const rawStatus = String(entry?.status || "Failure");
      const status: FoundryTestCaseResult["status"] =
        rawStatus === "Success" ? "Success" : rawStatus === "Skipped" ? "Skipped" : "Failure";
      const reason = entry?.reason ?? null;
      const counterexample = entry?.counterexample ?? undefined;
      const gasUsed =
        typeof entry?.kind?.Standard === "number"
          ? entry.kind.Standard
          : typeof entry?.kind?.Fuzz?.mean_gas === "number"
            ? entry.kind.Fuzz.mean_gas
            : undefined;
      tests.push({ name: testName, status, reason, counterexample, gasUsed });

      const isFailure = status === "Failure";
      facts.push({
        id: createHash("sha256")
          .update(`foundry|${logicalFile}|${suiteKey}|${testName}|${status}`)
          .digest("hex")
          .slice(0, 20),
        kind: isFailure ? "foundry_invariant_violated" : "foundry_property_held",
        language: "solidity",
        file: logicalFile,
        line: 1,
        symbol: testName,
        severity: isFailure ? "high" : "info",
        adapter: "foundry",
        detail: isFailure
          ? `Foundry test ${testName} FAILED (${reason || "invariant violated"})${counterexample ? ` counterexample=${JSON.stringify(counterexample)}` : ""}`
          : `Foundry test ${testName} PASSED`,
        metadata: { suite: suiteKey, status, reason, counterexample, gasUsed },
      });
    }
  }
  return { tests, facts };
}

export function runFoundrySolidityTest(req: FoundryProbeRequest): FoundryProbeResult {
  if (!isFoundryAvailable()) {
    return {
      adapter: "foundry",
      status: "unavailable",
      passedCount: 0,
      failedCount: 0,
      tests: [],
      facts: [],
    };
  }

  const tmp = mkdtempSync(join(tmpdir(), "lotus-foundry-"));
  try {
    const srcDir = join(tmp, "src");
    const testDir = join(tmp, "test");
    mkdirSync(srcDir, { recursive: true });
    mkdirSync(testDir, { recursive: true });

    const solName = basename(req.contractFileName || req.file || "Target.sol").replace(/[^A-Za-z0-9_.-]/g, "_");
    const fuzzRuns = Math.max(16, Math.min(req.fuzzRuns ?? 64, 512));
    const solcLine = req.solcVersion ? `solc_version = "${req.solcVersion}"\n` : "";

    writeFileSync(
      join(tmp, "foundry.toml"),
      `[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n${solcLine}offline = true\n\n[fuzz]\nruns = ${fuzzRuns}\n`,
      "utf8",
    );
    writeFileSync(join(srcDir, solName), req.contractSource, "utf8");
    writeFileSync(join(testDir, "Vm.sol"), VM_CHEATCODE_INTERFACE, "utf8");
    writeFileSync(join(testDir, "LotusProbe.t.sol"), req.testContractSource, "utf8");

    const proc = spawnSync("forge", ["test", "--json", "--offline", "--no-match-path", "none"], {
      cwd: tmp,
      encoding: "utf8",
      timeout: req.timeoutMs ?? 60_000,
      maxBuffer: 16 * 1024 * 1024,
    });

    const parsed = parseForgeJsonOutput(proc.stdout || "", req.file);
    if (parsed.tests.length === 0 && proc.status !== 0) {
      return {
        adapter: "foundry",
        status: "error",
        passedCount: 0,
        failedCount: 0,
        tests: [],
        facts: [],
        error: (proc.stderr || proc.stdout || `forge exited ${proc.status}`).slice(0, 600),
      };
    }

    const passedCount = parsed.tests.filter((t) => t.status === "Success").length;
    const failedCount = parsed.tests.filter((t) => t.status === "Failure").length;
    return {
      adapter: "foundry",
      status: "completed",
      passedCount,
      failedCount,
      tests: parsed.tests,
      facts: parsed.facts,
    };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
