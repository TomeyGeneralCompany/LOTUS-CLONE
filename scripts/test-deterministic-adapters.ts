/**
 * End-to-end verification of all 9 MIT/Apache-2.0 deterministic adapters +
 * legacy claude-runner deterministic paths (zero Qwen/Ollama/Claude calls).
 */
import assert from "node:assert/strict";
import {
  babelAstFactsAdapter,
  buildProgramFactsGraph,
  checkGuardFeasibilityFact,
  createHostFactsAdapters,
  detectAvailableAdapters,
  EXTERNAL_ADAPTER_CATALOG,
  generateHypotheses,
  isFoundryAvailable,
  isJavaParserAvailable,
  isJoernAvailable,
  isLibCstAvailable,
  isMythrilAvailable,
  isTreeSitterAvailable,
  isZ3Available,
  javaParserFactsAdapter,
  libCstFactsAdapter,
  parseForgeJsonOutput,
  parseJoernCpgJson,
  parseMythrilJsonOutput,
  runFastCheckJsProbe,
  runFoundrySolidityTest,
  runJoernCpgAnalysis,
  runMythrilSymbolicAnalysis,
  solveConstraintsWithZ3,
  treeSitterFactsAdapter,
} from "../packages/security-solver/src/deterministic";
import {
  deverbosifyReport,
  spawnComprehensiveReview,
} from "../packages/security-solver/src/claude-runner";

const requireCore = process.env.REQUIRE_ALL_CORE_ADAPTERS === "1";
const requireSymbolicCpg = process.env.REQUIRE_SYMBOLIC_CPG_ADAPTERS === "1";

process.env.LOCAL_MODEL_ADAPTER = "deterministic";
process.env.AUTOHACK_OLLAMA_URL = "http://127.0.0.1:1/api/chat";

async function main() {
  const executedLive: string[] = [];

  // 0. Catalog check: all 12 adapters (3 existing + 9 replacement) are integrated
  assert.equal(EXTERNAL_ADAPTER_CATALOG.length, 12);
  assert.ok(
    EXTERNAL_ADAPTER_CATALOG.every((a) => a.status === "integrated"),
    "All 12 cataloged adapters must have status=integrated",
  );
  const avail = detectAvailableAdapters();
  console.log(
    "Host adapter availability:",
    avail.map((a) => `${a.id}=${a.availableOnHost ? "YES" : "no"}`).join(", "),
  );

  // 1. @babel/parser (MIT) — ALWAYS LIVE
  const jsSource = `
import { execSync } from "node:child_process";
export function renderUnsafeProfile(name: string): string {
  return \`<div class="bio">\${name}</div>\`;
}
export function runAdminDiagnostic(req: any, res: any) {
  if (!req.user?.isAdmin) return res.status(403).end();
  return execSync("uptime");
}
export function runOpenExec(cmd: string) {
  return execSync(cmd);
}
`;
  const babelRes = babelAstFactsAdapter.extract({
    sources: [{ path: "src/profile.ts", sha256: "a".repeat(64), content: jsSource }],
  });
  assert.ok(babelRes.symbols.some((s) => s.qualifiedName === "renderUnsafeProfile"));
  assert.ok(babelRes.symbols.some((s) => s.qualifiedName === "runOpenExec"));
  assert.ok(babelRes.facts.some((f) => f.kind === "sink_html" && f.symbol === "renderUnsafeProfile"));
  assert.ok(babelRes.facts.some((f) => f.kind === "sink_command" && f.symbol === "runOpenExec"));
  assert.ok(babelRes.facts.some((f) => f.kind === "auth_guard" && f.symbol === "runAdminDiagnostic"));
  assert.ok(babelRes.edges.some((e) => e.kind === "calls" && e.to === "execSync"));
  executedLive.push("babel-parser");

  // 2. fast-check (MIT) — ALWAYS LIVE
  const fcUnsafe = runFastCheckJsProbe({
    file: "src/profile.js",
    symbol: "renderBio",
    sourceCode: `export function renderBio(bio) { return "<p>" + bio + "</p>"; }`,
    property: "no_raw_html_reflection",
    numRuns: 50,
  });
  assert.equal(fcUnsafe.status, "counterexample_found", "fast-check must find XSS counterexample");
  assert.ok(fcUnsafe.fact && fcUnsafe.fact.kind === "property_counterexample");

  const fcSafe = runFastCheckJsProbe({
    file: "src/safe-profile.js",
    symbol: "renderBio",
    sourceCode: `export function renderBio(bio) { return "<p>" + String(bio).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") + "</p>"; }`,
    property: "no_raw_html_reflection",
    numRuns: 50,
  });
  assert.equal(fcSafe.status, "property_held", "fast-check must pass escaped renderer");

  const fcProto = runFastCheckJsProbe({
    file: "src/merge.js",
    symbol: "unsafeMerge",
    sourceCode: `
      export function unsafeMerge(dst, src) {
        for (const k in src) {
          if (src[k] && typeof src[k] === "object") {
            if (!dst[k]) dst[k] = {};
            unsafeMerge(dst[k], src[k]);
          } else {
            dst[k] = src[k];
          }
        }
        return dst;
      }
    `,
    property: "no_prototype_pollution",
    numRuns: 40,
  });
  assert.equal(fcProto.status, "counterexample_found", "fast-check must detect prototype pollution");
  executedLive.push("fast-check");

  // 3. LibCST (MIT) — LIVE when Python libcst is installed
  const pySource = `
import subprocess
import yaml

@app.route("/run")
def run_cmd(user_input):
    return subprocess.run(user_input, shell=True)

@login_required
def load_safe_config(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)
`;
  if (isLibCstAvailable()) {
    const cstRes = libCstFactsAdapter.extract({
      sources: [{ path: "app/views.py", sha256: "b".repeat(64), content: pySource }],
    });
    assert.ok(cstRes.symbols.some((s) => s.qualifiedName === "run_cmd"));
    assert.ok(cstRes.facts.some((f) => f.adapter === "libcst" && f.kind === "sink_command" && f.symbol === "run_cmd"));
    assert.ok(cstRes.facts.some((f) => f.adapter === "libcst" && f.kind === "auth_guard" && f.symbol === "load_safe_config"));
    assert.ok(
      !cstRes.facts.some((f) => f.adapter === "libcst" && f.kind === "sink_deserialization" && f.symbol === "load_safe_config"),
      "LibCST must not flag yaml.load with SafeLoader",
    );
    executedLive.push("libcst");
  } else if (requireCore) {
    throw new Error("REQUIRE_ALL_CORE_ADAPTERS=1 but LibCST is unavailable");
  }

  // 4. Tree-sitter (MIT) — LIVE when tree_sitter is installed
  const javaSource = `
public class AdminController {
    @GetMapping("/exec")
    public Process runTool(String cmd) throws Exception {
        return Runtime.getRuntime().exec(cmd);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public String safeStatus() {
        return "ok";
    }
}
`;
  if (isTreeSitterAvailable()) {
    const tsRes = treeSitterFactsAdapter.extract({
      sources: [
        { path: "app/views.py", sha256: "b".repeat(64), content: pySource },
        { path: "src/AdminController.java", sha256: "c".repeat(64), content: javaSource },
        { path: "src/profile.ts", sha256: "a".repeat(64), content: jsSource },
      ],
    });
    assert.ok(tsRes.symbols.length >= 4, "Tree-sitter must extract symbols across languages");
    assert.ok(tsRes.facts.some((f) => f.adapter === "tree-sitter" && f.kind === "sink_command"));
    executedLive.push("tree-sitter");
  } else if (requireCore) {
    throw new Error("REQUIRE_ALL_CORE_ADAPTERS=1 but Tree-sitter is unavailable");
  }

  // 5. Z3 (MIT) — LIVE when z3-solver / z3 is installed
  if (isZ3Available()) {
    const unsatRes = solveConstraintsWithZ3({
      variables: { amount: "uint256" },
      constraints: ["amount > 100", "amount < 50"],
    });
    assert.equal(unsatRes.status, "unsat", "Z3 must prove amount > 100 && amount < 50 UNSAT");

    const satRes = solveConstraintsWithZ3({
      variables: { amount: "uint256", balance: "uint256" },
      constraints: ["balance == 1000", "amount > balance", "amount < 1005"],
    });
    assert.equal(satRes.status, "sat", "Z3 must find SAT witness");
    assert.ok(Number(satRes.model.amount) > 1000 && Number(satRes.model.amount) < 1005);

    const unsatFact = checkGuardFeasibilityFact({
      file: "contracts/Vault.sol",
      line: 12,
      language: "solidity",
      symbol: "Vault.deadBranch",
      constraints: ["x > 10", "x < 5"],
    });
    assert.equal(unsatFact?.kind, "smt_unsat_guard");

    const satFact = checkGuardFeasibilityFact({
      file: "contracts/Vault.sol",
      line: 18,
      language: "solidity",
      symbol: "Vault.withdraw",
      constraints: ["amount > balance", "balance == 100"],
    });
    assert.equal(satFact?.kind, "smt_sat_witness");
    executedLive.push("z3");
  } else if (requireCore) {
    throw new Error("REQUIRE_ALL_CORE_ADAPTERS=1 but Z3 is unavailable");
  }

  // 6. JavaParser (Apache-2.0) — LIVE when Java + javaparser-core.jar installed
  if (isJavaParserAvailable()) {
    const jpRes = javaParserFactsAdapter.extract({
      sources: [{ path: "src/AdminController.java", sha256: "c".repeat(64), content: javaSource }],
    });
    assert.ok(jpRes.symbols.some((s) => s.qualifiedName === "AdminController.runTool"));
    assert.ok(jpRes.facts.some((f) => f.adapter === "javaparser" && f.kind === "sink_command" && f.symbol === "AdminController.runTool"));
    assert.ok(jpRes.facts.some((f) => f.adapter === "javaparser" && f.kind === "auth_guard" && f.symbol === "AdminController.safeStatus"));
    executedLive.push("javaparser");
  } else if (requireCore) {
    throw new Error("REQUIRE_ALL_CORE_ADAPTERS=1 but JavaParser is unavailable");
  }

  // 7. Foundry (MIT/Apache-2.0) — parser always tested + LIVE when `forge` is installed
  const parsedForgeSample = parseForgeJsonOutput(
    JSON.stringify({
      "test/LotusProbe.t.sol:LotusProbeTest": {
        test_results: {
          "testFuzz_UnauthorizedTakeover(address)": {
            status: "Failure",
            reason: "Owner changed by non-owner",
            counterexample: { calldata: "0xdeadbeef" },
          },
        },
      },
    }),
    "contracts/Vault.sol",
  );
  assert.equal(parsedForgeSample.facts.length, 1);
  assert.equal(parsedForgeSample.facts[0].kind, "foundry_invariant_violated");

  if (isFoundryAvailable()) {
    const vulnSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OpenVault {
    address public owner;
    constructor() { owner = msg.sender; }
    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}
`;
    const forgeTest = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/OpenVault.sol";
import "./Vm.sol";

contract LotusProbeTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testFuzz_OwnerCannotBeTakenOver(address attacker) public {
        vm.assume(attacker != address(this) && attacker != address(0));
        OpenVault v = new OpenVault();
        vm.prank(attacker);
        v.setOwner(attacker);
        require(v.owner() == address(this), "INVARIANT_BROKEN: unauthorized owner takeover");
    }
}
`;
    const fRes = runFoundrySolidityTest({
      file: "contracts/OpenVault.sol",
      contractFileName: "OpenVault.sol",
      contractSource: vulnSol,
      testContractSource: forgeTest,
      fuzzRuns: 32,
    });
    assert.equal(fRes.status, "completed", `Foundry run failed: ${fRes.error}`);
    assert.equal(fRes.failedCount, 1, "Foundry fuzz test must catch unauthorized owner takeover");
    assert.ok(fRes.facts.some((f) => f.kind === "foundry_invariant_violated"));
    executedLive.push("foundry");
  } else if (requireCore) {
    throw new Error("REQUIRE_ALL_CORE_ADAPTERS=1 but Foundry (forge) is unavailable");
  }

  // 8. Mythril (MIT) — SWC ingestion always tested + LIVE when `myth` is installed
  const mythParsed = parseMythrilJsonOutput(
    JSON.stringify({
      success: true,
      issues: [
        {
          "swc-id": "106",
          title: "Unprotected SELFDESTRUCT Instruction",
          severity: "High",
          contract: "KillableVault",
          function: "destroy()",
          lineno: 8,
        },
      ],
    }),
    "contracts/KillableVault.sol",
  );
  assert.equal(mythParsed.length, 1);
  assert.equal(mythParsed[0].kind, "symbolic_finding");
  assert.equal(mythParsed[0].metadata?.swcId, "SWC-106");

  if (isMythrilAvailable()) {
    const mythSol = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;
contract KillableVault {
    function destroy(address payable to) public {
        selfdestruct(to);
    }
}
`;
    const mythRes = runMythrilSymbolicAnalysis({
      file: "contracts/KillableVault.sol",
      contractSource: mythSol,
      solv: "0.8.19",
      executionTimeoutSec: 30,
      maxDepth: 12,
    });
    assert.equal(mythRes.status, "completed", `Mythril failed: ${mythRes.error}`);
    console.log("Mythril live facts:", mythRes.facts.map((f) => f.detail).join(" | "));
    assert.ok(mythRes.issuesCount >= 1, "Mythril must detect unprotected selfdestruct");
    assert.ok(mythRes.facts.some((f) => f.kind === "symbolic_finding"));
    executedLive.push("mythril");
  } else if (requireSymbolicCpg) {
    throw new Error("REQUIRE_SYMBOLIC_CPG_ADAPTERS=1 but Mythril is unavailable");
  }

  // 9. Joern (Apache-2.0) — CPG JSON ingestion always tested + LIVE when `joern` is installed
  const joernParsed = parseJoernCpgJson(
    JSON.stringify({
      adapter: "joern",
      methods: [{ name: "runTool", qualifiedName: "AdminController.runTool", file: "src/AdminController.java", line: 3 }],
      sinks: [{ name: "exec", code: "Runtime.getRuntime().exec(cmd)", file: "src/AdminController.java", line: 4, method: "runTool" }],
      flows: [
        {
          sourceFile: "src/AdminController.java",
          sourceLine: 3,
          sourceCode: "String cmd",
          sinkFile: "src/AdminController.java",
          sinkLine: 4,
          sinkCode: "Runtime.getRuntime().exec(cmd)",
          steps: 3,
        },
      ],
    }),
  );
  assert.ok(joernParsed.facts.some((f) => f.kind === "taint_flow"));
  assert.ok(joernParsed.edges.some((e) => e.kind === "dataflow"));

  if (isJoernAvailable()) {
    const joernRes = runJoernCpgAnalysis({
      sources: [{ path: "src/AdminController.java", sha256: "c".repeat(64), content: javaSource }],
    });
    assert.equal(joernRes.status, "completed", `Joern failed: ${joernRes.error}`);
    console.log("Joern live results:", { symbols: joernRes.symbols.length, facts: joernRes.facts.map((f) => f.detail), edges: joernRes.edges.length });
    assert.ok(joernRes.symbols.length >= 1, "Joern must extract CPG methods");
    assert.ok(
      joernRes.facts.some((f) => f.kind === "taint_flow" || f.kind === "sink_command"),
      "Joern must extract CPG sinks or taint flows",
    );
    executedLive.push("joern");
  } else if (requireSymbolicCpg) {
    throw new Error("REQUIRE_SYMBOLIC_CPG_ADAPTERS=1 but Joern is unavailable");
  }

  // 10. Unified ProgramFactsGraph + Hypothesis Engine integration with host adapters
  const graph = buildProgramFactsGraph(
    {
      sources: [
        { path: "src/profile.ts", sha256: "a".repeat(64), content: jsSource },
        { path: "app/views.py", sha256: "b".repeat(64), content: pySource },
        { path: "src/AdminController.java", sha256: "c".repeat(64), content: javaSource },
      ],
    },
    createHostFactsAdapters(true),
  );
  // Inject fast-check counterexample + Mythril/Joern facts to prove Hypothesis Engine synthesis
  graph.facts.push(fcUnsafe.fact!, mythParsed[0], ...joernParsed.facts.filter((f) => f.kind === "taint_flow"));
  const hyps = generateHypotheses(graph);
  assert.ok(hyps.some((h) => h.recommendedAdapters.includes("fast-check")));
  assert.ok(hyps.some((h) => h.recommendedAdapters.includes("mythril")));
  assert.ok(hyps.some((h) => h.recommendedAdapters.includes("joern")));

  // 11. Legacy claude-runner deterministic paths (zero Claude/Ollama calls!)
  const reviewOut = await spawnComprehensiveReview(
    {
      id: "find-1",
      title: "Unescaped HTML reflection in renderBio",
      severity: "high",
      vulnerabilityType: "XSS",
      targetAsset: "src/profile.js",
      description: JSON.stringify({
        independentlyReplayed: true,
        verifiedLocalEntryInjection: true,
        replayedProbeKind: "html_reflection",
        sourceBackedEscaping: [],
      }),
      analysisNotes: "{}",
      reportBody: "Call renderBio('<script>alert(1)</script>')",
    } as any,
    { id: "prog-1", name: "Demo App" } as any,
    { workspacePath: "/tmp", clonedRepos: [], previousFindings: [] } as any,
  );
  const parsedRev = JSON.parse(reviewOut.output);
  assert.equal(parsedRev.mode, "deterministic");
  assert.equal(parsedRev.recommendation, "dont_submit");

  const cleaned = await deverbosifyReport(
    "## Summary\nIt's important to note that this — in order to trigger XSS — does not escape HTML.\n```js\nconst a = 'does not change inside code';\n```\n## Steps to Reproduce\n1. Run probe.",
  );
  assert.ok(!cleaned.includes("—"));
  assert.ok(cleaned.includes("doesn't escape HTML"));
  assert.ok(cleaned.includes("const a = 'does not change inside code';"), "Code block must stay verbatim");

  console.log(
    `Deterministic adapters suite PASSED (live executed: ${executedLive.join(", ")})`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
