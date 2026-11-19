/**
 * End-to-end verification of the Qwen-free deterministic LOTUS engine.
 * Sets AUTOHACK_OLLAMA_URL to an unreachable port (127.0.0.1:1) and
 * LOCAL_MODEL_ADAPTER=deterministic to guarantee ZERO Ollama/LLM calls.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildProgramFactsGraph,
  detectAvailableAdapters,
  evaluateAnalysisLead,
  evaluateDeterministicEvidenceReview,
  EXTERNAL_ADAPTER_CATALOG,
  generateHypotheses,
  isDeterministicMode,
  resolveLocalModelAdapter,
} from "../packages/security-solver/src/deterministic";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";
import { runEvidenceOnlyReview } from "../packages/security-solver/src/evidence-only-review";
import { assessFinding, assessProgram } from "../packages/security-analyzer/src/assessor";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

const prevAdapter = process.env.LOCAL_MODEL_ADAPTER;
const prevOllama = process.env.AUTOHACK_OLLAMA_URL;
const prevDet = process.env.LOTUS_DETERMINISTIC;

process.env.LOCAL_MODEL_ADAPTER = "deterministic";
process.env.AUTOHACK_OLLAMA_URL = "http://127.0.0.1:1/api/chat"; // guaranteed unreachable

try {
  // 1. Adapter resolution rules
  assert.equal(resolveLocalModelAdapter({}), "deterministic", "Default with no env must be deterministic");
  assert.equal(resolveLocalModelAdapter({ AUTOHACK_OLLAMA_URL: "http://127.0.0.1:11434/api/chat" }), "ollama", "Explicit AUTOHACK_OLLAMA_URL without adapter keeps Ollama compatibility");
  assert.equal(resolveLocalModelAdapter({ LOCAL_MODEL_ADAPTER: "deterministic", AUTOHACK_OLLAMA_URL: "http://127.0.0.1:11434/api/chat" }), "deterministic");
  assert.equal(isDeterministicMode(), true);

  // 2. Program-Facts IR across all 4 languages + static leads
  const solSource = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract TreasuryVault {
  address public owner;
  uint256 public fee;
  bool private initialized;
  modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
  function initialize(address _owner) external {
    owner = _owner;
  }
  function dangerousMint(address to, uint256 amount) external {
    _mint(to, amount);
  }
  function setFee(uint256 nextFee) external onlyOwner {
    fee = nextFee;
  }
  function _mint(address, uint256) internal {}
}
`;
  const jsSource = `
export function renderProfile(name) {
  return "<div class='user'>" + name + "</div>";
}
export function loadAsset(userPath) {
  return path.join("/srv/assets", userPath);
}
`;
  const pySource = `
def render_banner(msg):
    return f"<section>{msg}</section>"

def run_job(cmd):
    return subprocess.run(cmd, shell=True)
`;
  const javaSource = `
public class FileController {
  public String download(String name) throws Exception {
    return Files.readString(Paths.get("/var/data", name));
  }
}
`;

  const graph = buildProgramFactsGraph({
    sources: [
      { path: "source-1/contracts/TreasuryVault.sol", content: solSource, sha256: sha(solSource) },
      { path: "source-1/src/profile.js", content: jsSource, sha256: sha(jsSource) },
      { path: "source-1/app/views.py", content: pySource, sha256: sha(pySource) },
      { path: "source-1/src/FileController.java", content: javaSource, sha256: sha(javaSource) },
    ],
    staticLeads: [
      {
        path: "source-1/contracts/TreasuryVault.sol",
        line: 8,
        rule: "solidity-unguarded-initializer",
        message: "initialize lacks initializer modifier",
        severity: "WARNING",
        engine: "semgrep",
      },
    ],
  });

  assert.deepEqual(
    [...graph.languages].sort(),
    ["java", "javascript", "python", "solidity"],
    "All 4 languages must be indexed into common ProgramFactsGraph",
  );
  assert.ok(graph.facts.some((f) => f.kind === "mint_or_burn" && f.symbol === "TreasuryVault.dangerousMint"));
  assert.ok(graph.facts.some((f) => f.kind === "initializer" && f.symbol === "TreasuryVault.initialize"));
  assert.ok(graph.facts.some((f) => f.kind === "auth_guard" && f.symbol === "TreasuryVault.setFee"));
  assert.ok(graph.facts.some((f) => f.kind === "sink_html" && f.symbol === "renderProfile"));
  assert.ok(graph.facts.some((f) => f.kind === "sink_path" && f.symbol === "loadAsset"));
  assert.ok(graph.facts.some((f) => f.kind === "sink_command" && f.symbol === "run_job"));
  assert.ok(graph.facts.some((f) => f.kind === "sink_path" && f.symbol === "download"));
  assert.ok(graph.facts.some((f) => f.kind === "static_finding" && f.symbol === "TreasuryVault.initialize"));

  // 3. Hypothesis Engine ranking & lead evaluation
  const hypotheses = generateHypotheses(graph);
  assert.ok(hypotheses.length >= 6, "Must generate multi-language hypotheses");
  const mintHyp = hypotheses.find((h) => h.selector === "TreasuryVault.dangerousMint");
  const initHyp = hypotheses.find((h) => h.selector === "TreasuryVault.initialize");
  const htmlHyp = hypotheses.find((h) => h.selector === "renderProfile");
  assert.ok(mintHyp && mintHyp.priority >= 90 && mintHyp.disposition === "ready_for_experiment");
  assert.ok(initHyp && initHyp.priority >= 90 && initHyp.disposition === "ready_for_experiment");
  assert.ok(htmlHyp && htmlHyp.recommendedProbeKind === "html_reflection");

  const leadDecision = evaluateAnalysisLead(graph, {
    leadId: "a".repeat(64),
    path: "source-1/contracts/TreasuryVault.sol",
    selector: "TreasuryVault.initialize",
    sourceEvidence: "source-1/contracts/TreasuryVault.sol:8",
  });
  assert.equal(leadDecision.action, "assess_lead");
  assert.ok(leadDecision.answer.length >= 20);
  assert.ok(leadDecision.hypothesis.length >= 12);

  // 4. Adapter catalog check (all 12 tools present)
  const expectedTools = [
    "semgrep", "slither", "solidity-parser", "tree-sitter", "joern",
    "z3", "mythril", "foundry", "fast-check", "javaparser", "libcst", "babel-parser",
  ];
  for (const toolId of expectedTools) {
    assert.ok(EXTERNAL_ADAPTER_CATALOG.some((s) => s.id === toolId), `Missing catalog entry for ${toolId}`);
  }
  const availability = detectAvailableAdapters();
  assert.equal(availability.length, EXTERNAL_ADAPTER_CATALOG.length);
  assert.equal(availability.find((a) => a.id === "solidity-parser")?.availableOnHost, true);

  // 5. End-to-end runLocalAudit with LOCAL_MODEL_ADAPTER=deterministic (zero Ollama calls!)
  const tmp = await mkdtemp(join(tmpdir(), "lotus-deterministic-"));
  try {
    const repoDir = join(tmp, "source-1", "contracts");
    await mkdir(repoDir, { recursive: true });
    const vaultSource = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
abstract contract Ownable {
  address private _owner;
  constructor() { _owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == _owner, "owner"); _; }
  function owner() public view returns (address) { return _owner; }
}
contract GuardedVault is Ownable {
  uint256 public fee;
  function setFee(uint256 nextFee) external onlyOwner {
    fee = nextFee;
  }
}
`;
    await writeFile(join(repoDir, "GuardedVault.sol"), vaultSource, "utf8");
    const logFile = join(tmp, "audit.log");
    const finalSchema = {
      type: "object",
      additionalProperties: false,
      properties: {
        findings: { type: "array", items: { type: "object" } },
        outcome: { type: "string", enum: ["inspected", "no_testable_candidate"] },
        reason: { type: "string" },
      },
      required: ["findings", "outcome", "reason"],
    };

    const prevControllerOwned = process.env.LOCAL_CONTROLLER_OWNED_ACTIONS;
    const prevFullIndex = process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX;
    const prevGuided = process.env.AUTOHACK_GUIDED_SOURCE_PROBES;
    const prevProtocol = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
    process.env.LOCAL_CONTROLLER_OWNED_ACTIONS = "true";
    process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX = "true";
    process.env.AUTOHACK_GUIDED_SOURCE_PROBES = "true";
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = "json";
    let answer = "";
    try {
      answer = await runLocalAudit(
        "Run deterministic security audit of source-1/contracts/GuardedVault.sol",
        logFile,
        60_000,
        tmp,
        "deterministic",
        undefined,
        {
          numCtx: 8192,
          numPredict: 512,
          numThreads: 2,
          maxTurns: 30,
          productionWorkflow: true,
          initialSourcePaths: ["source-1/contracts/GuardedVault.sol"],
          finalSchema,
          staticLeads: [
            {
              path: "source-1/contracts/GuardedVault.sol",
              line: 11,
              rule: "solidity-owner-setter",
              message: "Owner-gated setter",
              severity: "INFO",
              engine: "semgrep",
            },
          ],
          verifyPython: async (_path, selector, kind) =>
            JSON.stringify({
              status: "behavior_not_observed",
              behavior_observed: false,
              kind,
              selector,
              observations: { steps: [{ operation: "send", reverted: true, passed: true }] },
            }),
          validateFinal: (text) => {
            const parsed = JSON.parse(text);
            if (!Array.isArray(parsed.findings)) return "findings must be an array";
            if (parsed.outcome !== "no_testable_candidate") return "expected no_testable_candidate";
            if (typeof parsed.reason !== "string" || parsed.reason.length < 20) return "reason too short";
            return null;
          },
        },
      );
    } finally {
      if (prevControllerOwned === undefined) delete process.env.LOCAL_CONTROLLER_OWNED_ACTIONS;
      else process.env.LOCAL_CONTROLLER_OWNED_ACTIONS = prevControllerOwned;
      if (prevFullIndex === undefined) delete process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX;
      else process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX = prevFullIndex;
      if (prevGuided === undefined) delete process.env.AUTOHACK_GUIDED_SOURCE_PROBES;
      else process.env.AUTOHACK_GUIDED_SOURCE_PROBES = prevGuided;
      if (prevProtocol === undefined) delete process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
      else process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = prevProtocol;
    }

    const parsed = JSON.parse(answer);
    assert.equal(parsed.outcome, "no_testable_candidate");
    assert.equal(parsed.findings.length, 0);
    const logText = await readFile(logFile, "utf8");
    assert.match(logText, /\[DETERMINISTIC_DRIVER_ACTION\]/, "Runner must invoke deterministic driver");
    assert.doesNotMatch(logText, /\[MODEL_REQUEST_RECOVERY\]/, "No Ollama retries may occur in deterministic mode");

    // 5b. Standalone runLocalAudit (productionWorkflow: false) must track terminalReadPages without stalling
    const standaloneLog = join(tmp, "standalone-audit.log");
    const standaloneAnswer = await runLocalAudit(
      "Inspect source-1/contracts/GuardedVault.sol without productionWorkflow",
      standaloneLog,
      30_000,
      tmp,
      "deterministic",
      undefined,
      {
        numCtx: 8192,
        numPredict: 512,
        numThreads: 2,
        maxTurns: 12,
        initialSourcePaths: ["source-1/contracts/GuardedVault.sol"],
        finalSchema,
        validateFinal: (text) => {
          const p = JSON.parse(text);
          return Array.isArray(p.findings) && p.outcome === "no_testable_candidate" ? null : "invalid standalone final";
        },
      },
    );
    assert.equal(JSON.parse(standaloneAnswer).outcome, "no_testable_candidate");
    const standaloneLogText = await readFile(standaloneLog, "utf8");
    assert.match(standaloneLogText, /\[DETERMINISTIC_DRIVER_ACTION\]/);
    assert.doesNotMatch(standaloneLogText, /AUDIT_STALLED/);

    // 6. Evidence-only review in deterministic mode (zero Ollama calls!)
    const reviewLog = join(tmp, "review.log");
    const approved = await runEvidenceOnlyReview({
      prompt: JSON.stringify({
        sourceDigest: "b".repeat(64),
        independentlyReplayed: true,
        verifiedLocalEntryInjection: true,
        replayedProbeKind: "html_reflection",
        sourceBackedEscaping: [],
        sourceBackedTextOnlyResponse: [],
        citation: "src/profile.js:3",
      }),
      schema: { type: "object", properties: { verdict: { type: "string" } }, required: ["verdict"] },
      model: "deterministic",
      signal: new AbortController().signal,
      logFile: reviewLog,
      numCtx: 8192,
      numPredict: 512,
      validate: (raw) => {
        const v = JSON.parse(raw);
        return v.verdict === "approve" && v.recommendation === "dont_submit" ? null : "expected approve/dont_submit";
      },
    });
    assert.equal(JSON.parse(approved).verdict, "approve");

    const mitigated = evaluateDeterministicEvidenceReview(
      JSON.stringify({
        sourceDigest: "c".repeat(64),
        independentlyReplayed: true,
        replayedProbeKind: "html_reflection",
        sourceBackedEscaping: ["src/profile.js:2: escapeHtml(name)"],
      }),
    );
    assert.equal(mitigated.verdict, "reject");
    assert.equal(mitigated.recommendation, "dont_submit");
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }

  // 7. Deterministic program & finding assessment (zero Ollama/Claude calls!)
  const progResult = await assessProgram({
    id: "prog-88mph",
    provider: "immunefi",
    providerProgramId: "88mph",
    name: "88mph v3",
    status: "active",
    rewardMinCents: 100_000,
    rewardMaxCents: 5_000_000,
    responseEfficiency: 0.9,
    scopeSummary: JSON.stringify({
      scopes: [
        { assetIdentifier: "https://github.com/88mphapp/88mph-contracts", assetType: "SOURCE_CODE", instruction: "Solidity smart contracts" },
      ],
    }),
  } as any);
  assert.equal(progResult.hasSourceCode, true);
  assert.ok(progResult.opportunityScore > 0.5);
  assert.ok(progResult.techStack.includes("Solidity"));

  const findingResult = await assessFinding(
    { id: "f-1", title: "Unguarded mint", severity: "high", vulnerabilityType: "CWE-284", confidenceScore: 0.8 } as any,
    { id: "prog-88mph", name: "88mph v3", provider: "immunefi", rewardMaxCents: 5_000_000 } as any,
  );
  assert.equal(findingResult.severity, "high");
  assert.equal(findingResult.estimatedRewardCents, 1_250_000);

  console.log("DETERMINISTIC_LOTUS_END_TO_END_PASSED");
} finally {
  if (prevAdapter === undefined) delete process.env.LOCAL_MODEL_ADAPTER;
  else process.env.LOCAL_MODEL_ADAPTER = prevAdapter;
  if (prevOllama === undefined) delete process.env.AUTOHACK_OLLAMA_URL;
  else process.env.AUTOHACK_OLLAMA_URL = prevOllama;
  if (prevDet === undefined) delete process.env.LOTUS_DETERMINISTIC;
  else process.env.LOTUS_DETERMINISTIC = prevDet;
}
