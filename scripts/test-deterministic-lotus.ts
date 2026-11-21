/**
 * End-to-end verification of the Qwen-free deterministic LOTUS engine.
 * Sets AUTOHACK_OLLAMA_URL to an unreachable port (127.0.0.1:1) and
 * LOCAL_MODEL_ADAPTER=deterministic to guarantee ZERO Ollama/LLM calls.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAnalysisCandidateQueue,
  isTestOrMockContractPath,
  isExternalAdapterOrMarketPath,
  buildProgramFactsGraph,
  detectAvailableAdapters,
  driveDeterministicAuditTurn,
  evaluateAnalysisLead,
  evaluateDeterministicAnalysisTurn,
  evaluateDeterministicEvidenceReview,
  EXTERNAL_ADAPTER_CATALOG,
  generateHypotheses,
  generateRelationalHypotheses,
  isDeterministicMode,
  resolveLocalModelAdapter,
  runClosedLoopLeadAnalysis,
  type DeterministicReviewEvidence,
} from "../packages/security-solver/src/deterministic";
import { constructSolidityExperiments, extractSourceInvariantDescriptor } from "../packages/security-solver/src/controller-solidity-experiment-planner";
import { parse as parseSolidity } from "@solidity-parser/parser";
import { controllerReviewGroundDefect } from "../packages/security-solver/src/controller-review-boundary";
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
  assert.equal(resolveLocalModelAdapter({ AUTOHACK_OLLAMA_URL: "http://127.0.0.1:11434/api/chat" }), "deterministic", "Legacy model URL must not reactivate Ollama");
  assert.throws(() => resolveLocalModelAdapter({ LOCAL_MODEL_ADAPTER: "ollama" }), /LOTUS_MODEL_REMOVED/);
  assert.throws(() => resolveLocalModelAdapter({ LOCAL_MODEL_ADAPTER: "qwen-agent" }), /LOTUS_MODEL_REMOVED/);
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
  // An eligible, non-setter entrypoint keeps ANALYZE non-empty so this
  // integration case proves the deterministic driver actually executes.
  function recordNothing(uint256 amount) external {
    require(amount == 0, "no state change");
  }
}
`;
    await writeFile(join(repoDir, "GuardedVault.sol"), vaultSource, "utf8");
    // Real candidate admission requires an acquired, versioned source revision.
    // Commit the test fixture instead of bypassing source-identity validation.
    execFileSync("git", ["init", "-q"], { cwd: repoDir });
    execFileSync("git", ["-c", "user.name=LOTUS Fixture", "-c", "user.email=fixture@localhost",
      "add", "GuardedVault.sol"], { cwd: repoDir });
    execFileSync("git", ["-c", "user.name=LOTUS Fixture", "-c", "user.email=fixture@localhost",
      "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Versioned source fixture"], { cwd: repoDir });
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

    // 6. Typed, independently verified deterministic evidence review (ZERO prompt regex scraping!)
    const reviewLog = join(tmp, "review.log");

    // 6a. Prompt-only without typed verifiedEvidence MUST fail closed (even if prompt mentions positive replay)
    const noTypedEvidence = await runEvidenceOnlyReview({
      prompt: JSON.stringify({
        sourceDigest: "b".repeat(64),
        independentlyReplayed: true,
        verifiedLocalEntryInjection: true,
        status: "behavior_observed",
        behavior_observed: true,
      }),
      schema: { type: "object", properties: { verdict: { type: "string" } }, required: ["verdict"] },
      model: "deterministic",
      signal: new AbortController().signal,
      logFile: reviewLog,
      numCtx: 8192,
      numPredict: 512,
      validate: (raw) => {
        const v = JSON.parse(raw);
        return v.verdict === "reject" && v.issues?.[0]?.category === "missing_typed_evidence"
          ? null
          : "expected fail-closed missing_typed_evidence";
      },
    });
    assert.equal(JSON.parse(noTypedEvidence).verdict, "reject");

    // 6b. Positive replay marker ALONE without typed security impact MUST REJECT
    const replayOnlyEvidence: DeterministicReviewEvidence = {
      grounds: {
        sourceDigest: "d".repeat(64),
        language: "javascript",
        verifiedLocalEntryInjection: false,
        independentlyReplayed: true,
        replayedProbeKind: "javascript_sequence",
        sourceBackedNonadminRoleMutation: false,
        immutableFacts: ["src/profile.js:3: return '<div>' + name + '</div>';"],
        unresolvedQuestions: [],
        sourceBackedTextOnlyResponse: [],
        sourceBackedEscaping: [],
      },
      replay: {
        status: "behavior_observed",
        kind: "javascript_sequence",
        behavior_observed: true,
        observations: { output: "<div>ok</div>" },
      },
      target: { file: "src/profile.js", selector: "renderBio", kind: "javascript_sequence" },
      securityImpact: null,
    };
    const replayOnlyVerdict = evaluateDeterministicEvidenceReview(replayOnlyEvidence);
    assert.equal(replayOnlyVerdict.verdict, "reject", "Positive replay alone MUST NOT establish a security vulnerability");
    assert.equal(replayOnlyVerdict.issues[0]?.category, "missing_security_impact");
    assert.equal(controllerReviewGroundDefect(replayOnlyVerdict, replayOnlyEvidence.grounds), null);

    // 6c. Solidity nonadmin role mutation replay WITHOUT downstream consumer impact MUST REJECT
    const roleMutationOnly: DeterministicReviewEvidence = {
      grounds: {
        sourceDigest: "e".repeat(64),
        language: "solidity",
        verifiedLocalEntryInjection: false,
        independentlyReplayed: true,
        replayedProbeKind: "solidity_sequence",
        sourceBackedNonadminRoleMutation: true,
        immutableFacts: ["contracts/Vault.sol:9: function setOperator(address next) external { operator = next; }"],
        unresolvedQuestions: [],
        sourceBackedTextOnlyResponse: [],
        sourceBackedEscaping: [],
      },
      replay: {
        status: "behavior_observed",
        kind: "solidity_sequence",
        behavior_observed: true,
        observations: { steps: [] },
      },
      target: { file: "contracts/Vault.sol", selector: "Vault.setOperator", kind: "solidity_sequence" },
      securityImpact: null,
    };
    const roleOnlyVerdict = evaluateDeterministicEvidenceReview(roleMutationOnly);
    assert.equal(roleOnlyVerdict.verdict, "reject", "Role mutation replay without downstream consumer impact must reject");
    assert.equal(roleOnlyVerdict.issues[0]?.category, "missing_security_impact");
    assert.equal(controllerReviewGroundDefect(roleOnlyVerdict, roleMutationOnly.grounds), null);

    // 6d. Solidity role mutation WITH typed verified downstream consumer impact -> APPROVE (dont_submit)
    const roleWithImpact = evaluateDeterministicEvidenceReview({
      ...roleMutationOnly,
      securityImpact: {
        verified: true,
        category: "solidity_role_consumer_impact",
        evidence: "contracts/Vault.sol:14: withdrawTreasury() permitted post-mutation with beneficiary balance delta",
        downstreamConsumerVerified: true,
      },
    });
    assert.equal(roleWithImpact.verdict, "approve");
    assert.equal(roleWithImpact.recommendation, "dont_submit");
    assert.equal(roleWithImpact.bet100, false);

    // 6e. Controller-verified local HTML entry injection (typed grounds + entryReplay) -> APPROVE (dont_submit)
    const htmlVerifiedEvidence: DeterministicReviewEvidence = {
      grounds: {
        sourceDigest: "b".repeat(64),
        language: "javascript",
        verifiedLocalEntryInjection: true,
        independentlyReplayed: true,
        replayedProbeKind: "html_reflection",
        sourceBackedNonadminRoleMutation: false,
        immutableFacts: [
          "src/profile.js:3: return '<div>' + name + '</div>';",
          "Independent sandbox entry replay preserved the exact attacker-chosen HTML markup in the handler output.",
        ],
        unresolvedQuestions: [],
        sourceBackedTextOnlyResponse: [],
        sourceBackedEscaping: [],
      },
      replay: {
        status: "behavior_observed",
        kind: "html_reflection",
        behavior_observed: true,
        observations: { attack_output: "<div><img src=x onerror=1></div>" },
      },
      entryReplay: {
        status: "behavior_observed",
        behavior_observed: true,
        observations: {
          control_input: "alice",
          control_output: "<div>alice</div>",
          attack_input: "<img src=x onerror=1>",
          attack_output: "<div><img src=x onerror=1></div>",
        },
      } as any,
      target: { file: "src/profile.js", selector: "renderBio", kind: "html_reflection", callerFile: "src/profile.js", callerLine: 3 },
    };
    const approved = await runEvidenceOnlyReview({
      prompt: "ignored-prose-when-deterministic",
      schema: { type: "object", properties: { verdict: { type: "string" } }, required: ["verdict"] },
      model: "deterministic",
      signal: new AbortController().signal,
      logFile: reviewLog,
      numCtx: 8192,
      numPredict: 512,
      verifiedEvidence: htmlVerifiedEvidence,
      validate: (raw) => {
        const v = JSON.parse(raw);
        return v.verdict === "approve" && v.recommendation === "dont_submit" ? null : "expected approve/dont_submit";
      },
    });
    assert.equal(JSON.parse(approved).verdict, "approve");

    // 6f. Source-backed escaping mitigation -> REJECT (mitigation_present)
    const mitigatedEvidence: DeterministicReviewEvidence = {
      grounds: {
        sourceDigest: "c".repeat(64),
        language: "javascript",
        verifiedLocalEntryInjection: false,
        independentlyReplayed: true,
        replayedProbeKind: "html_reflection",
        sourceBackedNonadminRoleMutation: false,
        immutableFacts: ["src/profile.js:2: return escapeHtml(name);"],
        unresolvedQuestions: [],
        sourceBackedTextOnlyResponse: [],
        sourceBackedEscaping: ["src/profile.js:2"],
      },
      replay: { status: "behavior_observed", kind: "html_reflection", behavior_observed: true },
    };
    const mitigated = evaluateDeterministicEvidenceReview(mitigatedEvidence);
    assert.equal(mitigated.verdict, "reject");
    assert.equal(mitigated.recommendation, "dont_submit");
    assert.equal(mitigated.issues[0]?.category, "mitigation_present");
    assert.equal(controllerReviewGroundDefect(mitigated, mitigatedEvidence.grounds), null);

    // 6g. Z3 UNSAT refutation fact -> REJECT (unreachable_guard_unsat)
    const unsatRejected = evaluateDeterministicEvidenceReview({
      ...htmlVerifiedEvidence,
      analyzerFacts: [
        {
          id: "z3-unsat-1",
          kind: "smt_unsat_guard",
          language: "javascript",
          file: "src/profile.js",
          line: 2,
          symbol: "renderBio",
          severity: "info",
          adapter: "z3",
          detail: "Z3 proved guard constraints UNSAT: x > 10 && x < 5",
        },
      ],
    });
    assert.equal(unsatRejected.verdict, "reject");
    assert.equal(unsatRejected.issues[0]?.category, "unreachable_guard_unsat");
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


  // 8. Regression Case 1: Candidate inventory > 6 across multiple files ->
  //    preserves every candidate, admits top-priority bounded batch, deterministic across runs.
  {
    const commitSha = "a".repeat(40);
    const makeVault = (idx: number) => `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MultiVault${idx} {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
    function ping(uint256 x) external {
        totalDeposits = totalDeposits + (x - x);
    }
}`;
    const items = [1, 2, 3, 4].map((idx) => ({
      path: `source-0/contracts/MultiVault${idx}.sol`,
      sourceCommit: commitSha,
      sourceContent: makeVault(idx),
      unqueuedSelectors: [
        `MultiVault${idx}.deposit`,
        `MultiVault${idx}.withdraw`,
        `MultiVault${idx}.ping`,
      ],
    }));
    const q1 = buildAnalysisCandidateQueue({
      items,
      staticLeads: [
        {
          path: "source-0/contracts/MultiVault3.sol",
          line: 10,
          rule: "solidity-accounting-check",
          message: "Inspect MultiVault3.withdraw accounting update",
          severity: "WARNING",
        },
      ],
      maxAdmitted: 6,
      maxPerFile: 2,
    });
    const q2 = buildAnalysisCandidateQueue({
      items,
      staticLeads: [
        {
          path: "source-0/contracts/MultiVault3.sol",
          line: 10,
          rule: "solidity-accounting-check",
          message: "Inspect MultiVault3.withdraw accounting update",
          severity: "WARNING",
        },
      ],
      maxAdmitted: 6,
      maxPerFile: 2,
    });
    assert.equal(q1.inventory.length, 12, "All 12 candidates across 4 files must be preserved");
    assert.equal(q1.admitted.length, 6, "Bounded admission must select exactly 6 candidates");
    assert.equal(q1.queued.length, 6, "Remaining 6 candidates must stay queued rather than discarded");
    assert.equal(q1.blocked.length, 0);
    assert.equal(
      q1.admitted[0].selector,
      "MultiVault3.withdraw",
      "Function-localized static lead + financial entrypoint must rank #1",
    );
    const countsByFile = new Map<string, number>();
    for (const c of q1.admitted) {
      countsByFile.set(c.path, (countsByFile.get(c.path) || 0) + 1);
    }
    for (const [f, cnt] of countsByFile) {
      assert.ok(cnt <= 2, `Per-file cap maxPerFile=2 violated for ${f}: ${cnt}`);
    }
    assert.deepEqual(
      q1.inventory.map((c) => ({ id: c.id, selector: c.selector, priority: c.priority, status: c.status })),
      q2.inventory.map((c) => ({ id: c.id, selector: c.selector, priority: c.priority, status: c.status })),
      "Candidate inventory IDs, scores, and ordering must be 100% deterministic across repeated runs",
    );
  }

  // Shared Toy Accounting-Defect Contracts (Buggy vs Corrected) for Tests 9-13
  const buggyAccountingVault = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract BuggyAccountingVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        // Accounting defect: forgets totalDeposits -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
`;
  const fixedAccountingVault = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FixedAccountingVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
`;
  const callResolutionContract = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IPriceFeed { function latestPrice() external view returns (uint256); }
contract BaseA { function _shared(uint256 a) internal virtual pure returns (uint256) { return a; } }
contract BaseB { function _shared(uint256 a) internal virtual pure returns (uint256) { return a + 1; } }
contract CallResolutionDemo is BaseA, BaseB {
    uint256 public counter;
    IPriceFeed public feed;
    address public unknownExt;
    function _bump(uint256 n) internal { counter += n; }
    function run(uint256 x) external returns (uint256) {
        _bump(x);
        uint256 v = _shared(x);
        (bool ok, ) = unknownExt.call("");
        require(ok);
        return v + feed.latestPrice();
    }
}
`;

  // 9. Regression Case 2: Shared-state multi-function edges + CallResolutionStatus + RelationalHypothesis
  {
    const relGraph = buildProgramFactsGraph({
      sources: [
        {
          path: "source-0/contracts/BuggyAccountingVault.sol",
          content: buggyAccountingVault,
          sha256: sha(buggyAccountingVault),
        },
        {
          path: "source-0/contracts/CallResolutionDemo.sol",
          content: callResolutionContract,
          sha256: sha(callResolutionContract),
        },
      ],
    });
    assert.ok(
      relGraph.edges.some((e) => e.kind === "writes_state" && e.from === "BuggyAccountingVault.deposit" && e.to.endsWith(".totalDeposits")),
      "Graph must emit writes_state edge from deposit to totalDeposits",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "reads_state" && e.from === "BuggyAccountingVault.withdraw" && e.to.endsWith(".balances")),
      "Graph must emit reads_state edge from withdraw to balances",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "value_flow" && e.from === "BuggyAccountingVault.deposit"),
      "Graph must emit value_flow edge on payable deposit",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "precedes" && e.from === "BuggyAccountingVault.deposit" && e.to === "BuggyAccountingVault.withdraw"),
      "Graph must emit producer->consumer precedes edge from deposit to withdraw",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "calls_resolved" && e.from === "CallResolutionDemo.run" && e.to === "CallResolutionDemo._bump" && e.resolution === "resolved"),
      "Unique internal call must be marked resolution=resolved",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "calls_resolved" && e.from === "CallResolutionDemo.run" && e.resolution === "ambiguous"),
      "Multi-base inherited call must be marked resolution=ambiguous",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "external_call" && e.from === "CallResolutionDemo.run" && e.to === "IPriceFeed.latestPrice" && e.resolution === "resolved"),
      "Typed interface external call must be marked external_call with resolution=resolved",
    );
    assert.ok(
      relGraph.edges.some((e) => e.kind === "external_call" && e.from === "CallResolutionDemo.run" && e.resolution === "unresolved"),
      "Low-level untyped external call must be marked external_call with resolution=unresolved",
    );

    const relHyps = generateRelationalHypotheses(relGraph);
    const vaultRel = relHyps.find(
      (r) =>
        r.entrypoints.includes("BuggyAccountingVault.deposit") &&
        r.entrypoints.includes("BuggyAccountingVault.withdraw"),
    );
    assert.ok(vaultRel, "Relational hypothesis engine must link deposit and withdraw across shared accounting state");
    assert.ok(
      vaultRel!.sourceWitnesses.some((w) => w.symbol === "BuggyAccountingVault.deposit") &&
        vaultRel!.sourceWitnesses.some((w) => w.symbol === "BuggyAccountingVault.withdraw"),
      "Relational hypothesis must attach source witnesses for both functions",
    );
    const allHyps = generateHypotheses(relGraph);
    assert.ok(
      allHyps.some((h) => h.category === "accounting_invariant" && h.relational?.id === vaultRel!.id),
      "generateHypotheses must integrate RelationalHypothesis into prioritized output",
    );
  }

  // 10. Regression Case 3: Insufficient evidence -> UNKNOWN_ASSERTION, zero fabricated experiments
  {
    const privateVault = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PrivateVault {
    mapping(address => uint256) private balances;
    uint256 private totalDeposits;
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
    }
}`;
    const privPath = "source-0/contracts/PrivateVault.sol";
    const privSha = sha(privateVault);
    const privLeadId = sha("priv-lead-1");
    const privSources = [{ path: privPath, sha256: privSha, content: privateVault }];
    const privDecls = [
      { selector: "PrivateVault.deposit", operation: "send" as const, inputs: [] },
      { selector: "PrivateVault.withdraw", operation: "send" as const, inputs: ["uint256"] },
    ];
    const privAnalysis = evaluateDeterministicAnalysisTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId: privLeadId,
        path: privPath,
        selector: "PrivateVault.deposit",
        sourceEvidence: `${privPath}:0-200:${privSha}`,
        sourceExcerpt: privateVault,
      },
      sources: privSources,
      repositoryCommit: "b".repeat(40),
      declarations: privDecls,
      enableSpecializedEscalation: false,
    });
    assert.ok(privAnalysis);
    assert.equal(privAnalysis!.experimentCandidates.length, 0, "Missing observable state must produce 0 fabricated experiments");
    assert.ok(
      privAnalysis!.unresolvedReasons.some((r) => r.includes("UNKNOWN_ASSERTION(missing_observable_state)") || r.includes("missing_public_getter")),
      `Expected missing_observable_state unresolved reason, got: ${JSON.stringify(privAnalysis!.unresolvedReasons)}`,
    );
    const privAction = driveDeterministicAuditTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId: privLeadId,
        path: privPath,
        selector: "PrivateVault.deposit",
        sourceEvidence: `${privPath}:0-200:${privSha}`,
        sourceExcerpt: privateVault,
      },
      sources: privSources,
      repositoryCommit: "b".repeat(40),
      declarations: privDecls,
      constraints: { action: ["assess_lead", "defer_lead", "discover_experiment"] },
      enableSpecializedEscalation: false,
    });
    assert.notEqual(privAction.action, "discover_experiment", "Driver must never emit discover_experiment when prerequisites are missing");
  }

  // 11. Regression Cases 4 & 5: Supported relational hypothesis -> discover_experiment ->
  //     [ANALYSIS_MODEL_EXPERIMENT_ADDED] in runLocalAudit + duplicate suppression/rejection.
  let generatedBuggySequence: any = null;
  {
    const vaultPath = "source-0/contracts/BuggyAccountingVault.sol";
    const vaultSha = sha(buggyAccountingVault);
    const vaultDecls = [
      { selector: "BuggyAccountingVault.deposit", operation: "send" as const, inputs: [] },
      { selector: "BuggyAccountingVault.withdraw", operation: "send" as const, inputs: ["uint256"] },
      { selector: "BuggyAccountingVault.totalDeposits", operation: "call" as const, inputs: [] },
      { selector: "BuggyAccountingVault.balances", operation: "call" as const, inputs: ["address"] },
    ];
    const leadId = sha("buggy-withdraw-lead");
    const sources = [{ path: vaultPath, sha256: vaultSha, content: buggyAccountingVault }];

    // Pretend legacy unauthorized ETH extraction probe is already queued -> driver must skip it
    // and emit discover_experiment for the financial conservation invariant!
    const preConstructed = constructSolidityExperiments({
      repositoryCommit: "c".repeat(40),
      targetPath: vaultPath,
      targetSelector: "BuggyAccountingVault.withdraw",
      sources,
      declarations: vaultDecls,
    });
    assert.equal(preConstructed.ok, true);
    const legacyExp = preConstructed.ok ? preConstructed.experiments[0] : null;
    const conservationExp = preConstructed.ok
      ? preConstructed.experiments.find((e) => e.securityProperty.includes("conservation"))
      : null;
    if(!conservationExp){
      const parsed=parseSolidity(buggyAccountingVault,{loc:true,range:true}) as any;
      const contract=parsed.children.find((n:any)=>n.type==='ContractDefinition'&&n.name==='BuggyAccountingVault');
      const debug=extractSourceInvariantDescriptor(sources[0],contract,'withdraw',vaultDecls,new Map(sources.map(x=>[x.path,x])));
      console.error("SOURCE_CONSERVATION_DIAGNOSTIC",JSON.stringify(debug));
    }
    assert.ok(legacyExp && conservationExp, "withdraw must yield both legacy and conservation candidates");

    const existingIds = new Set<string>([legacyExp!.id]);
    const discoverAction = driveDeterministicAuditTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId,
        path: vaultPath,
        selector: "BuggyAccountingVault.withdraw",
        sourceEvidence: `${vaultPath}:0-400:${vaultSha}`,
        sourceExcerpt: buggyAccountingVault,
      },
      sources,
      repositoryCommit: "c".repeat(40),
      declarations: vaultDecls,
      existingExperimentIds: existingIds,
      constraints: { action: ["assess_lead", "defer_lead", "discover_experiment"] },
      enableSpecializedEscalation: false,
    });
    assert.equal(discoverAction.action, "discover_experiment", "Supported financial invariant must emit discover_experiment");
    assert.equal(discoverAction.query, "BuggyAccountingVault.withdraw");
    assert.equal(discoverAction.answer, "solidity_sequence");
    assert.ok(discoverAction.sequence, "discover_experiment must include a valid solidity_sequence");
    assert.ok(
      discoverAction.sequence!.steps.some((s: any) => s.operation === "call" && s.function === "totalDeposits()" && s.expect === "600"),
      "Discovered experiment must assert totalDeposits() == 600",
    );
    generatedBuggySequence = discoverAction.sequence;

    // Duplicate suppression: once BOTH legacyExp and conservationExp are in existingExperimentIds,
    // driver must NOT re-propose a duplicate discover_experiment.
    existingIds.add(conservationExp!.id);
    const dupCheckAction = driveDeterministicAuditTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId,
        path: vaultPath,
        selector: "BuggyAccountingVault.withdraw",
        sourceEvidence: `${vaultPath}:0-400:${vaultSha}`,
        sourceExcerpt: buggyAccountingVault,
      },
      sources,
      repositoryCommit: "c".repeat(40),
      declarations: vaultDecls,
      existingExperimentIds: existingIds,
      constraints: { action: ["assess_lead", "defer_lead", "discover_experiment"] },
      enableSpecializedEscalation: false,
    });
    assert.notEqual(dupCheckAction.action, "discover_experiment", "Already-queued experiment must not be re-proposed as duplicate");

    // Full runLocalAudit integration with stageLock + controllerIndex + real git repo in source-0
    const auditDir = await mkdtemp(join(tmpdir(), "lotus-det-accounting-"));
    try {
      const repoDir = join(auditDir, "source-0");
      await mkdir(join(repoDir, "contracts"), { recursive: true });
      await writeFile(join(repoDir, "contracts/BuggyAccountingVault.sol"), buggyAccountingVault, "utf8");
      // Add 3 sibling contracts (>6 unqueued functions total) to verify candidate inventory persistence
      for (const n of [1, 2, 3]) {
        const sibling = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SiblingPool${n} {
    uint256 public marker;
    function pokeA(uint256 v) external { marker = v; }
    function pokeB(uint256 v) external { marker = v + 1; }
    function pokeC(uint256 v) external { marker = v + 2; }
}
`;
        await writeFile(join(repoDir, `contracts/SiblingPool${n}.sol`), sibling, "utf8");
      }
      execFileSync("git", ["init", "-q"], { cwd: repoDir });
      execFileSync("git", ["config", "user.email", "test@lotus.local"], { cwd: repoDir });
      execFileSync("git", ["config", "user.name", "LOTUS Test"], { cwd: repoDir });
      execFileSync("git", ["add", "."], { cwd: repoDir });
      execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: repoDir });

      const logPath = join(auditDir, "audit.log");
      const prevMaxLeads = process.env.LOCAL_ANALYZE_MAX_LEADS;
      process.env.LOCAL_ANALYZE_MAX_LEADS = "6";
      try {
        await runLocalAudit(
          "Audit Solidity contracts in source-0.",
          logPath,
          60_000,
          auditDir,
          "deterministic",
          undefined,
          {
            maxTurns: 40,
            numCtx: 8192,
            numPredict: 1024,
            productionWorkflow: true,
            verifyPython: true,
            controllerIndex: true,
            initialSourcePaths: [
              "source-0/contracts/BuggyAccountingVault.sol",
              "source-0/contracts/SiblingPool1.sol",
              "source-0/contracts/SiblingPool2.sol",
              "source-0/contracts/SiblingPool3.sol",
            ],
            // Stubbed verifier returning clean structured negative/observation records so test
            // verifies controller admission, graph reuse, candidate persistence & escalation logs
            // without requiring host bwrap/solc.
            validateFinal: () => null,
            verifySource: async (_path, _selector, _kind) =>
              JSON.stringify({ status: "not_observed", behavior_observed: false, note: "stubbed_local_verifier" }),
          },
        );
      } finally {
        if (prevMaxLeads === undefined) delete process.env.LOCAL_ANALYZE_MAX_LEADS;
        else process.env.LOCAL_ANALYZE_MAX_LEADS = prevMaxLeads;
      }

      const auditLog = await readFile(logPath, "utf8");
      if(!/\[ANALYSIS_MODEL_EXPERIMENT_ADDED\][^\n]*BuggyAccountingVault\.(?:deposit|withdraw)/.test(auditLog)){
        console.error("ADMISSION_DIAGNOSTIC",
          auditLog.split("\n").filter(line=>/\[ANALYSIS_|\[DETERMINISTIC_DRIVER_ACTION\]|\[STAGE_UNLOCK\]/.test(line))
            .slice(-120).join("\n").slice(-25000));
      }
      const graphBuilds = auditLog.match(/\[DETERMINISTIC_FACTS_GRAPH_BUILT\]/g) || [];
      assert.equal(graphBuilds.length, 1, "ProgramFactsGraph must be built ONCE per investigation and reused");
      assert.match(auditLog, /\[ANALYSIS_CANDIDATE_INVENTORY\]/, "Full candidate inventory telemetry must be logged");
      assert.match(
        auditLog,
        /\[ANALYSIS_MODEL_EXPERIMENT_ADDED\][^\n]*BuggyAccountingVault\.(?:deposit|withdraw)/,
        "Deterministic discover_experiment for BuggyAccountingVault must pass controller admission gate and log [ANALYSIS_MODEL_EXPERIMENT_ADDED]",
      );
      assert.match(
        auditLog,
        /\[DETERMINISTIC_ESCALATION\][^\n]*"steps":\[/,
        "Escalation telemetry must log complete specialist dispositions including unavailable tools",
      );
      const persistedQueue = JSON.parse(await readFile(logPath + ".analysis-candidates.json", "utf8"));
      assert.ok(
        persistedQueue.totalCandidates > 6,
        `Expected >6 candidates persisted in inventory, got ${persistedQueue.totalCandidates}`,
      );
      const startedBatches = auditLog.split("\n").filter(line=>line.startsWith("[ANALYSIS_BATCH_STARTED] "))
        .map(line=>JSON.parse(line.slice("[ANALYSIS_BATCH_STARTED] ".length)) as {admitted:number});
      assert.ok(startedBatches.length>=2, "More than six eligible functions require multiple analysis batches");
      assert.ok(startedBatches.every(batch=>batch.admitted>0&&batch.admitted<=6),
        "Every ANALYZE batch must preserve the configured six-candidate bound");
      assert.equal(persistedQueue.queuedCount,0,
        "Round 3 must process the entire inventory, not stop at the first batch");
      assert.equal(persistedQueue.admittedCount,persistedQueue.totalCandidates,
        "The persisted cumulative record must account for every eligible candidate");
    } finally {
      await rm(auditDir, { recursive: true, force: true });
    }
  }

  // 12. Regression Case 6: Unavailable specialist telemetry records explicit attempted=false, reason=tool_unavailable
  //     and NEVER claims a negative finding or flips assess_lead -> defer_lead.
  {
    const vaultPath = "source-0/contracts/BuggyAccountingVault.sol";
    const vaultSha = sha(buggyAccountingVault);
    const sources = [{ path: vaultPath, sha256: vaultSha, content: buggyAccountingVault }];
    const g = buildProgramFactsGraph({ sources });
    const esc = runClosedLoopLeadAnalysis({
      graph: g,
      lead: {
        leadId: sha("unavail-specialist-lead"),
        path: vaultPath,
        selector: "BuggyAccountingVault.withdraw",
        sourceEvidence: `${vaultPath}:0-400:${vaultSha}`,
        sourceExcerpt: buggyAccountingVault,
      },
      sources,
      hooks: {
        runMythril: () => ({ status: "unavailable", facts: [], error: "myth binary not installed" }),
        runFoundry: () => ({ status: "unavailable", facts: [], error: "forge binary not installed" }),
      },
    });
    const foundryStep = esc.steps.find((s) => s.adapter === "foundry");
    assert.ok(foundryStep, "Foundry unavailability must be recorded in steps for withdraw");
    assert.equal(foundryStep!.attempted, false);
    assert.equal(foundryStep!.status, "unavailable");
    assert.equal(foundryStep!.reason, "tool_unavailable");
    assert.equal(esc.reconsidered, false, "Unavailable specialists must never flip lead disposition");
    assert.equal(esc.finalDecision.action, esc.initialDecision.action);

    // Also verify deeper-analysis lead records both Mythril and Foundry unavailability explicitly
    const escDeposit = runClosedLoopLeadAnalysis({
      graph: g,
      lead: {
        leadId: sha("unavail-specialist-lead-deposit"),
        path: vaultPath,
        selector: "BuggyAccountingVault.deposit",
        sourceEvidence: `${vaultPath}:0-400:${vaultSha}`,
        sourceExcerpt: buggyAccountingVault,
      },
      sources,
      hooks: {
        runMythril: () => ({ status: "unavailable", facts: [], error: "myth binary not installed" }),
        runFoundry: () => ({ status: "unavailable", facts: [], error: "forge binary not installed" }),
      },
    });
    const mythStep = escDeposit.steps.find((s) => s.adapter === "mythril");
    const foundryStepDep = escDeposit.steps.find((s) => s.adapter === "foundry");
    assert.ok(mythStep && foundryStepDep, "Both Mythril and Foundry unavailability must be recorded for deeper lead");
    assert.equal(mythStep!.attempted, false);
    assert.equal(mythStep!.status, "unavailable");
    assert.equal(mythStep!.reason, "tool_unavailable");
    assert.equal(foundryStepDep!.attempted, false);
    assert.equal(foundryStepDep!.status, "unavailable");
    assert.equal(foundryStepDep!.reason, "tool_unavailable");
    assert.equal(escDeposit.reconsidered, false);
  }

  // 13. Regression Cases 7 & 8: Toy Accounting-Defect Acceptance Test
  //     (BuggyAccountingVault.sol vs FixedAccountingVault.sol)
  {
    // Verify identical conservation sequence is also constructed for FixedAccountingVault (no bug-specific hardcoding)
    const fixedPath = "source-0/contracts/FixedAccountingVault.sol";
    const fixedSha = sha(fixedAccountingVault);
    const fixedRes = constructSolidityExperiments({
      repositoryCommit: "d".repeat(40),
      targetPath: fixedPath,
      targetSelector: "FixedAccountingVault.withdraw",
      sources: [{ path: fixedPath, sha256: fixedSha, content: fixedAccountingVault }],
      declarations: [
        { selector: "FixedAccountingVault.deposit", operation: "send", inputs: [] },
        { selector: "FixedAccountingVault.withdraw", operation: "send", inputs: ["uint256"] },
        { selector: "FixedAccountingVault.totalDeposits", operation: "call", inputs: [] },
        { selector: "FixedAccountingVault.balances", operation: "call", inputs: ["address"] },
      ],
    });
    assert.equal(fixedRes.ok, true);
    const fixedSeq = fixedRes.ok
      ? fixedRes.experiments.find((e) => e.securityProperty.includes("conservation"))?.sequence
      : null;
    assert.deepEqual(
      fixedSeq,
      generatedBuggySequence,
      "Planner must construct the exact same source-derived accounting invariant test for both buggy and fixed contracts",
    );

    // Case 7: Negative control — when no violation is observed on FixedAccountingVault,
    // deterministic evidence review keeps finding unverified/rejected with dont_submit.
    const fixedReview = evaluateDeterministicEvidenceReview({
      grounds: {
        sourceDigest: fixedSha,
        sourcePath: fixedPath,
        language: "solidity",
        replayedProbeKind: "solidity_sequence",
        independentlyReplayed: true,
        sourceBackedNonadminRoleMutation: false,
        sourceBackedTextOnlyResponse: [],
        sourceBackedEscaping: [],
      },
      replay: {
        status: "not_observed",
        kind: "solidity_sequence",
        behavior_observed: false,
      },
      target: {
        file: fixedPath,
        selector: "FixedAccountingVault.withdraw",
        kind: "solidity_sequence",
      },
    });
    assert.equal(fixedReview.verdict, "reject", "No violation observed on corrected contract must stay rejected");
    assert.equal(fixedReview.recommendation, "dont_submit");
    assert.equal(fixedReview.issues[0]?.category, "unreproduced_behavior");

    // Live EVM execution via scripts/reproduction-runtime (solc + ganache + runSequence)
    // Runs whenever reproduction-runtime is installed, and is MANDATORY in CI (REQUIRE_EVM_ACCOUNTING_TEST=1).
    const requireEvm = process.env.REQUIRE_EVM_ACCOUNTING_TEST === "1";
    const solcPath = join(process.cwd(), "scripts/reproduction-runtime/node_modules/solc");
    const hasEvmRuntime = existsSync(solcPath);
    if (requireEvm && !hasEvmRuntime) {
      throw new Error("REQUIRE_EVM_ACCOUNTING_TEST=1 set, but scripts/reproduction-runtime/node_modules/solc is missing");
    }
    if (hasEvmRuntime) {
      const req = createRequire(import.meta.url);
      const solc = req("./reproduction-runtime/node_modules/solc");
      const ganache = req("./reproduction-runtime/node_modules/ganache");
      const { runSequence } = req("./reproduction-runtime/solidity-sequence.cjs");

      const runOnEvm = async (fileName: string, contractName: string, sourceCode: string, seq: unknown) => {
        const compiled = JSON.parse(
          solc.compile(
            JSON.stringify({
              language: "Solidity",
              sources: { [fileName]: { content: sourceCode } },
              settings: {
                evmVersion: "shanghai",
                outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
              },
            }),
          ),
        );
        const errs = (compiled.errors || []).filter((e: any) => e.severity === "error");
        assert.deepEqual(errs, [], `solc compile errors for ${contractName}: ${JSON.stringify(errs)}`);
        const artifact = compiled.contracts[fileName][contractName];
        const provider = ganache.provider({
          logging: { quiet: true },
          wallet: { deterministic: true, totalAccounts: 3 },
          chain: { hardfork: "shanghai", chainId: 1337, time: new Date("2020-01-01T00:00:00Z") },
          miner: { blockGasLimit: 12000000, timestampIncrement: 1 },
        });
        try {
          return await runSequence(artifact, seq, provider);
        } finally {
          await provider.disconnect();
        }
      };

      // BuggyAccountingVault: totalDeposits() remains 1000 instead of 600 -> assertion FAILS (violation observed!)
      const buggyRun = await runOnEvm(
        "BuggyAccountingVault.sol",
        "BuggyAccountingVault",
        buggyAccountingVault,
        generatedBuggySequence,
      );
      const buggyTotalStep = buggyRun.steps.find(
        (s: any) => s.operation === "call" && s.function === "totalDeposits()" && String(s.expected) === "600",
      );
      const buggyBalanceStep = buggyRun.steps.find(
        (s: any) => s.operation === "call" && s.function === "balances(address)" && String(s.expected) === "600",
      );
      assert.ok(
        buggyTotalStep && buggyBalanceStep,
        `Expected post-withdraw call assertions in steps: ${JSON.stringify(buggyRun.steps)}`,
      );
      assert.equal(buggyBalanceStep.passed, true, "balances($account0) decremented to 600 on BuggyAccountingVault");
      assert.equal(String(buggyTotalStep.actual), "1000", "BuggyAccountingVault totalDeposits() must remain stale at 1000");
      assert.equal(
        buggyTotalStep.passed,
        false,
        "BuggyAccountingVault must FAIL totalDeposits() == 600 assertion (accounting defect observed!)",
      );

      // FixedAccountingVault: ALL steps pass -> zero violation!
      const fixedRun = await runOnEvm(
        "FixedAccountingVault.sol",
        "FixedAccountingVault",
        fixedAccountingVault,
        fixedSeq,
      );
      assert.ok(
        fixedRun.steps.every((s: any) => (s.operation === "call" ? s.passed === true : s.reverted === false)),
        `FixedAccountingVault must pass every step with zero violation: ${JSON.stringify(fixedRun.steps)}`,
      );
      const fixedReplay = await runOnEvm(
        "FixedAccountingVault.sol",
        "FixedAccountingVault",
        fixedAccountingVault,
        fixedSeq,
      );
      assert.deepEqual(fixedReplay, fixedRun, "Independent deterministic EVM replay must match exactly");
      console.log("LIVE_EVM_BUGGY_VS_FIXED_ACCOUNTING_VAULT_PASSED");

      // Also execute acquired-source ERC20 Buggy vs Fixed Vault live on EVM!
      const liveMockErc20 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ERC20Mock {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        require(allowance[from][msg.sender] >= amount, "allow");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}`;
      const liveBuggyErc20Vault = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}
contract BuggyERC20Vault {
    IERC20 public stablecoin;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    constructor(address _stablecoin) { stablecoin = IERC20(_stablecoin); }
    function deposit(uint256 amount) external {
        require(stablecoin.transferFrom(msg.sender, address(this), amount), "tf");
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
        require(stablecoin.transfer(msg.sender, amount), "t");
    }
}`;
      const liveFixedErc20Vault = liveBuggyErc20Vault
        .replace(/BuggyERC20Vault/g, "FixedERC20Vault")
        .replace(
          'balances[msg.sender] -= amount;',
          'balances[msg.sender] -= amount;\n        totalDeposits -= amount;',
        );
      const mockPath = "contracts/mocks/ERC20Mock.sol";
      const mockSnap = { path: mockPath, sha256: sha(liveMockErc20), content: liveMockErc20 };
      const buggyErc20Path = "contracts/BuggyERC20Vault.sol";
      const buggyErc20Snap = { path: buggyErc20Path, sha256: sha(liveBuggyErc20Vault), content: liveBuggyErc20Vault };
      const fixedErc20Path = "contracts/FixedERC20Vault.sol";
      const fixedErc20Snap = { path: fixedErc20Path, sha256: sha(liveFixedErc20Vault), content: liveFixedErc20Vault };
      const makeErc20Decls = (name: string) => [
        { selector: `${name}.deposit`, operation: "send" as const, inputs: ["uint256"] },
        { selector: `${name}.withdraw`, operation: "send" as const, inputs: ["uint256"] },
        { selector: `${name}.totalDeposits`, operation: "call" as const, inputs: [] },
        { selector: `${name}.balances`, operation: "call" as const, inputs: ["address"] },
      ];
      const erc20CommitSha = "c".repeat(40);
      const buggyErc20Plan = constructSolidityExperiments({
        repositoryCommit: erc20CommitSha,
        targetPath: buggyErc20Path,
        targetSelector: "BuggyERC20Vault.withdraw",
        sources: [buggyErc20Snap, mockSnap],
        declarations: makeErc20Decls("BuggyERC20Vault"),
      });
      assert.equal(buggyErc20Plan.ok, true, "Controller must construct ERC20 accounting experiment for BuggyERC20Vault");
      const fixedErc20Plan = constructSolidityExperiments({
        repositoryCommit: erc20CommitSha,
        targetPath: fixedErc20Path,
        targetSelector: "FixedERC20Vault.withdraw",
        sources: [fixedErc20Snap, mockSnap],
        declarations: makeErc20Decls("FixedERC20Vault"),
      });
      assert.equal(fixedErc20Plan.ok, true, "Controller must construct ERC20 accounting experiment for FixedERC20Vault");
      const runMultiContractOnEvm = async (
        vaultFile: string,
        vaultContract: string,
        vaultSrc: string,
        seq: any,
      ) => {
        const compiled = JSON.parse(
          solc.compile(
            JSON.stringify({
              language: "Solidity",
              sources: {
                [mockPath]: { content: liveMockErc20 },
                [vaultFile]: { content: vaultSrc },
              },
              settings: { outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } } },
            }),
          ),
        );
        const errs = (compiled.errors || []).filter((e: any) => e.severity === "error");
        assert.deepEqual(errs, [], `solc compile errors for ${vaultContract}: ${JSON.stringify(errs)}`);
        const artifact = compiled.contracts[vaultFile][vaultContract];
        const prepArtifacts = {
          [mockPath]: { ERC20Mock: compiled.contracts[mockPath].ERC20Mock },
        };
        const provider = ganache.provider({
          logging: { quiet: true },
          wallet: { deterministic: true, totalAccounts: 3 },
          chain: { hardfork: "shanghai", chainId: 1337, time: new Date("2020-01-01T00:00:00Z") },
          miner: { blockGasLimit: 12000000, timestampIncrement: 1 },
        });
        try {
          return await runSequence(artifact, seq, provider, prepArtifacts);
        } finally {
          await provider.disconnect();
        }
      };
      const buggyErc20Run = await runMultiContractOnEvm(
        buggyErc20Path,
        "BuggyERC20Vault",
        liveBuggyErc20Vault,
        (buggyErc20Plan as any).experiments.find((e: any) => e.securityProperty.includes("conservation")).sequence,
      );
      const buggyErc20Total = buggyErc20Run.steps.find(
        (s: any) => s.operation === "call" && s.function === "totalDeposits()" && String(s.expected) === "600",
      );
      assert.ok(buggyErc20Total && buggyErc20Total.passed === false && String(buggyErc20Total.actual) === "1000",
        `BuggyERC20Vault must observe stale totalDeposits == 1000 on live EVM: ${JSON.stringify(buggyErc20Run.steps)}`);
      const fixedErc20Run = await runMultiContractOnEvm(
        fixedErc20Path,
        "FixedERC20Vault",
        liveFixedErc20Vault,
        (fixedErc20Plan as any).experiments.find((e: any) => e.securityProperty.includes("conservation")).sequence,
      );
      assert.ok(
        fixedErc20Run.steps.every((s: any) => (s.operation === "call" || s.operation === "setup" ? s.passed === true : s.reverted === false)),
        `FixedERC20Vault must pass every step on live EVM: ${JSON.stringify(fixedErc20Run.steps)}`,
      );
      console.log("LIVE_EVM_BUGGY_VS_FIXED_ERC20_VAULT_PASSED");
    }
  }

  // 12. Repository-level 88mph-style regression suite (Round 2 architectural repairs)
  {
    const commitSha = "b".repeat(40);
    const echidnaTestSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EchidnaDepositWithdrawTest {
    uint256 public totalDeposits;
    function deposit(uint256 amount) external { totalDeposits += amount; }
    function withdraw(uint256 amount) external { totalDeposits -= amount; }
}`;
    const benqiMarketSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function safeTransferFrom(address f, address t, uint256 a) external; function safeTransfer(address t, uint256 a) external; }
interface ICERC20 { function mint(uint256 a) external returns (uint256); function redeemUnderlying(uint256 a) external returns (uint256); }
interface IComptroller { function claimComp(address holder) external; }
contract BenqiERC20Market {
    IERC20 public stablecoin;
    ICERC20 public cToken;
    IComptroller public comptroller;
    function deposit(uint256 amount) external {
        stablecoin.safeTransferFrom(msg.sender, address(this), amount);
        cToken.mint(amount);
    }
    function withdraw(uint256 amount) external {
        cToken.redeemUnderlying(amount);
        comptroller.claimComp(address(this));
        stablecoin.safeTransfer(msg.sender, amount);
    }
}`;
    const harvestMarketSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function safeTransfer(address t, uint256 a) external; }
contract HarvestMarket {
    IERC20 public stablecoin;
    function initialize(address _stablecoin) external {
        stablecoin = IERC20(_stablecoin);
    }
    function withdraw(uint256 amount) external {
        stablecoin.safeTransfer(msg.sender, amount);
    }
}`;
    const dInterestSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DInterest {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }
    function topupDeposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalDeposits += amount;
    }
}`;
    const mphMinterSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../DInterest.sol";
contract MPHMinter {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mintVested(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
    function takeBackDepositedAmount(address from, uint256 amount) external {
        balances[from] -= amount;
        totalSupply -= amount;
    }
}`;

    const paths = {
      echidna: "contracts/echidna/EchidnaDepositWithdrawTest.sol",
      benqi: "contracts/models/moneymarket/benqi/BenqiERC20Market.sol",
      harvest: "contracts/models/moneymarket/harvest/HarvestMarket.sol",
      dInterest: "contracts/DInterest.sol",
      mphMinter: "contracts/rewards/MPHMinter.sol",
    };

    // 12a. Consistent test-harness classification
    assert.equal(isTestOrMockContractPath(paths.echidna), true);
    assert.equal(isTestOrMockContractPath("contracts/EchidnaDepositWithdrawTest.sol"), true);
    assert.equal(isTestOrMockContractPath("contracts/VaultTest.sol"), true);
    assert.equal(isTestOrMockContractPath(paths.dInterest), false);
    assert.equal(isTestOrMockContractPath(paths.mphMinter), false);
    assert.equal(isExternalAdapterOrMarketPath(paths.benqi), true);
    assert.equal(isExternalAdapterOrMarketPath(paths.harvest), true);
    assert.equal(isExternalAdapterOrMarketPath(paths.dInterest), false);

    const repoSources = [
      { path: paths.echidna, sha256: sha(echidnaTestSrc), content: echidnaTestSrc },
      { path: paths.benqi, sha256: sha(benqiMarketSrc), content: benqiMarketSrc },
      { path: paths.harvest, sha256: sha(harvestMarketSrc), content: harvestMarketSrc },
      { path: paths.dInterest, sha256: sha(dInterestSrc), content: dInterestSrc },
      { path: paths.mphMinter, sha256: sha(mphMinterSrc), content: mphMinterSrc },
    ];
    const repoGraph = buildProgramFactsGraph({ sources: repoSources });

    // 12b. Candidate queue excludes Echidna test harness & prioritizes DInterest/MPHMinter above Benqi/Harvest adapters
    const queue = buildAnalysisCandidateQueue({
      items: [
        { path: paths.echidna, sourceCommit: commitSha, sourceContent: echidnaTestSrc, unqueuedSelectors: ["EchidnaDepositWithdrawTest.deposit", "EchidnaDepositWithdrawTest.withdraw"] },
        { path: paths.benqi, sourceCommit: commitSha, sourceContent: benqiMarketSrc, unqueuedSelectors: ["BenqiERC20Market.deposit", "BenqiERC20Market.withdraw"] },
        { path: paths.harvest, sourceCommit: commitSha, sourceContent: harvestMarketSrc, unqueuedSelectors: ["HarvestMarket.initialize", "HarvestMarket.withdraw"] },
        { path: paths.dInterest, sourceCommit: commitSha, sourceContent: dInterestSrc, unqueuedSelectors: ["DInterest.deposit", "DInterest.withdraw", "DInterest.topupDeposit"] },
        { path: paths.mphMinter, sourceCommit: commitSha, sourceContent: mphMinterSrc, unqueuedSelectors: ["MPHMinter.mintVested", "MPHMinter.takeBackDepositedAmount"] },
      ],
      graph: repoGraph,
      maxAdmitted: 4,
      maxPerFile: 2,
    });
    assert.ok(
      queue.blocked.some((b) => b.path === paths.echidna && b.reason === "test_or_mock_contract"),
      "Echidna test contract must be blocked as test_or_mock_contract",
    );
    assert.ok(
      !queue.inventory.some((c) => c.path === paths.echidna),
      "Echidna test contract must never enter the production candidate inventory",
    );
    assert.ok(
      queue.admitted.every((c) => c.path === paths.dInterest || c.path === paths.mphMinter),
      `Top-4 admitted candidates must prioritize core protocol (DInterest & MPHMinter) ahead of thin adapters, got: ${queue.admitted.map((c) => c.selector).join(", ")}`,
    );

    // 12c. HarvestMarket.initialize + withdraw sharing `stablecoin` config pointer must NOT become a conservation invariant
    const repoRelHyps = generateRelationalHypotheses(repoGraph);
    assert.ok(
      !repoRelHyps.some((r) => r.file === paths.harvest && (r.propertyKind === "conservation" || r.stateDependencies.some((s) => /stablecoin/i.test(s)))),
      `HarvestMarket.initialize + withdraw sharing stablecoin must not emit a conservation invariant: ${JSON.stringify(repoRelHyps.filter((r) => r.file === paths.harvest))}`,
    );
    const dInterestRel = repoRelHyps.find((r) => r.file === paths.dInterest && r.propertyKind === "conservation");
    assert.ok(dInterestRel, "DInterest deposit/withdraw must still emit a real conservation hypothesis");
    assert.deepEqual(dInterestRel!.propertyRequiredPrerequisites, []);

    // 12d. Decoupled analytical disposition vs construction feasibility & Z3 SMT refutation gate
    // MixedProtocolVault shares a private `rewards` variable (causing the top interest-accrual
    // relational hypothesis to defer with missing_public_getter) while ALSO exposing public
    // `balances` and `totalDeposits` for a valid conservation experiment. Commit 3 ensures
    // construction feasibility is evaluated independently of the deferred relational disposition.
    const mixedSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MixedProtocolVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 private rewards;
    constructor() { owner = msg.sender; }
    function deposit(uint256 amount) external {
        require(msg.sender == owner, "only owner");
        balances[msg.sender] += amount;
        totalDeposits += amount;
        rewards += 1;
    }
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "only owner");
        require(balances[msg.sender] >= amount, "low");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        rewards += 1;
    }
}`;
    const mixedPath = "contracts/MixedProtocolVault.sol";
    const mixedSnap = { path: mixedPath, sha256: sha(mixedSrc), content: mixedSrc };
    const mixedDecls = [
      { selector: "MixedProtocolVault.deposit", operation: "send" as const, inputs: ["uint256"] },
      { selector: "MixedProtocolVault.withdraw", operation: "send" as const, inputs: ["uint256"] },
      { selector: "MixedProtocolVault.totalDeposits", operation: "call" as const, inputs: [] },
      { selector: "MixedProtocolVault.balances", operation: "call" as const, inputs: ["address"] },
    ];
    const mixedAnalysis = evaluateDeterministicAnalysisTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId: sha("mixed-lead"),
        path: mixedPath,
        selector: "MixedProtocolVault.withdraw",
        sourceEvidence: `${mixedPath}:0-200:${mixedSnap.sha256}`,
      },
      sources: [mixedSnap],
      repositoryCommit: commitSha,
      declarations: mixedDecls,
      enableSpecializedEscalation: false,
    });
    assert.ok(mixedAnalysis, "evaluateDeterministicAnalysisTurn must return structured result");
    assert.equal(mixedAnalysis!.analyticalDisposition.action, "defer_lead", "Private rewards getter must defer top relational hypothesis");
    assert.equal(mixedAnalysis!.analyticalDisposition.status, "uncertain");
    assert.equal(mixedAnalysis!.analyticalDisposition.smtRefuted, false);
    assert.equal(mixedAnalysis!.constructionFeasibility.attempted, true, "Deferred non-SMT-refuted lead must still check construction feasibility");
    assert.equal(mixedAnalysis!.constructionFeasibility.feasible, true, "Alternative supported conservation property must still construct");
    assert.ok(mixedAnalysis!.experimentCandidates.length >= 1);

    const mixedAction = driveDeterministicAuditTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId: sha("mixed-lead"),
        path: mixedPath,
        selector: "MixedProtocolVault.withdraw",
        sourceEvidence: `${mixedPath}:0-200:${mixedSnap.sha256}`,
      },
      sources: [mixedSnap],
      repositoryCommit: commitSha,
      declarations: mixedDecls,
      constraints: { action: ["discover_experiment", "assess_lead", "defer_lead"] },
      enableSpecializedEscalation: false,
    });
    assert.equal(
      mixedAction.action,
      "discover_experiment",
      "Driver must propose discover_experiment for constructible property even when a companion relational hypothesis was deferred",
    );

    // When Z3 proves smt_unsat_guard on the same lead, construction MUST be skipped
    const refutedGraph = buildProgramFactsGraph({ sources: [mixedSnap] });
    refutedGraph.byFile.get(mixedPath)!.facts.push({
      id: sha("z3-unsat-fact"),
      adapter: "z3",
      language: "solidity",
      kind: "smt_unsat_guard",
      file: mixedPath,
      line: 12,
      symbol: "MixedProtocolVault.withdraw",
      detail: "Guard proved unsatisfiable by Z3",
      severity: "info",
    });
    const refutedAnalysis = evaluateDeterministicAnalysisTurn({
      stage: "ANALYZE",
      analyzeModelPending: true,
      activeLead: {
        leadId: sha("mixed-lead-refuted"),
        path: mixedPath,
        selector: "MixedProtocolVault.withdraw",
        sourceEvidence: `${mixedPath}:0-200:${mixedSnap.sha256}`,
      },
      sources: [mixedSnap],
      graph: refutedGraph,
      repositoryCommit: commitSha,
      declarations: mixedDecls,
      enableSpecializedEscalation: false,
    });
    assert.equal(refutedAnalysis!.analyticalDisposition.status, "contradicted");
    assert.equal(refutedAnalysis!.analyticalDisposition.smtRefuted, true);
    assert.equal(refutedAnalysis!.constructionFeasibility.attempted, false);
    assert.equal(refutedAnalysis!.constructionFeasibility.skippedReason, "smt_unsat_guard");

    // 12e. Upfront host capability logging + batch-vs-inventory coverage in live runLocalAudit
    const covAuditDir = await mkdtemp(join(tmpdir(), "lotus-cov-"));
    try {
      const covRepoDir = join(covAuditDir, "source-0");
      await mkdir(join(covRepoDir, "contracts"), { recursive: true });
      await writeFile(join(covRepoDir, "contracts/DInterest.sol"), dInterestSrc, "utf8");
      execFileSync("git", ["init", "-q"], { cwd: covRepoDir });
      execFileSync("git", ["config", "user.email", "test@lotus.local"], { cwd: covRepoDir });
      execFileSync("git", ["config", "user.name", "LOTUS Test"], { cwd: covRepoDir });
      execFileSync("git", ["add", "."], { cwd: covRepoDir });
      execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: covRepoDir });
      const covLog = join(covAuditDir, "audit.log");
      const prevMaxLeads = process.env.LOCAL_ANALYZE_MAX_LEADS;
      process.env.LOCAL_ANALYZE_MAX_LEADS = "1";
      try {
        await runLocalAudit(
          "Audit DInterest.sol deterministically.",
          covLog,
          30_000,
          covAuditDir,
          "deterministic",
          undefined,
          {
            maxTurns: 25,
            numPredict: 512,
            numCtx: 8192,
            productionWorkflow: true,
            verifyPython: true,
            controllerIndex: true,
            initialSourcePaths: ["source-0/contracts/DInterest.sol"],
            validateFinal: () => null,
            verifySource: async () =>
              JSON.stringify({ status: "not_observed", behavior_observed: false, note: "stubbed_local_verifier" }),
          },
        );
      } finally {
        if (prevMaxLeads === undefined) delete process.env.LOCAL_ANALYZE_MAX_LEADS;
        else process.env.LOCAL_ANALYZE_MAX_LEADS = prevMaxLeads;
      }
      const covLogText = await readFile(covLog, "utf8");
      const capsIdx = covLogText.indexOf("[DETERMINISTIC_HOST_CAPABILITIES]");
      const winIdx = covLogText.indexOf("[ANALYSIS_MODEL_WINDOW_STARTED]");
      assert.ok(capsIdx >= 0, "Audit log must emit [DETERMINISTIC_HOST_CAPABILITIES] upfront");
      assert.ok(winIdx < 0 || capsIdx < winIdx, "[DETERMINISTIC_HOST_CAPABILITIES] must precede ANALYZE window");
      const completeMatch = covLogText.match(/\[ANALYSIS_COMPLETE\]\s+(\{[^\n]+\})/);
      assert.ok(completeMatch, "Audit log must record [ANALYSIS_COMPLETE]");
      const completePayload = JSON.parse(completeMatch![1]);
      assert.equal(completePayload.batchCoverage, "complete");
      assert.ok(completePayload.inventoryTotal >= 2, `Expected >=2 total candidates, got ${completePayload.inventoryTotal}`);
      const coverageBatches = covLogText.split("\n")
        .filter(line=>line.startsWith("[ANALYSIS_BATCH_STARTED] "))
        .map(line=>JSON.parse(line.slice("[ANALYSIS_BATCH_STARTED] ".length)) as {admitted:number});
      assert.ok(coverageBatches.length>=2, "Batch size one must process multiple batches");
      assert.ok(coverageBatches.every(batch=>batch.admitted===1), "Every batch must obey the one-candidate bound");
      assert.equal(completePayload.admittedCount, completePayload.inventoryTotal,
        "Every eligible candidate must be accounted for before ANALYZE closes");
      assert.equal(completePayload.queuedRemaining,0);
      assert.equal(completePayload.inventoryCoverage,"complete");
    } finally {
      await rm(covAuditDir, { recursive: true, force: true });
    }
  }

  console.log("DETERMINISTIC_LOTUS_END_TO_END_PASSED");
} finally {
  if (prevAdapter === undefined) delete process.env.LOCAL_MODEL_ADAPTER;
  else process.env.LOCAL_MODEL_ADAPTER = prevAdapter;
  if (prevOllama === undefined) delete process.env.AUTOHACK_OLLAMA_URL;
  else process.env.AUTOHACK_OLLAMA_URL = prevOllama;
  if (prevDet === undefined) delete process.env.LOTUS_DETERMINISTIC;
  else process.env.LOTUS_DETERMINISTIC = prevDet;
}
