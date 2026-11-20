// Nonsecret deterministic runtime settings used by local acceptance checks.
// Stale Ollama/Qwen variables in an imported .env have no execution authority.
import "dotenv/config";
import {hostModelTimeout} from "./model-check-settings";
console.log(JSON.stringify({
  analysisEngine:"deterministic",
  agentTimeoutMs:hostModelTimeout(),
  dbPath:process.env.DB_PATH || "data/bounty.db",
}));
