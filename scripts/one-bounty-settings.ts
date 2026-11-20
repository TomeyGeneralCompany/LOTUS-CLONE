/** Select the only authorized LOTUS-CLONE investigation engine.
 * Imported legacy model settings cannot activate inference.
 */
export function ensureOneBountyDeterministicEngine(env:NodeJS.ProcessEnv):'deterministic' {
  env.LOCAL_MODEL_ADAPTER='deterministic';
  delete env.LOCAL_OLLAMA_MODEL;
  delete env.LOCAL_MODEL_PROFILE;
  return 'deterministic';
}
