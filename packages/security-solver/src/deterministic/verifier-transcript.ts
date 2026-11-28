/** Keep the original source-bound verifier transcript for evidence checks.
 * fitAuditToolOutput may deliberately shorten the version shown to the model.
 * A display abbreviation is not the executed compiler/EVM transcript.
 *
 * Never reconstruct missing source identity from the candidate snapshot:
 * the original verifier must actually have reported it.
 */
export function unfittedVerifierTranscript(original:string|undefined,displayed:string):string {
  if(original===undefined)return displayed;
  try {
    const full=JSON.parse(original) as Record<string,unknown>;
    const view=JSON.parse(displayed) as Record<string,unknown>;
    if(!full||typeof full!=="object"||Array.isArray(full)||
      !view||typeof view!=="object"||Array.isArray(view))return displayed;
    // A differing status means the delivered transcript was transformed
    // semantically; do not silently substitute either as successful evidence.
    if(typeof full.status!=="string"||typeof view.status!=="string"||
      full.status!==view.status)return displayed;
    return original;
  } catch {
    return displayed;
  }
}
