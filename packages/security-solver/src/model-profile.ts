/** LOTUS-CLONE uses its deterministic controller, not model sampling profiles. */
export function modelProfile(_stage?:string) {
  const name=process.env.LOCAL_MODEL_PROFILE || 'deterministic';
  if(name!=='deterministic')throw new Error('LOTUS_MODEL_REMOVED: non-deterministic profiles are unsupported');
  return {name:'deterministic' as const,think:false,options:{temperature:0}};
}
