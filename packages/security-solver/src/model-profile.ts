/** LOTUS-CLONE has one controller engine; legacy model profile variables
 * cannot affect the investigation or its evidence evaluation.
 */
export function modelProfile(_stage?:string) {
  return {name:'deterministic' as const,think:false,options:{temperature:0}};
}
