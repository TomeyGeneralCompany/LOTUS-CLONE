/** Strict deterministic routing of source-identified, still-unmet security
 * property prerequisites. A completed experiment for one obligation does not
 * erase the unmet independent obligations of the same frozen source lead.
 * This returns routes, NEVER evidence or a conclusive disposition. */
export type SourceRepairCategory=
  |"missing_fixture"|"unresolved_dependency"
  |"no_supported_property"|"missing_observable_state";
export interface SourceRepairRoutes {
  categories:SourceRepairCategory[];
  concrete:boolean;
  callers:boolean;
  hasUnresolved:boolean;
}
export function sourceRepairRoutes(
  construction:SourceRepairCategory|null|undefined,
  outstanding:readonly string[],
  constructed:boolean,
):SourceRepairRoutes {
  const categories=new Set<SourceRepairCategory>();
  if(construction)categories.add(construction);
  for(const reason of outstanding){
    if(/(?:^|\W)no_supported_property(?:\W|$)|source_grounded_falsifier_missing/.test(reason))
      categories.add("no_supported_property");
    if(/(?:^|\W)missing_fixture(?:\W|$)|(?:^|\W)initializer_dependency(?:\W|$)/.test(reason))
      categories.add("missing_fixture");
    if(/(?:^|\W)unresolved_dependency(?:\W|$)|^(?:unresolved_external_call|unresolved_call|ambiguous_call):/.test(reason))
      categories.add("unresolved_dependency");
    if(/(?:^|\W)missing_observable_state(?:\W|$)|^missing_public_getter:/.test(reason))
      categories.add("missing_observable_state");
  }
  const hasUnresolved=!constructed||outstanding.length>0;
  const concrete=hasUnresolved&&categories.size>0;
  return {categories:[...categories].sort(),concrete,
    callers:concrete,hasUnresolved};
}
