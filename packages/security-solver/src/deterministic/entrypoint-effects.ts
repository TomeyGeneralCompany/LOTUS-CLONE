/** Resolved-only, cycle-safe internal-call effect summaries for source-grounded analysis. */
import type {ProgramFactsGraph,ProgramFact,ProgramEdge} from "./program-facts";

export interface EntrypointEffectSummary {
  entrypoint:string;
  reachableFunctions:string[];
  stateReads:string[];
  stateWrites:string[];
  valueTransfers:string[];
  externalCalls:ProgramEdge[];
  guards:ProgramFact[];
  unresolvedCalls:ProgramEdge[];
  facts:ProgramFact[];
}

export function summarizeEntrypointEffects(
  graph:ProgramFactsGraph,entrypoint:string
):EntrypointEffectSummary {
  const calls=new Map<string,Set<string>>();
  for(const edge of graph.edges){
    if(edge.kind!=="calls_resolved"||edge.resolution!=="resolved")continue;
    const list=calls.get(edge.from)||new Set<string>();
    list.add(edge.to);calls.set(edge.from,list);
  }
  const visited=new Set<string>();
  const todo=[entrypoint];
  while(todo.length){
    const symbol=todo.pop()!;
    if(visited.has(symbol))continue;
    visited.add(symbol);
    for(const target of calls.get(symbol)||[])if(!visited.has(target))todo.push(target);
  }
  const stateReads=new Set<string>(),stateWrites=new Set<string>();
  const externalCalls:ProgramEdge[]=[];
  const unresolvedCalls:ProgramEdge[]=[];
  for(const edge of graph.edges){
    if(!visited.has(edge.from))continue;
    if(edge.kind==="reads_state")stateReads.add(edge.to);
    if(edge.kind==="writes_state")stateWrites.add(edge.to);
    if(edge.kind==="external_call"){
      externalCalls.push(edge);
      if(edge.resolution!=="resolved")unresolvedCalls.push(edge);
    }
    if(edge.kind==="calls_resolved"&&edge.resolution!=="resolved")unresolvedCalls.push(edge);
  }
  // Facts remain tied to their originating symbol and source location.
  const facts=graph.facts.filter(f=>!!f.symbol&&visited.has(f.symbol));
  return {
    entrypoint,reachableFunctions:[...visited].sort(),
    stateReads:[...stateReads].sort(),stateWrites:[...stateWrites].sort(),
    valueTransfers:facts.filter(f=>f.kind==="value_transfer").map(f=>`${f.file}:${f.line}:${f.symbol}`),
    externalCalls,guards:facts.filter(f=>f.kind==="auth_guard"||f.kind==="constraint_guard"),
    unresolvedCalls,facts,
  };
}
