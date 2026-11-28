/** Canonical Solidity elementary ABI types. Invalid widths stay unresolved. */
export function canonicalElementaryAbiType(raw:string):string|null {
  const name=String(raw||'').trim();
  if(name==='uint')return 'uint256';
  if(name==='int')return 'int256';
  if(name==='address payable')return 'address';
  if(/^(?:address|bool|string|bytes)$/.test(name))return name;
  const integer=/^(u?int)([0-9]+)$/.exec(name);
  if(integer){
    const width=Number(integer[2]);
    return width>=8&&width<=256&&width%8===0?name:null;
  }
  const fixedBytes=/^bytes([0-9]+)$/.exec(name);
  if(fixedBytes){const width=Number(fixedBytes[1]);return width>=1&&width<=32?name:null;}
  return null;
}
