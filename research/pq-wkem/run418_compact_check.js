'use strict';
// Run 418: ideal black-box release on polynomially enumerable public controls.
// This is finite algebra, NOT a WE, QPT, obfuscation, or native-signature test.
let checks=0, subsets=0, queries=0, fixtures=0, falseChecks=0;
function ok(v) { checks++; if(!v) throw Error('assert '+checks); }
for(let n=1;n<=10;n++) for(let mask=1;mask<(1<<n);mask++) {
  let found=-1;
  for(let t=0;t<n;t++){queries++;if(mask & (1<<t)){found=t;break;}}
  ok(found>=0 && found<n); ok((mask & (1<<found))!==0);
  subsets++;
}
for(let x=0;x<128;x++) for(let n=3;n<=17;n++) {
  // The source witness may have an unknown preimage z and one additional bit.
  // The release never receives z: it only receives a public control index.
  const key=(x*2654435761+n*7919)>>>0;
  const t0=x%n, t1=(t0+1+(x%(n-1)))%n;
  ok(t0!==t1);
  const release=(active,t)=>(active && (t===t0 || t===t1))?key:null;
  ok(release(true,t0)===key && release(true,t1)===key);
  let recovered=null;
  for(let t=0;t<n;t++){const out=release(true,t); if(out!==null){recovered=out;break;}}
  ok(recovered===key); // no witness supplied
  for(let t=0;t<n;t++){ok(release(false,t)===null);falseChecks++;}
  fixtures++;
}
const result={run:418,subsets,queries,fixtures,falseChecks,assertions:checks,
  result:'bounded public-control enumeration recovers key without ORIGINAL witness',
  limits:'ideal opaque oracle and finite tests; no real cryptographic security established'};
const output=JSON.stringify(result,null,2)+'\n';
if(typeof console!=='undefined') console.log(JSON.stringify(result,null,2));
output;
