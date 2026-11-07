function run543(){
 const mask64=(1n<<64n)-1n;
 function mix(x){x=(x+0x9e3779b97f4a7c15n)&mask64;x=((x^(x>>30n))*0xbf58476d1ce4e5b9n)&mask64;x=((x^(x>>27n))*0x94d049bb133111ebn)&mask64;return(x^(x>>31n))&mask64;}
 function pop(x){let c=0;for(;x;x&=x-1)c++;return c;}
 function test(n,k,domain){let N=1<<n, half=n>>1,m=(1<<half)-1;
  function round(r,x){return Number(mix(BigInt((n<<20)|(r<<12)|x))&BigInt(m));}
  function p(x){let l=x>>half,r=x&m;for(let j=0;j<7;j++) [l,r]=[r,l^round(j,r)];return(l<<half)|r;}
  function inv(x){let l=x>>half,r=x&m;for(let j=6;j>=0;j--) [l,r]=[r^round(j,l),l];return(l<<half)|r;}
  function H(u){return mix((BigInt(domain)<<32n)|(BigInt(n)<<16n)|BigInt(u));}
  let vals=Array.from({length:N},(_,s)=>H(p(s))^H(p(s)^k));
  let fiber=new Map, diffs=[], inverse=0, correct=0;
  for(let s=0;s<N;s++){let u=p(s),t=inv(u^k);if(inv(u)!==s)throw Error('inverse');inverse++;if(t===s||vals[s]!==vals[t]||(u^p(t))!==k)throw Error('common capability');correct++;fiber.set(String(vals[s]),1+(fiber.get(String(vals[s]))||0));if(s<t)diffs.push(s^t);}
  if(fiber.size!==N/2||[...fiber.values()].some(v=>v!==2))throw Error('unexpected collision');
  let period=[];for(let d=1;d<N;d++)if(vals.every((v,s)=>v===vals[s^d]))period.push(d);
  if(period.length)throw Error('visible raw XOR period');
  let rawOutside=0,conjSupport=0,rawMass=0;
  for(let z=0;z<N;z++){let ct=0;for(const d of diffs)if(pop(z&d)%2===0)ct++;rawMass+=4*ct;if(pop(z&k)%2){if(ct)rawOutside++;}else conjSupport++;}
  if(rawMass!==N*N||!rawOutside||conjSupport!==N/2)throw Error('Fourier check');
  return {n,k,domain,inverse_checks:inverse,accepted_pair_checks:correct,cosets:diffs.length,distinct_raw_displacements:new Set(diffs).size,visible_raw_periods:period,raw_hadamard_outcomes_outside_conjugate_hyperplane:rawOutside,conjugate_hadamard_support:conjSupport};
 }
 return {run:543,checker:'exact nonlinear reversible frame / Simon conjugacy finite identities',hash:'toy SplitMix64, NOT cryptographic',cases:[test(8,37,101),test(8,161,102),test(10,391,103),test(10,719,104)],passed:true};
}
if(typeof process!=='undefined' && process.stdout)process.stdout.write(JSON.stringify(run543(),null,2)+'\n');
