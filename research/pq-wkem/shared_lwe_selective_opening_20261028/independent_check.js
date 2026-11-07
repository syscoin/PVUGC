'use strict';
// Independent finite and exact-integer checks; no external packages.
let checks = 0;
function ok(c,msg){if(!c)throw new Error(msg);checks++;}
const xor = xs=>xs.reduce((a,b)=>a^b,0);
let subsets=[];
for(let mask=0;mask<7;mask++)subsets.push([0,1,2].filter(i=>(mask>>i)&1));
for(const O of subsets){
  let baseline=null;
  for(let K=0;K<4;K++){
    let table=new Map();
    for(let U=0;U<4;U++)for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++){
      let Z=[a,b,c],D=U^xor(Z),V=K^U;
      let key=JSON.stringify([D,V,O.map(i=>Z[i])]);
      table.set(key,(table.get(key)||0)+1);
    }
    ok(table.size===4**(2+O.length),'support');
    for(const v of table.values())ok(v===4**(2-O.length),'perfectly uniform');
    const ser=JSON.stringify(Array.from(table.entries()).sort());
    if(baseline!==null)ok(ser===baseline,'independent native seed');
    baseline=ser;
  }
}
// An independent adaptive policy where second index depends on first revealed share.
let previous=null;
for(let K=0;K<4;K++){
  const map=new Map();
  for(let U=0;U<4;U++)for(let a=0;a<4;a++)for(let b=0;b<4;b++)for(let c=0;c<4;c++){
    const Z=[a,b,c],D=U^xor(Z),V=K^U;
    for(let C=0;C<8;C++){
      const first=(D+V+2*C)%3;
      const second=(first+1+(Z[first]&1))%3;
      const j=second===first?(first+1)%3:second;
      const key=JSON.stringify([D,V,C,first,Z[first],j,Z[j]]);
      map.set(key,(map.get(key)||0)+1);
    }
  }
  const ser=JSON.stringify(Array.from(map.entries()).sort());
  if(previous!==null)ok(previous===ser,'adaptive transcript independent of native seed');
  previous=ser;
}
// Generating-function coefficient of ((1+x)/(1-x))^m, independent of binomial formula.
const m=1600,h=696,q=65537n,n=128,ell=47;
let dp=Array(h+1).fill(0n);dp[0]=1n;
for(let row=0;row<m;row++){
  let next=Array(h+1).fill(0n),prefix=0n;
  next[0]=dp[0];
  for(let degree=1;degree<=h;degree++){
    prefix+=dp[degree-1];
    next[degree]=dp[degree]+2n*prefix;
  }
  dp=next;
}
const N=dp[h];
ok(N>3n**1600n,'strict entropy improvement');
ok(BigInt(256*ell)**2n*(q**129n-1n)*2n**256n<4n*N,'256-capsule statistical bound');
const G=2*696+1,base=Number(q)/G|0;
ok(base===47,'radix floor');
ok(Number(q)-G*(base-1)>2*696,'wrap gap');
// Deliberately verifies nonsecrecy upon all t openings (security game boundary).
for(let K=0;K<4;K++)for(let U=0;U<4;U++)for(let z0=0;z0<4;z0++)for(let z1=0;z1<4;z1++)for(let z2=0;z2<4;z2++){
 const D=U^z0^z1^z2,V=K^U;
 ok(K===(V^D^z0^z1^z2),'all-openings leakage boundary');
}
console.log(JSON.stringify({status:'PASS',suite:'independent_js_shared_key_adaptive_openings',checks,theta_cardinality_bit_length:N.toString(2).length,adaptive_policies:1,full_openings_tested:1024},null,2));
