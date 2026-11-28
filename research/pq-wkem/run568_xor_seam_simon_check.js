'use strict';
// Deterministic finite checks for an XOR-symmetric seam. NOT a quantum implementation.
const crypto=require('crypto');
const assert=require('assert');
let assertions=0,fixtures=0,orbits=0,walshChecks=0,derivedKeys=0;
function test(cond){assert.ok(cond);assertions++;}
function hash(seed,x,m){
  const h=crypto.createHash('sha256').update(seed+'|'+x).digest('hex');
  return BigInt('0x'+h)&((1n<<BigInt(m))-1n);
}
function parity(v){let p=0;while(v){p^=1;v&=v-1;}return p;}
for(let n=3;n<=9;n++)for(let rep=0;rep<6;rep++){
  const N=2**n, delta=1+((n*131+rep*73)%(N-1)), m=2*n+20;
  const seed='RUN568/H/'+n+'/'+rep;
  const H=Array.from({length:N},(_,x)=>hash(seed,x,m));
  const F=H.map((v,x)=>v^H[x^delta]);
  const pairs=new Map();
  for(let x=0;x<N;x++){
    test(F[x]===F[x^delta]);
    const k=F[x].toString(16);
    if(!pairs.has(k))pairs.set(k,[]);
    pairs.get(k).push(x);
  }
  test(pairs.size===N/2);
  for(const xs of pairs.values()){
    test(xs.length===2 && (xs[0]^xs[1])===delta);
    orbits++;
  }
  // Fourier amplitudes of (|a>+|a xor delta>)/sqrt(2):
  // zero exactly when y.dot(delta)=1; nonzero otherwise.
  for(const xs of Array.from(pairs.values()).slice(0,3)){
    const a=xs[0];
    for(let y=0;y<N;y++){
      const sum=(parity(a&y)?-1:1)+(parity((a^delta)&y)?-1:1);
      test((sum===0)===(parity(delta&y)===1));
      test((Math.abs(sum)===2)===(parity(delta&y)===0));
      walshChecks+=2;
    }
  }
  // Exact sampling from the analytically derived Simon measurement law.
  const measured=[];
  for(let ctr=0;measured.length<n+16;ctr++){
    const y=Number(hash('RUN568/measure/'+seed,ctr,n));
    if(parity(y&delta)===0)measured.push(y);
    test(ctr<5000);
  }
  const possible=[];
  for(let d=1;d<N;d++)if(measured.every(y=>parity(y&d)===0))possible.push(d);
  test(possible.length===1 && possible[0]===delta);
  // Once delta is learned, a separate domain-separated key is public-computable.
  const K=crypto.createHash('sha256').update('RUN568/key/'+delta+'/claim-'+n+'-'+rep).digest('hex');
  const recovered=crypto.createHash('sha256').update('RUN568/key/'+possible[0]+'/claim-'+n+'-'+rep).digest('hex');
  test(K===recovered);derivedKeys++;
  fixtures++;
}
// At small output widths the strict Simon promise fails by pigeonhole.
{
 const n=5,N=2**n,delta=3,m=1;
 const H=Array.from({length:N},(_,x)=>hash('RUN568/lowwidth',x,m));
 const F=H.map((v,x)=>v^H[x^delta]);
 const distinct=new Set(F.map(v=>v.toString()));
 test(distinct.size<=2 && distinct.size<N/2);
}
console.log(JSON.stringify({run:568,result:'PASS',assertions,fixtures,orbits,walshChecks,derivedKeys,low_width_extra_collisions:true,model:'Finite classical evaluation and exact Fourier-identity checks. No quantum hardware.',security_proved:false},null,2));
