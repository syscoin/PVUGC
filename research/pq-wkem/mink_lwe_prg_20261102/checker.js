'use strict';
// Independently executed small-parameter algebra checker. NOT a QPT or 128-bit test.
const crypto=require('crypto');
let assertions=0;
function ok(v,m){assertions++;if(!v)throw Error('check '+assertions+': '+m)}
const shake=(tag,n)=>crypto.createHash('shake256',{outputLength:n}).update(tag).digest();
const H=x=>crypto.createHash('sha256').update(x).digest('hex');
const n=4,m=24,a=3,q=256,L=n*8+m*a,O=m*8;
ok(L<O,'strict expansion');
const A=shake('TOY-ONLY/MINK-LWE-PRG/A',n*m);
const seed=shake('TOY-ONLY/MINK-LWE-PRG/seed',L/8);
function generator(S){
  ok(S.length===L/8,'state length');
  const secret=[...S.subarray(0,n)];
  let eBig=BigInt('0x'+Buffer.from(S.subarray(n)).reverse().toString('hex'));
  const out=Buffer.alloc(m);
  for(let i=0;i<m;i++){
    const e=Number(eBig&7n)-4;eBig>>=3n;
    let acc=e;
    for(let j=0;j<n;j++)acc+=A[i*n+j]*secret[j];
    out[i]=acc&255;
    ok(out[i]>=0&&out[i]<256,'correct field range');
  }
  ok(eBig===0n,'exact bit seed consumption');return out;
}
function expand(S,t){let data=Buffer.alloc(0);for(let i=0;i<t;i++){
  const b=generator(S);S=b.subarray(0,L/8);data=Buffer.concat([data,b.subarray(L/8)]);
}return data;}
const stretch=expand(seed,5);
ok(stretch.length===5*(O-L)/8,'5 rounds output');
const TRUE=[6,12],FALSE=[6,12,11],delta=7;
const parity=x=>(x.toString(2).replace(/0/g,'').length&1);
const evaluates=(rows,z)=>rows.every(row=>!parity(row&(1|((z&1)<<1)|((z&2)<<1)|((z&4)<<1))));
const satisfiers=rows=>Array.from({length:8},(_,i)=>i).filter(z=>evaluates(rows,z));
ok(JSON.stringify(satisfiers(TRUE))==='[0,7]','two original witnesses');
ok(satisfiers(FALSE).length===0,'false original');
ok(FALSE.reduce((x,y)=>x^y,0)===1,'public false refutation');
const C=(rows,r,bit)=>rows.reduce((c,v,i)=>c^((r>>i&1)?v:0),bit);
for(const witness of [0,7])for(let k=0;k<2;k++)for(let a=0;a<2;a++)for(let b=0;b<2;b++)
  for(let r0=0;r0<4;r0++)for(let r1=0;r1<4;r1++)for(let r2=0;r2<4;r2++){
    const t=1|(witness<<1),ms=[a,b,k^a^b];
    const cs=[C(TRUE,r0,ms[0]),C(TRUE,r1,ms[1]),C(TRUE,r2,ms[2])];
    ok((cs.reduce((acc,c)=>acc^parity(t&c),0))===k,'all-witness common capability');
  }
function visible(k,pair){const D=new Map();for(let a=0;a<2;a++)for(let b=0;b<2;b++)
 for(let r0=0;r0<8;r0++)for(let r1=0;r1<8;r1++)for(let r2=0;r2<8;r2++){
  const ms=[a,b,k^a^b],rs=[r0,r1,r2],cs=rs.map((r,j)=>C(FALSE,r,ms[j]));
  const key=JSON.stringify([cs,pair.map(j=>[ms[j],rs[j]])]);
  D.set(key,(D.get(key)||0)+1);
 }return D;}
for(const pair of [[0,1],[0,2],[1,2]]){
 const d0=visible(0,pair),d1=visible(1,pair);
 ok(d0.size===d1.size&&d0.size===2048,'same support');
 for(const [v,c] of d0)ok(d1.get(v)===c,'exact visible distribution');
 for(let r=0;r<8;r++)for(let bit=0;bit<2;bit++)
  ok(C(FALSE,r^((bit)?delta:0),bit)===C(FALSE,r,0),'simulated opening');
}
console.log(JSON.stringify({run_id:'MINK-LWE-PRG-20261102-T20',kind:'independent-small-fixture',assertions,
 q,n,m,a,seed_bits:L,output_bits:O,stretch_bytes:stretch.length,
 false_distributions:'exact for all three two-lane openings',true_witnesses:[0,7],
 matrix_sha256:H(A),stretch_sha256:H(stretch),
 caveat:'Toy algebra only; full-size Python and proof in offline archive.'},null,2));
