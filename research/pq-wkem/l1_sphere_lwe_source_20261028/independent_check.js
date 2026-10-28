'use strict';
// Independently derives the cardinality by a generating-function DP, not by the
// binomial-support/composition formula used in verify.py. Pure exact bigint arithmetic.
const assert=require('assert').strict;
const m=1600,h=696,q=65537,n=128,bits=256;
let checks=0;
function check(v,msg){checks++;assert.ok(v,msg);}
const prev=Array(h+1).fill(0n); prev[0]=1n;
let cur=prev;
let prevLevel;
for(let d=1;d<=m;d++){
  const nxt=Array(h+1).fill(0n);
  let prefix=0n;
  nxt[0]=cur[0];
  for(let t=1;t<=h;t++){
    prefix+=cur[t-1];
    nxt[t]=cur[t]+2n*prefix;
    if(d<=6&&t<=5){
      check(nxt[t]>=0n,'non-negative coefficient');
    }
  }
  if(d===m-1)prevLevel=nxt;
  cur=nxt;
}
const count=cur[h], ternary=3n**BigInt(m);
check(count>ternary,'strict entropy improvement');
const g=2*h+1,radix=Math.floor(q/g);
check(g===1393&&radix===47,'exact release parameters');
check(BigInt(radix)**46n<2n**BigInt(bits) && 2n**BigInt(bits)<=BigInt(radix)**47n,'radix minimum');
check(47n*47n*ternary < 60n*60n*count,'stronger joint TV bound');
check(2*h<q,'all distinct integer noise vectors stay distinct modulo q');
const nzeroNum=count-prevLevel[h];
const expectedSupportNum=BigInt(m)*nzeroNum;
const expectedSupport=Number(expectedSupportNum*100000000n/count)/100000000;
check(expectedSupport>550&&expectedSupport<553,'independent expected support');
function exactCountSmall(mm,hh){
  let a=Array(hh+1).fill(0n);a[0]=1n;
  for(let i=0;i<mm;i++){
    const b=Array(hh+1).fill(0n);let sum=0n;
    b[0]=a[0];for(let j=1;j<=hh;j++){sum+=a[j-1];b[j]=a[j]+2n*sum;}
    a=b;
  }
  return a[hh];
}
check(exactCountSmall(3,2)===18n,'independent small sphere = 18');
check(exactCountSmall(4,3)===88n,'independent small sphere = 88');
// Count all norm-2 3-vectors and independently verify hash-collision identity over F7.
const V=[];
for(let a=-2;a<=2;a++)for(let b=-2;b<=2;b++)for(let c=-2;c<=2;c++)
  if(Math.abs(a)+Math.abs(b)+Math.abs(c)===2)V.push([a,b,c]);
check(V.length===18,'exact small l1 sphere enumerable');
let collisionTotal=0;
for(let a=0;a<7;a++)for(let b=0;b<7;b++)for(let c=0;c<7;c++){
  let bins=Array(7).fill(0);
  for(const r of V){let y=((a*r[0]+b*r[1]+c*r[2])%7+7)%7;bins[y]++;}
  collisionTotal+=bins.reduce((s,z)=>s+z*z,0);
}
check(collisionTotal===7**3*18+7**2*18*17,'two universality independent collision');
console.log(JSON.stringify({record:'l1-sphere-lwe-source-20261028-turn11-independent',status:'PASS',checks,
    count_bit_length:count.toString(2).length,
    entropy_greater_than_ternary:count>ternary,
    q,m,n,h,g,radix,columns:47,
    expected_nonzero_coordinates:expectedSupport,
    exact_joint_bound_stronger:true,
    elementary_collision_matrices:343,
    security:'exact integer algebra only; not QPT cryptanalysis'},null,2));
