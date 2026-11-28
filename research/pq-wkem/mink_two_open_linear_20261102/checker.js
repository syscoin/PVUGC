'use strict';
// R17 exact finite algebra checker, not a quantum-security test.
const crypto = require('crypto');
let checks = 0;
function ok(x,why='check'){ checks++; if(!x) throw new Error(why+' at '+checks); }
function M(x,D){let y=0;for(let i=0;i<D;i+=2){let a=(x>>i)&1,b=(x>>(i+1))&1;y|=b<<i;y|=(a^b)<<(i+1);}return y;}
function invM(x,D){let y=0;for(let i=0;i<D;i+=2){let a=(x>>i)&1,b=(x>>(i+1))&1;y|=(a^b)<<i;y|=a<<(i+1);}return y;}
function invIpM(x,D){let y=0;for(let i=0;i<D;i+=2){let a=(x>>i)&1,b=(x>>(i+1))&1;y|=b<<i;y|=(a^b)<<(i+1);}return y;}
function L(c,u,D){return c===0?0:c===1?u:M(u,D);}
function back(a,b,z,D){const pair=[a,b].sort().join('');return pair==='01'?z:pair==='02'?invM(z,D):invIpM(z,D);}
function F(seed,D){return crypto.createHash('sha256').update('R17 toy '+D+' '+seed).digest().readUInt16LE(0)&((1<<D)-1);}
const results={};
for(const D of [2,4,6,8]){
 const Z=1<<D;
 for(let a=0;a<3;a++)for(let b=a+1;b<3;b++){
  const seen=new Set();
  for(let u=0;u<Z;u++){const z=L(a,u,D)^L(b,u,D);seen.add(z);ok(back(a,b,z,D)===u,'linear inverse');}
  ok(seen.size===Z,'pairwise uniform');
  for(let sa=0;sa<2;sa++)for(let sb=0;sb<2;sb++){
   const ya=F(sa,D),yb=F(sb,D),u=back(a,b,ya^yb,D),c=ya^L(a,u,D);
   ok((c^L(a,u,D))===ya,'first opening');ok((c^L(b,u,D))===yb,'second opening');
  }
  for(const c of [a,b])for(let s=0;s<2;s++){
   const other=c===a?b:a, y=F(s,D);
   const lhs=new Map(),rhs=new Map();
   for(let yOther=0;yOther<Z;yOther++){
    const u=back(c,other,y^yOther,D), com=y^L(c,u,D), key=u+','+com;
    lhs.set(key,(lhs.get(key)||0)+1);
   }
   for(let u=0;u<Z;u++){const key=u+','+(y^L(c,u,D));rhs.set(key,(rhs.get(key)||0)+1);}
   ok(JSON.stringify([...lhs].sort())===JSON.stringify([...rhs].sort()),'revealed-seed exact joint law');
  }
  if(D<=6){const seenPairs=new Set();for(let ya=0;ya<Z;ya++)for(let yb=0;yb<Z;yb++){
   const u=back(a,b,ya^yb,D),c=ya^L(a,u,D);seenPairs.add(u+','+c);
  }ok(seenPairs.size===Z*Z,'unopened joint uniformity');}
 }
 let bad=0;
 for(let u=0;u<Z;u++){
  const image=Array.from({length:3},(_,c)=>new Set([F(0,D)^L(c,u,D),F(1,D)^L(c,u,D)]));
  let collision=false;for(let a=0;a<3;a++)for(let b=a+1;b<3;b++)for(const k of image[a])if(image[b].has(k))collision=true;
  if(collision)bad++;
  ok(invM(M(u,D),D)===u,'M inverse');ok(invIpM(u^M(u,D),D)===u,'I+M inverse');
 }
 ok(bad/Z <= 12/Z,'seed-pair union bound');
 results[D]={bad_keys:bad,total_keys:Z,statistical_bound:12/Z};
}
for(let a=0;a<3;a++)for(let b=0;b<3;b++)if(a!==b){
 const D=8, vertices=[];
 for(let v=0;v<4;v++){
  const sa=v%2,sb=(v+1)%2,ya=F(sa,D),yb=F(sb,D);
  const u=back(a,b,ya^yb,D);vertices.push([u,ya^L(a,u,D),sa,sb]);
 }
 for(let v=0;v<4;v++)for(let w=v+1;w<4;w++){
  ok((vertices[v][1]^L(a,vertices[v][0],D))===F(vertices[v][2],D),'false K4 opening 1');
  ok((vertices[w][1]^L(b,vertices[w][0],D))===F(vertices[w][3],D),'false K4 opening 2');
 }
}
console.log(JSON.stringify({candidate:'MINK-TWO-OPEN-LINEAR-R17',checks,results,
 security:'finite algebra only; QPT-LWE conditional; no SOURCE release'},null,2));
