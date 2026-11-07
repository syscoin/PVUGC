"use strict";
function run() {
  let assertions=0;
  function check(x,label){assertions++;if(!x)throw Error("assert "+assertions+" "+label);}
  const id=[0,1,2,3], cn=[0,1,3,2], perms=[];
  function gen(a,b){if(!b.length){perms.push(a);return;}for(let i=0;i<b.length;i++)gen(a.concat(b[i]),b.slice(0,i).concat(b.slice(i+1)));}
  gen([],id);
  function mul(p,q){return q.map(i=>p[i]);}
  function inv(p){let z=Array(4);p.forEach((v,i)=>z[v]=i);return z;}
  function key(p){return p.join("");}
  function same(p,q){return key(p)===key(q);}
  function edge(t,g,s){return mul(mul(t,g),inv(s));}
  function fixed(p){return p.filter((v,i)=>v===i).length;}
  function recover(a,b){let h=mul(a,inv(b));let n=fixed(h);check(n===2||n===4,"type");return {bit:n===2?1:0,h};}
  const samples={};
  let totalTwo=0, totalThree=0;
  for(const bit of [0,1]){
    const gate=bit?cn:id;
    const A=new Map(),B=new Map(),J=new Map();
    for(const ps of perms)for(const pt of perms){
      const a=edge(pt,gate,ps),b=edge(pt,id,ps),result=recover(a,b);
      check(result.bit===bit,"recover pair");
      check(same(result.h,edge(pt,gate,pt)),"conjugacy");
      A.set(key(a),(A.get(key(a))||0)+1);
      B.set(key(b),(B.get(key(b))||0)+1);
      const p=key(a)+":"+key(b);J.set(p,(J.get(p)||0)+1);
      totalTwo++;
    }
    check(A.size===24 && [...A.values()].every(z=>z===24),"A uniform");
    check(B.size===24 && [...B.values()].every(z=>z===24),"B uniform");
    const support=bit?144:24, freq=bit?4:24;
    check(J.size===support && [...J.values()].every(z=>z===freq),"joint support");
    samples[String(bit)]={framePairs:576, marginalDistinct:24, marginalCountEach:24,jointSupport:support,jointFrequencyEach:freq,fixedPoints:bit?2:4,bitRecovery:"576/576"};
    for(const ps of perms)for(const pm of perms)for(const pt of perms){
      const a1=edge(pm,gate,ps),a2=edge(pt,id,pm),b=edge(pt,id,ps);
      const r=recover(mul(a2,a1),b);
      check(r.bit===bit,"two hop bit");
      check(same(r.h,edge(pt,gate,pt)),"two hop seam");
      totalThree++;
    }
  }
  check(totalTwo===1152,"two count");
  check(totalThree===27648,"three count");
  return {run:502,assertions,twoEndpointCases:totalTwo,threeFrameCases:totalThree,
    exactMarginalAndJoint:samples,
    attack:"public reconvergent path-pair fixed-point invariant",
    scope:"finite exposed S4 gate truth tables, classical PPT attack (therefore QPT); no deployed RIO, native PQ, FHE, ZK or completed WKEM"};
}
const data=run();
if(typeof module!=="undefined" && module && typeof console!=="undefined")console.log(JSON.stringify(data,null,2));
