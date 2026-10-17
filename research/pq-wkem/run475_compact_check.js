"use strict";
// Run 475 semantic-only checker. Not FHE/FE, not PQ.
function run475(){
 let count=0;const check=(b,s)=>{count++;if(!b)throw Error(s)};
 const W=Array.from({length:16},(_,i)=>[3,2,1,0].map(j=>i>>j&1));
 const R=(x,w)=>x==="true"&&w.length===4&&w[0]===1&&(w[2]^w[3])===1;
 const tag=(a,x,b,w)=>{let v=a>>>0;for(const c of x+"|"+b+"|"+w.join(""))v=Math.imul(v^c.charCodeAt(0),16777619)>>>0;return v};
 const inv=(a,b)=>{let [x,y,u,v]=[a,b,1n,0n];while(y){const q=x/y;[x,y]=[y,x-q*y];[u,v]=[v,u-q*v]}return [x,u]};
 const power=(a,k,n)=>{let r=1n;for(;k;k>>=1n,a=a*a%n)if(k&1n)r=r*a%n;return r};
 const msgNum=(s,n)=>{let t=17;for(const c of s)t=(Math.imul(t,131)+c.charCodeAt(0))>>>0;return BigInt(2+t%Number(n-3n))};
 const P=[101,103,107,109,113,127,131,137],Q=[139,149,151,157,163,167,173,179];
 const stat={contexts:0,honest_valid_releases:0,false_witnesses:0,false_honest_releases:0,false_attacker_releases:0,source_checked_false_releases:0,native_checks:0};
 for(let i=0;i<8;i++){
  const x=i%2?"false":"true",ctx="UTXO-"+i+"|challenge|anchor-"+i,p=BigInt(P[i]),q=BigInt(Q[i]),n=p*q,phi=(p-1n)*(q-1n),e=65537n,[g,d0]=inv(e,phi);
  check(g===1n,"inverse");const d=(d0%phi+phi)%phi,store=new Map();let counter=0;
  const seal=z=>{let h=ctx+":"+(++counter);store.set(h,z);return h};
  const c0=seal({d,alpha:(100001+i*991)>>>0,ctx,x,b:0,w:[0,0,0,0],t:0});
  const Eval=(c,F)=>seal(F({...store.get(c)}));
  const Open=(c,request,source)=>{const z=store.get(c);return z.ctx===request&&z.b===1&&z.t===tag(z.alpha,z.ctx,z.b,z.w)&&(!source||R(z.x,z.w))?z.d:null};
  const honest=w=>z=>{const b=Number(R(z.x,w));return {...z,b,w,t:tag(z.alpha,z.ctx,b,w)}};
  const evil=z=>{const w=[0,0,0,0];return {...z,b:1,w,t:tag(z.alpha,z.ctx,1,w)}};
  let hit=0;stat.contexts++;check(Open(c0,ctx,false)===null,"premature release");
  for(const w of W){const k=Open(Eval(c0,honest(w)),ctx,false),valid=R(x,w);check((k!==null)===valid,"honest correctness");if(valid){hit++;stat.honest_valid_releases++;check(k===d,"same key")};if(x==="false"&&k!==null)stat.false_honest_releases++}
  check(hit===(x==="true"?4:0),"valid-witness count");if(x==="false")stat.false_witnesses+=hit;
  const cbad=Eval(c0,evil),k=Open(cbad,ctx,false);check(k===d,"unauthorized recovery");
  const message=ctx+"|native-challenge";let wrong=ctx+"|normal";
  while(msgNum(wrong,n)===msgNum(message,n))wrong+="x";
  const signature=power(msgNum(message,n),k,n);
  check(power(signature,e,n)===msgNum(message,n),"native authorized");
  check(power(signature,e,n)!==msgNum(wrong,n),"wrong branch");
  stat.native_checks++;
  check(Open(cbad,ctx+"|other-UTXO",false)===null,"context replay");
  check(Open(cbad,ctx,true)===null,"source control");
  if(x==="false")stat.false_attacker_releases++;
 }
 check(stat.contexts===8&&stat.honest_valid_releases===16,"counts");
 check(stat.false_witnesses===0&&stat.false_honest_releases===0,"false controls");
 check(stat.false_attacker_releases===4&&stat.source_checked_false_releases===0,"bypass controls");
 return {run:475,assertions_passed:count,results:stat,model:"opaque unrestricted ideal Eval; NO actual FHE/FE",native_signature:"textbook toy RSA, insecure and non-PQ",security_claim:"none"};
}
if(typeof process!=="undefined")console.log(JSON.stringify(run475(),null,2));
