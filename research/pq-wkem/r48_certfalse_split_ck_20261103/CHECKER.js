function checkR48(){
 let assertions=0;const eq=(a,b,m)=>{if(JSON.stringify(a)!==JSON.stringify(b))throw Error(m);assertions++};const yes=(v,m)=>{if(!v)throw Error(m);assertions++};
 function inv(a,q){for(let i=1;i<q;i++)if((a*i)%q===1)return i;throw Error("inv")}
 function ind(n,active,val){
  let a=Array(1<<n).fill(0);a[0]=1;
  for(let i=0;i<active;i++){let b=Array(1<<n).fill(0);
   for(let j=0;j<a.length;j++)if(val&(1<<i))b[j|(1<<i)]+=a[j];else{b[j]+=a[j];b[j|(1<<i)]-=a[j]}a=b}
  return a;
 }
 function mul(a,b,q){let c=Array(a.length).fill(0);for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)c[i|j]=((c[i|j]+a[i]*b[j])%q+q)%q;return c}
 function quotient(n,active,q,forbid){
  const M=1<<n,fs=forbid.map(i=>ind(n,active,i));
  let rows=[];for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)rows.push(mul(fs[i],fs[j],q));
  rows=rows.filter(r=>r.some(x=>x!==0)).map(r=>r.map(x=>(x%q+q)%q));
  let piv=[],k=0;
  for(let c=0;c<M;c++){let h=rows.findIndex((r,i)=>i>=k&&r[c]);if(h<0)continue;
   [rows[k],rows[h]]=[rows[h],rows[k]];let f=inv(rows[k][c],q);rows[k]=rows[k].map(x=>x*f%q);
   for(let i=0;i<rows.length;i++)if(i!==k&&rows[i][c]){let t=rows[i][c];rows[i]=rows[i].map((x,j)=>(x-t*rows[k][j]%q+q)%q)}
   piv.push(c);if(++k===rows.length)break;
  }
  rows=rows.slice(0,k);const free=Array.from({length:M},(_,i)=>i).filter(i=>!piv.includes(i));
  function project(a){a=a.map(x=>(x%q+q)%q);for(let i=0;i<piv.length;i++){let f=a[piv[i]];if(f)a=a.map((x,j)=>(x-f*rows[i][j]%q+q)%q)}return free.map(i=>a[i])}
  function lift(z){let a=Array(M).fill(0);free.forEach((p,i)=>a[p]=z[i]);return a}
  function evalAt(a,w){return a.reduce((v,x,i)=>((i&~w)===0?v+x:v),0)%q}
  function decode(z,w){let v=evalAt(lift(z),w),Delta=(q-1)/2;let distance=x=>Math.min((v-x+q)%q,(x-v+q)%q);return +(distance(Delta)<distance(0))}
  return {q,M,rows,piv,free,project,lift,evalAt,decode};
 }
 const f=quotient(3,2,257,[0,1,2,3]),t=quotient(3,2,257,[0,1,2]),one=[1,0,0,0,0,0,0,0];
 eq([f.piv.length,f.free.length],[4,4],"false rank");
 eq([t.piv.length,t.free.length],[3,5],"true rank");
 yes(f.project(one).every(x=>x===0),"false 1 in span");
 yes(t.project(one).some(x=>x!==0),"true 1 outside span");
 for(let w of [3,7])for(let r of t.rows)eq(t.evalAt(r,w),0,"true mask vanishing");
 let seed=480711;function rng(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed}
 const bytes=n=>Array.from({length:n},()=>rng()%256),bits=a=>a.flatMap(x=>Array.from({length:8},(_,i)=>(x>>(7-i))&1));
 const xor=(a,b)=>a.map((x,i)=>x^b[i]);
 function enc(C,b){let e=Array.from({length:C.M},()=>rng()%3-1);e[0]+=((C.q-1)/2)*b;return C.project(e)}
 const pack=(C,b)=>bits(b).map(v=>enc(C,v));
 const dec=(C,z,w)=>Array.from({length:z.length/8},(_,i)=>z.slice(8*i,8*i+8).reduce((v,zi)=>v*2+C.decode(zi,w),0));
 const sig=bytes(8),pad=bytes(8),bind=bytes(4),D=xor(sig,pad);
 let Zb=pack(t,bind),Zp=pack(t,pad),context=["R","claim","UTXO","anchor","path","native VK"];
 const ck=(kb,Zb,Zp,d,c)=>JSON.stringify([kb,Zb,Zp,d,c]);let tag=ck(bind,Zb,Zp,D,context),decoded=0;
 for(let w of [3,7]){let b=dec(t,Zb,w),p=dec(t,Zp,w);
  eq(b,bind,"witness bind");eq(p,pad,"witness pad");eq(xor(D,p),sig,"witness signature");eq(ck(b,Zb,Zp,D,context),tag,"witness CK");decoded+=Zb.length+Zp.length}
 yes(ck(bind,Zb,Zp,D,[...context,"mutation"])!==tag,"ctx mutation");
 yes(ck(bind,Zb,Zp,[D[0]^1,...D.slice(1)],context)!==tag,"DEM mutation");
 let sig2=bytes(8),pad2=xor(pad,xor(sig,sig2));eq(xor(sig,pad),xor(sig2,pad2),"same DEM coupling");
 let padBits=bits(pad),padBits2=bits(pad2);
 for(let j=0;j<64;j++){let e=Array.from({length:f.M},()=>rng()%3-1);
  eq(f.project([e[0]+128*padBits[j],...e.slice(1)]),f.project([e[0]+128*padBits2[j],...e.slice(1)]),"certified FALSE capsule coupling")
 }
 const s=quotient(2,1,5,[0,1]);eq(s.free.length,2,"small quotient");yes(s.project([1,0,0,0]).every(x=>x===0),"small false certificate");
 let errors=Array.from({length:16},(_,i)=>Array.from({length:4},(_,j)=>(i>>j)&1));
 function distr(sig,exposePad){let f=new Map;for(let kb=0;kb<2;kb++)for(let kp=0;kp<2;kp++)for(let e1 of errors)for(let e2 of errors){
   let d=sig^kp,z1=s.project([e1[0]+2*kp,...e1.slice(1)]),z2=s.project([e2[0]+2*kp,...e2.slice(1)]);
   let CK=exposePad?kp:(13*kb+7*d+3*z1.reduce((a,b)=>a+b,0)+5*z2.reduce((a,b)=>a+b,0))%31;
   let key=JSON.stringify([d,z1,z2,CK]);f.set(key,(f.get(key)||0)+1);
  }return f}
 function same(a,b){return a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v)}
 let a=distr(0,false),b=distr(1,false),bad0=distr(0,true),bad1=distr(1,true);
 yes(same(a,b),"full secret-CK joint equality");yes(!same(bad0,bad1),"bad CK leakage");eq([...a.values()].reduce((u,v)=>u+v,0),1024,"exhaustive finite cases");
 eq(xor(D,dec(t,Zp,3)),sig,"related TRUE capsule opens pad");
 return {run:"R48-CERTFALSE-SPLIT-CK-20261103",status:"qualified FALSE secret-CK simulator; hard-TRUE remains unsolved",assertions,true_original_witnesses:[3,7],true_decoded_bit_instances:decoded,false_rank:f.piv.length,false_quotient_coordinates:f.free.length,true_rank:t.piv.length,true_quotient_coordinates:t.free.length,coupled_false_pad_bits:64,finite_cases_per_signature:1024,distinct_finite_public_views:a.size,exact_joint_equality:same(a,b),leaking_ck_equality:same(bad0,bad1),quantum_hardness:"NOT TESTED"};
}
const first=checkR48();
const repeat=checkR48();
if(JSON.stringify(first)!==JSON.stringify(repeat))throw Error("nondeterministic output");
console.log(JSON.stringify({result:first,repeat_identical:true},null,2));
