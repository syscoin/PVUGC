// Run 509 deterministic finite quantum-amplitude check, Node >=18 or plain JS.
// Ideal action-oracle model ONLY; not a PQ KEM or a concrete security proof.
function run() {
 let seed=509, assertions=0, fixtures=0, nonzero=0, maxGap=0, maxViolation=0;
 const rnd=()=>{seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed/4294967296;};
 const ck=(p,msg)=>{assertions++;if(!p)throw Error(msg);};
 const perm=(v,p)=>{let o=Array(v.length).fill(0);for(let i=0;i<v.length;i++)o[p[i]]=v[i];return o;};
 const had=(v,b)=>{let o=v.slice(),m=1<<b;for(let i=0;i<v.length;i++)if(!(i&m)){let j=i|m;o[i]=(v[i]+v[j])/Math.SQRT2;o[j]=(v[i]-v[j])/Math.SQRT2;}return o;};
 const norm=v=>v.reduce((s,z)=>s+z*z,0);
 const rot=(w,n)=>(w>>>1)|((w&1)<<(n-1));
 for(let n=1;n<=3;n++)for(let mask=0;mask<(1<<(1<<n));mask++){
  if(n===3 && mask>12 && mask!==255)continue;
  const size=1<<(n+2), pack=(k,w,t)=>(k<<(n+1))|(w<<1)|t;
  const decode=s=>[(s>>(n+1))&1,(s>>1)&((1<<n)-1),s&1];
  for(let key of [0,1])for(let rep=0;rep<2;rep++){
   let P=Array.from({length:size},(_,i)=>i);
   for(let i=size-1;i>0;i--){let j=Math.floor(rnd()*(i+1));[P[i],P[j]]=[P[j],P[i]];}
   let inv=Array(size);P.forEach((y,s)=>inv[y]=s);
   const conj=fn=>Array.from({length:size},(_,y)=>P[fn(inv[y])]);
   const X=conj(s=>{let[k,w,t]=decode(s);return pack(k,w^1,t);});
   const R=conj(s=>{let[k,w,t]=decode(s);return pack(k,rot(w,n),t);});
   const T=conj(s=>{let[k,w,t]=decode(s);return pack(k,w,t^(k&((mask>>w)&1)));});
   const moved=Array.from({length:size},(_,y)=>T[y]!==y);
   const valid=Array.from({length:size},(_,y)=>(mask>>decode(inv[y])[1])&1);
   ck(T.every((y,i)=>T[y]!==undefined&&T[T[i]]===i),'involution');
   ck(moved.every((v,i)=>!v||valid[i]),'moved=>source');
   const a=P[pack(key,0,0)];
   for(let q=1;q<=4;q++){
    fixtures++;let real=Array(size).fill(0),zero=Array(size).fill(0);real[a]=1;zero[a]=1;
    let hits=0;
    for(let j=0;j<q;j++){
     let bit=(j+rep)% (n+2);
     real=had(perm(real,j%2?X:R),bit);zero=had(perm(zero,j%2?X:R),bit);
     ck(Math.abs(norm(real)-1)<1e-9&&Math.abs(norm(zero)-1)<1e-9,'unitary');
     hits+=zero.reduce((v,z,i)=>v+(valid[i]?z*z:0),0);
     real=perm(real,T);
    }
    real=had(real,(q+rep)% (n+2));zero=had(zero,(q+rep)% (n+2));
    const dist=Math.sqrt(real.reduce((v,z,i)=>v+(z-zero[i])**2,0));
    const p=hits/q;
    ck(dist<=2*q*Math.sqrt(p)+1e-9,'hybrid bound');
    for(let bit=0;bit<2;bit++){
     const pr=v=>v.reduce((s,z,i)=>s+((i>>bit)&1?z*z:0),0);
     let d=Math.abs(pr(real)-pr(zero));
     ck(d<=dist+1e-9,'event norm bound');
     ck(p+1e-9>=d*d/(4*q*q),'source query extraction');
     if(d>1e-10)nonzero++;
     maxGap=Math.max(maxGap,d);maxViolation=Math.max(maxViolation,d-2*q*Math.sqrt(p));
     if(mask===0)ck(d<1e-9,'false source null');
    }
   }
  }
 }
 ck(nonzero>100,'nontrivial differences');
 return {run:509,model:'black-box framed guarded-terminal oracle',fixture_count:fixtures,assertions,nonzero_event_gaps:nonzero,max_event_gap:Number(maxGap.toFixed(10)),max_bound_violation:Number(maxViolation.toFixed(10)),status:'PASS; does not establish concrete QPT security'};
}
console.log(JSON.stringify(run(),null,2));
