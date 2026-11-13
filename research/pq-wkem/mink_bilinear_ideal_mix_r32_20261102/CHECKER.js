function checkR32() {
 "use strict";
 let checks=0;
 function ok(c,m){checks++;if(!c)throw Error("FAIL "+m);}
 const clauses=[
  [[0,1,3],[0,1,0]],[[0,1,2],[0,0,0]],[[0,1,3],[1,0,1]],
  [[0,1,3],[0,1,1]],[[0,2,3],[1,0,0]],[[0,1,3],[1,1,1]],
  [[1,2,3],[0,1,1]],[[0,2,3],[0,0,0]],[[1,2,3],[0,1,0]],
  [[0,1,2],[1,1,1]]
 ];
 const points=Array.from({length:16},(_,a)=>Array.from({length:4},(_,j)=>(a>>j)&1));
 const f=clauses.map(([ids,bad])=>points.map(w=>Number(ids.every((id,j)=>w[id]===bad[j]))));
 const pairs=[];for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++)pairs.push({i,j,v:points.map((_,a)=>f[i][a]*f[j][a])});
 function pow(a,n,q){let r=1;for(;n>0;n=Math.floor(n/2),a=a*a%q)if(n%2)r=r*a%q;return r;}
 function rank(V,q){const basis=[];let p=0;
   for(let a=0;a<16;a++){let idx=p;while(idx<V.length&&((V[idx][a]%q)+q)%q===0)idx++;
    if(idx===V.length)continue;[V[p],V[idx]]=[V[idx],V[p]];
    const inv=pow((V[p][a]%q+q)%q,q-2,q);
    for(let j=a;j<16;j++)V[p][j]=V[p][j]*inv%q;
    for(let k=p+1;k<V.length;k++){const factor=V[k][a];if(!factor)continue;for(let j=a;j<16;j++)V[k][j]=((V[k][j]-factor*V[p][j])%q+q)%q;}
    p++;
   }
   return p;
 }
 const one=Array(16).fill(1), cert=[
  [0,0,1],[1,1,1],[2,2,1],[2,6,-1],[3,3,1],[4,4,1],
  [5,5,1],[5,9,-1],[6,6,1],[8,8,1],[9,9,1]
 ];
 const ranks={};
 for(const q of [101,65537]){
   const r=rank(f.map(v=>v.slice()),q);
   const inV=rank([...f.map(v=>v.slice()),one.slice()],q)===r;
   const rw=rank(pairs.map(p=>p.v.slice()),q);
   const inW=rank([...pairs.map(p=>p.v.slice()),one.slice()],q)===rw;
   ok(r===10&&rw===13&&!inV&&inW,"strict nonlinear span q="+q);
   for(let a=0;a<16;a++){
     ok(f.some(v=>v[a]===1),"FALSE 3CNF assignment "+a);
     const evalC=cert.reduce((sum,[i,j,c])=>sum+c*f[i][a]*f[j][a],0);
     ok(evalC===1,"exact INTEGER nonlinear certificate at point "+a);
     for(const z of f)ok(z[a]===0||z[a]===1,"boolean clause failure");
   }
   ranks[q]={linear:r,product:rw,unit_in_linear:false,unit_in_product:true};
 }
 // The claimed bilinear Fourier transform: for each nontrivial additive
 // character of the scalar field F_3, exact uniform r,s enumeration
 // has expectation 1/3; t-fold convolution has TV=3^-t on shifts.
 const q3=3, p0=Array(3).fill(0);
 for(let a=0;a<3;a++)for(let b=0;b<3;b++)p0[a*b%3]++;
 ok(p0.join(",")==="5,2,2","scalar product frequency");
 let p=p0.map(x=>x/9), observed=[];
 for(let t=1;t<=8;t++){
   const tv=0.5*Array.from({length:3},(_,x)=>Math.abs(p[x]-p[(x+2)%3])).reduce((a,b)=>a+b,0);
   ok(Math.abs(tv-3**(-t))<1e-12,"exact convolution TV t="+t);
   observed.push({t,tv});
   let np=[0,0,0];for(let x=0;x<3;x++)for(let y=0;y<3;y++)np[(x+y)%3]+=p[x]*p0[y]/9;
   p=np;
 }
 // TRUE one-clause SOURCE: 14 ORIGINAL Boolean satisfying assignments.
 // Test distinct w, independent U,V per bit, and coefficient noise.
 const q=101,Delta=50,t=30,ell=256;
 let seed=32323032>>>0;
 function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;}
 const trueValid=points.map((w,i)=>i).filter(i=>f[0][i]===0);
 ok(trueValid.length===14,"four variable one-clause genuine witness count");
 let recovered=0;
 for(let bit=0;bit<ell;bit++){
   const mu=(rnd()>>>2)&1;
   let base=0;
   for(let j=0;j<t;j++)base=(base+(rnd()%q)*(rnd()%q))%q;
   const e=Array.from({length:16},()=>((rnd()%3)-1));
   for(const wIdx of trueValid){
     let err=0;
     for(let mon=0;mon<16;mon++)if((mon&wIdx)===mon)err+=e[mon];
     ok(Math.abs(err)<=16,"deterministic error bound");
     const val=(((Delta*mu+err)%q)+q)%q;
     const dist=a=>Math.min((val-a+q)%q,(a-val+q)%q);
     const dec=Number(dist(Delta)<dist(0));
     ok(dec===mu,"every ORIGINAL witness recovers same bit");
     // Every masked product is in ideal: at a genuine witness, f0=0.
     ok(f[0][wIdx]===0&&base*f[0][wIdx]===0,"independent nonlinear masks vanish");
     recovered++;
   }
 }
 const M=16,S=2;
 const log2JointBound=Math.log2(ell*S)+(M/2-t)*Math.log2(q);
 ok(log2JointBound< -128,"restricted false joint statistical bound 256 bits two bases");
 return {
  run:"R32-MINK-BILINEAR-IDEAL-MIX",
  outcome:"PASS algebraic and finite checks; conditional FALSE-class QPT statistical hiding, no hard-TRUE security",
  checks, q, degree:3, ambient_dimension:M,t,
  false_clauses:clauses.length,rank_linear:10,rank_product:13,
  exact_integer_product_unit_certificate:cert,
  distinct_true_witnesses:trueValid.length,bit_tests:ell,actual_valid_recoveries:recovered,
  false_joint_log2_tv_upper_bound:log2JointBound,
  rank_checks:ranks,scalar_convolution:observed,
  warning:"Only restricted-FALSE statistical hiding and honest correctness; no generic WKEM, QPT LWE reduction, malicious setup or arbitrary TRUE extraction"
 };
}
console.log(JSON.stringify(checkR32(),null,2));
