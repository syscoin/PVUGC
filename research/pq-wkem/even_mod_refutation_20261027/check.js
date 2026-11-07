'use strict';
const checker=function checker() {
  let assertions=0; const ck=(v,s)=>{assertions++;if(!v)throw Error(s)};
  const pop=(v)=>{let n=0;while(v){v&=v-1;n++}return n};
  const S=[7,25,42,52], bf=[1,1,1,-1], bt=[1,1,1,1];
  const masks=Array.from({length:64},(_,i)=>i).filter(i=>pop(i)<=4);
  const ix=new Map(masks.map((m,i)=>[m,i]));
  ck(masks.length===57 && ix.get(0)===0,"57 moments");
  const build=b=>{const rows=[],lookup=new Map();for(let j=0;j<4;j++)for(const t of masks){let p=S[j]^t;if(!ix.has(p))continue;lookup.set(j+":"+t,rows.length);rows.push([ix.get(p),ix.get(t),b[j]])}return {rows,lookup}};
  const f=build(bf),t=build(bt);
  ck(f.rows.length===200 && t.rows.length===200,"200 source constraints");
  const evalM=(rows,u,q)=>{const z=Array(57).fill(0);for(let j=0;j<rows.length;j++){const [p,m,b]=rows[j];z[p]+=u[j];z[m]-=b*u[j]}return q?z.map(x=>((x%q)+q)%q):z};
  const chi=(w,m)=>pop(w&m)%2?-1:1;
  const sat=(w,b)=>S.every((s,j)=>chi(w,s)===b[j]);
  const ws=Array.from({length:64},(_,i)=>i),trueW=ws.filter(w=>sat(w,bt)),falseW=ws.filter(w=>sat(w,bf));
  ck(trueW.length===8 && falseW.length===0,"true eight false zero");
  for(const w of trueW){let z=masks.map(m=>chi(w,m));for(const [p,m,b] of t.rows)ck(z[p]-b*z[m]===0,"real witness polynomial constraint");ck(z[0]===1,"anchor")}
  const cert=Array(f.rows.length).fill(0),lk=f.lookup;
  cert[lk.get("0:"+S[1])]=-1;cert[lk.get("1:0")]=-1;cert[lk.get("2:"+S[3])]=1;cert[lk.get("3:0")]=1;
  const e2=evalM(f.rows,cert,0);
  ck(e2[0]===2 && e2.slice(1).every(v=>v===0),"integer certificate 2 anchor");
  const q=1048576,g=620,radix=Math.floor(q/g),sc=cert.map(v=>v*(g/2));
  const eg=evalM(f.rows,sc,0);
  ck(eg[0]===g && eg.slice(1).every(v=>v===0),"integer certificate g anchor");
  let seed=341027;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};const R=n=>rand()%n;
  for(let rep=0;rep<240;rep++){
    const digit=R(radix),u0=f.rows.map(()=>R(q)),ureal=u0.map((v,i)=>((v-digit*sc[i])%q+q)%q);
    const err=masks.map(()=>R(3)-1);
    const p0=evalM(f.rows,u0,q).map((v,i)=>(v+err[i]+q)%q);
    const pr=evalM(f.rows,ureal,q).map((v,i)=>(v+err[i]+(i===0?g*digit:0)+q)%q);
    ck(p0.every((v,i)=>v===pr[i]),"joint real-null coupling");
  }
  const quad=[[0,-1,0,1],[-1,1,0,0],[0,0,-1,1],[1,0,1,0]];
  const ccoeff=[-1,-1,1,1];
  ck(Array.from({length:4},(_,i)=>quad.reduce((a,r,j)=>a+ccoeff[j]*r[i],0)).join(",")==="2,0,0,0","toy certificate");
  const tc=[];
  for(let digit=0;digit<4;digit++){
    const freq=new Map();
    for(let u=0;u<4096;u++){
      const v=[u&7,(u>>3)&7,(u>>6)&7,(u>>9)&7];
      const pp=Array.from({length:4},(_,i)=>((quad.reduce((a,r,j)=>a+v[j]*r[i],0)+(i===0?2*digit:0))%8+8)%8);
      const key=pp[0]+(pp[1]<<3)+(pp[2]<<6)+(pp[3]<<9);
      freq.set(key,(freq.get(key)||0)+1);
    }
    tc.push(freq);
  }
  const equalMap=(a,b)=>a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v);
  for(let i=1;i<4;i++)ck(equalMap(tc[0],tc[i]),"exact finite ciphertext distribution");
  for(let K=0;K<4;K++){
    const real=new Map(),sim=new Map();
    const add=(map,k,v)=>map.set(k,(map.get(k)||0)+v);
    for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++)for(const [p,v] of tc[Z])add(real,`${U^Z},${K^U},${p}`,v);
    for(let D=0;D<4;D++)for(let V=0;V<4;V++)for(const [p,v] of tc[0])add(sim,`${D},${V},${p}`,v);
    ck(equalMap(real,sim),"fixed native key full joint distribution");
    ck([...real.values()].reduce((a,v)=>a+v,0)===4096*16,"joint probability mass");
  }
  let L=0;while(BigInt(radix)**BigInt(L)<(1n<<256n))L++;
  ck(L===24,"exact radix capacity");
  const rand256=()=>{let v=0n;for(let i=0;i<8;i++)v=(v<<32n)|BigInt(rand());return v};
  const toDigits=v0=>{let v=v0,ds=[];for(let i=0;i<L;i++){ds.push(Number(v%BigInt(radix)));v/=BigInt(radix)}ck(v===0n,"radix conversion");return ds};
  const fromDigits=ds=>ds.reduceRight((a,v)=>a*BigInt(radix)+BigInt(v),0n);
  const nearest=y=>{const a=Math.floor(y/g),candidates=[a-1,a,a+1,0,radix-1].filter(v=>v>=0&&v<radix);
    let best=-1,dist=q;for(const j of candidates){const cj=g*j,d=Math.min((y-cj+q)%q,(cj-y+q)%q);if(d<dist){best=j;dist=d}}return best};
  for(let trial=0;trial<6;trial++){
    const K=rand256(),U=rand256(),Z=rand256(),Dp=U^Z,V=K^U,digits=toDigits(Z),columns=[];
    for(const digit of digits){const u=t.rows.map(()=>R(q)),err=masks.map(()=>R(3)-1);
      const p=evalM(t.rows,u,q).map((v,i)=>(v+err[i]+(i===0?g*digit:0)+q)%q);columns.push(p)}
    for(const w of trueW){
      const z=masks.map(m=>chi(w,m)),rec=[];
      for(let j=0;j<L;j++){
        let y=0;for(let k=0;k<57;k++)y+=z[k]*columns[j][k];y=((y%q)+q)%q;
        const ideal=g*digits[j];ck(Math.min((y-ideal+q)%q,(ideal-y+q)%q)<=57,"bounded decryption error");
        const d=nearest(y);ck(d===digits[j],"all witnesses recover digit");rec.push(d)
      }
      const ZZ=fromDigits(rec);ck(ZZ===Z && (Dp^V^ZZ)===K,"every witness same precommitted seed");
    }
  }
  return {status:"RESTRICTED_INFORMATION_THEORETIC_FALSE_SOURCE_ONLY",source_rows:f.rows.length,moment_columns:masks.length,zero_false_witnesses:falseW.length,true_witnesses:trueW.length,integer_row_certificate:"2*e_anchor",q,g,radix,columns:L,paired_full_matrix_samples:240,exhaustive_toy_masks:4096,toy_key_conditioned_views:4,true_witness_openings:48,assertions,seed:341027,hard_true_original_extraction:"NOT ESTABLISHED",standard_lwe_simulator:"NOT ESTABLISHED; exact row-shift false null only"};
};
console.log(JSON.stringify(checker(),null,2));
