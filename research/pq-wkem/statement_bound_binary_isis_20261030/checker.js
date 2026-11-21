/* Executed in the research commit process. Native signatures and QPT hardness are NOT tested. */
const checker = function checker() {
  let checks = 0;
  const assert = (v,msg) => { checks++; if (!v) throw Error(`${checks}: ${msg}`); };
  let state = 20261030 >>> 0;
  const rand32 = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  const rand = n => rand32() % n;
  const dot = (a,b) => a.reduce((s,x,i)=>s+x*b[i],0);
  const mod = (x,q) => ((x%q)+q)%q;
  const center = (x,M) => { const y=mod(x,M); return y<M/2 ? y : y-M; };
  const release = (y,h,q,M) => mod(y-center(y-h,M),q);
  const q=4096,M=8,B=1,n=2,m=6,w=2,d=57;
  assert(B*(w+1)<M/2,"honest error bound");
  let openings=0;
  for(let trial=0;trial<32;trial++) {
    const A=Array.from({length:n},()=>Array.from({length:m},()=>rand(q)));
    for(const row of A) {row[1]=row[0];row[3]=row[2];}
    const w1=[1,0,1,0,0,0], w2=[0,1,0,1,0,0];
    let u=A.map(row=>mod(dot(row,w1),q));
    if(u.every(v=>v%2===0)){A[0][0]=mod(A[0][0]+1,q);A[0][1]=A[0][0];u=A.map(row=>mod(dot(row,w1),q));}
    assert(u.some(v=>v%2===1),"primitive u");
    const valid=[];
    for(let a=0;a<m;a++)for(let b=a+1;b<m;b++){
      const z=Array(m).fill(0);z[a]=z[b]=1;
      if(A.every((row,i)=>mod(dot(row,z),q)===u[i]))valid.push(z);
    }
    assert(valid.length>=2,"two original witnesses");
    const t=[],h=[],beta=[];
    for(let j=0;j<d;j++){
      const secret=Array.from({length:n},()=>rand(q));
      const e=Array.from({length:m},()=>rand(3)-1);
      const et=rand(3)-1;
      const tj=mod(dot(u,secret)+et,q);
      const bj=Array.from({length:m},(_,i)=>mod(dot(A.map(row=>row[i]),secret)+e[i],q));
      t.push(tj);h.push(tj%M);beta.push(bj);
    }
    const bits=ts=>ts.map(v=>(v/M)|0).map(v=>v.toString(2).padStart(9,'0')).join('').slice(0,512);
    const master=bits(t);
    for(const z of valid) {
      const got=beta.map((b,j)=>release(mod(dot(b,z),q),h[j],q,M));
      assert(got.every((v,j)=>v===t[j]),"all legal openings decode same t");
      assert(bits(got)===master,"all legal openings decode same K");
      openings++;
    }
    assert(valid.some(z=>z.every((v,i)=>v===w1[i]))&&valid.some(z=>z.every((v,i)=>v===w2[i])),"two explicit distinct openings");
  }
  for(let t=0;t<4096;t++){
    const h=t%8,k=Math.floor(t/8);
    assert(h+8*k===t,"exact independent low-high bits");
  }
  let falseRecover=0;
  for(let s=0;s<4096;s++)for(let e=-1;e<=1;e++)for(let et=-1;et<=1;et++){
    const t=mod(3*s+et,4096),beta=mod(s+e,4096);
    const got=release(mod(3*beta,4096),t%16,4096,16);
    assert(got===t,"FALSE recovery with nonbinary 3x shortcut"); falseRecover++;
  }
  const nLarge=128,qLarge=1<<24,Mlarge=1<<19,BLarge=128,dLarge=103;
  assert(BLarge*(2004+1)<Mlarge/2,"strict large margin");
  for(let trial=0;trial<40;trial++)for(let j=0;j<dLarge;j++){
    const s=rand(qLarge), e=rand(257)-128,et=rand(257)-128;
    const t=mod(3*s+et,qLarge),beta=mod(s+e,qLarge);
    assert(release(mod(3*beta,qLarge),t%Mlarge,qLarge,Mlarge)===t,"full-sized FALSE recovery");
  }
  const T=[];
  for(let i=0;i<4;i++)for(let j=i+1;j<4;j++){const z=[0,0,0,0];z[i]=z[j]=1;T.push(z);}
  const collisions=Array(15).fill(0);
  for(let x0=0;x0<8;x0++)for(let x1=0;x1<8;x1++)for(let x2=0;x2<8;x2++)for(let x3=0;x3<8;x3++){
    const a=[x0,x1,x2,x3]; let idx=0;
    for(let i=0;i<T.length;i++)for(let j=i+1;j<T.length;j++){
      if(mod(dot(a,T[i]),8)===mod(dot(a,T[j]),8))collisions[idx]++;
      idx++;
    }
  }
  for(const c of collisions)assert(c===512,"2-universal Z_8 binary-weight hashing");
  const log2choose=(n,k)=>{let v=0;for(let i=1;i<=k;i++)v+=Math.log2(n-i+1)-Math.log2(i);return v;};
  const logSource=log2choose(4469,2004),logEpsilon=-1+0.5*(128*24-logSource);
  assert(logEpsilon< -128,"illustrative planted source statistical bound");
  assert(Math.ceil(512/(24-19))===103,"512-bit master columns");
  return {checks, toy_setups:32, legal_openings:openings, false_exact_cases:falseRecover,
    false_large_complete_masters:40, universal_source_pairs:15,
    illustrative_log2_source_entropy:Number(logSource.toFixed(6)),
    illustrative_log2_leftover_bound:Number(logEpsilon.toFixed(6)),
    illustrative_reconciliation_margin:Mlarge/2-BLarge*(2004+1),
    status:"Restricted planted-source theorem only; arbitrary FALSE broken; no calibrated QPT hardness or native signing test"};
};
console.log(JSON.stringify(checker(), null, 2));
