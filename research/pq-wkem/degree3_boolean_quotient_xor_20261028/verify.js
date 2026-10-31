function main(){
  const q=257;let checks=0;const ck=(v,m)=>{checks++;if(!v)throw Error(m)};
  const mod=x=>((x%q)+q)%q, pc=x=>{let n=0;while(x){n+=x&1;x>>>=1}return n};
  const basis=(n,d)=>Array.from({length:1<<n},(_,i)=>i).filter(i=>pc(i)<=d).sort((a,b)=>pc(a)-pc(b)||a-b);
  const fs=(i,j,b)=>[[0,-b],[1<<i,1],[1<<j,1],[(1<<i)|(1<<j),-2]];
  function compile(d,edges){
    const mons=basis(3,d),ix=new Map(mons.map((v,i)=>[v,i])),rows=[],meta=[];
    edges.forEach(([i,j,b],ei)=>{
      const terms=fs(i,j,b);
      for(const m of mons){if(terms.some(([t])=>pc(m|t)>d))continue;
        const row=mons.map(()=>0);for(const [t,v] of terms)row[ix.get(m|t)]+=v;
        rows.push(row.map(mod));meta.push(`${ei}:${m}`)}
    });return {mons,rows,meta};
  }
  function rank(rows){
    if(!rows.length)return 0;
    const a=rows.map(x=>x.map(mod));let rr=0;
    for(let j=0;j<a[0].length;j++){
      const k=a.findIndex((row,i)=>i>=rr&&row[j]!==0);if(k<0)continue;
      [a[rr],a[k]]=[a[k],a[rr]];
      const inv=pow(a[rr][j],q-2);a[rr]=a[rr].map(v=>mod(v*inv));
      for(let i=rr+1;i<a.length;i++)if(a[i][j]){
        const t=a[i][j];a[i]=a[i].map((v,h)=>mod(v-t*a[rr][h]));
      }rr++;if(rr===a.length)break;
    }return rr;
  }
  function pow(a,n){let r=1;while(n){if(n&1)r=r*a%q;a=a*a%q;n>>=1}return r}
  const phi=(mons,w)=>mons.map(m=>{for(let i=0;i<w.length;i++)if((m>>i&1)&&!w[i])return 0;return 1});
  const mul=(G,w)=>G.map(r=>mod(r.reduce((acc,t,i)=>acc+t*w[i],0)));
  const mt=(G,u)=>G[0].map((_,j)=>mod(G.reduce((s,row,i)=>s+row[j]*u[i],0)));
  function selected(rows){const G=[];let r=0;for(const row of rows){if(rank([...G,row])>r){G.push(row);r++}}return G}
  function solve(A,b){
    const a=A.map((row,i)=>[...row.map(mod),mod(b[i])]),n=b.length;
    for(let col=0;col<n;col++){
      const k=a.findIndex((row,i)=>i>=col&&row[col]!==0);ck(k>=0,"certificate linear system invertible");
      [a[col],a[k]]=[a[k],a[col]];
      const t=pow(a[col][col],q-2);a[col]=a[col].map(v=>mod(v*t));
      for(let i=0;i<n;i++)if(i!==col&&a[i][col]){
        const c=a[i][col];a[i]=a[i].map((v,j)=>mod(v-c*a[col][j]));
      }
    }return a.map(row=>row[n]);
  }
  const F=[[0,1,1],[1,2,1],[0,2,1]],T=[[0,1,1],[1,2,1],[0,2,0]];
  const f2=compile(2,F),f3=compile(3,F),t2=compile(2,T),t3=compile(3,T);
  const anchor=rows=>[1,...Array(rows.mons.length-1).fill(0)];
  ck(f2.rows.length===12&&rank(f2.rows)===6&&rank([...f2.rows,anchor(f2)])===7,"false d2 not certified");
  ck(f3.rows.length===24&&rank(f3.rows)===8&&rank([...f3.rows,anchor(f3)])===8,"false d3 certified");
  ck(rank(t2.rows)===5&&rank(t3.rows)===6,"true ranks");
  const key=f3.meta.reduce((s,k,i)=>(s[k]=f3.rows[i],s),{});
  const cert=[["0:0",-1],["2:0",-1],["1:0",1],["1:1",-2],["1:2",-2],["1:3",4]];
  const lhs=Array.from({length:8},(_,j)=>mod(cert.reduce((s,[k,c])=>s+c*key[k][j],0)));
  ck(lhs.every((v,i)=>v===anchor(f3)[i]),"explicit six-row cubic certificate");
  for(let wnum=0;wnum<8;wnum++){
    const w=[wnum&1,(wnum>>1)&1,(wnum>>2)&1];
    const f=(i,j,b=1)=>w[i]+w[j]-2*w[i]*w[j]-b;
    const id=-f(0,1)-f(0,2)+(1-2*w[0]-2*w[1]+4*w[0]*w[1])*f(1,2);
    ck(id===1,"Boolean quotient identity each original input");
  }
  const half=pow(2,q-2),fake=f2.mons.map(m=>pc(m)===0?1:pc(m)===1?half:0);
  ck(fake[0]===1&&mul(f2.rows,fake).every(v=>v===0),"d2 pseudo-moment kernel");
  const lifted=f3.mons.map(m=>pc(m)===0?1:pc(m)===1?half:0);
  ck(mul(f3.rows,lifted).some(v=>v!==0),"d3 rejects fake");
  const Gf=selected(f3.rows),Gt=selected(t3.rows);
  ck(Gf.length===8&&Gt.length===6,"original independent row selection");
  const lam=solve(Gf[0].map((_,j)=>Gf.map(row=>row[j])),anchor(f3));
  ck(mt(Gf,lam).every((v,i)=>v===anchor(f3)[i]),"selected-source refutation certificate");
  let state=0xA61C02D3;
  const rand32=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const ri=n=>rand32()%n;
  const rb=()=>{let x=0n;for(let i=0;i<8;i++)x=x*4294967296n+BigInt(rand32());return x};
  for(let trial=0;trial<512;trial++){
    const a=ri(15),u=Gf.map(()=>ri(q)),eps=anchor(f3).map(()=>ri(3)-1);
    const left=mt(Gf,u).map((v,j)=>mod(v+eps[j]+17*a*(j===0)));
    const moved=mt(Gf,u.map((v,i)=>mod(v+17*a*lam[i]))).map((v,j)=>mod(v+eps[j]));
    ck(left.every((v,j)=>v===moved[j]),"whole-vector digit shift coupling");
  }
  const valid=[];for(let k=0;k<8;k++){const w=[k&1,(k>>1)&1,(k>>2)&1];if(T.every(([i,j,b])=>(w[i]^w[j])===b))valid.push(w)}
  ck(valid.length===2&&JSON.stringify(valid)===JSON.stringify([[0,1,0],[1,0,1]]),"two original true witnesses");
  const M=8,g=17,b=15,ell=66;
  const decode=x=>{const c=[];for(let a=0;a<b;a++){let d=mod(x-g*a);if(d>q/2)d-=q;if(Math.abs(d)<=M)c.push(a)}ck(c.length===1,"unique cyclic digit");return c[0]};
  for(let trial=0;trial<16;trial++){
    const K=rb(),U=rb(),Z=rb(),D=U^Z,V=K^U;let z=Z,ds=[];
    for(let j=0;j<ell;j++){ds.push(Number(z%15n));z/=15n}ck(z===0n,"256bit radix fits");
    const ps=ds.map(a=>{const u=Gt.map(()=>ri(q)),eps=Array.from({length:M},()=>ri(3)-1);
      return mt(Gt,u).map((v,i)=>mod(v+eps[i]+g*a*(i===0)))});
    for(const w of valid){const m=phi(t3.mons,w);ck(m[0]===1&&mul(Gt,m).every(v=>v===0),"true original kernel");
      const got=ps.map(p=>decode(mod(p.reduce((s,v,i)=>s+v*m[i],0))));
      const zhat=got.reduceRight((v,a)=>v*15n+BigInt(a),0n);
      ck((V^D^zhat)===K,"same precommitted 256bit K for different original W");
    }
  }
  for(let K=0;K<4;K++){
    const joint=new Set();for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++)joint.add(`${U^Z}:${K^U}`);
    ck(joint.size===16,"checking-key-conditioned XOR shares uniformly bijective");
  }
  return {status:"PASS",assertions:checks,q,
    false_d2:{M:7,rows:12,rank:6,anchor_certificate:false},
    false_d3:{M:8,rows:24,rank:8,anchor_certificate:true,independent_rows:Gf.length},
    true_d3:{M:8,rows:24,rank:6,independent_rows:Gt.length,distinct_original_witnesses:valid},
    certificate:cert,whole_vector_shift_trials:512,same_capability_256bit_trials:16,
    radix:{g,b,ell,ciphertext_coordinates:M*ell},limits:"Classical algebra and mock signing seeds; no generic NP, QPT-hardness, malicious setup, or Bitcoin native PQ deployment proof."};
}
console.log(JSON.stringify(main(),null,2));
