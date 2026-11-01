function runCheck() {
  const counts={};
  const check=(b,k)=>{if(!b)throw Error("Assertion failed: "+k);counts[k]=(counts[k]||0)+1};
  const mod=(x,q)=>((x%q)+q)%q;
  const centered=(x,q)=>{const z=mod(x,q);return z<=Math.floor(q/2)?z:z-q};
  const dot=(a,b)=>a.reduce((v,x,i)=>v+x*b[i],0);
  function ring(n) {
    const basis=[0];
    for(let i=0;i<n;i++)basis.push(1<<i);
    for(let i=0;i<n;i++)for(let j=i+1;j<n;j++)basis.push((1<<i)|(1<<j));
    const rows=[];
    for(let i=0;i<n;i++){
      const j=(i+1)%n;
      const r=Array(basis.length).fill(0);
      r[0]=-1;r[basis.indexOf(1<<i)]++;r[basis.indexOf(1<<j)]++;
      r[basis.indexOf((1<<i)|(1<<j))]-=2;rows.push(r);
    }
    return {basis,rows};
  }
  function evalv(basis,w){return basis.map(mask=>(w&mask)===mask?1:0)}
  function enc(rows,m,q,g,s,e){
    return e.map((v,j)=>mod(rows.reduce((a,row,i)=>a+row[j]*s[i],0)+v+(j===0?g*m:0),q));
  }
  const q=257,g=128,odd=[],even=[];
  for(const n of [3,5,7]) {
    const {basis,rows}=ring(n),M=basis.length,delta=Array(n).fill((q+1)/2);
    const h=basis.map((_,j)=>centered(rows.reduce((a,row,i)=>a+row[j]*delta[i],0)+(j===0?g:0),q));
    const H=h.reduce((a,v)=>a+Math.abs(v),0);
    check(h[0]===-(n+1)/2,"odd_constant_shift");
    check(H===(5*n+1)/2,"odd_shift_l1");
    check(M===1+n+(n*(n-1))/2,"quadratic_basis_size");
    for(let w=0;w<(1<<n);w++){
      const all=rows.every(row=>dot(row,evalv(basis,w))===0);
      check(!all,"odd_false_witness_exclusion");
    }
    for(let t=0;t<25;t++){
      const s=Array.from({length:n},(_,i)=>((13*t+11*i+3)%q));
      const e=Array.from({length:M},(_,j)=>((t+j)%3)-1);
      const beta1=enc(rows,1,q,g,s,e);
      const betadummy=enc(rows,0,q,g,s.map((a,i)=>mod(a-delta[i],q)),e.map((a,i)=>a+h[i]));
      check(JSON.stringify(beta1)===JSON.stringify(betadummy),"odd_exact_shift_coupling");
    }
    odd.push({n,M,H,shift:h,fixture_tv_bound:H/131073});
  }
  for(const n of [4,6]){
    const {basis,rows}=ring(n),M=basis.length,witnesses=[];
    for(let w=0;w<(1<<n);w++)if(rows.every(row=>dot(row,evalv(basis,w))===0))witnesses.push(w);
    check(witnesses.length===2,"even_two_valid_witnesses");
    for(let t=0;t<30;t++)for(const m of [0,1]){
      const s=Array.from({length:n},(_,i)=>(19*t+7*i+1)%q);
      const e=Array.from({length:M},(_,j)=>((t+j)%3)-1);
      const beta=enc(rows,m,q,g,s,e);
      for(const w of witnesses){
        const v=evalv(basis,w);
        check(rows.every(row=>dot(row,v)===0),"true_original_kernel");
        const rho=mod(dot(v,beta),q);
        const expectedNoise=dot(v,e);
        check(mod(rho-g*m-expectedNoise,q)===0,"true_original_residual");
        const distance=k=>Math.min(mod(rho-g*k,q),mod(g*k-rho,q));
        check((distance(0)<=distance(1)?0:1)===m,"true_same_bit_release");
      }
    }
    even.push({n,M,validWitnesses:witnesses});
  }
  const clauses=[[1,-1,-1,1,0,0,0,0],[0,1,0,-1,0,0,0,0],[0,0,1,-1,0,0,0,0],[0,0,0,1,0,0,0,0]];
  const histogram=m=>{
    const h=new Map();
    for(let a=0;a<7;a++)for(let b=0;b<7;b++)for(let c=0;c<7;c++)for(let d=0;d<7;d++){
      const v=enc(clauses,m,7,3,[a,b,c,d],[1,0,-1,1,0,0,0,0]).join(",");
      h.set(v,(h.get(v)||0)+1);
    }
    return h;
  };
  const h0=histogram(0),h1=histogram(1);
  check(h0.size===2401&&h1.size===2401,"false_orbit_size");
  check(h0.size===h1.size&&[...h0].every(([k,v])=>h1.get(k)===v),"false_exact_joint_distribution");
  check(2*3*512*18/(2*65536+1)<1,"joint_tv_union_example");
  return {research_id:"NIDR-2026-11-01-T07",status:"restricted-family noise-smoothed false hiding; NOT generic PQ WKEM",total_checks:Object.values(counts).reduce((a,b)=>a+b,0),checks:counts,odd,even,exact_false_orbit_size:2401,limitations:["No hard TRUE arbitrary recovery-to-ORIGINAL extraction","No generic NP FALSE security","No structured-A standard QPT-LWE simulator","No selective coin-disclosure theorem","No actual native PQ Bitcoin endpoint"]};
}
const one=runCheck(),two=runCheck();
if(JSON.stringify(one)!==JSON.stringify(two))throw Error('Nondeterministic');
console.log(JSON.stringify(one,null,2));
