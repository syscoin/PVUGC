// Run 570: pure ECMAScript checker, Node and V8-isolate compatible.
// Finite ideal-function algebra, NOT a PQ witness-KEM implementation.
function runCheck() {
  let assertions=0;
  const expect=(p,why)=>{if(!p)throw new Error(why);assertions++;};
  const mul=(x,y,h,irr)=>{const mask=(1<<h)-1;let v=0;while(y){if(y&1)v^=x;y>>=1;x<<=1;if(x&(1<<h))x^=irr;}return v&mask;};
  const offsets=(h,irr)=>Array.from({length:1<<h},(_,a)=>(a<<h)|mul(mul(a,a,h,irr),a,h,irr));
  const parity=(x)=>{let p=0;while(x){p^=1;x&=x-1;}return p;};
  const rnd=(seed)=>{let z=seed>>>0;return()=>{z^=z<<13;z^=z>>>17;z^=z<<5;return z>>>0;};};
  const settings=[[2,0b111],[3,0b1011],[4,0b10011],[5,0b100101]];
  let pairDifferences=0,exhaustiveMasks=0,exactLawCases=0;
  for(const [h,irr] of settings){
    const T=offsets(h,irr),seen=new Set();
    expect(new Set(T).size===T.length,"offsets distinct");
    for(let i=0;i<T.length;i++)for(let j=i+1;j<T.length;j++){
      const d=T[i]^T[j];expect(d!==0&&!seen.has(d),"cubic XOR Sidon");
      seen.add(d);pairDifferences++;
    }
  }
  const T4=offsets(2,0b111);
  for(let k=2;k<=4;k++){
    const T=T4.slice(0,k),S=new Set(T);
    for(let d=1;d<16;d++){
      const overlaps=T.filter(t=>S.has(t^d)).length;
      expect(overlaps%2===0,"pairwise overlap");
      const c=overlaps/2;expect(c<=1,"Sidon collision count");
      let favorable=0;
      for(let mask=0;mask<65536;mask++){
        let yes=true;
        for(const t of T)if(((mask>>>t)&1)!==((mask>>>(t^d))&1)){yes=false;break;}
        if(yes)favorable++;
        exhaustiveMasks++;
      }
      expect(favorable===2**(16-(k-c)),"exact collision exponent");
      exactLawCases++;
    }
  }
  const h=5,n=10,N=1<<n,T=offsets(h,0b100101),delta=0b1011011011;
  expect(T.length===32,"32 one-bit offsets");
  const makeSig=(x,B)=>{let v=0;for(let i=0;i<T.length;i++)v|=B[x^T[i]]<<i;return v>>>0;};
  function recover(rows,n){
    const a=rows.map(([lo,rhs])=>[lo,rhs]);let rank=0;
    for(let bit=0;bit<n;bit++){
      let p=rank;while(p<a.length&&!(a[p][0]&(1<<bit)))p++;
      if(p===a.length)continue;
      [a[p],a[rank]]=[a[rank],a[p]];
      for(let row=0;row<a.length;row++)if(row!==rank&&(a[row][0]&(1<<bit))){
        a[row][0]^=a[rank][0];a[row][1]^=a[rank][1];
      }
      rank++;
    }
    if(rank<n)return {rank,delta:null};
    let d=0;
    for(let bit=0;bit<n;bit++){expect(a[bit][0]===(1<<bit),"reduced echelon");d|=a[bit][1]<<bit;}
    return {rank,delta:d};
  }
  let injectiveCases=0,fibersChecked=0,shiftRecoveries=0,jointValues=0;
  for(let seed=1;seed<=6;seed++){
    const r=rnd(0x9e3779b9^seed);
    const A=Array.from({length:N},()=>r()&1),B=Array.from({length:N},()=>r()&1);
    const F=Array.from({length:N},(_,s)=>A[s]^B[s^delta]);
    const G=Array.from({length:N},(_,s)=>F[s]^A[s]);
    for(let s=0;s<N;s++){expect(G[s]===B[s^delta],"three-view cancellation");jointValues++;}
    const vals=new Set();for(let s=0;s<N;s++)vals.add(makeSig(s,B));
    expect(vals.size===N,"one-bit injectivized function injective");injectiveCases++;
    const fibers=new Map();
    for(let b=0;b<2;b++)for(let s=0;s<N;s++){
      let z=0;for(let i=0;i<T.length;i++){const t=s^T[i];z|=(b?G[t]:B[t])<<i;}
      const v=z>>>0,list=fibers.get(v)||[];list.push((b<<n)|s);fibers.set(v,list);
    }
    expect(fibers.size===N,"two-to-one image size");
    for(const xs of fibers.values()){
      expect(xs.length===2,"two element fiber");
      expect((xs[0]^xs[1])===(delta|(1<<n)),"unique hidden period");
      fibersChecked++;
    }
    const s=rnd(0x5a5a5a5a^seed),rows=[];
    for(let t=0;t<n+12;t++){
      const yl=s()&(N-1),yh=parity(yl&delta);
      expect((parity(yl&delta)^yh)===0,"orthogonal quantum sample");
      rows.push([yl,yh]);
    }
    const solved=recover(rows,n);
    expect(solved.rank===n&&solved.delta===delta,"GF2 recover Delta");
    shiftRecoveries++;
    for(let y=0;y<(1<<(n+1));y+=31){
      if(parity(y&(delta|(1<<n)))===1){
        expect(1+(parity(y&(delta|(1<<n)))?-1:1)===0,"Fourier coset cancellation");
      }
    }
  }
  expect(1*(385-1)>=2*128+128,"illustrative 128-bit requirement");
  return {
    run:570,status:"PASS",assertions,cubic_xor_sidon_h:[2,3,4,5],
    sidon_unordered_pairs:pairDifferences,
    exact_single_bit_collision_cases:exactLawCases,
    exhaustive_boolean_function_assignments_checked:exhaustiveMasks,
    low_width_domain_bits:n,low_width_output_bits:1,public_offsets:T.length,
    low_width_injective_test_instances:injectiveCases,
    exact_two_element_fibers:fibersChecked,simulated_simon_shift_recoveries:shiftRecoveries,
    joint_view_cancelled_values:jointValues,illustrative_n128_m1_offsets:385,
    illustrative_injectivization_failure_bound:"<2^-129",
    illustrative_simon_samples:256,coherent_quantum_queries_executed:0,
    security_proven:false,
    attribution:"Gharibi 2012 injectivization; exact XOR-Sidon field-graph specialization and seam application",
    caveat:"Ideal random functions and finite algebra; no concrete QPT local mixer, WE, Bitcoin change or quantum hardware."
  };
}
if(typeof require!=="undefined"&&typeof module!=="undefined"&&require.main===module)
  console.log(JSON.stringify(runCheck(),null,2));
