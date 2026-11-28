function sstoChecker() {
  let x=20261031>>>0,nchecks=0;
  const rnd=m=>{x=(Math.imul(x,1664525)+1013904223)>>>0;return Math.floor(x/65536)%m};
  const assert=(b,m)=>{if(!b)throw Error(m+" at "+nchecks);nchecks++};
  const q=257,n=6,d=4,g=64,B=1,ell=512,lanes=3,caps=2;
  const mod=v=>((v%q)+q)%q, err=()=>rnd(3)-1;
  const A=Array.from({length:d},()=>Array.from({length:n},()=>rnd(q)));
  A.forEach(row=>row[1]=row[0]);
  const t=A.map(r=>r[0]), W=[[1,0,0,0,0,0],[0,1,0,0,0,0]];
  const dot=(v,w)=>v.reduce((s,a,i)=>s+a*w[i],0);
  for(const w of W)for(let i=0;i<d;i++)assert(mod(dot(A[i],w))===t[i],"valid original");
  assert(g>2*B*(n+1)&&2*(g+B*(n+1))<q,"gap");
  const phi=BigInt((1019-1)*(1237-1)),nativeN=1019n*1237n;
  const gcd=(a,b)=>{while(b){[a,b]=[b,a%b]}return a};
  const inv=(a,m)=>{let [oldR,r]=[a,m],[oldS,s]=[1n,0n];while(r){const k=oldR/r;[oldR,r]=[r,oldR-k*r];[oldS,s]=[s,oldS-k*s];}return ((oldS%m)+m)%m};
  let key=1n;for(let j=0;j<ell;j++)key=(key<<1n)+BigInt(rnd(2));
  key|=1n;while(gcd(key,phi)!==1n)key+=2n;
  const nativeE=inv(key,phi);
  const keybits=Array.from({length:ell},(_,j)=>Number((key>>BigInt(j))&1n));
  const shares=[Array.from({length:ell},()=>rnd(2)),Array.from({length:ell},()=>rnd(2))];
  shares.push(Array.from({length:ell},(_,j)=>shares[0][j]^shares[1][j]^keybits[j]));
  for(let j=0;j<ell;j++)assert((shares[0][j]^shares[1][j]^shares[2][j])===keybits[j],"same-key xor");
  const enc=b=>{
    const s=Array.from({length:d},()=>rnd(q)),e=Array.from({length:n},err),star=err();
    const beta=Array.from({length:n},(_,j)=>mod(e[j]+s.reduce((v,si,i)=>v+si*A[i][j],0)));
    return {beta,tau:mod(dot(t,s)+star+g*b),s,e,star};
  };
  const dec=(ct,w)=>{
    const residual=mod(ct.tau-dot(ct.beta,w));
    const distance=v=>Math.min(mod(v),mod(-v));
    return Number(distance(residual-g)<distance(residual));
  };
  const C=Array.from({length:lanes},(_,a)=>Array.from({length:caps},()=>Array.from({length:ell},(_,j)=>enc(shares[a][j]))));
  for(let a=0;a<lanes;a++)for(let cap=0;cap<caps;cap++)for(let j=0;j<ell;j++){
    const ct=C[a][cap][j];
    for(const w of W)assert(dec(ct,w)===shares[a][j],"all original witnesses");
    assert(ct.beta.every((b,k)=>b===mod(ct.e[k]+ct.s.reduce((v,si,i)=>v+si*A[i][k],0))) &&
      ct.tau===mod(dot(t,ct.s)+ct.star+g*shares[a][j]),"coin consistency");
  }
  for(const w of W)for(let cap=0;cap<caps;cap++)for(let j=0;j<ell;j++)
    assert((dec(C[0][cap][j],w)^dec(C[1][cap][j],w)^dec(C[2][cap][j],w))===keybits[j],"one common key");
  for(let skbit=0;skbit<2;skbit++)for(let hidden=0;hidden<lanes;hidden++){
    let seen=new Map();
    for(let a=0;a<2;a++)for(let b=0;b<2;b++){
      let share=[a,b,skbit^a^b],view=share.filter((_,j)=>j!==hidden).join("");
      seen.set(view,(seen.get(view)||0)+1);
    }
    assert(seen.size===4&&[...seen.values()].every(v=>v===1),"uniform other lanes");
  }
  const opened=[0,2];
  for(const a of opened)for(let cap=0;cap<caps;cap++)for(let j=0;j<ell;j++)
    assert(dec(C[a][cap][j],W[0])===shares[a][j],"same-key opened lane");
  for(let hidden=0;hidden<lanes;hidden++){
    let other=Array.from({length:lanes},(_,a)=>a===hidden?null:Array.from({length:ell},()=>rnd(2)));
    let sim=Array.from({length:lanes},(_,a)=>Array.from({length:ell},(_,j)=>a===hidden?
      {beta:Array.from({length:n},()=>rnd(q)),tau:rnd(q)}:enc(other[a][j])));
    for(let a=0;a<lanes;a++)if(a!==hidden)for(let j=0;j<ell;j++)
      assert(dec(sim[a][j],W[0])===other[a][j],"honest other-lane simulator");
  }
  const pow=(a,b,m)=>{let y=1n;for(a%=m;b;b>>=1n,a=a*a%m)if(b&1n)y=y*a%m;return y};
  const msgHash=m=>{let y=7n;for(const c of m)y=(y*131n+BigInt(c.charCodeAt(0)))%nativeN;return y};
  const sign=m=>pow(msgHash(m),key,nativeN);
  const verify=(m,sig)=>pow(sig,nativeE,nativeN)===msgHash(m);
  let commitment=0;for(const lane of C)for(const cap of lane)for(const ct of cap)
    commitment=(commitment+ct.beta[0]+ct.tau)%1000003;
  const ctx="claim:toy:0|vk:"+nativeN+":"+nativeE+"|ciphertext:"+commitment;
  const preauth=[0,1,2].map(i=>"P|"+ctx+"|"+i),challenge="C|"+ctx+"|challenge";
  for(const m of preauth)assert(verify(m,sign(m)),"native public signature");
  assert(preauth.every(m=>m!==challenge)&&verify(challenge,sign(challenge)),"fresh challenge");
  for(let j=0;j<ell;j++){
    let candidate=0;
    for(let a=0;a<lanes;a++){
      const s=rnd(q),e=err(),star=err(),ct={beta:[mod(s+e)],tau:mod(3*s+star+g*shares[a][j])};
      const v=dec(ct,[3]);assert(v===shares[a][j],"chosen false nonbinary share");
      candidate^=v;
    }
    assert(candidate===keybits[j],"chosen false final key");
  }
  return {case:"SSTO actual 2-of-3 same-key share lane openings",seed:20261031,assertions_passed:nchecks,
    q,d,n,gap:g,error_bound:B,lanes,related_capsules:caps,secret_bits:ell,valid_original_witnesses:W.length,
    opened_lanes:opened,chosen_false_recovered_key_bits:ell,authentic_toy_signatures:true,
    QPT_hardness:"NOT TESTED",generic_WKEM:"NOT ESTABLISHED"};
}

console.log(JSON.stringify(sstoChecker(),null,2));
