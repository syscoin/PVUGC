const checkR41 = function checkR41() {
  let state=0x41c0ffee, assertions=0, recovered=0, openings=0;
  const ok=(v,msg)=>{assertions++;if(!v)throw Error("failed "+msg)};
  const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
  const ri=n=>rnd()%n, q=257,n=2,m=12,B=1,delta=128,kappa=16,scopes=2;
  const mod=(v,Q=q)=>((v%Q)+Q)%Q, dist=(x,y)=>Math.min(mod(x-y),mod(y-x));
  const fnv=s=>{let z=2166136261>>>0;for(let i=0;i<s.length;i++)z=Math.imul(z^s.charCodeAt(i),16777619)>>>0;return z;};
  const pow=(v,e,N)=>{let a=1,b=v%N;while(e){if(e%2)a=a*b%N;b=b*b%N;e=Math.floor(e/2)}return a};
  const vk={N:3233,e:17},d=2753;
  const sign=m=>pow(fnv(m)%vk.N,d,vk.N);
  const verify=(m,s)=>pow(s,vk.e,vk.N)===fnv(m)%vk.N;
  const prg=(K,claim)=>fnv("R41-TOY-PRG|"+K+"|"+claim)&65535;
  const source=()=>{const A=Array.from({length:n},()=>Array.from({length:m},()=>ri(q)));
    const s=Array.from({length:n},()=>ri(q)),e=Array.from({length:m},()=>ri(3)-1);
    const b=Array.from({length:m},(_,i)=>mod(e[i]+A[0][i]*s[0]+A[1][i]*s[1]));return {A,b,s,e}};
  const valid=(pk,w)=>pk.b.every((b,i)=>Math.abs(w.e[i])<=B&&mod(pk.A[0][i]*w.s[0]+pk.A[1][i]*w.s[1]+w.e[i])===b);
  const enc=(pk,bit)=>{const r=Array.from({length:m},()=>ri(2));
    return{u:pk.A.map(row=>mod(row.reduce((a,x,i)=>a+x*r[i],0))),
      v:mod(pk.b.reduce((a,x,i)=>a+x*r[i],delta*bit))}};
  const dec=(ct,w)=>{const v=mod(ct.v-ct.u.reduce((a,x,i)=>a+x*w.s[i],0));return +(dist(v,delta)<dist(v,0))};
  const create=(name,J)=>{const sources=Array.from({length:J},source);
    const pk=sources.map(x=>({A:x.A,b:x.b}));
    const context={relation:"OR_LWE",claim:name,utxo:"claim-"+name,branch:"native-challenge",window:"fixed",vk};
    const msg=String(fnv(JSON.stringify({pk,context}))),sig=sign(msg),K=ri(65536);
    const D=sig^prg(K,name);
    const capsules=pk.map(p=>Array.from({length:kappa},(_,i)=>Array.from({length:scopes},()=>enc(p,(K>>>i)&1))));
    const base={context,pk,msg,vk,D,capsules},CK=String(fnv(JSON.stringify(base))),aux=String(fnv("aux"+CK));
    return{sources,K,sig,public:{...base,CK,aux}}};
  const claims=[create("alpha",3),create("beta",2),create("gamma",2)],target=0;
  const openBranch=(c,j,w)=>{ok(valid(c.public.pk[j],w),"original restricted OR witness");
    let K=0;for(let b=0;b<kappa;b++){const bits=c.public.capsules[j][b].map(ct=>dec(ct,w));
      ok(bits.every(x=>x===bits[0]),"each scope same bit");K|=bits[0]<<b;recovered+=bits.length;}
    const sig=c.public.D^prg(K,c.public.context.claim);
    ok(verify(c.public.msg,sig),"toy native verification");return {K,sig}};
  for(const c of claims){
    const {CK,aux,...base}=c.public;
    ok(CK===String(fnv(JSON.stringify(base))),"public CK");
    ok(aux===String(fnv("aux"+CK)),"public aux");
    ok(verify(c.public.msg,c.sig),"presign");
    for(let j=0;j<c.sources.length;j++){const w={s:c.sources[j].s,e:c.sources[j].e};
      const a=openBranch(c,j,w);ok(a.K===c.K&&a.sig===c.sig,"same capability across OR witnesses")}
  }
  const openClaim=i=>{if(i===target)return null;openings++;
    return {K:claims[i].K,sig:claims[i].sig,witnesses:claims[i].sources.map(v=>({s:v.s,e:v.e}))}};
  ok(openClaim(0)===null,"all target branches withheld");
  for(let i=1;i<claims.length;i++){const o=openClaim(i);
    ok(o.witnesses.every((w,j)=>valid(claims[i].public.pk[j],w)),"all non-target witnesses");
    ok(o.K===claims[i].K&&o.sig===claims[i].sig,"non-target capability")}
  const leaked=openBranch(claims[0],2,{s:claims[0].sources[2].s,e:claims[0].sources[2].e});
  ok(leaked.K===claims[0].K,"target branch opening destroys target secrecy");
  const other=claims[1].sources[0],alias=enc({A:other.A,b:other.b},1);
  ok(dec(alias,{s:other.s,e:other.e})===1,"public key alias bypass");
  return {run:"R41-CLAIM-OR-LWE-SAME-CAPABILITY",assertions,recovered_bit_decodings:recovered,
    target_distinct_valid_branches:3,non_target_all_source_openings:openings,claims:3,
    parameters:{q,n,m,B,delta,kappa,scopes},source:"deterministic algebraic toy; NOT QPT hardness",
    target_public_fingerprint:fnv(JSON.stringify(claims[0].public)).toString(16)};
};
console.log(JSON.stringify(checkR41(),null,2));
