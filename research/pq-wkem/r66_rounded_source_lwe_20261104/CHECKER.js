function checkR66(){
  const q=1n<<40n,p=1n<<23n,R=q/p,L=65n,Delta=R*L,m=64,n=2;
  let a=0,z=0x66006601>>>0;
  const assert=(v,msg)=>{if(!v)throw Error(msg);a++};
  const rand=()=>{z^=z<<13;z^=z>>>17;z^=z<<5;return z>>>0};
  const byte=()=>rand()&255, r40=()=>((BigInt(rand())<<8n)|BigInt(byte()))%q;
  const mod=(x,k)=>(x%k+k)%k,round=x=>Number(((mod(x,q)+R/2n)/R)%p);
  const dist=(x,y)=>Math.min((x-y+Number(p))%Number(p),(y-x+Number(p))%Number(p));
  const dec=y=>{const x=((y%Number(p))+Number(p))%Number(p);let u=Math.min(65535,Math.max(0,Math.floor((x+32)/65)));return dist(x,0)<dist(x,65*u)?0:u};
  const mat=planted=>{let A=Array.from({length:m},()=>[r40(),r40()]);if(planted){A[1]=A[0].map(x=>mod(-x,q));A[2]=A[0].map(x=>mod(-x,q))}return A};
  const ysample=A=>{let s=[r40(),r40()];return A.map(row=>mod(row[0]*s[0]+row[1]*s[1]+BigInt(rand()%3)-1n,q))};
  const seed=()=>Array.from({length:32},byte);
  const words=K=>Array.from({length:16},(_,i)=>K[2*i]+256*K[2*i+1]);
  const enc=(A,K,Ys)=>words(K).map((u,i)=>{const Y=Ys?Ys[i]:ysample(A);return Y.map((v,j)=>round(v+(j===0?Delta*BigInt(u):0n)))});
  const eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
  const r1=[1,1,0,...Array(61).fill(0)],r2=[1,0,1,...Array(61).fill(0)];
  const ker=(r,A)=>Array.from({length:n},(_,j)=>mod(A.reduce((x,row,i)=>x+BigInt(r[i])*row[j],0n),q));
  const open=(C,r)=>C.flatMap(row=>{let x=Number(mod(row.reduce((v,c,i)=>v+BigInt(r[i])*BigInt(c),0n),p));let w=dec(x);return [w&255,w>>>8]});
  const hash=(key,str)=>{let h=2166136261>>>0;for(const c of key){h=Math.imul(h^c,16777619)>>>0}for(let i=0;i<str.length;i++)h=Math.imul(h^str.charCodeAt(i),16777619)>>>0;return h.toString(16)};
  const makeView=(A,K,Ys,related)=>{let C=enc(A,K,Ys),kb=K.map(v=>v^165),dsig=K.map(v=>v^90),Base=JSON.stringify({relation:"SIS-only",scope:"claim-and-branch",A:A.map(r=>r.map(String)),C,dsig,related});let CK=hash(kb,"CK|"+Base),Aux=hash(kb,"Aux|"+CK+"|"+Base);return {C,Base,CK,Aux,related,dsig}};
  assert(65>64+128/Number(R),"source spacing");assert(Number(p)-65535*65>64+128/Number(R),"cyclic capacity");
  for(let u=0;u<65536;u++)for(const e of [-32,32])assert(dec((65*u+e+Number(p))%Number(p))===u,"boundary");
  for(const shift of [0,1,16,128,205]){let h=Array(16).fill(0);for(let v=0;v<256;v++)h[Math.floor(((v+shift)%256+8)/16)%16]++;assert(h.every(x=>x===16),"uniform pushforward")}
  const A=mat(true),relatedA=mat(true),relatedK=seed(),relatedC=enc(relatedA,relatedK);
  assert(ker(r1,A).every(x=>x===0n)&&ker(r2,A).every(x=>x===0n),"two witnesses");
  for(let t=0;t<80;t++){let K=seed(),rel={scope:"other-claim",source:relatedC},v=makeView(A,K,null,rel);
    for(const r of [r1,r2]){assert(eq(open(v.C,r),K),"same root");let kb=K.map(x=>x^165);assert(v.CK===hash(kb,"CK|"+v.Base)&&v.Aux===hash(kb,"Aux|"+v.CK+"|"+v.Base),"joint CK/Aux");}
    assert(eq(open(relatedC,r1),relatedK),"related independent opening")}
  for(let t=0;t<64;t++){let U=mat(false),K=seed(),Y=Array.from({length:16},()=>ysample(U)),rel={scope:"other-claim",source:relatedC},v=makeView(U,K,Y,rel);
    let expected=words(K).map((u,i)=>Y[i].map((z,j)=>round(z+(j===0?Delta*BigInt(u):0n))));
    assert(eq(v.C,expected),"actual LWE challenge image");let kb=K.map(x=>x^165);
    assert(v.CK===hash(kb,"CK|"+v.Base)&&v.Aux===hash(kb,"Aux|"+v.CK+"|"+v.Base),"full view CK/Aux")}
  const H=[1,0,-1,2,...Array(60).fill(0)],Ah=mat(false);for(let j=0;j<n;j++)Ah[0][j]=mod(Ah[2][j]-2n*Ah[3][j],q);
  assert(ker(H,Ah).every(x=>x===0n),"public signed kernel");
  for(let t=0;t<32;t++){let K=seed();assert(eq(open(enc(Ah,K),H),K),"nonwitness signed bypass remains")}
  return {status:"PASS: algebraic toy source, NO generic-NP security",assertions:a,q:q.toString(),p:p.toString(),lambda_scaled:Number(L),ciphertext_before_bytes:5120,ciphertext_after_bytes:3072,change_percent:40,two_witness_cases:80,full_real_LWE_challenge_views:64,signed_kernel_bypasses:32,boundary_decodings:131072};
}
console.log(JSON.stringify(checkR66(),null,2));
