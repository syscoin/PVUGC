// Exact executed self-contained Node/V8 checker. No network or cryptographic-security test.
const runChecker=function runChecker() {
  let assertions=0;
  function ok(condition,label){assertions++;if(!condition)throw new Error(label);}
  const q=1099511627689,n=21008,d=512,B=16384,bits=12,L=4096,g=Math.floor(q/L),T=6*Math.ceil(512/bits);
  const mu=B*(B+1)/(2*(2*B+1));
  const gap=g/2-B-n*mu;
  const log2eps=1-2*gap*gap/(n*B*B)/Math.log(2);
  const log2Teps=log2eps+Math.log2(T);
  const log2False=d*Math.log2(q)-n;
  ok(g===268435455,"g");ok(gap>0,"positive gap");ok(log2Teps< -1100,"negligible coupling bound");
  ok(log2False < -500,"uniform source false bound");
  const qty=97, nt=8, bt=4, Lt=16,gt=Math.floor(qty/Lt),At=[1,1,2,3,5,8,13,21],tt=1,Bt=1;
  let state=0x20261031;
  function rand(m){state^=state<<13;state^=state>>>17;state^=state<<5;return (state>>>0)%m;}
  function good(e){let p=0,z=0;for(const x of e){if(x>0)p+=x;else z-=x;}return 2*(Bt+Math.max(p,z))<gt;}
  const witnesses=[];
  for(let mask=0;mask<(1<<nt);mask++){const w=At.map((_,j)=>(mask>>j)&1);if(At.reduce((v,a,j)=>v+a*w[j],0)%qty===tt)witnesses.push(w);}
  ok(witnesses.length>=2,"two distinct true toy witnesses");
  let secret=Array.from({length:6},()=>rand(256));
  let a=secret.map(()=>rand(256)),c=secret.map(()=>rand(256)),e=secret.map((v,i)=>v^a[i]^c[i]);
  const shares=[a,c,e];
  for(let i=0;i<secret.length;i++)ok((a[i]^c[i]^e[i])===secret[i],"identical key");
  function pack(bytes){let out=[];for(const byte of bytes){out.push(byte&15,byte>>4);}return out;}
  function unpack(symbols){let out=[];for(let i=0;i<symbols.length;i+=2)out.push(symbols[i]|(symbols[i+1]<<4));return out;}
  let attempts=0, encryptedCount=0;
  function enc(m){
    let errors,tries=0;
    do { errors=Array.from({length:nt},()=>rand(3)-1);tries++;ok(tries<25000,"bounded toy coin search");} while(!good(errors));
    attempts+=tries;
    const s=rand(qty),e0=rand(3)-1;
    const beta=At.map((v,j)=>(v*s+errors[j]+qty)%qty);
    const tau=(tt*s+e0+gt*m)%qty;
    ok(good(errors),"accepted certificate");
    for(const value of errors)ok(value>=-1&&value<=1,"legal errors");
    encryptedCount++;
    return {beta,tau};
  }
  function dec(ct,w){let sum=0;for(let i=0;i<nt;i++)sum+=w[i]*ct.beta[i];const rho=((ct.tau-sum)%qty+qty)%qty;let best=-1,dist=qty+1;for(let m=0;m<Lt;m++){const delta=((rho-gt*m)%qty+qty)%qty;const cur=Math.min(delta,qty-delta);if(cur<dist){best=m;dist=cur;}}return best;}
  const caps=Array.from({length:2},()=>shares.map(share=>pack(share).map(enc)));
  for(const w of witnesses)for(const cap of caps){let recovered=[];for(let i=0;i<3;i++){const values=cap[i].map(ct=>dec(ct,w));const expected=pack(shares[i]);for(let j=0;j<values.length;j++)ok(values[j]===expected[j],"all witness symbol");recovered.push(unpack(values));}for(let i=0;i<6;i++)ok((recovered[0][i]^recovered[1][i]^recovered[2][i])===secret[i],"all witness same capability");}
  ok(!good(Array(nt).fill(1)),"non-certified bounded error can fail");
  for(let m=0;m<16;m++){const s=rand(qty),beta=s,tau=(3*s+gt*m)%qty,rho=((tau-3*beta)%qty+qty)%qty;let nearest=-1,dist=qty+1;for(let k=0;k<16;k++){const z=((rho-gt*k)%qty+qty)%qty,v=Math.min(z,qty-z);if(v<dist){nearest=k;dist=v;}}ok(nearest===m,"chosen FALSE z=3 still opens");}
  return {run_id:"2026-10-31-certified-12bit-coin-release",start_sha:"f267d64d43a3b66df2c329bb891adfc98632d29e",status:"restricted_efficiency_not_generic_WKEM",q,d,n,B,bits,g,T,source_log2_false_bound:Number(log2False.toFixed(3)),log2_error_reject_bound:Number(log2eps.toFixed(3)),log2_all_conditional_loss:Number(log2Teps.toFixed(3)),ciphertext_vectors_b8:384,ciphertext_vectors_b10:312,ciphertext_vectors_b11:282,ciphertext_vectors_b12:258,ciphertext_bytes_b12:27101610,shared_matrix_bytes:53780480,toy:{distinct_valid_witnesses:witnesses.length,capsules:2,ciphertexts:encryptedCount,rejection_tries:attempts,chosen_false_z3_recovers:true},assertions,warning:"No 128-bit QPT hardness or Bitcoin native signatures tested. Adversarial FALSE and hard TRUE ORIGINAL witness reductions unresolved."};
};
console.log(JSON.stringify(runChecker(),null,2));
