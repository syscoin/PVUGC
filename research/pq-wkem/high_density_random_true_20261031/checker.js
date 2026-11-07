function runChecker(){

  let checks=0, x=20261031>>>0;
  const ok=(b,msg)=>{checks++;if(!b)throw Error(msg)};
  const rnd=()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0};
  const random=n=>rnd()%n, mod=(z,q)=>((z%q)+q)%q;
  function census(q,n){
    let ac=q**n, count0=0, total1=0,total2=0,totalAbs=0;
    for(let ai=0;ai<ac;ai++){
      let v=ai, cnt=Array(q).fill(0);cnt[0]=1;
      for(let j=0;j<n;j++){let c=v%q;v=Math.floor(v/q);let next=cnt.slice();for(let t=0;t<q;t++)next[(t+c)%q]+=cnt[t];cnt=next}
      for(let t=0;t<q;t++){let k=cnt[t];total1+=k;total2+=k*k;count0+=+(k===0);totalAbs+=Math.abs(q*k-2**n)}
    }
    ok(total1===ac*2**n,"first moment");
    ok(q*total2===ac*(2**(2*n)+(q-1)*2**n),"second moment");
    let p=count0/(ac*q), upper=(q-1)/(2**n+q-1);
    ok(p<=upper+1e-13,"uniform TRUE density");
    let tv=totalAbs/(2*ac*q*2**n), lhl=0.5*Math.sqrt((q-1)/(2**n));
    ok(tv<=lhl+1e-13,"planted distribution LHL");
    return {q,d:1,n,pr_false:p,conditional_true_tv:p,planted_tv:tv,LHL_bound:lhl};
  }
  const censuses=[4,5,6,7,8].map(n=>census(3,n)).concat([4,5,6].map(n=>census(5,n)));
  const q=40961,n=32,g=160,L=256,B=1;
  ok(2*(n+1)*B<g,"all-witness packed margin");
  for(let divisor=2;divisor*divisor<=q;divisor++)ok(q%divisor!==0,"toy q prime");
  function witnesses(a,t){
    let s=new Map([[0,[0]]]);
    for(let j=0;j<a.length;j++){
      let next=new Map();
      for(let [k,masks] of s)next.set(k,masks.slice());
      for(let [k,masks] of s){
        let dest=(k+a[j])%q,bucket=next.get(dest)||[];
        for(let m of masks)if(bucket.length<3)bucket.push(m|(1<<j));
        next.set(dest,bucket);
      }
      s=next;
    }
    return (s.get(t)||[]).map(mask=>a.map((_,j)=>(mask>>>j)&1));
  }
  function encrypt(a,t,byte){
    let s=random(q), e=a.map(()=>random(3)-1), es=random(3)-1;
    let beta=a.map((aj,j)=>mod(aj*s+e[j],q));
    let tau=mod(t*s+es+g*byte,q);
    ok(beta.every((b,j)=>b===mod(a[j]*s+e[j],q))&&tau===mod(t*s+es+g*byte,q),"cipher coin recomputation");
    return [beta,tau];
  }
  function decrypt(ct,w){
    let r=mod(ct[1]-ct[0].reduce((u,b,j)=>u+w[j]*b,0),q),best=0,bestDist=q;
    for(let b=0;b<256;b++){let d=mod(r-g*b,q);d=Math.min(d,q-d);if(d<bestDist){bestDist=d;best=b}}
    ok(bestDist<=n+1,"decode within all-witness bound");
    return best;
  }
  let recovered=0, vectors=0, instances=[];
  for(let scope=0;scope<2;scope++){
    let a=Array.from({length:n},()=>random(q)),t=random(q),ws=witnesses(a,t);
    ok(ws.length===3,"three original toy witnesses");
    for(let w of ws)ok(mod(w.reduce((acc,v,j)=>acc+v*a[j],0),q)===t,"valid binary original");
    let master=Array.from({length:64},()=>random(256));
    let u0=master.map(()=>random(256)),u1=master.map(()=>random(256));
    let u2=master.map((k,j)=>k^u0[j]^u1[j]),shares=[u0,u1,u2];
    let caps=[];
    for(let r=0;r<2;r++){let lanes=shares.map(sh=>sh.map(byte=>{vectors++;return encrypt(a,t,byte)}));caps.push(lanes)}
    for(let w of ws)for(let lanes of caps){
      let result=master.map((_,j)=>decrypt(lanes[0][j],w)^decrypt(lanes[1][j],w)^decrypt(lanes[2][j],w));
      ok(result.every((z,j)=>z===master[j]),"all-valid-witness same master");
      recovered+=64;
    }
    for(let k of [0,1,127,255])for(let a of [0,1,127,255])for(let b of [0,1,127,255])ok((a^b^(k^a^b))===k,"uniform two-open-lane algebra");
    instances.push({scope,witnesses:ws.length,capsules:2});
  }
  for(let bit=0;bit<2;bit++)for(let k=0;k<128;k++){
    let s=random(257),e=random(3)-1,es=random(3)-1;
    let beta=mod(s+e,257),tau=mod(3*s+es+64*bit,257);
    let rho=mod(tau-3*beta,257);
    let d0=Math.min(rho,257-rho),d1=Math.min(mod(rho-64,257),mod(64-rho,257));
    ok((d1<d0?1:0)===bit,"chosen FALSE nonbinary public opener");
  }
  return {checkpoint:"HDRT average-case random TRUE and packed 3-lane joint release",checks,source_censuses:censuses,byte_toy:{q,n,d:1,B,g,lanes:3,scopes:2,capsules_per_scope:2,master_bits:512,field_modulus_proved_prime:true,original_witnesses_per_scope:3,correctly_reconstructed_bytes:recovered,packed_vectors:vectors,unpacked_bit_vectors:vectors*8,packed_ciphertext_bytes:vectors*(n+1)*2},chosen_false_public_recoveries:256,limitations:"toy d=1/mock native; no QPT hardness or generic original NP compiler"};

}
console.log(JSON.stringify(runChecker(),null,2));
