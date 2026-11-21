'use strict';
function runChecker(){
  let z=0x52f913af,checks=0;
  const next=()=>{z^=z<<13;z^=z>>>17;z^=z<<5;return z>>>0;};
  const rand=n=>next()%n;
  const ok=(v,m)=>{checks++;if(!v)throw Error("ASSERT "+m);};
  const signed=(x,q)=>{let r=((x%q)+q)%q;return r<=Math.floor(q/2)?r:r-q;};
  const centers=q=>[0,1,2,3].map(i=>Math.floor(i*q/4));
  const dec=(v,q)=>{const ds=centers(q).map(c=>Math.abs(signed(v-c,q)));const a=Math.min(...ds);ok(ds.filter(x=>x===a).length===1,"no decoding tie");return ds.indexOf(a);};
  const source=(q,m,eta)=>{const A=[],b=[];for(let i=0;i<m;i++){let a=rand(q);A.push([a,a]);b.push((18*a+rand(2*eta+1)-eta+q*q)%q);}return {A,b};};
  const enc=(q,t,src,mu)=>{const inds=new Set();while(inds.size<t)inds.add(rand(src.A.length));const ix=[...inds];const u=[0,1].map(j=>ix.reduce((a,i)=>a+src.A[i][j],0)%q);const v=(ix.reduce((a,i)=>a+src.b[i],0)+centers(q)[mu])%q;return {u,v,ix,mu};};
  const open=(q,c,s)=>dec(c.v-c.u[0]*s[0]-c.u[1]*s[1],q);
  const q=257,m=64,t=12,eta=1,src=source(q,m,eta),s1=[5,13],s2=[6,12];
  for(const s of [s1,s2])for(let i=0;i<m;i++)ok(Math.abs(signed(src.b[i]-src.A[i][0]*s[0]-src.A[i][1]*s[1],q))<=eta,"valid ORIGINAL witness");
  ok(s1.toString()!==s2.toString(),"two distinct witnesses");
  const digits=Array.from({length:128},()=>rand(4));
  let caps=0;
  for(let capsule=0;capsule<3;capsule++){
    const rec=[[],[]];
    for(const mu of digits){
      const a=rand(4),b=rand(4),d=(mu-a-b+8)%4;
      const lanes=[a,b,d];
      for(let j=0;j<3;j++){
        const c=enc(q,t,src,lanes[j]);
        ok(c.ix.length===t && new Set(c.ix).size===t,"fixed weight");
        ok(c.u.every((v,k)=>v===c.ix.reduce((x,i)=>x+src.A[i][k],0)%q),"ciphertext u");
        ok(c.v===(c.ix.reduce((x,i)=>x+src.b[i],0)+centers(q)[lanes[j]])%q,"ciphertext v");
        for(let v=0;v<2;v++){const recovered=open(q,c,[s1,s2][v]);ok(recovered===lanes[j],"each witness opens digit");if(j===0)rec[v].push(recovered);else rec[v][rec[v].length-1]=(rec[v][rec[v].length-1]+recovered)%4;}
      }
    }
    for(const r of rec)ok(r.every((x,j)=>x===digits[j]),"same 256bit tape, independent capsule");
    caps++;
  }
  function pack(vals){let v=0n;for(let i=0;i<vals.length;i++){ok(vals[i]>=0 && vals[i]<65537,"field bounded");v |= BigInt(vals[i])<<(17n*BigInt(i));}return v;}
  function unpack(v,n){ok((v>>(17n*BigInt(n)))===0n,"no padding bits");const out=[];for(let i=0;i<n;i++){let x=Number((v>>(17n*BigInt(i)))&131071n);ok(x<65537,"canonical field");out.push(x);}return out;}
  const fields=Array.from({length:257},()=>rand(65537));const packed=pack(fields);
  ok(unpack(packed,257).every((x,i)=>x===fields[i]),"canonical 257-word roundtrip");
  let rejected=false;try{unpack(65537n,1);}catch(e){rejected=true;}ok(rejected,"reject >= q");
  rejected=false;try{unpack(131072n,1);}catch(e){rejected=true;}ok(rejected,"reject upper padding");
  const E=2400*3,Q=65537,C=centers(Q);
  for(let j=0;j<4;j++)for(const e of [-E,-E+1,-1,0,1,E-1,E])ok(dec(C[j]+e,Q)===j,"full dimension worst-case decode");
  ok(5*(2*E+1)>Q,"five center error balls impossible");
  const bad={A:Array.from({length:64},()=>[0,0]),b:[10,...Array(63).fill(0)]};
  for(let digit=0;digit<4;digit++)for(let k=0;k<40;k++){const c=enc(257,12,bad,digit);ok(dec(c.v,257)===digit,"FALSE source leaks all digits");}
  const maxBytes=Math.ceil(257*17/8),oldBytes=256*3*771,newBytes=128*3*maxBytes;
  ok(oldBytes===592128 && newBytes===210048,"exact capsule sizes");
  let logBinom=0;for(let i=1;i<=2400;i++)logBinom+=Math.log2(4800-2400+i)-Math.log2(i);
  const logEps=-1+.5*(257*Math.log2(65537)-logBinom);
  ok(logEps< -341.7 && logEps> -341.9,"fixed-weight collision entropy bound");
  return {candidate:"MINK-QUAD-PACK-20261102-R13",checks,related_capsules:caps,
    same_256bit_tape_by_two_distinct_original_witnesses:true,
    q:65537,n:256,m:4800,t:2400,eta:3,centers:C,max_error:E,
    fixed_weight_leftover_log2_epsilon:logEps,
    canonical_17bit_ciphertext_bytes:maxBytes,previous_binary_capsule_bytes:oldBytes,
    new_quaternary_capsule_bytes:newBytes,compression_factor:oldBytes/newBytes,
    malformed_adversarial_FALSE_exposes_capability:true,
    QPT_security_tested:false,full_setup_simulator_tested:false,generic_NP_compiler_instantiated:false};
}
console.log(JSON.stringify(runChecker(), null, 2));
