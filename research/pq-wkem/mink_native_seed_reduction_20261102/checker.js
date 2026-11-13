'use strict';
// Exact executable checker; one-bit modular toy signature is NOT PQ-native.
function runChecker() {
  let state=0x52391a13, checks=0;
  const rng=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
  const rand=n=>rng()%n;
  const ok=(a,m)=>{checks++;if(!a)throw Error("ASSERT "+m);};
  const q=257,m=64,n=2,t=12,eta=1,gap=128;
  const A=Array.from({length:m},()=>{const a=1+rand(q-1);return [a,a];});
  const s1=[5,13],s2=[6,12];
  const b=A.map(row=>(row[0]*s1[0]+row[1]*s1[1]+rand(3)-1+q*q)%q);
  const centered=x=>{const r=((x%q)+q)%q;return r<=q/2?r:r-q;};
  const valid=s=>A.every((row,i)=>Math.abs(centered(b[i]-row[0]*s[0]-row[1]*s[1]))<=eta);
  ok(valid(s1)&&valid(s2)&&String(s1)!==String(s2),"distinct originals");
  ok(t*eta<gap/2,"radius");
  function enc(bit,A0=A,b0=b) {
    const support=new Set();while(support.size<t)support.add(rand(m));
    const ids=[...support], u=[0,1].map(j=>ids.reduce((z,i)=>z+A0[i][j],0)%q);
    const v=(ids.reduce((z,i)=>z+b0[i],0)+gap*bit)%q;
    return {u,v,ids,bit};
  }
  function dec(c,s) {
    let v=((c.v-(c.u[0]*s[0]+c.u[1]*s[1]))%q+q)%q;
    const dist0=Math.min(v,q-v), d=(v-gap+q)%q, dist1=Math.min(d,q-d);
    return +(dist1<dist0);
  }
  const key=Array.from({length:32},()=>rand(256));
  const bits=key.flatMap(x=>Array.from({length:8},(_,j)=>(x>>>j)&1));
  const toyHash=a=>a.reduce((z,x)=>(z*131+x+1)%1000000007,17);
  const vk=[toyHash(key.slice(0,16)),toyHash(key.slice(16,32))];
  const sign=bit=>key.slice(16*bit,16*(bit+1));
  const verify=(pub,bit,sig)=>sig.length===16&&toyHash(sig)===pub[bit];
  const real=Array.from({length:3},()=>bits.map(bit=>{
    const a=rand(2),b0=rand(2);return [enc(a),enc(b0),enc(bit^a^b0)];
  }));
  for(const cap of real) {
    for(const ct of cap)for(const c of ct)ok(dec(c,s1)===c.bit&&dec(c,s2)===c.bit,"decryption");
    for(const s of [s1,s2]) {
      const recovered=cap.map(ct=>dec(ct[0],s)^dec(ct[1],s)^dec(ct[2],s));
      ok(recovered.every((x,i)=>x===bits[i]),"same key");
      ok(verify(vk,1,sign(1)),"toy sig");
    }
    for(let i=0;i<bits.length;i++) {
      const c=cap[i][i%2];
      ok(c.ids.length===t&&new Set(c.ids).size===t,"fixed support");
      ok(c.u.every((x,j)=>x===c.ids.reduce((z,idx)=>z+A[idx][j],0)%q),"u audit");
      ok(c.v===(c.ids.reduce((z,idx)=>z+b[idx],0)+gap*c.bit)%q,"v audit");
    }
  }
  function keyFreeView(pub,signingOracle) {
    const capsules=Array.from({length:3},()=>Array.from({length:bits.length},()=>[enc(rand(2)),enc(rand(2)),enc(0)]));
    return {vk:pub,signature:signingOracle(0),capsules};
  }
  const sim=keyFreeView(vk,sign);
  ok(verify(sim.vk,0,sim.signature),"oracle signature");
  for(const cap of sim.capsules)for(const lanes of cap)ok(lanes[2].bit===0,"key-free protected lane");
  const badA=Array.from({length:m},()=>[0,0]),badB=Array(m).fill(0);badB[0]=10;
  for(const bit of [0,1])for(let j=0;j<96;j++){
    const c=enc(bit,badA,badB);ok(+(c.v>=gap)===bit,"malformed false leakage");
  }
  const oldBits=45056,newBits=256,bytesPerCiphertext=771,M_caps=3;
  const oldBytes=oldBits*3*bytesPerCiphertext*M_caps,newBytes=newBits*3*bytesPerCiphertext*M_caps;
  ok(oldBytes===312643584&&newBytes===1776384&&oldBytes/newBytes===176,"resource");
  return {candidate:"MINK-NATIVE-SEED-20261102-R12",checks,
    toy_parameters:{q,n,m,t,eta},original_witnesses:2,related_capsules:3,
    same_key_correctness:true,key_free_hybrid_assembly:true,
    malformed_false_leakage_reconfirmed:true,signature_test_double:"insecure toy modulo tag, not native PQ",
    source_capsule_one_256bit_bytes:592128,three_related_256bit_bytes:newBytes,
    reduction_factor_vs_LWE_PRG_Lamport_seed:176,
    QPT_security_tested:false,generic_NP_compiler_implemented:false,
    malicious_N_of_N_implemented:false,ECZK_graph_simulator_executed:false};
}
console.log(JSON.stringify(runChecker(), null, 2));
