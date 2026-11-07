'use strict';
// Offline exact finite-field checker for the compact LWE SOURCE; not QPT testing.
let tests=0, state=0x4a661a57;
const assert=(v,msg)=>{tests++;if(!v)throw new Error(msg||'assertion failed');};
const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0;};
const mod=(x,q)=>((x%q)+q)%q;
const dot=(x,y,q)=>mod(x.reduce((a,v,i)=>a+v*y[i],0),q);
const At=(A,r,q)=>A[0].map((_,j)=>mod(A.reduce((a,row,i)=>a+row[j]*r[i],0),q));
const err=()=>[-1,0,1][rnd()%3];
const radix=(v,b)=>{let out=[];do{out.push(Number(v%BigInt(b)));v/=BigInt(b);}while(v);return out;};
const secret=()=>Array.from({length:8},()=>rnd()).reduce((x,v)=>(x<<32n)|BigInt(v),0n);
const q=257,m=12,n=3,g=2*m+1,base=Math.floor(q/g);
const A=Array.from({length:m},()=>[0,rnd()%q,rnd()%q]);
const s0=[0,3,4],s1=[1,3,4],e=Array.from({length:m},err);
const b=A.map((r,i)=>mod(dot(r,s0,q)+e[i],q));
for(let i=0;i<m;i++) assert(mod(dot(A[i],s1,q)+e[i],q)===b[i],'second valid witness');
for(let trial=0;trial<16;trial++){
  const K=secret(),U=secret(),Z=secret(),D=U^Z,V=K^U;
  let out=[];
  for(const digit of radix(Z,base)){
    const r=Array.from({length:m},err),c=At(A,r,q),d=mod(dot(b,r,q)+g*digit,q);
    for(const s of [s0,s1]){
      const p=mod(d-dot(s,c,q),q);
      const dist=k=>Math.min(mod(p-g*k,q),mod(g*k-p,q));
      const recovered=Array.from({length:base},(_,i)=>i).reduce((best,i)=>dist(i)<dist(best)?i:best,0);
      assert(recovered===digit,'same-capability radix release');
      assert(dist(recovered)<=m,'bounded error');
    }
    out.push(digit);
  }
  const recoveredZ=out.reduceRight((x,d)=>x*BigInt(base)+BigInt(d),0n);
  assert((D^V^recoveredZ)===K,'full SAME K');
}
for(let trial=0;trial<100;trial++){
  const u=Array.from({length:m},()=>rnd()%q),r=Array.from({length:m},err),a=rnd()%base;
  const ps=At(A,u,q),pe=u.map((x,i)=>mod(x+r[i],q)),pt=mod(-dot(b,u,q)+g*a,q);
  const c=At(A,pe,q).map((x,i)=>mod(x-ps[i],q)),d=mod(dot(b,pe,q)+pt,q);
  assert(c.every((x,i)=>x===At(A,r,q)[i]),'row-source projection c');
  assert(d===mod(dot(b,r,q)+g*a,q),'row-source projection d');
}
let collisionSum=0;
const R=[];for(let x=-1;x<=1;x++)for(let y=-1;y<=1;y++)for(let z=-1;z<=1;z++)R.push([x,y,z]);
for(let h=0;h<15625;h++){
  let z=h;const H=Array.from({length:3},()=>[z%5,(z=Math.floor(z/5))%5]);
  const counts=Array(25).fill(0);
  for(const r of R){const v=At(H,r,5);counts[v[0]*5+v[1]]++;}
  collisionSum+=counts.reduce((x,y)=>x+y*y,0);
}
assert(collisionSum===860625,'exact universal hashing collision identity');
for(let K=0;K<4;K++){
  const pairs=new Set();for(let U=0;U<4;U++)for(let Z=0;Z<4;Z++)pairs.add(`${U^Z}:${K^U}`);
  assert(pairs.size===16,'conditional XOR share bijection');
}
console.log(JSON.stringify({record:'lwe-syndrome-source-20261028-turn11',tests,full_seed_trials:16,multi_original_witnesses:2,source_compression_trials:100,exact_hash_collision_sum:collisionSum,exact_hash_matrices:15625,security:'finite algebra only; QPT DecLWE is a separate unverified assumption',status:'PASS'},null,2));
