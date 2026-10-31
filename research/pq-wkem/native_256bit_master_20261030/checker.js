#!/usr/bin/env node
'use strict';
function runCheck(){
  let ncheck=0;
  const ck=(v,m)=>{ncheck++;if(!v)throw Error(m)};
  const choose=(n,k)=>{let z=1n;for(let i=1;i<=k;i++)z=z*BigInt(n-k+i)/BigInt(i);return z};
  const gf=(a,b)=>{let o=0;for(let j=0;j<8;j++){if(b&1)o^=a;const high=a&128;a=(a<<1)&255;if(high)a^=27;b>>=1}return o};
  const inverse=a=>{ck(a!==0,"zero inverse");for(let k=1;k<256;k++)if(gf(k,a)===1)return k;throw Error("no inverse")};
  let seed=20261030;
  const byte=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)&255};
  const randBytes=n=>Array.from({length:n},byte);
  const pack=arr=>{let v=0n;for(let i=arr.length-1;i>=0;i--)v=(v<<8n)+BigInt(arr[i]);return Array.from({length:Math.ceil(8*arr.length/5)},(_,i)=>Number((v>>(5n*BigInt(i)))&31n))};
  const unpack=(digits,n)=>{const L=Math.ceil(8*n/5);if(digits.length!==L||digits.some(x=>x<0||x>31)||digits[L-1] >=(1<<(8*n-5*(L-1))))throw Error("noncanonical");let z=0n;for(let i=L-1;i>=0;i--)z=(z<<5n)+BigInt(digits[i]);return Array.from({length:n},(_,i)=>Number((z>>(8n*BigInt(i)))&255n))};
  const q=16777213n,n=256,m=4469,g=524287,B=128,scopes=400;
  const thresholds={};
  for(const [name,L] of [["old_256bit",52],["new_512bit",103]]){
    const J=BigInt(scopes*3*2*L);
    const threshold=J*J*(q**BigInt(n)-1n)*(1n<<256n);
    let found=0;
    for(let w=1;w<=m;w++){
      if(threshold<=4n*(1n<<BigInt(w))*choose(m,w)){
        ck(threshold>4n*(1n<<BigInt(w-1))*choose(m,w-1),"minimum");
        found=w;break;
      }
    }
    thresholds[name]={L,J:Number(J),minimum_w:found};
  }
  ck(thresholds.old_256bit.minimum_w===2004,"old minimum");
  ck(thresholds.new_512bit.minimum_w===2006,"new minimum");
  const w=2006;
  const low=g-2*B*(w+1),high=Number(q)-31*g-2*B*(w+1);
  ck(low===10495&&high===10524,"digit separation");
  let recoveredPairs=0;
  for(let iter=0;iter<64;iter++){
    const K=randBytes(64),V=randBytes(64);
    const share=[1,2,3].map(a=>K.map((k,i)=>k^gf(a,V[i])));
    for(let i=0;i<3;i++){
      const d=pack(share[i]);
      ck(d.length===103&&d[102]<4,"digits");
      ck(JSON.stringify(unpack(d,64))===JSON.stringify(share[i]),"decode");
      const bad=d.slice();bad[102]=4;
      let rejects=false;try{unpack(bad,64)}catch(e){rejects=true}
      ck(rejects,"reject noncanonical");
    }
    for(const [i,j] of [[0,1],[0,2],[1,2]]){
      const denom=inverse((i+1)^(j+1));
      const k=share[i].map((s,b)=>s^gf(i+1,gf(s^share[j][b],denom)));
      ck(JSON.stringify(k)===JSON.stringify(K),"same precommitted K");
      recoveredPairs++;
    }
  }
  for(const a of [1,2,3])for(const s of [0,1,127,255]){
    const aInv=inverse(a);let possible=0n;
    for(let k=0;k<256;k++){
      const v=gf(s^k,aInv);
      ck(k^gf(a,v)===s,"one-share perfect hiding");
      possible|=1n<<BigInt(v);
    }
    ck(possible===(1n<<256n)-1n,"all master bytes compatible");
  }
  const Abytes=n*m*3;
  const before=Abytes+scopes*(3*n*52+3*(m+52))*3;
  const after=Abytes+scopes*(3*n*103+3*(m+103))*3;
  ck(before===67630992&&after===114816192,"bytes");
  return {candidate:"Native 256-bit seed-width SOURCE packet correction, not ORIGINAL WKEM",checks:ncheck,seed_bytes:32,prf_bytes:32,master_bytes:64,packet_digits:103,parameters:{q:Number(q),n,m,w,g,B},thresholds,noise_bound:B*(w+1),digit_gap_margin:[low,high],shamir_pairs_recovered:recoveredPairs,public_bytes_before:before,public_bytes_after:after,original_lift:false,actual_native_signature_test:false,complete_wkem_qpt_proof:false};
}
console.log(JSON.stringify(runCheck(),null,2));
