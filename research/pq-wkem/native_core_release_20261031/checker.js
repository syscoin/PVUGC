'use strict';
// NCSR-20261031 — exact executable offline toy arithmetic and hash-only signature fixture.
// Neither LWE hardness nor QPT signature security is claimed for this fixture.
const crypto = require('crypto');
const Q = 2147483647n; const PACK=14; const M=1<<PACK; const G=Q/BigInt(M);
let assertions=0;
function ok(cond,msg){assertions++;if(!cond)throw Error('assertion '+assertions+': '+msg);}
function H(...values){const h=crypto.createHash('sha256');for(const v of values) h.update(Buffer.isBuffer(v)?v:Buffer.from(String(v)));return h.digest();}
function xor(a,b){ok(a.length===b.length,'xor lengths');return Buffer.from(a.map((v,i)=>v^b[i]));}
function mod(a){let r=a%Q;return r<0n?r+Q:r;}
function prng(seed){let x=seed>>>0;return function(){x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0;};}
const rnd=prng(0x4e435352);
function raw(){return BigInt(rnd());}
function small(){return BigInt(rnd()%5)-2n;}
function chunks(buf){const out=[];let acc=0,count=0;for(const byte of buf){for(let bit=7;bit>=0;bit--){acc=(acc<<1)|((byte>>bit)&1);count++;if(count===PACK){out.push(acc);acc=0;count=0;}}}if(count)out.push(acc<<(PACK-count));return out;}
function unchunks(vals,nbytes){const bits=[];for(const v of vals){ok(Number.isInteger(v)&&v>=0&&v<M,'chunk range');for(let bit=PACK-1;bit>=0;bit--)bits.push((v>>bit)&1);}ok(bits.slice(nbytes*8).every(b=>b===0),'zero padding');const bytes=Buffer.alloc(nbytes);for(let i=0;i<nbytes*8;i++)bytes[i>>3]|=bits[i]<<(7-(i%8));return bytes;}
function rootAndPaths(core,pubseed){
  const skseed=core.subarray(0,16), skprf=core.subarray(16,32);let leaves=[];
  for(let i=0;i<64;i++){const idx=Buffer.from([i]);const secret=H('NC-OTS-SECRET',skseed,skprf,pubseed,idx);leaves.push(H('NC-OTS-LEAF',idx,secret));}
  const levels=[leaves];for(let k=0;k<6;k++){const prev=levels[k], next=[];for(let j=0;j<prev.length;j+=2)next.push(H('NC-NODE',prev[j],prev[j+1]));levels.push(next);}
  return levels;
}
function nativeFixtureKeyGen(){const core=H('NC-CANONICAL-CORE').subarray(0,32);const pubseed=H('NC-PUBSEED').subarray(0,16);const pkroot=rootAndPaths(core,pubseed)[6][0].subarray(0,16);const vk=Buffer.concat([pubseed,pkroot]);return {core,vk,sk:Buffer.concat([core,vk])};}
function nativeSign(sk,msg){ok(sk.length===64,'canonical secret length');const core=sk.subarray(0,32),vk=sk.subarray(32,64),pubseed=vk.subarray(0,16);const levels=rootAndPaths(core,pubseed);ok(levels[6][0].subarray(0,16).equals(vk.subarray(16)),'native root matches');const digest=H('NC-MESSAGE',msg);const pieces=[];for(let i=0;i<32;i++){const bit=(digest[i>>3]>>(7-(i%8)))&1;const idx=2*i+bit;const secret=H('NC-OTS-SECRET',core.subarray(0,16),core.subarray(16),pubseed,Buffer.from([idx]));pieces.push(secret);for(let k=0;k<6;k++)pieces.push(levels[k][(idx>>k)^1]);}return Buffer.concat(pieces);}
function nativeVerify(vk,msg,sig){if(vk.length!==32||sig.length!==32*7*32)return false;const digest=H('NC-MESSAGE',msg);let off=0;for(let i=0;i<32;i++){const bit=(digest[i>>3]>>(7-(i%8)))&1;const idx=2*i+bit;const secret=sig.subarray(off,off+32);off+=32;let cur=H('NC-OTS-LEAF',Buffer.from([idx]),secret);for(let k=0;k<6;k++){const other=sig.subarray(off,off+32);off+=32;cur=((idx>>k)&1)?H('NC-NODE',other,cur):H('NC-NODE',cur,other);}if(!cur.subarray(0,16).equals(vk.subarray(16)))return false;}return true;}
const A=[[2n,2n,4n,4n,19n,31n],[3n,3n,5n,5n,29n,43n]],t=[6n,8n];
const W=[[1n,0n,1n,0n,0n,0n],[0n,1n,0n,1n,0n,0n]];
function isWitness(w){if(w.length!==6||w.some(v=>v!==0n&&v!==1n))return false;return A.every((row,k)=>mod(row.reduce((a,v,i)=>a+v*w[i],0n))===t[k]);}
function enc(m,sourceA=A,sourceT=t,forceZero=false){const d=sourceA.length,n=sourceA[0].length,s=Array.from({length:d},()=>raw()%Q),e=Array.from({length:n},()=>forceZero?0n:small()),es=forceZero?0n:small();const beta=Array.from({length:n},(_,i)=>mod(e[i]+s.reduce((v,si,k)=>v+sourceA[k][i]*si,0n)));const tau=mod(sourceT.reduce((v,tk,k)=>v+tk*s[k],0n)+es+G*BigInt(m));return {beta,tau};}
function decode(c,w){const r=mod(c.tau-c.beta.reduce((v,bi,i)=>v+bi*w[i],0n));const nearest=Number((r+G/2n)/G)%M;return nearest;}
function setupCoreCapsules(core,ncaps=2){const u0=Buffer.alloc(32),u1=Buffer.alloc(32);for(let i=0;i<32;i++){u0[i]=rnd()&255;u1[i]=rnd()&255;}const u2=xor(xor(u0,u1),core), shares=[u0,u1,u2];return {shares,capsules:Array.from({length:ncaps},()=>shares.map(s=>chunks(s).map(m=>enc(m))))};}
function lift(capsule,w,nativeVK){const out=[];for(const lane of capsule){const values=lane.map(c=>decode(c,w));out.push(unchunks(values,32));}const core=xor(xor(out[0],out[1]),out[2]);return Buffer.concat([core,nativeVK]);}
const native=nativeFixtureKeyGen();ok(native.core.length===32,'256-bit core');ok(native.vk.length===32,'256-bit public half');ok(native.sk.length===64,'512-bit canonical secret');ok(Buffer.concat([native.core,native.vk]).equals(native.sk),'exact core/public reconstruction');
const msg=Buffer.from('CHALLENGE-CLAIM-UTXO-A/BRANCH-INVALID-FORK');
const signed=nativeSign(native.sk,msg);ok(nativeVerify(native.vk,msg,signed),'hash-only fixture signature verifies');ok(!nativeVerify(native.vk,Buffer.from('DIFFERENT-CLAIM'),signed),'claim scope changes message');
for(const w of W)ok(isWitness(w),'valid original fixture witness');ok(!W[0].every((x,i)=>x===W[1][i]),'different witness states');
const manifest={relation:'BINARY-ISIS-TOY',claim:'claim:123',utxo:'btc-txid:0',branch:'challenge',anchors:'BTC/SYS',window:'height-100-to-110',vk:native.vk.toString('hex')};
const manifestDigest=H('NC-MANIFEST',JSON.stringify(manifest));ok(!manifestDigest.equals(H('NC-MANIFEST',JSON.stringify({...manifest,utxo:'btc-txid:1'}))),'UTXO bound');ok(!manifestDigest.equals(H('NC-MANIFEST',JSON.stringify({...manifest,branch:'refund'}))),'branch bound');
const caps=setupCoreCapsules(native.core);ok(caps.capsules.length===2,'related capsules');ok(caps.capsules[0].length===3,'three XOR lanes');ok(caps.capsules[0][0].length===19,'256-bit/14-bit symbol count');
let recovered=0;for(const w of W){for(const capsule of caps.capsules){const key=lift(capsule,w,native.vk);ok(key.equals(native.sk),'every-witness SAME precommitted key');const sig=nativeSign(key,msg);ok(nativeVerify(native.vk,msg,sig),'reconstructed native fixture signs');recovered++;}}
ok(!caps.capsules[0][0][0].tau.toString().endsWith('FAKE'),'capsule is public ciphertext');ok(caps.capsules[0][0][0].tau!==caps.capsules[1][0][0].tau,'related ciphertext fresh coins');
// Known adversarial-FALSE source attack remains, including after native-core stripping.
const fA=[[1n]], ft=[3n], fz=[3n], fakeShares=[...caps.shares];const fakeCapsule=fakeShares.map(s=>chunks(s).map(m=>enc(m,fA,ft,true)));
const attackParts=fakeCapsule.map(lane=>unchunks(lane.map(c=>decode(c,fz)),32));
const attackCore=xor(xor(attackParts[0],attackParts[1]),attackParts[2]);
ok(attackCore.equals(native.core),'chosen FALSE nonbinary opener recovers full secret core');
const fakeKey=Buffer.concat([attackCore,native.vk]);ok(nativeVerify(native.vk,msg,nativeSign(fakeKey,msg)),'chosen FALSE can sign intended path');ok(![0n,1n].some(w=>mod(fA[0][0]*w)===ft[0]),'chosen source has no binary ORIGINAL witness');
// Illustrative analytical RS14 bound; uncalibrated QPT-LWE parameters.
const qh=1099511627689,dh=512,nh=20680,Bh=16384,bh=14,Th=114;
const gh=Math.floor(qh/2**bh),uh=Math.ceil(gh/2),variance=(nh+1)*Bh*(Bh+1)/3;
const log2Tail=1-(uh*uh/(2*(variance+Bh*uh/3)))/Math.LN2;
const log2Eta=Math.log2(Th)+nh-dh*Math.log2(qh)+log2Tail;
const oldCount=222,newCount=114;const oldBytes=oldCount*(nh+1)*5,newBytes=newCount*(nh+1)*5;
ok(log2Eta< -190,'all-witness success overwhelming over honest coins');ok(oldBytes-newBytes===11167740,'ciphertext saving arithmetic');ok(newCount===2*3*Math.ceil((256)/bh),'count is exact');
const result={candidate:'NCSR-2026-10-31',status:'restricted source native core release, NOT generic PQ WKEM',assertions,core_bits:256,public_native_bits:256,canonical_sk_bits:512,lwe_symbols_per_capsule:57,related_capsules:2,total_symbols:114,old_total_symbols:222,ciphertext_bytes:newBytes,old_ciphertext_bytes:oldBytes,saved_bytes:oldBytes-newBytes,pct_ciphertext_saved:Number((100*(oldBytes-newBytes)/oldBytes).toFixed(6)),log2_all_witness_fail_bound:Number(log2Eta.toFixed(6)),distinct_valid_witnesses_tested:W.length,recovered_keys_tested:recovered,toy_native_signature_bytes:signed.length,adversarial_FALSE_public_nonbinary_recovery:true,sha256_manifest:manifestDigest.toString('hex'),no_qpt_security_tested:true,no_native_bitcoin_support_claimed:true};
console.log(JSON.stringify(result,null,2));
