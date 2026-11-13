// Offline reproducible check. Ed25519 is a FUNCTIONAL MOCK, not PQ; H is a tiny structured SOURCE.
'use strict';
const C=require('crypto');
const q=257,N=3,J=2,m=6,n=3,B=1,g=Math.floor(q/8);
let assertions=0;
function ok(cond,label){ assertions++;if(!cond)throw Error(label); }
function mod(a){return ((a%q)+q)%q;}
function rand(){return C.randomInt(0,q);}
function dot(x,y){return x.reduce((s,v,i)=>s+v*y[i],0);}
function msg(d){return Buffer.concat([Buffer.from('PVUGC/SETUP-ATTEST/1\0'),Buffer.from(JSON.stringify(d))]);}
const {privateKey:sk,publicKey:pk}=C.generateKeyPairSync('ed25519');
const secret=sk.export({format:'der',type:'pkcs8'});
const keybits=Array.from(secret).flatMap(b=>Array.from({length:8},(_,i)=>(b>>i)&1));
const digits=[];for(let k=0;k<keybits.length;k+=3){digits.push((keybits[k]||0)+2*(keybits[k+1]||0)+4*(keybits[k+2]||0));}
const A=Array.from({length:n},(_,i)=>Array.from({length:m},()=>i===n-1?0:rand()));
const s=[6,11,20],s2=[6,11,99],e=Array.from({length:m},()=>[-1,0,1][C.randomInt(0,3)]);
const b=Array.from({length:m},(_,k)=>mod(A.reduce((acc,row,i)=>acc+row[k]*s[i],e[k])));
for(let k=0;k<m;k++)ok(mod(b[k]-A.reduce((sum,row,i)=>sum+row[k]*s2[i],0))===mod(e[k]),'two SOURCE witnesses');
const shares=digits.map(a=>{const x=rand(),y=rand();return [x,y,mod(a-x-y)];});
const coins=[],caps=[];
for(let j=0;j<J;j++){
 const cc=[],rr=[];
 for(let k=0;k<digits.length;k++){
  const row=[],rrow=[];
  for(let i=0;i<N;i++){
   const r=Array(m).fill(0),pos=C.randomInt(0,m);r[pos]=C.randomInt(0,2)?1:-1;
   const u=A.map(a=>mod(dot(a,r))),v=mod(dot(b,r)+g*shares[k][i]);
   row.push({u,v});rrow.push(r);
   ok(u.every((ui,idx)=>ui===mod(dot(A[idx],r)))&&v===mod(dot(b,r)+g*shares[k][i]),'encryption');
  }
  cc.push(row);rr.push(rrow);
 }
 caps.push(cc);coins.push(rr);
}
const pkDer=pk.export({format:'der',type:'spki'}).toString('hex');
const D={domain:'setup-only',relation:'ORIGINAL-R binding; no ORIGINAL compiler',claim:'claim-001',utxo:'mock:0',
 branch:'qualified-fork-challenge',context:'anchors/window',challengePath:'claim-001/challenge',
 pk:pkDer,source:{q,A,b,B},caps,related:['claim-001/c0','claim-001/c1'],aux:{source:'public-independent'}};
const sig=C.sign(null,msg(D),sk);
ok(C.verify(null,msg(D),pk,sig),'same-native-key setup attestation');
function nativeOracleSignNonchallenge(m){ok(m.subarray(0,21).toString().startsWith('PVUGC/SETUP-ATTEST/1'),'only setup signed');return C.sign(null,m,sk);}
const oracleSig=nativeOracleSignNonchallenge(msg(D));
ok(C.verify(null,msg(D),pk,oracleSig),'EUF signing-oracle simulation interface');
for(const change of ['claim','pk','branch','caps','aux','related']){
 const t=JSON.parse(JSON.stringify(D));
 if(change==='claim')t.claim='claim-002';
 if(change==='pk')t.pk='00'+t.pk.slice(2);
 if(change==='branch')t.branch='timeout';
 if(change==='caps')t.caps[0][0][0].v=mod(t.caps[0][0][0].v+1);
 if(change==='aux')t.aux.source='corrupted';
 if(change==='related')t.related.pop();
 ok(!C.verify(null,msg(t),pk,sig),'tamper rejected: '+change);
}
function release(witness, j){
 const recovered=[];
 for(let k=0;k<digits.length;k++){
  const u=Array.from({length:n},(_,row)=>mod(caps[j][k].reduce((a,c)=>a+c.u[row],0)));
  const v=mod(caps[j][k].reduce((a,c)=>a+c.v,0)), d=mod(v-dot(witness,u));
  const distances=Array.from({length:8},(_,z)=>{const t=mod(d-g*z);return Math.min(t,q-t);});
  const value=distances.indexOf(Math.min(...distances));
  ok(value===digits[k]&&distances[value]<=N*B,'same-capability complete release');
  recovered.push(value);
 }
 const bits=recovered.flatMap(v=>[(v&1),((v>>1)&1),((v>>2)&1)]).slice(0,keybits.length);
 const result=Buffer.from(Array.from({length:secret.length},(_,i)=>bits.slice(8*i,8*i+8).reduce((a,b,j)=>a+(b<<j),0)));
 ok(result.equals(secret),'whole same actual serialized native key');
 const restored=C.createPrivateKey({key:result,format:'der',type:'pkcs8'});
 const challenge=Buffer.from('PVUGC/CHALLENGE-PATH/1\0claim-001/mock-sighash');
 const nativeSig=C.sign(null,challenge,restored);
 ok(C.verify(null,challenge,pk,nativeSig),'intended native signature');
 ok(!C.verify(null,challenge,pk,sig),'setup signature cannot replay for challenge');
}
for(const w of [s,s2])for(let j=0;j<J;j++)release(w,j);
for(const corrupted of [[0,1],[0,2],[1,2]])for(let j=0;j<J;j++)for(let k=0;k<digits.length;k++)for(const i of corrupted){
 const r=coins[j][k][i],c=caps[j][k][i];
 ok(c.u.every((v,row)=>v===mod(dot(A[row],r)))&&c.v===mod(dot(b,r)+g*shares[k][i]),'adaptive open full coins');
}
const badSource={q:7,A:[[0,0,0]],b:[1,0,0],B:0};
const falseD={domain:'setup-only',claim:'untrusted-malicious-dealer',pk:pkDer,source:badSource};
const falseSig=nativeOracleSignNonchallenge(msg(falseD));
ok(C.verify(null,msg(falseD),pk,falseSig),'signature still authenticates false SOURCE');
ok(badSource.b[0]!==0,'false SOURCE has no preimage');
console.log(JSON.stringify({status:'PASS',assertions,n,m,q,N,J,sourcePreimages:2,fullNativeSecretBytes:secret.length,
 individualCiphertexts:J*N*digits.length,relatedCapsules:J,tamperRejections:6,
 falseSourceSignedDespiteNoPreimage:true,signature:'Ed25519 mock, NOT PQ',security:'NO ORIGINAL witness reduction'},null,2));
