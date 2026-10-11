'use strict';
// Deterministic finite verification of a public bounded-unary-orbit bypass.
// Toy checking credential, NOT an actual signature or cryptographic security.
const crypto=require('crypto');let assertions=0,fixtures=0;
function ok(b){assertions++;if(!b)throw Error('assertion '+assertions)}
function H(x){return crypto.createHash('sha256').update(x).digest('hex')}
function vk(k){return H('vk/'+k)}
function sig(k,ctx){return {key:k,mac:H('sig/'+k+'/'+ctx)}}
function verify(v,ctx,s){return !!s&&vk(s.key)===v&&s.mac===H('sig/'+s.key+'/'+ctx)}
function U(s,T){return {k:s.k,j:(s.j+1)%T}}
for(let T=2;T<=8;T++) for(const k of [0,1,7,15,37,255]) {
 const context='utxo:'+T+':'+k, v=vk(k),initial={k,j:0};
 for(let mask=1;mask<(1<<T);mask++) {
  let state=initial,first=-1;
  for(let t=0;t<T;t++){
   const candidate=(mask&(1<<state.j))?sig(state.k,context):null;
   if(verify(v,context,candidate)&&first<0)first=t;
   state=U(state,T);
  }
  ok(first>=0);ok((mask&(1<<first))!==0);
  for(let t=0;t<T;t++)if(mask&(1<<t)){
   let s=initial;for(let j=0;j<t;j++)s=U(s,T);
   ok(verify(v,context,sig(s.k,context)));
  }
  fixtures++;
 }
}
const output={run:397,status:'PASS',assertions,fixtures,scope:'public bounded unary orbit only',real_CLZ:false,QPT_proven:false,WKEM_solved:false};
console.log(JSON.stringify(output,null,2));
