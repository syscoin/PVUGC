'use strict';
// Exact finite attack check: NOT LWE, CCO, or a PQ construction.
const C=require('crypto'),A=require('assert').strict;
let checks=0, falseInstances=0, trueWitnesses=0, targetRecoveries=0;
const H=(...s)=>C.createHash('sha256').update(s.join('|')).digest();
const X=(a,b)=>Buffer.from(a.map((v,i)=>v^b[i]));
const ok=(b)=>{checks++;A.ok(b)};
for(let i=0;i<48;i++){
 const ctx=`claim:${i}|UTXO:${i*7+1}|disprove`, a=(i>>1)&1,b=(i>>2)&1,unsat=i&1;
 const rho=w=>unsat?[w[0]^a,w[0]^(1-a),w[1]^b]:[w[0]^a,w[1]^b,0];
 const g=w=>X(H(ctx,'mask',rho(w).join('')),H(ctx,'mask','000'));
 const T=H('fresh deterministic fixture target',ctx);
 const F=w=>X(T,g(w));
 const trial=[0,0,0], guess=X(F(trial),g(trial));
 ok(guess.equals(T));targetRecoveries++;
 const caps=H('capability',ctx,T.toString('hex'));
 ok(H('capability',ctx,guess.toString('hex')).equals(caps));
 let validCount=0;
 for(let p=0;p<2;p++)for(let q=0;q<2;q++)for(let j=0;j<2;j++){
   const w=[p,q,j],valid=rho(w).every(t=>t===0),accepted=F(w).equals(T);
   ok(valid===accepted);if(valid){validCount++;ok(caps.equals(H('capability',ctx,T.toString('hex'))));}
 }
 if(unsat){ok(validCount===0);falseInstances++;}else{ok(validCount===2);trueWitnesses+=2;}
}
console.log(JSON.stringify({run:485,assertions:checks,fixtures:48,false_instances:falseInstances,valid_witness_releases:trueWitnesses,chosen_input_target_recoveries:targetRecoveries,claim:'public target recovery identity and derived-capability test only; no actual obfuscation'},null,2));
