#!/usr/bin/env node
'use strict';
// Run 536: finite algebra and deliberately limited noisy parity oracle.
// No cryptographic hardness, no practical QPT proof is tested here.
const crypto = require('crypto');
let seed=53620261015n;
function rand32(){seed=(seed*6364136223846793005n+1442695040888963407n)&((1n<<64n)-1n);return Number((seed>>32n)&0xffffffffn);}
function parity(x){let b=0;while(x){b^=1;x&=x-1;}return b;}
function digest(x,width){return crypto.createHash('sha256').update(`${width}:${x}`).digest('hex');}
function recoveredBit(noisyOracle,n,i,repetitions){let sum=0;for(let j=0;j<repetitions;j++){const r=rand32()&((1<<n)-1);const a=noisyOracle(r);const b=noisyOracle(r^(1<<i));sum+=(a^b)?1:-1;}return sum>0?1:0;}
let exactBalanced=0;
for(let n=1;n<=9;n++){
  const N=1<<n;
  for(let K=1;K<N;K++){
    let ones=0;
    for(let r=0;r<N;r++)ones+=parity(r&K);
    if(ones!==N/2)throw Error('unbalanced parity');
    exactBalanced++;
  }
}
// Public verification key makes the *naive full-key XOR* chosen-message
// encryption distinguishable without ever recovering K from the public key.
let naiveDistinguishWins=0,naiveCases=96;
for(let j=0;j<naiveCases;j++){
 const n=20,K=rand32()&((1<<n)-1),m0=0,m1=(1<<n)-1,b=rand32()&1;
 const check=digest(K,n),c=K^(b?m1:m0);
 const c0=digest(c^m0,n)===check,c1=digest(c^m1,n)===check;
 if(c0===c1)throw Error('bad toy checker collision');
 const guess=c1?1:0;if(guess!==b)throw Error('naive distinguish error');naiveDistinguishWins++;
}
// Special iid-noise predictor: elementary two-query pairwise parity decoder.
// This is NOT a substitute for Goldreich-Levin against arbitrary predictors.
let oracleRecoveries=0,oracleCases=40,queries=0;
for(let j=0;j<oracleCases;j++){
 const n=16,K=rand32()&0xffff;
 function oracle(r){queries++;const noisy=(rand32()%100)<9;return parity(r&K)^(noisy?1:0);}
 let out=0;
 for(let i=0;i<n;i++)out|=recoveredBit(oracle,n,i,80)<<i;
 if(out!==K)throw Error('iid-noise decoder failed');
 oracleRecoveries++;
}
const report={run:536,checker:'run536_we_boundary_check.js',seed:'53620261015',status:'PASS',
  balanced_nonzero_secret_cases:exactBalanced,
  naive_public_key_otp_distinguish_wins:naiveDistinguishWins,
  naive_cases:naiveCases,
  iid_noise_pairwise_parity_recoveries:oracleRecoveries,
  iid_noise_cases:oracleCases,
  iid_noise_oracle_calls:queries,
  qualification:'Finite algebra, flawed-OTP attack and iid-noise decoding only; arbitrary-predictor inversion uses Goldreich-Levin theorem, not this checker. No concrete QPT WKEM.'};
process.stdout.write(JSON.stringify(report,null,2)+'\n');
