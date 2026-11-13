// Run 486: exact finite GL parity and ciphertext-distinguisher diagnostics.
// Toy public view leaks key prefix. This is NOT a WE/local mixer/PQ construction.
const assert = require('node:assert/strict');
const rows=[]; let checks=0;
const parity=x=>{let p=0;for(;x;x>>=1)p^=x&1;return p};
for(let h=1;h<=5;h++){
  let wins=0, guesses=0, tv=0;
  for(let k=0;k<256;k++){
    const prefix=k>>h, candidate=prefix<<h;
    guesses+=(candidate===k);
    for(let r=0;r<256;r++) wins+=(parity(candidate&r)===parity(k&r));
  }
  for(let r=0;r<256;r++) tv+=((r&((1<<h)-1))===0);
  assert.equal(2*wins-65536,65536/(1<<h));checks++;
  assert.equal(guesses,256/(1<<h));checks++;
  assert.equal(tv,256/(1<<h));checks++;
  rows.push({hidden_bits:h,key_guess:`1/${1<<h}`,parity_predict_advantage:`1/${1<<(h+1)}`,ciphertext_TV:`1/${1<<h}`});
}
console.log(JSON.stringify({run:486,checks,rows,scope:'finite identities only; no security claim'},null,2));
