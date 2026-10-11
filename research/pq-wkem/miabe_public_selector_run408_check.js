function run408() {
  let checks = 0, trials = 0, state = 0x408A5A >>> 0;
  const check = ok => { if (!ok) throw Error("assertion " + (++checks)); checks++; };
  const next = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  const rand = n => next() % n;
  const mul = (a,b,q) => (a*b)%q;
  const power = (a,e,q) => { let r=1; while(e>0) {if(e%2)r=mul(r,a,q); a=mul(a,a,q);e=Math.floor(e/2);}return r; };
  const inv = (a,q) => power(a,q-2,q);
  for (const q of [17,257,65537]) {
    for (const width of [1,2,3,5,8]) {
      for (let repeat=0;repeat<120;repeat++) {
        trials++;
        const t1=1+rand(q-1), w0=1+rand(q-1);
        const firstBase=mul(t1,w0,q);
        const W=Array.from({length:width},()=>[1+rand(q-1),1+rand(q-1)]);
        const A=Array.from({length:width},()=>[rand(q),rand(q)]);
        const selectorBase=inv(w0,q);
        check(mul(firstBase,selectorBase,q)===t1);
        for(let i=0;i<width;i++) {
          const normalized=[];
          for(let b=0;b<2;b++) {
            const main=mul(mul(t1,A[i][b],q),W[i][b],q);
            const knownCoin=1+rand(q-1);
            const second=mul(knownCoin,inv(W[i][b],q),q);
            const paired=mul(main,second,q);
            const unmasked=mul(paired,inv(knownCoin,q),q);
            check(unmasked===mul(t1,A[i][b],q));
            check(mul(main,0,q)===0);
            normalized.push(unmasked);
          }
          const sameFrameDifference=((normalized[1]-normalized[0])%q+q)%q;
          check(sameFrameDifference===mul(t1,((A[i][1]-A[i][0])%q+q)%q,q));
        }
      }
    }
  }
  return {run:408,model:"exact exponent-group algebra; target-group scalar normalization, not key recovery",seed:"0x408a5a",trials,assertions_passed:checks,moduli:[17,257,65537],widths:[1,2,3,5,8],original_witness_extracted:false,cryptographic_security_established:false,actual_lattice_or_pairing_implemented:false};
}
console.log(JSON.stringify(run408(),null,2));
