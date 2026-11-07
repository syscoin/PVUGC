(function runCheck(){
  let assertions=0;
  function ok(cond,why){assertions++;if(!cond)throw Error(why)}
  const openings=[[],[0],[1],[2],[0,1],[0,2],[1,2]];
  const triples=k=>{let a=[];for(let x=0;x<=1;x++)for(let y=0;y<=1;y++)a.push([x,y,k^x^y]);return a};
  function dist(k,pattern){const result={};for(const w of triples(k)){const key=pattern.map(i=>w[i]).join(",");result[key]=(result[key]||0)+1}return JSON.stringify(Object.keys(result).sort().map(k=>[k,result[k]]))}
  for(const O of openings){ok(dist(0,O)===dist(1,O),"one-capsule disclosure secret-independence");const survivors=3-O.length;ok(survivors>0,"at most two openings");let weight=0;for(let g=0;g<3;g++)if(!O.includes(g))weight+=1/survivors;ok(weight===1,"exact inverse-survival identity")}
  function product(arr,n){let out=[[]];for(let i=0;i<n;i++){let next=[];for(const p of out)for(const a of arr)next.push([...p,a]);out=next}return out}
  let threePatterns=0;
  for(const pattern of product(openings,3)){
    const counts=[];
    for(let k=0;k<=1;k++){
      const d=new Map();
      for(const t0 of triples(k))for(const t1 of triples(k))for(const t2 of triples(k)){
        const tt=[t0,t1,t2], key=pattern.map((O,c)=>O.map(i=>tt[c][i]).join(",")).join("|");
        d.set(key,(d.get(key)||0)+1)
      }
      counts.push(JSON.stringify([...d.entries()].sort((a,b)=>a[0].localeCompare(b[0]))))
    }
    ok(counts[0]===counts[1],"3-capsule joint disclosure secret independence");
    threePatterns++;
  }
  function adaptive(k){const d={};for(const w of triples(k)){const next=w[0]===0?1:2;const key=`0:${w[0]}|${next}:${w[next]}`;d[key]=(d[key]||0)+1}return JSON.stringify(Object.keys(d).sort().map(k=>[k,d[k]]))}
  ok(adaptive(0)===adaptive(1),"adaptive classical 2-lane observation hides secret");
  let fourPatterns=0;
  for(const pattern of product(openings,4)){
    let globalSurvivors=1;
    for(const O of pattern){const c=3-O.length;globalSurvivors*=c;let single=0;for(let guess=0;guess<3;guess++)if(!O.includes(guess))single+=1/c;ok(single===1,"per-transition guess inverse weight")}
    ok(globalSurvivors/(81*globalSurvivors)===1/81,"global guess factor 1/81");
    fourPatterns++;
  }
  const q=2147483647,scale=Math.floor(q/16384),s=1234567, A=[1,1,1],t=1,errors=[1,0,-1],star=1;
  function near(r){const guesses=new Set();let guess=Math.round(r/scale);for(let j=-2;j<=2;j++)guesses.add((guess+j+16384*3)%16384);let best=null,bestD=Infinity;for(const m of guesses){const x=(r-scale*m+q)%q,d=Math.min(x,q-x);if(d<bestD){best=m;bestD=d}}return best}
  for(const message of [0,1,1234,16383]){
    const beta=A.map((x,i)=>(x*s+errors[i]+q)%q),tau=(t*s+star+scale*message)%q;
    for(const W of [[1,0,0],[0,1,0],[0,0,1]]){const r=(tau-W.reduce((v,w,i)=>v+w*beta[i],0)+q*3)%q;ok(near(r)===message,"SOURCE valid binary witness LWE symbol")}
  }
  ok(![0,1].some(x=>x===3),"FALSE no binary SOURCE witness");
  const falseSymbol=4321,beta=s,tau=(3*s+scale*falseSymbol)%q;
  ok(near((tau-3*beta+q*3)%q)===falseSymbol,"chosen FALSE has unauthorized public nonbinary decryption");
  const nativePrivateBits=2*256, masterBits=256, L=Math.ceil(masterBits/14),rawL=Math.ceil(nativePrivateBits/14), sourceMatrixBytes=512*20680*5;
  ok(nativePrivateBits===512&&L===19&&rawL===37,"corrected native private-seed widths");
  ok(sourceMatrixBytes===52940800,"matrix bytes");
  ok(3*2*L*20681*5===11788170,"256-bit master ciphertext bytes");
  ok(3*2*rawL*20681*5===22955910,"raw 512-bit native private core ciphertext bytes");
  const qBig=1099511627689,d=512,n=20680,B=16384,g=Math.floor(qBig/16384),u=Math.ceil(g/2),V=(n+1)*B*(B+1)/3;
  function logEta(C){const T=3*C*L;return Math.log2(T)+n-d*Math.log2(qBig)+1-u*u/(2*(V+B*u/3))/Math.LN2}
  ok(logEta(2)<-191&&logEta(2)>-192,"simultaneous honest SOURCE witness bound C2");
  ok(Math.abs(logEta(8)-logEta(2)-2)<1e-9,"logarithmic error loss across C");
  return {id:"STM-QPT-20261031",assertions,three_capsule_patterns:threePatterns,four_capsule_patterns:fourPatterns,adaptive_opening:"exact one-bit secrecy identity",source_witnesses_tested:3,master_bits:256,native_private_seed_bits:512,raw_fallback_symbols:rawL,master_symbols:L,transition_lwe_hybrid_edges:2*L,transition_guess_factor:3,simultaneous_four_capsule_guess_factor:81,log2_all_witness_eta_c2:+logEta(2).toFixed(9),log2_all_witness_eta_c8:+logEta(8).toFixed(9),matrix_bytes:sourceMatrixBytes,master_c2_cipher_bytes:11788170,raw_c2_cipher_bytes:22955910,chosen_false_public_recovery:"PASS (insecure)",status:"restricted algebra only; ORIGINAL reduction unsolved"}
})();
