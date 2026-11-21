function jscheck() {
  let n=0;
  const ok=(x,msg="assertion")=>{n++;if(!x)throw Error(msg+" at "+n);};
  const q=65521, d=256, m=2000;
  const bound=7n**2000n, bits=(bound-1n).toString(2).length;
  ok(bits===5615);ok((1n<<5614n)<bound);ok(bound<(1n<<5615n));
  const rankE=(e)=>{let v=0n;for(let i=e.length-1;i>=0;i--){ok(e[i]>=-3&&e[i]<=3);v=7n*v+BigInt(e[i]+3);}return v;};
  const unrankE=(r,len)=>{if(r<0n||r>=7n**BigInt(len))throw Error("invalid rank");const e=[];for(let i=0;i<len;i++){e.push(Number(r%7n)-3);r/=7n;}return e;};
  for(let length=1;length<=4;length++) {
    const end=7**length;
    for(let v=0;v<end;v++){const e=unrankE(BigInt(v),length);ok(rankE(e)===BigInt(v));}
  }
  const e=Array.from({length:m},(_,i)=>(i*17+5)%7-3);
  const rank=rankE(e);ok(rank<bound);
  const back=unrankE(rank,m);for(let i=0;i<m;i++)ok(e[i]===back[i]);
  let threw=false;try{unrankE(bound,m);}catch(_){threw=true;}ok(threw);
  const seedBits=2*d*16+2*bits, dataGroups=Math.ceil(seedBits/256), groups=dataGroups+6;
  ok(seedBits===19422);ok(dataGroups===76);ok(groups===82);
  const ciphertext=groups*(512+64), old=85*(512+64);
  ok(ciphertext===47232);ok(old===48960);ok(old-ciphertext===1728);
  const choose=(n,k)=>{let a=1;for(let j=1;j<=k;j++)a=a*(n-j+1)/j;return a;};
  const coefficient=256*choose(groups,4);
  ok(coefficient===447759360);ok(coefficient<2**29);ok(groups-dataGroups+1===7);
  // GF(256) arithmetic regression for the systematic evaluation-code field.
  const mul=(a,b)=>{let c=0;while(b){if(b&1)c^=a;a<<=1;if(a&256)a^=0x11d;b>>=1;}return c;};
  const pow=(a,k)=>{let r=1;while(k){if(k&1)r=mul(r,a);a=mul(a,a);k>>=1;}return r;};
  for(let a=0;a<256;a++){if(a)ok(mul(a,pow(a,254))===1);for(const b of [0,1,2,3,127,255])ok(mul(a,b^3)===(mul(a,b)^mul(a,3)));}
  // Final-hybrid finite FULL PUBLIC deterministic-CK/aux mock, no random-oracle claim.
  const worlds=[];
  for(let secret=0;secret<8;secret++){
    const histogram=new Map();
    for(let a=0;a<8;a++)for(let b=0;b<8;b++)for(let uniformPad=0;uniformPad<8;uniformPad++){
      const missing=a^b^secret;ok((a^b^missing)===secret);
      const dsig=secret^uniformPad;
      const pub="VKfixed|UTXObound|siblingfixed|"+a+"|"+b+"|"+dsig;
      const ck=(a*17+b*29+dsig*37+101)%251; // deterministic CK from public bytes
      const key=pub+"|CK"+ck;
      histogram.set(key,(histogram.get(key)||0)+1);
    }
    worlds.push(histogram);
  }
  const reference=[...worlds[0]].sort((a,b)=>a[0].localeCompare(b[0]));
  for(const w of worlds) {
    const sorted=[...w].sort((a,b)=>a[0].localeCompare(b[0]));
    ok(JSON.stringify(sorted)===JSON.stringify(reference));
  }
  return {run:"R118-BASE7-RS82-20261106", assertions:n, errorRankBits:bits, oldSeedBits:20192, seedBits,
    groupsOld:85, groupsNew:groups, bytesOld:old, bytesNew:ciphertext,
    savedBytesPerOccurrence:old-ciphertext, savedBytes256:(old-ciphertext)*256,
    correction:"RS(82,76) distance 7; up to 3 groups", 
    simultaneousUnionCoefficient:coefficient, jointPublicToyWorlds:worlds.length,
    scope:"finite correctness/histogram checks; no generic NP source or quantum-hardness proof"};
}
console.log(JSON.stringify(jscheck(), null, 2));
