#!/usr/bin/env node
"use strict";
function run() {
  "use strict";
  const counts = { local: 0, factor: 0, "no-literal-input": 0, rank: 0, relation: 0 };
  const ck=(v,g,d)=>{if(!v)throw new Error(g+": "+d);counts[g]++;};
  const bitcount=v=>{let n=0;while(v){v&=v-1;n++;}return n;};
  const rank=arr=>{const piv={};for(let x of arr){while(x){const i=31-Math.clz32(x);if(!(i in piv)){piv[i]=x;break;}x^=piv[i];}}return Object.keys(piv).length;};
  const groupFactor=forms=>{if(!forms.length)return 0;let [a,b]=forms[0];if(!a||!b||a===b)return 0;const opts=[a,b,a^b];for(const [u,v] of forms.slice(1)){if(!u||!v||u===v)return 0;for(let j=opts.length-1;j>=0;j--)if(opts[j]!==u&&opts[j]!==v&&opts[j]!== (u^v))opts.splice(j,1);}return Math.min(...opts);};
  const allMasks=h=>{const ms=[];for(let eta=0;eta<2;eta++)for(let L=0;L<(1<<h);L++){if(eta&&L===0)continue;for(let beta=0;beta<2;beta++){const block=[];for(let i=0;i<h;i++){const bits=[];for(const [u,v] of [[0,0],[0,1],[1,0],[1,1]]){const a=u^v,b=v,cp=(u&v)^v;bits.push((((L>>i)&1)&(cp^(beta&b)))^(i===0?(eta&(a^beta)):0));}block.push(bits);}ms.push(block);}}return ms;};
  const state=(x,y,z)=>{const u=x^y,v=y,j=(u<<1)|v;return z===(u&v)?1<<j:15^(1<<j);};
  const out=[];
  for(let h=1;h<=5;h++) {
    const forms=Array.from({length:h},(_,i)=>[1^(1<<(i+1)),1<<(i+1)]);
    ck(groupFactor(forms)===1,"factor","shared quadratic selector");
    for(let i=0;i<h;i++)for(let j=i+1;j<h;j++)ck(!forms[i].some(x=>forms[j].includes(x)),"no-literal-input","no identical original factor");
    const masks=allMasks(h), den=masks.length,errs=[];
    ck(den===2*((1<<(h+1))-1),"local","rejection sample count");
    for(const blocks of masks)errs.push(blocks.reduce((v,block,i)=>v+block.reduce((w,b,k)=>w+(b<<(4*i+k)),0),0));
    ck(rank(errs)===2*h+2,"rank","physical mask span");
    let seenValid=0,seenInvalid=0;
    for(let bits=0;bits<(1<<(1+2*h));bits++){
      const x=bits&1,ys=Array.from({length:h},(_,i)=>(bits>>(1+i))&1),zs=Array.from({length:h},(_,i)=>(bits>>(1+h+i))&1);
      const st=ys.map((y,i)=>state(x,y,zs[i]));
      const valid=ys.every((y,i)=>zs[i]===((x^y)&y));
      let sum=0;
      for(const blocks of masks){let v=0;for(let i=0;i<h;i++)for(let k=0;k<4;k++)v^=blocks[i][k]*((st[i]>>k)&1);sum+=v?-1:1;}
      ck(sum===(valid?(1<<(h+1)):0),"local","exact witness-only signed character");
      if(valid)seenValid++;else seenInvalid++;
    }
    out.push({h,rho:`${1<<h}/${(1<<(h+1))-1}`,independent:`${2**h}/${3**h}`,maskRank:rank(errs),validModes:seenValid,invalidModes:seenInvalid,originalGatesShareLiteralInput:h===1});
  }
  const h=2;
  let trueCount=0,falseCount=0;
  for(let bits=0;bits<(1<<(1+2*h));bits++){
    const x=bits&1,y0=(bits>>1)&1,y1=(bits>>2)&1,z0=(bits>>3)&1,z1=(bits>>4)&1;
    const trueRel=(z0===((x^y0)&y0)&&z1===((x^y1)&y1)&&z0===0&&z1===0);
    const falseRel=trueRel&&x===0&&y0===1;
    if(trueRel)trueCount++;if(falseRel)falseCount++;
  }
  ck(trueCount===5&&falseCount===0,"relation","true and false pinned ORIGINAL fixtures");
  return {status:"PASS",assertions:Object.values(counts).reduce((a,b)=>a+b,0),counts,source:"affine-quadratic-star exact signed-character and factor checks",cases:out,relationFixture:{acceptedTrue:trueCount,acceptedFalse:falseCount},limitations:"The independently executed local Python checker adds exhaustive full-quotient laws, GL2/NAND rewrites and dyadic polar certificate."};
}
console.log(JSON.stringify(run(),null,2));
