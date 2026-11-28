/* AXLR exact finite checker, no dependencies. */
const check = function axlrChecker(){
  let assertions=0;
  function ok(x,msg){if(!x)throw Error(msg||"assertion");assertions++;}
  function rows(n,edges){return edges.map(([u,v,b])=>{ok(u!==v&&u>=0&&v<n&&(b===0||b===1));return b^(1<<(u+1))^(1<<(v+1));});}
  function comb(A,s){let z=0;for(let i=0;i<A.length;i++)if((s>>i)&1)z^=A[i];return z;}
  function solve(A,target){const basis={};for(let i=0;i<A.length;i++){let z=A[i],c=1<<i;while(z){let p=31-Math.clz32(z);if(!basis[p]){basis[p]=[z,c];break;}z^=basis[p][0];c^=basis[p][1];}}let z=target,c=0;while(z){let p=31-Math.clz32(z);if(!basis[p])return null;z^=basis[p][0];c^=basis[p][1];}ok(comb(A,c)===target);return c;}
  function dot(a,b){let x=a&b,p=0;while(x){x&=x-1;p^=1;}return p;}
  function enc(A,m,s){return comb(A,s)^m;}
  let ng=0,nt=0,nf=0;
  const pairs=[[0,1],[0,2],[0,3],[1,2],[1,3],[2,3]];
  for(let t=0;t<729;t++){let z=t,edges=[];for(let j=0;j<6;j++){let dig=z%3;z=Math.floor(z/3);if(dig)edges.push([...pairs[j],dig-1]);}
    let A=rows(4,edges),good=[];
    for(let w=0;w<16;w++){let v=(w<<1)|1;if(A.every(r=>dot(v,r)===0))good.push(v);}
    let delta=solve(A,1);
    ok((delta===null)===(good.length>0),"false/true rowspace duality");
    if(good.length){nt++;for(let s=0;s<(1<<A.length);s++)for(let m=0;m<2;m++){let c=enc(A,m,s);for(let v of good)ok(dot(c,v)===m,"all witness correctness");}}
    else{nf++;const D0=new Map(),D1=new Map();for(let s=0;s<(1<<A.length);s++){let c0=enc(A,0,s),c1=enc(A,1,s);D0.set(c0,(D0.get(c0)||0)+1);D1.set(c1,(D1.get(c1)||0)+1);for(let m=0;m<2;m++)ok(enc(A,m,s^(m?delta:0))===c0,"equivocal coin");}ok(JSON.stringify([...D0].sort((a,b)=>a[0]-b[0]))===JSON.stringify([...D1].sort((a,b)=>a[0]-b[0])),"exact false distribution");}
    ng++;
  }
  function histories(K,pair,adaptive){
    const A=rows(3,[[0,1,0],[1,2,0],[0,2,1]]),h=new Map();
    for(let a=0;a<2;a++)for(let b=0;b<2;b++){let sh=[a,b,K^a^b];for(let x=0;x<8;x++)for(let y=0;y<8;y++)for(let z=0;z<8;z++){
      let co=[x,y,z],c=co.map((s,i)=>enc(A,sh[i],s)),j=adaptive?1+((c[2]^sh[0])&1):pair[1],i=adaptive?0:pair[0],k=JSON.stringify([...c,sh[i],co[i],j,sh[j],co[j]]);
      h.set(k,(h.get(k)||0)+1);
    }}
    return [...h].sort((a,b)=>a[0].localeCompare(b[0]));
  }
  for(let p of [[0,1],[0,2],[1,2]]){ok(JSON.stringify(histories(0,p,false))===JSON.stringify(histories(1,p,false)),"2-open joint exact K-independence");}
  ok(JSON.stringify(histories(0,[0,1],true))===JSON.stringify(histories(1,[0,1],true)),"adaptive transcript K-independence");
  let sizes={};for(let [n,old] of [[31,3870720],[101,12472320],[1001,129217536]]){let bytes=3072*Math.ceil((n+1)/8);sizes[n]={pnidr_bytes:old,axlr_bytes:bytes,factor:old/bytes};ok(bytes<old);}
  return {run:"AXLR-2026-11-01-T11",description:"restricted exact affine signed-XOR release, NOT generic NP WKEM",assertions,graphs:{count:ng,true:nt,false:nf},selective_opening:{pairs:3,adaptive:1},sizes,claim:"Finite algebra only; no native signature or QPT experiment."};
};
console.log(JSON.stringify(check(),null,2));
