'use strict';
// Reproducible offline finite test. Toy G is NOT a proven QPT PRG.
let n=0; function assert(x,m){n++;if(!x)throw Error(m);}
const R=32,T=20,MASK=(1<<T)-1,G=x=>(Math.imul(x+1,2654435761)>>>0)&MASK;
const D=new Set();for(let a=0;a<R;a++)for(let b=0;b<R;b++)D.add(G(a)^G(b));
let a=1,b=2;while(D.has(a))a++;while(D.has(b)||D.has(a^b))b++;
const delta=(c,s,t)=>c===0?0:c===1?s:t;
const verify=(p,c,r)=>c>=0&&c<=2&&(G(r)^delta(c,p.s,p.t))===p.C;
for(let c=0;c<3;c++)for(let r=0;r<R;r++){
 const p={s:a,t:b,C:G(r)^delta(c,a,b)};
 assert(verify(p,c,r),'honest opening');
 for(let d=0;d<3;d++)if(c!==d)for(let v=0;v<R;v++)assert(!verify(p,d,v),'statistical color binding');
}
for(let k=0;k<256;k++){
 const r=[(k*7+1)%R,(k*13+5)%R,(k*17+9)%R];
 const p={s:G(r[0])^G(r[1]),t:G(r[0])^G(r[2]),C:G(r[0])};
 for(let c=0;c<3;c++)assert(verify(p,c,r[c]),'simulated color opening');
}
const edges=[];for(let x=0;x<4;x++)for(let y=x+1;y<4;y++)edges.push([x,y]);
let max=0,enumerated=0;
for(let x=0;x<3;x++)for(let y=0;y<3;y++)for(let z=0;z<3;z++)for(let w=0;w<3;w++){
 const cs=[x,y,z,w],pass=edges.filter(([u,v])=>cs[u]!==cs[v]).length;
 assert(pass<=5,'K4 not 3-colorable');max=Math.max(max,pass);enumerated++;
}
assert(max===5&&enumerated===81,'tight K4 soundness');
// Ideal hybrid: after opening one seed, other two outputs are independent uniforms.
let bijections=0;
for(let c=0;c<3;c++)for(let fixed=0;fixed<4;fixed++){
 const images=new Set();for(let u=0;u<4;u++)for(let v=0;v<4;v++){
 const z=c===0?[fixed,u,v]:c===1?[u,fixed,v]:[u,v,fixed];
 const s=z[0]^z[1],t=z[0]^z[2],C=z[0];
 assert(C===(fixed^delta(c,s,t)),'opening matches real distribution');
 images.add([s,t].join(','));
 }assert(images.size===16,'exact uniform pair bijection');bijections++;
}
const m=2048,kappa=256,t0=896,t1=898;
const old=4*m*t0,now=3*m*t1;
const oldBound=Math.log2(2*m)+2*kappa-t0,newBound=Math.log2(3*m)+2*kappa-t1;
assert(now<old&&newBound<=oldBound,'size lower, statistical binding no weaker');
console.log(JSON.stringify({status:'PASS',assertions:n,toy_opposite_color_checks:6144,
 simulated_three_opening_fixtures:256,exhaustive_false_K4_colorings:enumerated,
 ideal_one_opened_bijection_cases:bijections,old_bits:old,new_bits:now,
 saved_percent:Number(((1-now/old)*100).toFixed(9)),
 old_log2_binding:Number(oldBound.toFixed(6)),new_log2_binding:Number(newBound.toFixed(6)),
 limitation:'classical toy algebra only; no QPT/native PQ/ORIGINAL NP proof'},null,2));
