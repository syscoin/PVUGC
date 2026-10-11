// Run 424: exact S3 public-boundary pin law. Node >=16; no dependencies.
let checks=0;const ok=x=>{checks++;if(!x)throw Error('assertion '+checks)};
const P=[];for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)
 if(a!==b&&b!==c&&a!==c)P.push([a,b,c]);
const I=[0,1,2],S=[1,0,2];
const mul=(p,q)=>q.map(i=>p[i]),inv=p=>p.map((_,i)=>p.indexOf(i));
const edge=(u,f,v)=>mul(mul(v,f),inv(u));
const key=x=>JSON.stringify(x);
const fs=[];for(const a of P)for(const b of P)fs.push([a,b]);
function law(f,pins){let m=new Map();for(const a of P)for(const b of P)for(const c of P){
 const masks=[a,b,c],g=[edge(a,f[0],b),edge(b,f[1],c)];
 const k=key([g,pins.map(i=>masks[i])]);m.set(k,(m.get(k)||0)+1);
 }return m}
let compared=0,disjoint=0;
for(const pins of [[],[0],[2],[0,2]]){
 const laws=fs.map(f=>law(f,pins));
 for(let i=0;i<fs.length;i++){
  const hist=laws[i];ok([...hist.values()].reduce((a,b)=>a+b,0)===216);
  ok(hist.size===(pins.length===0?36:216));
  ok([...hist.values()].every(v=>v===(pins.length===0?6:1)));
  for(const s of hist.keys())if(pins.length===2){
   const [g,m]=JSON.parse(s);const recovered=mul(mul(inv(m[1]),mul(g[1],g[0])),m[0]);
   ok(key(recovered)===key(mul(fs[i][1],fs[i][0])));
  }
 }
 for(let i=0;i<fs.length;i++)for(let j=0;j<fs.length;j++){
  const eq=pins.length<2||key(mul(fs[i][1],fs[i][0]))===key(mul(fs[j][1],fs[j][0]));
  const a=laws[i],b=laws[j];ok((a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v))===eq);
  if(!eq){ok(![...a.keys()].some(k=>b.has(k)));disjoint++}compared++;
 }
}
// Two individual one-pinned capsules share hidden M1; joined views reveal F_A.
let stitched=0;
for(const f of P)for(const m0 of P)for(const m1 of P)for(const m2 of P){
 const ga=edge(m0,f,m1),gb=edge(m1,I,m2);
 const exposed=mul(mul(inv(m2),mul(gb,ga)),m0);
 ok(key(exposed)===key(f));stitched++;
}
console.log(JSON.stringify({run:424,checks,functions:36,mask_assignments_per_law:216,anchor_sets:4,distribution_pairs_compared:compared,disjoint_pairs:disjoint,stitched_shared_frame_cases:stitched,criterion:'forest with <=1 public frame per component hides full-table source assignment',qpt:'classical attack / unconditional finite distribution only',complete_wkem:false},null,2));
