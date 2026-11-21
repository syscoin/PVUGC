// Run 423: exact finite S3 table-mixer negative control. Node >=16.
let checks=0;const ok=(v)=>{checks++;if(!v)throw Error("assertion "+checks)};
const P=[];for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)
 if(a!==b&&a!==c&&b!==c)P.push([a,b,c]);
const I=[0,1,2],S=[1,0,2],C=[1,2,0];
const mul=(p,q)=>q.map(i=>p[i]),inv=p=>p.map((_,i)=>p.indexOf(i));
const sign=p=>(Number(p[0]>p[1])+Number(p[0]>p[2])+Number(p[1]>p[2]))%2;
const ty=p=>{const seen=new Set(),lens=[];for(let i=0;i<3;i++){if(seen.has(i))continue;
 let j=i,n=0;while(!seen.has(j)){seen.add(j);n++;j=p[j]}lens.push(n)}
 return lens.sort().join(",")};
const edge=(u,f,v)=>mul(mul(v,f),inv(u));
const loop=gs=>gs.reduce((a,g)=>mul(g,a),I);
const masks=[];for(const a of P)for(const b of P)for(const c of P)masks.push([a,b,c]);
const distributions=[];
for(const [f1,f2] of [[I,I],[S,I],[I,S],[S,S]]){
 const counts=new Map();
 for(const [m0,m1,m2] of masks){
  const g1=edge(m0,f1,m1),g2=edge(m1,f2,m2);
  const key=g1.join("")+":"+g2.join("");
  counts.set(key,(counts.get(key)||0)+1);
  ok(mul(g2,g1).join("")===edge(m0,mul(f2,f1),m2).join(""));
 }
 ok(counts.size===36);
 for(const a of P)for(const b of P)ok(counts.get(a.join("")+":"+b.join(""))===6);
 distributions.push(counts);
}
for(let i=1;i<4;i++)for(const [k,n] of distributions[0])ok(distributions[i].get(k)===n);
const supports=[],individual=[];
for(let bit=0;bit<=1;bit++){
 const fs=[I,I,bit?S:I],seen=new Set(),marg=[new Map(),new Map(),new Map()];
 for(const [m0,m1,m2] of masks){
  const gs=[edge(m0,fs[0],m1),edge(m1,fs[1],m2),edge(m2,fs[2],m0)];
  const hol=loop(gs);ok(hol.join("")===edge(m0,loop(fs),m0).join(""));
  ok(sign(hol)===bit);seen.add(gs.map(g=>g.join("")).join(":"));
  gs.forEach((g,j)=>{const k=g.join("");marg[j].set(k,(marg[j].get(k)||0)+1)});
 }
 for(const mm of marg)for(const p of P)ok(mm.get(p.join(""))===36);
 supports.push(seen);individual.push(marg);
}
for(const k of supports[0])ok(!supports[1].has(k));
for(let j=0;j<3;j++)for(const p of P)ok(individual[0][j].get(p.join(""))===individual[1][j].get(p.join("")));
ok(sign(I)===sign(C) && ty(I)!==ty(C));
let diamond=0;for(let bit=0;bit<=1;bit++)
 for(const m0 of P)for(const m1 of P)for(const m2 of P)for(const m3 of P){
  const g01=edge(m0,I,m1),g02=edge(m0,I,m2),g13=edge(m1,bit?S:I,m3),g23=edge(m2,I,m3);
  const h=mul(inv(g02),mul(inv(g23),mul(g13,g01)));
  ok(h.join("")===edge(m0,bit?S:I,m0).join(""));ok(sign(h)===bit);diamond++;
 }
let recovered=0;
for(let claim=0;claim<16;claim++)for(let j=0;j<256;j++){
 const bit=(j*73+claim*17+Math.floor(j/7))%2;
 const m0=P[(j+claim)%6],m1=P[(j*3+claim)%6],m2=P[(j*5+claim)%6];
 const gs=[edge(m0,I,m1),edge(m1,I,m2),edge(m2,bit?S:I,m0)];
 ok(sign(loop(gs))===bit);recovered++;
}
console.log(JSON.stringify({run:423,assertions:checks,tree_mask_assignments:216,forest_uniform_pair_count:36,forest_count_per_pair:6,cycle_supports_disjoint:true,each_cycle_edge_marginal_uniform:true,undirected_cycle_in_dag_diamond_checks:diamond,capability_bits_recovered_without_witness:recovered,scope:"complete public S3 edge tables; NOT RIO",post_quantum:"classical attack also available to QPT",complete_wkem:false},null,2));
