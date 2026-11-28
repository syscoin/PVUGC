function checker() {
 const q=65537,M=64,D=32768;
 const clauses=[
 [[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],
 [[1,3,5],[1,0,1]],[[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],
 [[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],[[0,4,5],[1,1,0]],
 [[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
 [[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],
 [[0,3,5],[0,0,1]],[[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],
 [[1,2,4],[1,1,0]]
 ];
 let assertions=0;
 const ok=(v,m)=>{assertions++;if(!v)throw Error(m);};
 const mod=v=>(v%q+q)%q,z=()=>Array(M).fill(0);
 const cn=v=>{let a=z();a[0]=mod(v);return a;};
 const vr=i=>{let a=z();a[1<<i]=1;return a;};
 const add=(a,b)=>a.map((v,i)=>mod(v+b[i]));
 const mul=(a,b)=>{let v=z();for(let i=0;i<M;i++)if(a[i])for(let j=0;j<M;j++)if(b[j])v[i|j]=mod(v[i|j]+a[i]*b[j]);return v;};
 const fail=([vars,bits])=>{let v=cn(1);for(let i=0;i<3;i++)v=mul(v,bits[i]?vr(vars[i]):add(cn(1),vr(vars[i]).map(t=>-t)));return v;};
 const at=(v,w)=>mod(v.reduce((s,x,i)=>s+((i&w)===i?x:0),0));
 const inv=v=>{let a=1,b=v,k=q-2;while(k){if(k&1)a=mod(a*b);b=mod(b*b);k=Math.floor(k/2);}return a;};
 const rref=gs=>{
  let rows=gs.map(g=>g.slice()),piv=[],rank=0;
  for(let col=0;col<M&&rank<rows.length;col++){
   let i=rank;while(i<rows.length&&!rows[i][col])i++;
   if(i===rows.length)continue;
   [rows[rank],rows[i]]=[rows[i],rows[rank]];
   const scale=inv(rows[rank][col]);rows[rank]=rows[rank].map(x=>mod(x*scale));
   for(let j=0;j<rows.length;j++)if(j!==rank){let t=rows[j][col];if(t)rows[j]=rows[j].map((x,k)=>mod(x-t*rows[rank][k]));}
   piv.push(col);rank++;
  }
  return {b:rows.slice(0,rank),piv,free:Array.from({length:M},(_,i)=>i).filter(i=>!piv.includes(i))};
 };
 const P=(v,R)=>{
  let t=v.slice();R.piv.forEach((p,i)=>{let a=t[p];if(a)t=t.map((x,j)=>mod(x-a*R.b[i][j]));});
  ok(R.piv.every(p=>t[p]===0),'pivot elimination');return R.free.map(j=>t[j]);
 };
 const S=(v,R)=>{let a=z();R.free.forEach((j,i)=>a[j]=v[i]);return a;};
 let seed=0x14e56a3;
 const rng=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
 const noise=()=>Array.from({length:M},()=>rng()&1?1:-1);
 const mask=gs=>{let a=z();for(const g of gs){let v=rng()%q;for(let j=0;j<M;j++)a[j]=mod(a[j]+v*g[j]);}return a;};
 const bit=v=>{v=mod(v);let d0=Math.min(v,q-v),d1=Math.min(Math.abs(v-D),q-Math.abs(v-D));return +(d1<d0);};
 const fixture=(cs,lift)=>{
  const fs=cs.map(fail),gs=[];
  for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)gs.push(mul(fs[i],fs[j]));
  if(lift)gs.push(mul(vr(1),mul(fs[8],fs[14])));
  const R=rref(gs),valid=Array.from({length:64},(_,i)=>i).filter(w=>fs.every(f=>at(f,w)===0));
  const unit=P(cn(1),R).every(v=>v===0);
  ok(!valid.length||!unit,'TRUE unit-span');
  let openings=0;
  for(let mu=0;mu<2;mu++)for(let i=0;i<128;i++){
   const e=noise(),pt=add(e,cn(D*mu)),raw=add(pt,mask(gs));
   const a=P(raw,R),b=P(pt,R);
   ok(a.every((v,k)=>v===b[k]),'masked quotient differs');
   const sec=S(a,R);
   ok(P(sec,R).every((v,k)=>v===a[k]),'section differs');
   const hydrated=add(sec,mask(gs));
   ok(P(hydrated,R).every((v,k)=>v===a[k]),'fiber mismatch');
   for(const w of valid){ok(at(raw,w)===at(sec,w),'witness eval differs');ok(bit(at(sec,w))===mu,'bit opening differs');openings++;}
  }
  return {clauses:cs.length,generators:gs.length,rank:R.piv.length,old_coefficients:M,compact_coefficients:R.free.length,valid_original_assignments:valid,genuine_openings:openings,unit_in_mask_span:unit};
 };
 const f=fixture(clauses,true),t=fixture(clauses.filter((_,i)=>i!==10),false);
 ok(f.rank===51&&f.compact_coefficients===13&&f.unit_in_mask_span&&f.valid_original_assignments.length===0,'FALSE mismatch');
 ok(t.rank===49&&t.compact_coefficients===15&&t.valid_original_assignments.join(',')==='10,11,43','TRUE mismatch');
 // Exact small finite distribution, including a public checking-key function.
 const plus=(a,b)=>a.map((v,i)=>(v+b[i]+6)%3),scale=(i,v)=>v.map(x=>(i*x)%3);
 const p=v=>[(v[1]-2*v[0]+6)%3,v[2]],s=v=>[0,v[0],v[1]],ck=v=>(v[0]+2*v[1]+v[2])%3;
 let total=0;
 for(let mu=0;mu<2;mu++){
  const old=new Map(),fresh=new Map();
  for(let j=0;j<8;j++){
   const e=[0,1,2].map(i=>(j>>i)&1?1:2),plain=plus(e,[mu,0,0]),v=p(plain);
   for(let a=0;a<3;a++){
    const raw=plus(plain,scale(a,[1,2,0])),newraw=plus(s(v),scale(a,[1,2,0]));
    const x=JSON.stringify([v,raw,ck(raw)]),y=JSON.stringify([v,newraw,ck(newraw)]);
    old.set(x,(old.get(x)||0)+1);fresh.set(y,(fresh.get(y)||0)+1);total++;
   }
  }
  ok(old.size===fresh.size,'joint size');
  for(const [key,count] of old)ok(fresh.get(key)===count,'full joint distribution');
 }
 return {run:'R46-MINK-QUOTIENT-EXACT-20261103',q,delta:D,assertions,certified_false:f,three_witness_true:t,exact_joint_cases:total,security:'exact restricted conditional distribution equivalence; no generic WKEM or QPT-hardness proof'};
}
console.log(JSON.stringify(checker(),null,2));
