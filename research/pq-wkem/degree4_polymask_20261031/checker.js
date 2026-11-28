// Offline exact checker; small parameters and mock native key. NOT PQ security evidence.
const q=65537, g=8192;
let state=20261031, checks=0;
const rnd=n=>((state=(Math.imul(1664525,state)+1013904223)>>>0)%n);
const assert=(x,s)=>{checks++;if(!x)throw Error(s)};
const combos=(n,k,start=0)=>k===0?[[]]:Array.from({length:n-start},(_,j)=>combos(n,k-1,start+j+1).map(a=>[start+j,...a])).flat();
const mons=(n,d)=>Array.from({length:d+1},(_,k)=>combos(n,k)).flat();
const key=a=>a.join(',');
function poly([vs,bits],mon){
 const idx=new Map(mon.map((v,i)=>[key(v),i])),out=Array(mon.length).fill(0);
 for(let mask=0;mask<8;mask++){
  let sign=1,vars=[];
  for(let i=0;i<3;i++){
   const bit=(mask>>i)&1;
   if(!bit && bits[i]){sign=0;break}
   if(bit){vars.push(vs[i]);if(!bits[i])sign=-sign}
  }
  if(sign)out[idx.get(key(vars))]+=sign;
 }
 return out;
}
function makeD(cs,n,d){
 const mon=mons(n,d),idx=new Map(mon.map((v,i)=>[key(v),i])),rows=[];
 for(const c of cs){const p=poly(c,mon);
  for(let k=0;k<=d-3;k++)for(const extra of combos(n,k)){
   const row=Array(mon.length).fill(0);
   p.forEach((x,j)=>{if(x){const m=[...new Set([...mon[j],...extra])].sort((a,b)=>a-b);if(m.length<=d)row[idx.get(key(m))]+=x}});
   rows.push(row);
  }
 }
 return {mon,rows};
}
function sat(cs,n){let out=[];for(let a=0;a<(1<<n);a++){
 const w=Array.from({length:n},(_,i)=>(a>>i)&1);
 if(cs.every(([v,b])=>v.some((x,j)=>w[x]!==b[j])))out.push(w);
 }return out;
}
const dot=(a,b)=>a.reduce((s,x,i)=>s+x*b[i],0);
const mod=x=>((x%q)+q)%q;
function span(rows){
 const a=rows.map(r=>r.map(mod)),m=a.length,n=a[0].length;
 const tr=Array.from({length:m},(_,i)=>Array.from({length:m},(_,j)=>+(i===j)));
 let rank=0,piv=[];
 for(let j=0;j<n && rank<m;j++){
  let p=rank;while(p<m && !a[p][j])p++;
  if(p===m)continue;
  [a[rank],a[p]]=[a[p],a[rank]];[tr[rank],tr[p]]=[tr[p],tr[rank]];
  let t=1,b=a[rank][j],e=q-2;while(e){if(e&1)t=mod(t*b);b=mod(b*b);e=Math.floor(e/2)}
  a[rank]=a[rank].map(x=>mod(x*t));tr[rank]=tr[rank].map(x=>mod(x*t));
  for(let i=0;i<m;i++)if(i!==rank && a[i][j]){
   let c=a[i][j];a[i]=a[i].map((x,k)=>mod(x-c*a[rank][k]));tr[i]=tr[i].map((x,k)=>mod(x-c*tr[rank][k]));
  }
  piv.push(j);rank++;
 }
 let e=[1,...Array(n-1).fill(0)],h=Array(m).fill(0);
 for(let i=0;i<rank;i++){let c=e[piv[i]];if(c){e=e.map((x,j)=>mod(x-c*a[i][j]));h=h.map((x,j)=>mod(x+c*tr[i][j]));}}
 const yes=e.every(x=>!x);
 if(yes)assert(rows[0].every((_,j)=>mod(rows.reduce((s,r,i)=>s+h[i]*r[j],0))===(j===0?1:0)),'span certificate');
 return {rank,yes,h:yes?h:null};
}
const F=[[[1,2,3],[0,0,0]],[[1,2,4],[1,1,0]],[[0,1,4],[1,0,1]],[[0,1,2],[1,1,0]],[[0,2,3],[0,0,1]],[[0,1,3],[0,1,0]],[[0,1,4],[1,0,0]],[[1,2,4],[1,1,1]],[[0,2,4],[0,1,0]],[[1,2,4],[0,1,1]]];
assert(sat(F,5).length===0,'F10 false');
const D3=makeD(F,5,3),D4=makeD(F,5,4);
const v3=D3.mon.map(t=>+(t.length===0||key(t)==='1,2,3'));
assert(dot(v3,v3)===2,'2 sparse pseudo');
D3.rows.forEach(r=>assert(dot(r,v3)===0,'pseudo annihilator'));
const c3=span(D3.rows),c4=span(D4.rows);
assert(!c3.yes&&c4.yes,'degree 3/4 transition');
for(let k=0;k<16;k++){
 let S=D4.rows.map(()=>rnd(q)),P0=D4.mon.map((_,j)=>mod(D4.rows.reduce((s,row,i)=>s+S[i]*row[j],0)));
 let S1=S.map((s,i)=>mod(s-c4.h[i]));
 let P1=D4.mon.map((_,j)=>mod((j===0?1:0)+D4.rows.reduce((s,row,i)=>s+S1[i]*row[j],0)));
 assert(JSON.stringify(P0)===JSON.stringify(P1),'identical false public mask');
}
function basis(D){
 const U=Array.from({length:4},()=>rnd(q)),R=Array.from({length:4},()=>D.rows.map(()=>rnd(q)));
 const B=R.map((row,i)=>D.mon.map((_,j)=>mod((j===0?U[i]:0)+D.rows.reduce((s,r,k)=>s+row[k]*r[j],0))));
 return {U,B};
}
function encrypt(D,bit,{U,B}){
 const S=D.rows.map(()=>rnd(q)),P=D.mon.map((_,j)=>mod((j===0?bit:0)+D.rows.reduce((s,r,k)=>s+S[k]*r[j],0)));
 const s=U.map(()=>rnd(q)),noise=D.mon.map(()=>rnd(3)-1),noiseStar=rnd(3)-1;
 const c=P.map((x,j)=>mod(B.reduce((z,row,i)=>z+row[j]*s[i],0)+noise[j]+g*x)),t=mod(dot(U,s)+noiseStar);
 return {c,t};
}
function decode(v,{c,t}){
 const x=mod(dot(v,c)-t),d0=Math.min(x,q-x),z=mod(x-g),d1=Math.min(z,q-z);
 return +(d1<d0);
}
const bf=basis(D3);
let falseRecover=0;
for(let j=0;j<512;j++){const bit=rnd(2);assert(decode(v3,encrypt(D3,bit,bf))===bit,'FALSE bit released without W');falseRecover++}
const Ft=F.filter((_,i)=>i!==3),ws=sat(Ft,5),Dt=makeD(Ft,5,4);assert(ws.length===4,'four true witnesses');
const bt=basis(Dt);
let trueReleases=0;
for(let j=0;j<48;j++){
 const bit=rnd(2),packet=encrypt(Dt,bit,bt);
 for(const w of ws){let v=Dt.mon.map(t=>t.every(i=>w[i])?1:0);
 Dt.rows.forEach(row=>assert(dot(row,v)===0,'TRUE moment'));
 assert(decode(v,packet)===bit,'TRUE bit recovered from SAME capsule');trueReleases++}
}
const parity=[[[0,1,2],0],[[0,3,4],0],[[1,3,5],0],[[2,4,5],1]];
let xor=[];for(const [vs,p] of parity)for(let a=0;a<8;a++){
 let bits=[(a&1),(a>>1)&1,(a>>2)&1];if(bits.reduce((x,y)=>x+y,0)%2!==p)xor.push([vs,bits]);
}
assert(sat(xor,6).length===0,'3XOR false');
const x4=makeD(xor,6,4),x5=makeD(xor,6,5),sx4=span(x4.rows),sx5=span(x5.rows);
assert(!sx4.yes&&sx5.yes,'XOR degree 4/5 transition');
const zz=new Set(['0,1,2','0,3,4','1,3,5']),qq=new Set(['0,2,4,5','1,2,4,5','2,3,4,5']);
const pseudo8=x4.mon.map(m=>m.length===0?8:m.length===1?4:m.length===2?2:m.length===3?(zz.has(key(m))?0:key(m)==='2,4,5'?2:1):+(qq.has(key(m))));
x4.rows.forEach(r=>assert(dot(r,pseudo8)===0,'rational pseudo moment'));
assert(mod(8*g)===q-1,'fractional pseudo scaled symbol aliases at q');
console.log(JSON.stringify({checks,full_false_bits: falseRecover,true_witnesses:ws.length,true_bit_releases:trueReleases,F10_d3_rank:c3.rank,F10_d4_rank:c4.rank,F10_d4_mask_independent:c4.yes,XOR_d4_rank:sx4.rank,XOR_d5_rank:sx5.rank,XOR_d4_mask_independent:sx4.yes,complete_generic_WKEM:false},null,2));
