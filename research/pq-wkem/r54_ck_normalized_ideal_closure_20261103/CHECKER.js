function run(){
const Q=65537,M=64,D=32768,mod=x=>((x%Q)+Q)%Q;
let checks=0;function ok(x,msg){checks++;if(!x)throw Error(msg)}
const CS=[
[[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],[[1,3,5],[1,0,1]],[[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],[[0,4,5],[1,1,0]],[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],[[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],[[0,3,5],[0,0,1]],[[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],[[1,2,4],[1,1,0]]
];
const z=()=>Array(M).fill(0),c=()=>{let a=z();a[0]=1;return a},v=i=>{let a=z();a[1<<i]=1;return a};
function mul(a,b){let t=z();for(let i=0;i<M;i++)if(a[i])for(let j=0;j<M;j++)if(b[j])t[i|j]+=a[i]*b[j];return t.map(mod)}
function fail([vars,bits]){let a=c();for(let i=0;i<3;i++){let x=v(vars[i]);a=mul(a,bits[i]?x:c().map((e,j)=>e-x[j]))}return a}
function pow(a,e){let t=1;while(e){if(e%2)t=mod(t*a);a=mod(a*a);e=Math.floor(e/2)}return t}
function basis(gs){let rows=gs.map(r=>r.map(mod)),piv=[],h=0;for(let j=0;j<M&&h<rows.length;j++){let k=h;while(k<rows.length&&!rows[k][j])k++;if(k===rows.length)continue;[rows[h],rows[k]]=[rows[k],rows[h]];
let inv=pow(rows[h][j],Q-2);rows[h]=rows[h].map(a=>mod(a*inv));
for(let i=0;i<rows.length;i++)if(i!==h&&rows[i][j]){let a=rows[i][j];rows[i]=rows[i].map((u,k)=>mod(u-a*rows[h][k]))}piv.push(j);h++}
return {rank:h,rows:rows.slice(0,h),piv,free:Array.from({length:M},(_,i)=>i).filter(i=>!piv.includes(i))}}
function P(a,b){let t=a.map(mod);b.piv.forEach((j,i)=>{let x=t[j];if(x)t=t.map((u,k)=>mod(u-x*b.rows[i][k]))});return b.free.map(j=>t[j])}
function S(a,b){let t=z();b.free.forEach((j,i)=>t[j]=a[i]);return t}
const eq=(a,b,msg)=>ok(JSON.stringify(a)===JSON.stringify(b),msg);
const ev=(a,w)=>mod(a.reduce((s,u,j)=>s+((w&j)===j?u:0),0));
const mono=[];for(let i=0;i<M;i++)if(i.toString(2).replace(/0/g,'').length<=2){let a=z();a[i]=1;mono.push(a)}
function fixture(cs){const f=cs.map(fail),square=[],cl=[];for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++)square.push(mul(f[i],f[j]));
cl.push(...square);for(const a of f)for(const b of mono)cl.push(mul(a,b));
const old=basis(square),end=basis(cl),valid=Array.from({length:64},(_,i)=>i).filter(w=>f.every(a=>ev(a,w)===0));
return {old,end,valid,squares:square.length,closure:cl.length,enc:(mu,e)=>P(e.map((a,i)=>a+(i===0?D*mu:0)),end),trans:v=>P(S(v,old),end),Pold:(mu,e)=>P(e.map((a,i)=>a+(i===0?D*mu:0)),old),opens:(v,w)=>{let a=ev(S(v,end),w),dist=b=>Math.min(mod(a-b*D),mod(b*D-a));return +(dist(1)<dist(0))}}}
const f=fixture(CS),t=fixture(CS.filter((_,i)=>i!==10));
eq([f.old.rank,f.end.rank,t.old.rank,t.end.rank],[50,64,49,61],'ranks');
eq([f.valid,t.valid],[[],[10,11,43]],'truth');
ok(f.closure===608&&t.closure===567,'generator counts');
ok(P(c(),f.old).some(x=>x!==0),'old FALSE does not certify');
ok(P(c(),f.end).length===0,'new FALSE certifies');
for(let j=0;j<M;j++){let a=z();a[j]=1;eq(f.trans(P(a,f.old)),P(a,f.end),'FALSE T');eq(t.trans(P(a,t.old)),P(a,t.end),'TRUE T')}
let seed=11235813;function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
const noise=()=>Array.from({length:M},()=>rnd()%3-1);
let trueOpenings=0;for(let b=0;b<2;b++)for(let j=0;j<32;j++){const e=noise(),Z0=t.Pold(b,e),Zplus=t.enc(b,e);eq(t.trans(Z0),Zplus,'target transform');for(const w of t.valid){ok(t.opens(Zplus,w)===b,'true witness bit');trueOpenings++}}
let coupled=0;for(let i=0;i<128;i++){const b0=i&255,s0=0x2a,s1=0x95,mask0=b0,mask1=mask0^s0^s1;
const pad0=Array.from({length:8},(_,j)=>(mask0>>j)&1),pad1=Array.from({length:8},(_,j)=>(mask1>>j)&1),kb=[1,0,1,1],auxCoins=[3,7,11],ctx=['claim42','branchA','anchor','vk'];
const noises=Array.from({length:12},()=>noise()),Z0=[...pad0,...kb].map((b,j)=>f.enc(b,noises[j])),Z1=[...pad1,...kb].map((b,j)=>f.enc(b,noises[j]));
eq(Z0,Z1,'FALSE bound source pad independent');
const D0=s0^mask0,D1=s1^mask1;ok(D0===D1,'D coupling');
const related=t.enc(i&1,noise());const ck=(Z,D)=>JSON.stringify(['CK_VERSION_PLUS',kb,ctx,Z,D,related]);
const aux=(Z,D)=>JSON.stringify([ck(Z,D),auxCoins,'independent',related]);
eq([D0,ck(Z0,D0),aux(Z0,D0),related],[D1,ck(Z1,D1),aux(Z1,D1),related],'secret-correlated complete CK/AUX');coupled++}
return {run:'R54-CK-NORMALIZED-IDEAL-CLOSURE-20261103',assertions:checks,source_field:Q,unsat:{clauses:CS.length,old_pair_rank:f.old.rank,old_quotient:64-f.old.rank,old_certified:false,new_closure_rank:f.end.rank,new_quotient:64-f.end.rank,new_certified:true},true:{clauses:CS.length-1,witnesses:t.valid,old_quotient:64-t.old.rank,new_quotient:64-t.end.rank,successful_witness_openings:trueOpenings},composition:{exact_basis_transform_tests:128,full_CK_aux_false_couplings:coupled},hard_TRUE_extraction:'UNPROVED',QPT_hardness:'NOT TESTED'} }
console.log(JSON.stringify(run()));
