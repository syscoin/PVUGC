function run(){
const Q=16777259,DELTA=65536,M=64;
let checks=0;function ok(c,s){checks++;if(!c)throw Error(s)}
function ring(n){const N=1<<n, mod=x=>((x%Q)+Q)%Q, zero=()=>Array(N).fill(0),one=()=>{let a=zero();a[0]=1;return a},v=i=>{let a=zero();a[1<<i]=1;return a};
function mul(a,b){let c=zero();for(let i=0;i<N;i++)if(a[i])for(let j=0;j<N;j++)if(b[j])c[i|j]=mod(c[i|j]+a[i]*b[j]);return c}
function fail(lits){let a=one();for(const [i,pos] of lits){let u=v(i);a=mul(a,pos?one().map((t,k)=>mod(t-u[k])):u)}return a}
function pow(a,e){let t=1;while(e>0){if(e%2)t=mod(t*a);a=mod(a*a);e=Math.floor(e/2)}return t}
function basis(gs){let piv=new Map();for(const g of gs){let r=g.map(mod);for(;;){let j=r.findIndex(x=>x);if(j<0)break;if(!piv.has(j)){const inv=pow(r[j],Q-2);piv.set(j,r.map(x=>mod(x*inv)));break;}let rr=piv.get(j),coef=r[j];r=r.map((x,k)=>mod(x-coef*rr[k]))}}let pivot=[...piv.keys()].sort((a,b)=>a-b),free=Array.from({length:N},(_,i)=>i).filter(i=>!piv.has(i));
function P(x){let r=x.map(mod);for(const j of pivot)if(r[j]){let a=r[j],rr=piv.get(j);r=r.map((z,k)=>mod(z-a*rr[k]))}return free.map(i=>r[i])}
function S(x){let y=zero();free.forEach((i,j)=>y[i]=x[j]);return y}
return {rank:pivot.length,P,S,dim:free.length}}
function ev(a,w){let sum=0;for(let i=0;i<N;i++)if((i&w)===i)sum+=a[i];return mod(sum)}
function fixture(cs){let fs=cs.map(fail),mono=[];for(let i=0;i<N;i++)if(i.toString(2).replace(/0/g,"").length<=2){let v=zero();v[i]=1;mono.push(v)}
let gs=[];for(let i=0;i<fs.length;i++)for(let j=i;j<fs.length;j++)gs.push(mul(fs[i],fs[j]));for(const f of fs)for(const z of mono)gs.push(mul(f,z));let bs=basis(gs),valid=Array.from({length:N},(_,i)=>i).filter(w=>fs.every(f=>ev(f,w)===0));return {...bs,valid}}
return {N,mod,zero,one,ev,fixture}}
const raw=[
[[1,3,4],[0,0,0]],[[0,1,4],[0,0,0]],[[0,1,4],[1,0,1]],
[[1,3,5],[1,0,1]],[[1,3,4],[1,0,0]],[[0,1,2],[0,0,0]],
[[0,3,4],[0,1,1]],[[2,3,5],[1,0,0]],[[0,4,5],[1,1,0]],
[[1,2,5],[1,1,1]],[[1,2,4],[1,0,0]],[[0,3,4],[1,0,0]],
[[0,4,5],[0,0,1]],[[2,4,5],[1,0,0]],[[2,3,4],[0,1,1]],
[[0,3,5],[0,0,1]],[[0,4,5],[0,1,0]],[[1,3,4],[0,1,0]],
[[1,2,4],[1,1,0]]
];
const clauses=raw.map(([vs,bs])=>vs.map((i,j)=>[i,!Boolean(bs[j])]));const R=ring(6),TRUE=R.fixture(clauses.filter((_,i)=>i!==10)),FALSE=R.fixture(clauses);
ok(TRUE.rank===61&&TRUE.dim===3&&JSON.stringify(TRUE.valid)==='[10,11,43]','TRUE fixture');
ok(FALSE.rank===64&&FALSE.dim===0&&FALSE.valid.length===0,'FALSE fixture');
const R4=ring(4),F4=R4.fixture([[[0,true],[0,true],[0,true]],[[0,false],[0,false],[0,false]]]);
ok(F4.rank===14&&F4.dim===2&&!F4.valid.length&&F4.P(R4.one()).every(x=>x===0),'nonempty FALSE certified quotient');
ok(DELTA>2*64&&Q-255*DELTA>2*64,'cyclic code spacing');
let seed=11235813;function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
const noise=N=>Array.from({length:N},()=>rnd()%3-1);
function enc(r,b,byte,e){let a=e.slice();a[0]+=DELTA*byte;return b.P(a)}
function open(r,b,z,w){let v=r.ev(b.S(z),w),best=1e99,found=-1;for(let k=0;k<256;k++){let d=Math.min(r.mod(v-k*DELTA),r.mod(k*DELTA-v));if(d<best){best=d;found=k}}if(best>r.N)throw Error('decoding radius');return found}
let openings=0;for(let k=0;k<256;k++){let z=enc(R,TRUE,k,noise(64));for(const w of TRUE.valid){ok(open(R,TRUE,z,w)===k,'genuine ORIGINAL byte opening');openings++}}
let source=Array.from({length:96},()=>rnd()%256),zs=source.map(x=>enc(R,TRUE,x,noise(64)));
for(const w of TRUE.valid)ok(source.every((x,i)=>open(R,TRUE,zs[i],w)===x),'all-witness same 96-byte capability seed');
let couplings=0;for(let i=0;i<256;i++){let nn=Array.from({length:4},()=>noise(16)),left=nn.map((e,j)=>enc(R4,F4,(i+9*j)%256,e)),right=nn.map((e,j)=>enc(R4,F4,(i*73+31+13*j)%256,e));ok(JSON.stringify(left)===JSON.stringify(right),'four-target capsule joint coupling');let kb='hidden-kbind-'+i,ctx='claim/outpoint/branch/anchor/window/vk',D='unchanged-public-D-'+i,related='independently-opened-nontarget';
let transcript=z=>{let ck=['CK_v55',kb,ctx,D,z,related].join('|');return JSON.stringify([z,ck,'AUX:'+kb+':'+ck,ctx,D,related])};
ok(transcript(left)===transcript(right),'whole correlated CK + AUX coupling');couplings++}
return {run:'R55-BYTE-PACKED-ORIGINAL-CK-20261103',assertions:checks,q_source:Q,delta:DELTA,radix:256,min_cyclic_distance:Math.min(DELTA,Q-255*DELTA),true:{witnesses:TRUE.valid,rank:TRUE.rank,quotient:TRUE.dim,openings,full_seed_witnesses:3,bytes_old_per_256_bits:256*TRUE.dim*3,bytes_new_per_256_bits:32*TRUE.dim*4},false19:{rank:FALSE.rank,quotient:FALSE.dim},cert_false4:{rank:F4.rank,quotient:F4.dim,joint_four_capsule_ck_aux_couplings:couplings,bytes_old_per_256_bits:256*F4.dim*3,bytes_new_per_256_bits:32*F4.dim*4},hard_TRUE_extraction:'UNPROVED',QPT_hardness:'NOT TESTED'}
}
console.log(JSON.stringify(run(),null,2));
