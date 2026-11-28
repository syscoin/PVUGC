function checker(){
const q=65537,D=128;let seed=2026110225,count=0;
const ck=(x,s)=>{count++;if(!x)throw Error("assertion "+s)};
const mod=x=>((x%q)+q)%q,rnd=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%q};
const add=(a,b,k=1)=>{let c={...a};for(const [m,v] of Object.entries(b)){let t=mod((c[m]||0)+k*v);if(t)c[m]=t;else delete c[m];}return c;};
const mul=(a,b)=>{let c={};for(const [m,v] of Object.entries(a))for(const [n,w] of Object.entries(b)){let idx=(+m)|(+n);c[idx]=mod((c[idx]||0)+v*w)}return Object.fromEntries(Object.entries(c).filter(([m,v])=>v))};
const gp=cl=>{let p={0:1};for(const [v,pos] of cl)p=mul(p,pos?{0:1,[1<<v]:q-1}:{[1<<v]:1});return p};
const L=f=>mod((f[0]||0)-(f[5]||0));
const same=(a,b)=>{const ks=[...new Set([...Object.keys(a),...Object.keys(b)])];return ks.every(k=>mod((a[k]||0)-(b[k]||0))===0)};
const false9=[[[3,0],[1,1],[2,0]],[[0,1],[3,1],[2,1]],[[2,1],[0,1],[3,0]],[[3,1],[2,0],[1,0]],[[1,1],[0,0],[3,1]],[[1,0],[2,1],[0,0]],[[2,0],[3,0],[1,0]],[[1,1],[2,0],[3,1]],[[2,1],[3,0],[0,0]]];
const sat=(cs,a)=>cs.every(cl=>cl.some(([i,p])=>((a>>i)&1)===p));
ck(Array.from({length:16},(_,a)=>a).every(a=>!sat(false9,a)),"false");
const gs=false9.map(gp);for(let g of gs){ck(L(g)===0,"fake annihilates");ck(same(mul(g,g),g),"idempotence")}
let cert={};for(const g of gs)cert=add(cert,g);cert=add(add(cert,mul(gs[4],gs[7]),-1),mul(gs[5],gs[8]),-1);
ck(same(cert,{0:1}),"full coefficient certificate");
let pairs=[];for(let i=0;i<9;i++)for(let j=i+1;j<9;j++)if(Object.keys(mul(gs[i],gs[j])).length)pairs.push(`${i},${j}`);
ck(pairs.join("|")==="4,7|5,8","pair support");
let total=0,wrong=[0,0];
for(let bit=0;bit<=1;bit++)for(let j=0;j<512;j++){
let p={0:D*bit},rs=gs.map(()=>rnd());
for(let i=0;i<9;i++)p=add(p,gs[i],rs[i]);
ck(L(p)===D*bit,"original clear");
const square=mul(p,p);ck(L(square)===mod(D*D*bit-2*rs[4]*rs[7]),"square scalar");
let t=rnd(),u=rnd();
const f10=mul(add(p,{0:t}),add(p,{0:t}));
const f01=mul(add(p,{0:u}),add(p,{0:u}));
const f11=mul(add(p,{0:t+u}),add(p,{0:t+u}));
const alpha=L(add(f10,square,-1)),beta=L(add(f01,square,-1));
const diff=add(add(f11,f10,-1),add(f01,square,-1),-1),delta=mod(2*t*u);
ck(same(diff,delta?{0:delta}:{}),"two dummy mixed difference");
ck(alpha===mod(t*t+2*D*bit*t),"alpha");
ck(beta===mod(u*u+2*D*bit*u),"beta");
const guess=mod(delta*delta-4*alpha*beta)===0?0:1;
const exception=bit===1&&(t===0||u===0||mod(t+u+2*D)===0);
ck((guess!==bit)===exception,"attack failure iff");
if(guess!==bit)wrong[bit]++;total++;
}
const trueCl=[[[0,1],[1,1],[2,1]],[[0,0],[1,1],[2,1]]],wg=Array.from({length:8},(_,a)=>a).filter(a=>sat(trueCl,a));
ck(wg.length===6,"six witnesses");
for(let bit=0;bit<=1;bit++)for(let j=0;j<32;j++){let p={0:D*bit};for(const g of trueCl.map(gp))p=add(p,g,rnd());let f=mul(p,p);for(let a of wg){let v=Object.entries(f).reduce((acc,[k,c])=>((+k & ~a)===0?acc+c:acc),0);ck(mod(v)===D*D*bit,"every original witness agrees")}}
return {id:"MINK-GLOBAL-SQUARE-R25",checks:count,pass:true,q,delta:D,false_certificate:"1=sum(g0..g8)-g4*g7-g5*g8",nonzero_clause_pairs:pairs,square_projection:"Delta^2*mu-2*r4*r7",single_projection_TV:"1/q",full_public_two_dummy_trials_per_bit:512,full_public_attack_errors:wrong,exact_mu1_attack_error_probability:"(3q-3)/q^2",true_distinct_witnesses:wg.length,status:"NO positive advance: noiseless nonlinear carrier broken; noisy full view unproved"};
}
console.log(JSON.stringify(checker(),null,2));
