(()=>{
const must=(x,m)=>{if(!x)throw Error(m)};
const same=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const conj=(p,f)=>{const a=Array(p.length);for(let i=0;i<p.length;i++)a[p[i]]=p[f[i]];return a};
const perm=(n,cb)=>{let a=Array.from({length:n},(_,i)=>i);function rec(i){if(i===n){cb(a.slice());return}for(let j=i;j<n;j++){[a[i],a[j]]=[a[j],a[i]];rec(i+1);[a[i],a[j]]=[a[j],a[i]]}}rec(0)};
const rng=(()=>{let x=517;return()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x>>>0}})();
const shuffle=n=>{let a=Array.from({length:n},(_,i)=>i);for(let i=n-1;i>0;i--){const j=rng()%(i+1);[a[i],a[j]]=[a[j],a[i]]}return a};
let counts={S8frames:0,S8couplings:0,S8editBreaks:0,S8keyRecovery:0,S8nonfixTotal:0,S16multiclaim:0,S16coupledOps:0,S16keyRecovery:0,S16nonfixTotal:0,S16true:0,S16trueRecoveries:0};
const B=Array.from({length:8},(_,s)=>s^(((s>>2)&1)&&((s>>1)&1)?1:0));
const F=Array.from({length:8},(_,s)=>s^2);
const T=Array.from({length:8},(_,s)=>s^(((s>>1)&1)?0:4));
perm(8,p=>{
 const pt=T.map(t=>p[t]),ab=conj(p,B),af=conj(p,F);
 must(same(ab,conj(pt,B)),"S8 false coupling");
 must(!same(af,conj(pt,F)),"S8 editor destroys coupling");
 counts.S8couplings++;counts.S8editBreaks++;counts.S8nonfixTotal+=ab.filter((v,i)=>v!==i).length;
 for(const k of [0,1]){const a=p[k<<2],y=af[a];must(Number(ab[y]!==y)===k,"S8 release leak");counts.S8keyRecovery++}
 counts.S8frames++;
});
const b16=Array.from({length:16},(_,s)=>s^(((s>>3)&1)&&((s>>1)&1)&&(((s>>2)&1)===0)?1:0));
const r16=Array.from({length:16},(_,s)=>s^(((s>>3)&1)&&((s>>1)&1)&&(((s>>2)&1)===1)?1:0));
const f16=Array.from({length:16},(_,s)=>s^(((s>>2)&1)===0?2:0));
const er16=Array.from({length:16},(_,s)=>s^(((s>>2)&1)===1?2:0));
const t16=Array.from({length:16},(_,s)=>s^((((s>>2)&1)===0&&((s>>1)&1)===0)?8:0));
for(let j=0;j<128;j++){
 const p=shuffle(16),pt=t16.map(s=>p[s]);
 for(const op of [b16,r16,er16]){must(same(conj(p,op),conj(pt,op)),"multiclaim complete-view coupling");counts.S16coupledOps++}
 const A=conj(p,b16),F=conj(p,f16);
 for(let k=0;k<2;k++){const ax=p[k<<3],ar=p[(k<<3)|4];must(pt[(k^1)<<3]===ax&&pt[(k<<3)|4]===ar,"anchor coupling");const y=F[ax];must(Number(A[y]!==y)===k,"same-sector edit recovery");counts.S16keyRecovery++}
 counts.S16nonfixTotal+=A.filter((v,i)=>v!==i).length;counts.S16multiclaim++;
}
const bt=Array.from({length:16},(_,s)=>s^(((s>>3)&1)&&((s>>1)&1)?1:0));
const w=Array.from({length:16},(_,s)=>s^4);
const et=Array.from({length:16},(_,s)=>s^(((s>>2)&1)?2:0));
for(let j=0;j<128;j++){const p=shuffle(16),a=conj(p,bt),l=conj(p,w),e=conj(p,et);for(let k=0;k<2;k++){const y=e[l[p[k<<3]]];must(Number(a[y]!==y)===k,"valid original witness");counts.S16trueRecoveries++}counts.S16true++}
must(counts.S8frames===40320&&counts.S8nonfixTotal===80640&&counts.S8keyRecovery===80640&&counts.S16multiclaim===128&&counts.S16coupledOps===384&&counts.S16keyRecovery===256&&counts.S16nonfixTotal===256&&counts.S16trueRecoveries===256,"counts");
return JSON.stringify({run:517,status:"PASS",counts,scope:"ideal-frame public-admission flag; no concrete QPT mixer or source extraction"},null,2)+"\n"
})()
