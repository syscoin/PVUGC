'use strict';
// Exact finite SPHF projection and correlated multi-capsule checker.
let assertions=0, groups=0, smooth=0, determined=0, attacks=0;
function ok(b,msg){assertions++;if(!b)throw Error(msg);}
function vecs(q,m){let v=[[]];for(let j=0;j<m;j++)v=v.flatMap(a=>Array.from({length:q},(_,i)=>a.concat(i)));return v;}
function dot(a,b,q){return a.reduce((s,x,i)=>s+x*b[i],0)%q;}
function rank(cols,q){if(!cols.length)return 0;let M=cols[0].map((_,i)=>cols.map(c=>c[i])),r=0;for(let j=0;j<cols.length;j++){let k=M.findIndex((row,i)=>i>=r && row[j]%q);if(k<0)continue;[M[r],M[k]]=[M[k],M[r]];let inv=Array.from({length:q-1},(_,i)=>i+1).find(t=>(t*M[r][j])%q===1);M[r]=M[r].map(x=>x*inv%q);for(let i=0;i<M.length;i++)if(i!==r){let a=M[i][j];M[i]=M[i].map((x,c)=>(x-a*M[r][c]%q+q)%q);}r++;if(r===M.length)break;}return r;}
for(const q of [2,3,5]){const vs=vecs(q,2);for(const a of vs)for(const b of vs){const r=rank([a,b],q);const by=new Map();for(const h of vs){let P=[dot(a,h,q),dot(b,h,q)];let id=P.join(',');if(!by.has(id))by.set(id,[]);by.get(id).push(h);}for(const y of vs){let publicKey=rank([a,b,y],q)===r;for(const hs of by.values()){let counts=Array(q).fill(0);for(const h of hs)counts[dot(y,h,q)]++;if(publicKey){ok(counts.filter(c=>c).length===1,'determined');determined++;}else{ok(counts.every(c=>c*q===hs.length),'uniform');smooth++;}}groups++;}}}
for(const q of [2,3,5]){let e1=[1,0],e2=[0,1];for(const h of vecs(q,2)){let P1=dot(e1,h,q),P2=dot(e2,h,q),K1=dot(e2,h,q),K2=dot(e1,h,q);ok(K1===P2&&K2===P1,'two false capsules expose both keys');attacks++;}}
console.log(JSON.stringify({run:576,status:'PASS',assertions,projection_families_and_targets:groups,joint_determined:determined,joint_smooth:smooth,two_false_capsule_recoveries:attacks,scope:'finite-field algebra only; not LWE or a QPT construction'},null,2));
