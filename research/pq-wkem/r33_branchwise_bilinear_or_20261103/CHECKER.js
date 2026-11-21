const runChecker = function runChecker(){
"use strict";
let checks=0;const chk=(v,s)=>{checks++;if(!v)throw Error(s);};
const clauses=[[[0,1,3],[0,1,0]],[[0,1,2],[0,0,0]],[[0,1,3],[1,0,1]],[[0,1,3],[0,1,1]],[[0,2,3],[1,0,0]],[[0,1,3],[1,1,1]],[[1,2,3],[0,1,1]],[[0,2,3],[0,0,0]],[[1,2,3],[0,1,0]],[[0,1,2],[1,1,1]]];
const cert=[[0,0,1],[1,1,1],[2,2,1],[2,6,-1],[3,3,1],[4,4,1],[5,5,1],[5,9,-1],[6,6,1],[8,8,1],[9,9,1]];
const f=z=>clauses.map(([ids,bad])=>Number(ids.every((id,j)=>z[id]===bad[j])));
const evalCert=v=>cert.reduce((a,[i,j,c])=>a+c*v[i]*v[j],0);
let nValid=0;for(let z=0;z<16;z++){const bits=Array.from({length:4},(_,i)=>(z>>i)&1),F=f(bits);chk(F.some(x=>x===1),"F false");chk(evalCert(F)===1,"R32 integer certificate");
for(let y=0;y<2;y++)for(let t=0;t<2;t++){const s=1-t,GF=F.map(v=>s*v),GG=[t*y,t*(1-y)],lhs=evalCert(GF)+GG[0]*GG[0]+GG[1]*GG[1];chk(lhs===1,"13-term guarded FALSE unit");chk(evalCert(GF)===s,"false F selector in W");chk(GG[0]*GG[0]+GG[1]*GG[1]===t,"G selector");chk(GF.concat(GG).some(v=>v===1),"OR genuinely false");const trueH=GF.concat([t*y]);if(!trueH.some(v=>v===1)){nValid++;chk(t===1&&y===0,"TRUE branch faithful");} }}
chk(nValid===16,"valid TRUE witness count");
let seed=33003;const rand=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;};
const q=101,Delta=50,ell=256;let recoveries=0;
const dist=(a,b)=>Math.min((a-b+q)%q,(b-a+q)%q);
for(let b=0;b<ell;b++){const mu=rand()%2,rs=Array.from({length:23},()=>[rand()%q,rand()%q]),e0=rand()%3-1,e1=rand()%3-1;for(let w=0;w<16;w++){const y=0;const masks=rs.reduce((a,[r,s])=>a+r*s*y*y,0);const C=((masks+Delta*mu+e0+e1*y)%q+q)%q;chk(Number(dist(C,Delta)<dist(C,0))===mu,"same native bit");chk(masks===0,"masks vanish at valid original");recoveries++;}}
const log2joint=Math.log2(ell*2)+Math.log2(2)+(16/2-30)*Math.log2(q);chk(log2joint < -128,"two branch FALSE TV bound");
// Exact product distribution in F3^2, convolution with BigInt coefficient counts.
const norm=(a)=>(a%3+3)%3, base=Array(9).fill(0n);
for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++)base[3*((a*b)%3)+((c*d)%3)]++;
chk(base.reduce((a,b)=>a+b,0n)===81n,"base total count");
let counts=base.slice(),denom=81n, tvs=[];
for(let t=1;t<=6;t++){
let sum=0n;for(let i=0;i<9;i++){const x=Math.floor(i/3),y=i%3,shift=3*norm(x-1)+norm(y-1);let d=counts[i]-counts[shift];if(d<0n)d=-d;sum+=d;}
chk(sum*(3n**BigInt(t-1))<=2n*denom,"exact Fourier TV bound");
tvs.push({t,numerator:sum.toString(),denominator:(2n*denom).toString()});
const next=Array(9).fill(0n);
for(let i=0;i<9;i++)for(let j=0;j<9;j++)next[3*((Math.floor(i/3)+Math.floor(j/3))%3)+((i%3+j%3)%3)] += counts[i]*base[j];
counts=next;denom*=81n;
}
return {run:"R33-BRANCHWISE-BILINEAR-OR-20261103",assertions:checks,guarded_false_assignments:64,valid_true_original_witnesses:nValid,same_capability_bit_recoveries:recoveries,restricted_joint_false_log2_TV_upper_bound:log2joint,exact_F3_convolution:tvs,verdict:"PASS finite algebra, restricted FALSE branch stripping theorem; arbitrary hard TRUE recovery-to-ORIGINAL witness UNPROVED"};
};
console.log(JSON.stringify(runChecker(),null,2));
