// Run 391 compact checker. Pure deterministic JavaScript, no external libraries.
function main() {
  let count=0; const ck=(x,msg)=>{count++;if(!x)throw Error(msg+" #"+count)};
  let state=391391;
  const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const pick=n=>rnd()%n;
  const shuffle=a=>{for(let i=a.length-1;i>0;i--){let j=pick(i+1);[a[i],a[j]]=[a[j],a[i]]}return a};
  function nextPerm(a){let i=a.length-2;while(i>=0&&a[i]>=a[i+1])i--;if(i<0)return false;let j=a.length-1;while(a[j]<=a[i])j--;[a[i],a[j]]=[a[j],a[i]];let u=i+1,v=a.length-1;while(u<v){[a[u],a[v]]=[a[v],a[u]];u++;v--}return true}
  let permutationCount=0,tab=[0,1,2,3,4,5,6,7];
  do {for(let j=0;j<3;j++){let ones=0,xor=0;for(const x of tab){const bit=(x>>>j)&1;ones+=bit;xor^=bit}ck(ones===4&&xor===0,"all 3-bit balanced top ANF zero")}permutationCount++}while(nextPerm(tab));
  ck(permutationCount===40320,"all gates exhaustive");
  const layers=(n,L)=>Array.from({length:L},()=>{let w=shuffle(Array.from({length:n},(_,i)=>i));return Array.from({length:n/3},(_,g)=>({p:w.slice(3*g,3*g+3),t:shuffle([0,1,2,3,4,5,6,7])}))});
  function circuit(x,ls){for(const l of ls){let y=x;for(const g of l){let z=0;for(let j=0;j<3;j++)z|=((x>>>g.p[j])&1)<<j;const v=g.t[z];for(let j=0;j<3;j++){const mask=1<<g.p[j];if((v>>>j)&1)y|=mask;else y&=~mask}}x=y}return x}
  function degree(vals,n){let a=vals.slice();for(let i=0;i<n;i++)for(let m=0;m<(1<<n);m++)if(m&(1<<i))a[m]^=a[m^(1<<i)];let d=-1;for(let m=0;m<a.length;m++)if(a[m]){let b=m,c=0;while(b){b&=b-1;c++}if(c>d)d=c}return d}
  let degreeFixtures=0;
  for(let L=1;L<=2;L++)for(let t=0;t<12;t++){const ls=layers(6,L);for(let bit=0;bit<6;bit++){let vals=Array.from({length:64},(_,x)=>(circuit(x,ls)>>>bit)&1);ck(degree(vals,6)<=(1<<L),"six-bit ANF degree")}degreeFixtures++}
  function parity(f,ds,base,bit){let ans=0;for(let m=0;m<(1<<ds.length);m++){let x=base;for(let j=0;j<ds.length;j++)if((m>>>j)&1)x^=1<<ds[j];ans^=(f(x)>>>bit)&1}return ans}
  function isEven(p){const seen=new Uint8Array(p.length);let cycles=0;for(let i=0;i<p.length;i++){if(seen[i])continue;cycles++;let j=i;while(!seen[j]){seen[j]=1;j=p[j]}}return ((p.length-cycles)&1)===0}
  function randomEven(n){const p=shuffle(Array.from({length:n},(_,i)=>i));if(!isEven(p))[p[0],p[1]]=[p[1],p[0]];ck(isEven(p),"even baseline");return p}
  const n=12,N=1<<n,results={};
  for(let L=1;L<=3;L++){const D=1<<L,r=D+1,Q=1<<r;ck(r<=n&&Q<=N-2,"valid cube");let local=0,ideal=0;
    for(let t=0;t<80;t++){const ds=shuffle(Array.from({length:n},(_,i)=>i)).slice(0,r),a=pick(N),bit=pick(n),ls=layers(n,L);local+=parity(x=>circuit(x,ls),ds,a,bit);const p=randomEven(N);ideal+=parity(x=>p[x],ds,a,bit)}
    ck(local===0,"shallow derivative zero");ck(18<=ideal&&ideal<=62,"uniform-even nonzero frequency");results[String(L)]={degree_bound:D,derivative_order:r,queries:Q,fixtures:80,shallow_nonzero:local,uniform_even_nonzero:ideal}}
  return {run:391,status:"PASS",assertions:count,all_three_bit_gates:permutationCount,six_bit_degree_fixtures:degreeFixtures,seed:391391,n,results,scope:"isolated chosen-input depth<=3 3-local reversible forward mixers",wkem:false,prp_security:false,rio_break:false,qpt_security:false};
}
