'use strict';
// Run 707 compact independent finite-field checker; standard Node.js only.
const q=3;let checks=0;
const ok=(b,m)=>{checks++;if(!b)throw Error(m)};
const Z=n=>Array.from({length:n},()=>Array(n).fill(0));
const rank=A=>{let n=A.length,T=A.map(r=>r.slice()),k=0;for(let c=0;c<n;c++){let p=k;while(p<n&&T[p][c]===0)p++;if(p===n)continue;[T[p],T[k]]=[T[k],T[p]];let d=T[k][c]===1?1:2;for(let j=c;j<n;j++)T[k][j]=T[k][j]*d%q;for(let i=k+1;i<n;i++)if(T[i][c]){let a=T[i][c];for(let j=c;j<n;j++)T[i][j]=(T[i][j]-a*T[k][j]+9)%q;}k++;}return k};
const choose=(n,k)=>{let z=1;for(let i=1;i<=k;i++)z=z*(n-i+1)/i;return Math.round(z)};
let census=[];
for(let n=2;n<=5;n++){
  const ms=[Z(n),Array.from({length:n},(_,i)=>Array.from({length:n},(_,j)=>+(i===j))),Array.from({length:n},(_,i)=>Array.from({length:n},(_,j)=>+(j===i+1)))];
  for(let mi=0;mi<ms.length;mi++){
    let dist=Array(n+1).fill(0),total=3**n;
    for(let code=0;code<total;code++){
      let a=ms[mi].map(r=>r.slice()),v=code;
      for(let i=0;i<n;i++){a[i][i]=(a[i][i]+v%q)%q;v=Math.floor(v/q)}
      let d=n-rank(a);dist[d]++;ok(d>=0&&d<=n,'nullity');
    }
    for(let s=1;s<=n;s++){
      const got=dist.slice(s).reduce((a,b)=>a+b,0);
      let footprint=0;for(let j=0;j<=n-s;j++)footprint+=choose(n,j)*2**j;
      ok(got<=footprint,'footprint');ok(got<=choose(n,s)*3**(n-s),'binomial');
      if(mi===0)ok(got===footprint,'tightness');
    }
    census.push({n,matrix:mi,nullity:dist});
  }
}
// Entire-public-transcript key translation for r_1=t,r_2=1-t,
// with independent diagonal matrices and two distinct protected keys.
const n=4,mod=101,aa=[4,35,87,5],bb=[74,63,13,98],K=7,D=19;
const shift=a=>a.map(v=>(v-D+mod)%mod);
const make=(k,a,b)=>({constant:a.map((_,i)=>(k+b[i])%mod),linear:a.map((v,i)=>(v-b[i]+mod)%mod)});
const left=make(K,aa,bb),right=make(K+D,shift(aa),shift(bb));
ok(JSON.stringify(left)===JSON.stringify(right),'whole coefficient array');
for(let y=0;y<mod;y++)for(let i=0;i<n;i++)ok((left.constant[i]+y*left.linear[i])%mod===(right.constant[i]+y*right.linear[i])%mod,'all evaluations');
console.log(JSON.stringify({run:707,checks,census,entire_public_polynomial_coupling:true,claim:'diagonal mask rank/false-unit correctness only; hard-true QPT security unproved'}));
