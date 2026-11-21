function run510(){
let ck=0,oracles=0,fourier=0,ranks=0;const assert=(p)=>{ck++;if(!p)throw Error('Run510 check '+ck);};const parity=(x)=>{let p=0;while(x){p^=1;x&=x-1;}return p;};
for(let h=1;h<=7;h++){const N=1<<h;for(let d=0;d<N;d++){oracles++;const F=(v)=>(v*5+3)%N,G=(v)=>F(v^d),H=(b,v)=>b?G(v):F(v);
for(let v=0;v<N;v++)assert(H(0,v)===H(1,v^d));
if(h<=5)for(let v=0;v<N;v++)for(let beta=0;beta<N;beta++)for(let alpha=0;alpha<2;alpha++){const a=(parity(beta&v)?-1:1)+(alpha^parity(beta&(v^d))?-1:1),p=a*a/(4*N);assert(p===(alpha===parity(beta&d)?1/N:0));fourier++;}
}
for(let m=Math.max(0,h-1);m<=h+5;m++){let p=Array(h+1).fill(0);p[0]=1;for(let j=0;j<m;j++){const q=Array(h+1).fill(0);for(let r=0;r<=h;r++){const z=2**(r-h);q[r]+=p[r]*z;if(r<h)q[r+1]+=p[r]*(1-z);}p=q;}let e=m<h?0:1;if(m>=h)for(let i=0;i<h;i++)e*=1-2**(i-m);assert(Math.abs(e-p[h])<1e-12);ranks++;}
}
return {run:510,exact_oracle_fixtures:oracles,exact_fourier_checks:fourier,rank_formula_checks:ranks,assertions:ck,status:'PASS; pure algebra, no concrete security proof'};}
console.log(JSON.stringify(run510(),null,2));
