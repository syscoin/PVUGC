const result = (function checker(){
 let n=0;
 const check=(b,msg)=>{n++;if(!b)throw new Error(msg||"failed "+n)};
 const vals=[[0,0],[0,1],[1,0],[1,1]];
 const source=(forbid)=>{
  const cols=[["c"]],v={},f={},rows=[],allow=[];
  for(let i=0;i<2;i++)for(let b=0;b<2;b++){v[`${i}:${b}`]=cols.length;cols.push(["v",i,b])}
  for(let k=0;k<4;k++){allow[k]=vals.filter(a=>a.join("")!==forbid[k].join(""));
   for(const a of allow[k]){f[`${k}:${a.join("")}`]=cols.length;cols.push(["f",k,a])}}
  const bit=j=>(1<<j);
  for(let i=0;i<2;i++)rows.push(bit(0)^bit(v[`${i}:0`])^bit(v[`${i}:1`]));
  for(let k=0;k<4;k++){
   let total=bit(0);
   for(const a of allow[k])total^=bit(f[`${k}:${a.join("")}`]);
   rows.push(total);
   for(let i=0;i<2;i++)for(let b=0;b<2;b++){
    let z=bit(v[`${i}:${b}`]);for(const a of allow[k])if(a[i]===b)z^=bit(f[`${k}:${a.join("")}`]);rows.push(z);
   }
  }
  return {cols,v,f,rows,allow,m:cols.length};
 };
 const pop=z=>{let n=0;while(z){z&=z-1;n++}return n};
 const parity=z=>pop(z)&1;
 const ker=s=>{
  let rows=s.rows.slice(), piv=[],i=0;
  for(let col=0;col<s.m;col++){
   let k=-1;for(let j=i;j<rows.length;j++)if((rows[j]>>col)&1){k=j;break}
   if(k<0)continue;
   [rows[i],rows[k]]=[rows[k],rows[i]];
   for(let j=0;j<rows.length;j++)if(j!==i&&((rows[j]>>col)&1))rows[j]^=rows[i];
   piv.push(col);i++;if(i===rows.length)break;
  }
  const free=[];for(let j=0;j<s.m;j++)if(!piv.includes(j))free.push(j);
  const basis=free.map(j=>{let z=1<<j;for(let a=0;a<piv.length;a++)if((rows[a]>>j)&1)z^=1<<piv[a];return z});
  for(const z of basis)for(const r of s.rows)check(parity(z&r)===0,"kernel error");
  return {basis,rank:piv.length};
 };
 const F=source(vals),T=source([vals[0],vals[0],vals[0],vals[0]]);
 const f=ker(F),t=ker(T);check(F.m===17&&T.m===17&&f.rank===14&&f.basis.length===3&&t.basis.length===3,"bad dimensions");
 const span=(bs,a)=>bs.reduce((z,b,i)=>z^(((a>>i)&1)?b:0),0);
 const factorMask=s=>s.cols.reduce((z,c,i)=>z^((c[0]==="f")?(1<<i):0),0);
 const fm=factorMask(F),tm=factorMask(T);
 const chars=Array.from({length:8},(_,a)=>span(f.basis,a));
 const profile={odd6:0,even8:0,zero:0};
 for(const v of chars){const weight=pop(v&fm);if(!v)profile.zero++;else if(v&1){check(weight===6);profile.odd6++}else{check(weight===8);profile.even8++}}
 check(profile.odd6===4&&profile.even8===3&&profile.zero===1,"profile");
 const positions=F.cols.flatMap((c,i)=>c[0]==="f"?[i]:[]);check(positions.length===12);
 const pow5=Array.from({length:13},(_,i)=>5n**BigInt(i)),den=6n**12n;
 const counts=[Array(8).fill(0n),Array(8).fill(0n)];
 for(let bits=0;bits<(1<<12);bits++){
  let e=0;for(let i=0;i<12;i++)if((bits>>i)&1)e^=1<<positions[i];
  const w=pow5[12-pop(bits)];
  for(let X=0;X<2;X++){
   let q=0;for(let i=0;i<3;i++)q|=(parity(f.basis[i]&e)^(X&(f.basis[i]&1)))<<i;
   counts[X][q]+=w;
  }
 }
 for(let X=0;X<2;X++)check(counts[X].reduce((a,b)=>a+b,0n)===den,"normalization");
 for(let X=0;X<2;X++)for(let q=0;q<8;q++){
  let numer=0n;
  for(let a=0;a<8;a++){
   const weight=pop(chars[a]&fm);
   const z=weight===0?3n**8n:(weight===6?2n**6n*3n**2n:2n**8n);
   numer+=((parity(a&q)^(X&(chars[a]&1)))?(-z):z);
  }
  check(counts[X][q]*(8n*3n**8n)===numer*den,"full Fourier quotient mismatch");
 }
 const rho=2/3, D=1+3*rho**8, u=4*rho**6/D;
 const J=z=>{const b=(1+z)/2;const c=(1-z)/2;return 1+b*Math.log2(b)+c*Math.log2(c)};
 const Ch=J(rho**4),If=D/4*J(u),gap=Ch-If;
 const ro=17/25,Do=1+2*ro**10+ro**12;
 const old=J(ro**7)-Do/4*J(4*ro**9/Do);
 check(gap>0.008&&gap/old>13.33,"rate gain");
 const witness=a=>{let z=1;for(let i=0;i<2;i++)z^=1<<T.v[`${i}:${a[i]}`];for(let k=0;k<4;k++)z^=1<<T.f[`${k}:${a.join("")}`];return z};
 const opens=vals.slice(1).map(a=>{
  const v=witness(a);
  check(pop(v&tm)===4&&pop(v)===7,"honest lift weight");
  for(const r of T.rows)check(parity(v&r)===0,"honest lift consistency");
  const alphas=Array.from({length:8},(_,i)=>i).filter(i=>span(t.basis,i)===v);
  check(alphas.length===1,"honest lift not uniquely represented");
  return {v,alpha:alphas[0]};
 });
 let seed=20261026;
 const rng=()=>{seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0};
 const tp=T.cols.flatMap((c,i)=>c[0]==="f"?[i]:[]);
 for(let test=0;test<128;test++){
  let e=0;for(const i of tp)if(rng()%6===0)e^=1<<i;
  const X=rng()&1;
  let q=0;for(let i=0;i<3;i++)q|=(parity(t.basis[i]&e)^(X&(t.basis[i]&1)))<<i;
  for(const a of opens)check(parity(q&a.alpha)===(X^parity(a.v&e)),"honest opening identity");
 }
 return {status:"PASS",checks:n,fixture:"2-variable / 4-factor complete false and 3-witness true control",source:{m:F.m,rank:f.rank,quotient_dimension:3},false_kernel_factor_profile:profile,exhaustive_error_masks:4096,exact_Fourier_probabilities_checked:16,noise:"factor columns Ber(1/6); constant and variable noise exactly zero",honest_capacity:Ch,false_information:If,secrecy_rate_gap:gap,old_gap:old,rate_gap_factor:gap/old,limits:"Restricted fixed SOURCE only; no arbitrary key recovery to ORIGINAL witness or QPT-LWE challenge simulator; no practical polar parameters."};
})();
console.log(JSON.stringify(result,null,2));
