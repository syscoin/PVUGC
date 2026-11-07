const runChecker = function runChecker(){
  const q=257,delta=128,E=1,E0=1;let checks=0,seed=0xA144;
  function ck(b,s){checks++;if(!b)throw Error("assert "+checks+": "+s)}
  function rand(n){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return (seed>>>0)%n}
  function mod(v,n=q){return ((v%n)+n)%n}
  function circ(v,n=q){let a=mod(v,n);return Math.min(a,n-a)}
  function dot(a,b){return a.reduce((s,v,i)=>s+v*b[i],0)}
  function mk(n,clauses){let m=clauses.length,B=n+2*m,D=2*B,H=[],b=[];
    for(let i=0;i<B;i++){let row=Array(D).fill(0);row[2*i]=row[2*i+1]=1;H.push(row);b.push(1)}
    for(let j=0;j<m;j++){let row=Array(D).fill(0);for(const [v,pos] of clauses[j])row[2*v+(pos?0:1)]++;row[2*(n+2*j)]--;row[2*(n+2*j+1)]--;H.push(row);b.push(1)}
    return {H,b,B,D}}
  function Z(n,clauses,d){let z=[];for(let i=0;i<n;i++)z.push(d===2?1:1,d===2?1:2);
    for(const clause of clauses){let L=clause.reduce((a,[v,pos])=>a+(d===2?1:(pos?1:2)),0);z.push(L-d,2*d-L,0,d)}return z}
  function zw(n,clauses,w){let z=[];for(const v of w)z.push(v,1-v);
    for(const clause of clauses){let L=clause.reduce((a,[v,pos])=>a+(pos?w[v]:1-w[v]),0);if(L<1)return null;let a=Math.min(1,L-1),b=L-1-a;z.push(a,1-a,b,1-b)}
    return z}
  function mv(H,z){return H.map(row=>dot(row,z))}
  function checkCase(n,clauses){let {H,b,B,D}=mk(n,clauses);for(const d of [2,3]){let v=Z(n,clauses,d);
      ck(v.length===D,"z length");ck(mv(H,v).every((x,i)=>x===d*b[i]),"all clause equalities");
      ck(v.reduce((a,x)=>a+Math.abs(x),0)===d*B,"l1");ck(v.reduce((a,x)=>a+x*x,0)<=d*d*B,"squared norm")}
    for(let w=0;w<(1<<n);w++){let bits=Array.from({length:n},(_,j)=>(w>>j)&1),v=zw(n,clauses,bits);
      if(v){ck(mv(H,v).every((x,i)=>x===b[i]),"original witness opens");ck(dot(v,v)===B,"original norm")}}}
  const falseClauses=[[[0,1],[0,1],[0,1]],[[0,0],[0,0],[0,0]]];
  const {H,b,B,D}=mk(1,falseClauses);ck(zw(1,falseClauses,[0])===null&&zw(1,falseClauses,[1])===null,"false instance");
  checkCase(1,falseClauses);const M=E0+E*B,v=Z(1,falseClauses,3);
  ck(circ(2*delta)===1&&circ(3*delta)===127,"phase alias vs odd denom");
  ck(circ(3*delta)>2*3*M,"all tape false decoding");
  for(let trial=0;trial<4096;trial++){let s=b.map(()=>rand(q)),e=Array.from({length:D},()=>rand(3)-1),eta=rand(3)-1,k=rand(2);
    let c=Array.from({length:D},(_,j)=>mod(H.reduce((a,row,i)=>a+row[j]*s[i],0)+e[j]));
    let cp=mod(dot(b,s)+delta*k+eta),phase=mod(3*cp-dot(v,c));
    let noise=3*eta-dot(v,e);
    ck(mod(phase-3*delta*k)===mod(noise),"actual public phase");
    ck(Math.abs(noise)<=3*M,"error bound");
    let guess=circ(phase)<=circ(phase-3*delta)?0:1;
    ck(guess===k,"full false-source recovery")}
  for(let t=0;t<500;t++){let n=1+rand(5),m=1+rand(7),clauses=Array.from({length:m},()=>Array.from({length:3},()=>[rand(n),rand(2)]));checkCase(n,clauses)}
  for(const m of [17,19,31,127,257])for(let a=1;a<m;a++)ck(circ(a,m)<=circ(3*a,m)+circ(2*a,m),"coprime margin triangle");
  return {run:"R144",candidate:"parity-aliased LWE projection",status:"REJECTED (classical false-instance key recovery)",q,delta,legitimate_M:M,odd_denominator_error_bound:3*M,two_scale_signal:circ(2*delta),three_scale_signal:circ(3*delta),false_instance_public_recoveries:4096,random_formula_cases:500,assertions:checks};
};
console.log(JSON.stringify(runChecker(), null, 2));
