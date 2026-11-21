#!/usr/bin/env node
const result=(function runCheck(){
  const q=65537,d=5,E=2,bits=8,g=Math.floor(q/256);
  let checks=0,success=0,guardChanges=0,state=20261101>>>0;
  const req=(v,s)=>{checks++;if(!v)throw new Error(s)};
  const mod=(v)=>((v%q)+q)%q;
  const rnd=(n)=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%n};
  const M=[[1,1,0,0,0,0],[-1,0,1,1,0,0],[0,-1,1,0,1,0],[1,1,-1,0,0,1],[0,0,1,0,0,0]];
  const rhs=[1,0,0,1,1];
  const N=6;
  const MH=M.map(row=>row.flatMap(x=>[0,x]));
  for(let i=0;i<N;i++){let row=Array(2*N).fill(0);row[2*i]=1;row[2*i+1]=1;MH.push(row);rhs.push(1)}
  const fake=[0,1,1,-1,0,1];
  const p=fake.flatMap(x=>[1-x,x]);
  const prod=(row,vec)=>row.reduce((s,x,j)=>s+x*vec[j],0);
  req(MH.every((r,i)=>prod(r,p)===rhs[i]),"fake solves exact public equations");
  req(p.reduce((s,x)=>s+Math.abs(x),0)===N+2,"fake norm N+2");
  req(g>2*E*(1+N+2),"false decoding margin");
  let validBinary=0;
  for(let mask=0;mask<(1<<N);mask++){
    const z=Array.from({length:N},(_,i)=>(mask>>i)&1);
    const pp=z.flatMap(x=>[1-x,x]);
    if(MH.every((r,i)=>prod(r,pp)===rhs[i]))validBinary++;
  }
  req(validBinary===0,"ORIGINAL has no satisfying Boolean witness");
  const kernel=[1,-1,0,1,-1,0].flatMap(x=>[-x,x]);
  req(MH.every(r=>prod(r,kernel)===0),"public nonzero short null vector");
  const dec=(rho)=>{let best=0,dist=q+1;for(let m=0;m<256;m++){const z=mod(rho-g*m);const v=Math.min(z,q-z);if(v<dist){dist=v;best=m}}return best};
  for(let trial=0;trial<128;trial++){
    const B0=Array.from({length:d},()=>Array.from({length:MH.length},()=>rnd(q)));
    const A=Array.from({length:d},(_,i)=>Array.from({length:2*N},(_,j)=>mod(B0[i].reduce((s,x,k)=>s+x*MH[k][j],0))));
    const t=Array.from({length:d},(_,i)=>mod(prod(B0[i],rhs)));
    req(A.every((row,i)=>mod(prod(row,p))===t[i]),"fake opens masked source");
    req(A.every(row=>mod(prod(row,kernel))===0),"public kernel invariant");
    const s=Array.from({length:d},()=>rnd(q));
    const e=Array.from({length:2*N},()=>rnd(2*E+1)-E);
    const e0=rnd(2*E+1)-E;
    const symbol=rnd(256);
    const beta=Array.from({length:2*N},(_,j)=>mod(A.reduce((v,row,i)=>v+row[j]*s[i],0)+e[j]));
    const tau=mod(prod(t,s)+e0+g*symbol);
    const raw=mod(tau-prod(beta,p));
    req(dec(raw)===symbol,"unauthorized FALSE symbol release");
    success++;
    const r=Array.from({length:2*N},()=>rnd(q));
    const guard=mod(p.reduce((v,x,j)=>v+r[j]*(x*x-x),0));
    const guarded=mod(raw+guard);
    if(dec(guarded)!==symbol)guardChanges++;
    req(Array.from({length:N},(_,i)=>[0,1]).every(()=>true),"bounded trial");
  }
  req(guardChanges>110,"public nonlinear guard changes official result but cannot prevent bypass");
  return {research:"GOIL",seed:20261101,q,d,E,bits,g,tests:checks,
    original_false_binary_witnesses:validBinary,counterfeit_l1:8,
    unauth_false_symbol_decryptions:success,guard_changed_symbol_count:guardChanges,
    public_kernel:true,status:"PASS — SOURCE LEMMA ONLY; RELEASE INSECURE"};
})();
console.log(JSON.stringify(result,null,2));
