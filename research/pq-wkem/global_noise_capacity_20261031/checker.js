function check(){
  const q=2147483647,B=20,g=100;
  let assertions=0;
  const ok=(condition,label)=>{assertions++;if(!condition)throw Error(label)};
  const row=o=>Array.from({length:14},(_,j)=>o[j]||0);
  const A=[
    row({0:1,1:1}),row({2:1,3:1,4:1,5:1}),
    row({1:-1,4:1,5:1}),row({1:-1,3:1,5:1}),row({2:1,3:1,4:1}),
    row({6:1,7:1,8:1,9:1}),row({1:-1,8:1,9:1}),
    row({1:-1,7:1,9:1}),row({6:1,7:1,8:1}),
    row({10:1,11:1,12:1,13:1})
  ],t=[1,1,0,0,0,1,0,0,1,1];
  const dot=(a,b)=>a.reduce((v,x,i)=>v+x*b[i],0);
  const norm=z=>dot(z,z);
  const keys=[],sol=[];
  for(let x=0;x<2;x++)for(let d=0;d<4;d++){
    const z=[...(x===0?[1,0]:[0,1]),...(x===0?[2,-1,-1,1]:[0,0,0,1]),
      ...(x===0?[1,0,0,0]:[-1,1,1,0]),...Array.from({length:4},(_,i)=>Number(i===d))];
    keys.push({x,d});sol.push(z);
    ok(A.every((r,i)=>dot(r,z)===t[i]),"bad affine solution");
    ok(norm(z)===(x===0?10:6),"wrong integer norm");
  }
  const coeff=keys.map(k=>(k.x===0?5:9)/56);
  const zbar=Array.from({length:14},(_,j)=>sol.reduce((a,z,i)=>a+coeff[i]*z[j],0));
  ok(Math.abs(norm(zbar)-97/28)<1e-12,"mixture norm");
  ok(norm(zbar)<4,"must beat honest onehot norm");
  ok(A.every((r,i)=>Math.abs(dot(r,zbar)-t[i])<1e-12),"mixture must be affine");
  let state=20261031>>>0;
  const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
  const mod=v=>((v%q)+q)%q;
  const center=v=>{let r=mod(v);return r<=q/2?r:r-q};
  let mses=[0,0,0],errors=[0,0,0];
  const samples=3000;
  for(let j=0;j<samples;j++){
    const s=A.map(()=>rnd()%q),e=Array.from({length:14},()=>rnd()%41-20);
    const ep=rnd()%41-20,m=rnd()%2;
    const beta=Array.from({length:14},(_,k)=>mod(A.reduce((a,r,i)=>a+r[k]*s[i],0)+e[k]));
    const tau=mod(dot(t,s)+ep+g*m);
    const residues=sol.map(z=>center(tau-dot(z,beta)));
    for(let i=0;i<8;i++)ok(residues[i]===g*m+ep-dot(sol[i],e),"public-residual identity");
    const mix=residues.reduce((a,r,i)=>a+coeff[i]*r,0);
    ok(Math.abs(mix-(g*m+ep-dot(zbar,e)))<1e-9,"affine interpolation");
    const baseline=g*m+ep-[0,2,6,10].reduce((a,k)=>a+e[k],0);
    const options=[residues[4],baseline,mix];
    for(let k=0;k<3;k++){
      mses[k]+=(options[k]-g*m)**2;
      errors[k]+=Number(Math.round(options[k]/g)!==m);
    }
  }
  mses=mses.map(v=>v/samples);
  ok(mses[2]<mses[1]&&mses[1]<mses[0],"noise-gap reversal");
  ok(errors[2]<errors[1]&&errors[1]<errors[0],"bit-error reversal");
  return {result:"PASS",assertions,samples,public_openers:8,
    false_relation:"NAND(x,x)=0 AND NAND(x,x)=1",honest_onehot_norm2:4,
    minimum_fake_integer_norm2:6,mixed_public_norm2:"97/28",
    predicted_noise_variance:{single_fake:980,honest_reference:700,public_mix:625},
    observed_noise_mse:{single_fake:mses[0],honest_reference:mses[1],public_mix:mses[2]},
    bit_errors:{single_fake:errors[0],honest_reference:errors[1],public_mix:errors[2]},
    assumptions:"toy qary ciphertext, centered bounded independent errors; no QPT claim"};
}
console.log(JSON.stringify(check(),null,2));
