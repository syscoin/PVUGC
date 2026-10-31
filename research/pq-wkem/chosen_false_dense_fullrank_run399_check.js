(()=>{
  const cases=[[31,3,6],[12289,3,512],[12289,8,512]], out=[];
  let checks=0, state=3992026>>>0;
  function next(){state=(Math.imul(state,1664525)+1013904223)>>>0;return state;}
  function ck(c,m){checks++;if(!c)throw Error("check "+checks+": "+m);}
  function mod(x,q){return ((x%q)+q)%q;}
  function inv(a,q){let b=q-2,r=1;while(b){if(b&1)r=r*a%q;a=a*a%q;b=Math.floor(b/2);}return r;}
  function rank(rows,q){let z=rows.map(x=>x.map(v=>mod(v,q))),k=0;
    for(let col=0;col<z[0].length;col++){let p=k;while(p<z.length&&z[p][col]===0)p++;if(p===z.length)continue;
      [z[k],z[p]]=[z[p],z[k]];let a=inv(z[k][col],q);z[k]=z[k].map(v=>v*a%q);
      for(let j=0;j<z.length;j++)if(j!==k){let h=z[j][col];if(h)z[j]=z[j].map((v,t)=>mod(v-h*z[k][t],q));}
      if(++k===z.length)break;}return k;}
  for(const [q,n,m] of cases){
    const B=1,t=10,mu=Math.floor(q/2), e=j=>Array.from({length:n},(_,i)=>+(i===j));
    const A0=[Array.from({length:n},(_,j)=>+(j===0||j===1)),
              Array.from({length:n},(_,j)=>+(j===0||j===2)),
              Array.from({length:n},(_,j)=>j===0?2:(j===1||j===2?1:0)),e(0)];
    for(let j=3;j<n;j++){const x=e(0);x[j]=1;A0.push(x);}
    while(A0.length<m){const x=e(0);x[1]=20+(A0.length-(n+1));x[2]=2;A0.push(x);}
    const sOld=Array.from({length:n},(_,j)=>j<3?j+1:20+j);
    const A=A0.map(r=>{const sum=r.reduce((a,v)=>a+v,0);return r.map(v=>mod(sum+v,q));});
    const b=A0.map((r,i)=>mod(r.reduce((a,v,j)=>a+v*sOld[j],0)+(i===2?t:0),q));
    const factor=mod(sOld.reduce((a,v)=>a+v,0)*inv(n+1,q),q);
    const near=sOld.map(v=>mod(v-factor,q));
    ck(new Set(A.map(r=>r.join(","))).size===m,"distinct rows");
    ck(A.every(r=>r.every(x=>x!==0)),"every matrix entry nonzero");
    ck(new Set(b).size===m&&b.every(x=>x!==0),"distinct nonzero b entries");
    ck(A[2].every((v,j)=>mod(v-A[0][j]-A[1][j],q)===0),"short dual relation");
    ck(mod(b[2]-b[0]-b[1],q)===t,"false certificate");
    ck(3*B<t&&t<q-3*B&&m*B<q/4,"error bound");
    ck(rank(A,q)===n&&rank(A.map((r,i)=>[...r,b[i]]),q)===n+1,"full rank");
    const anchors=[0,1,3,...Array.from({length:n-3},(_,i)=>i+4)];
    ck(rank(anchors.map(i=>A[i]),q)===n,"public source anchors");
    ck(anchors.every(i=>mod(A[i].reduce((z,v,j)=>z+v*near[j],0)-b[i],q)===0),"public near secret");
    let enumerated=0;
    if(m===6){for(let a=0;a<q;a++)for(let bb=0;bb<q;bb++)for(let c=0;c<q;c++){
      const s=[a,bb,c], good=A.every((row,i)=>{const x=mod(b[i]-row.reduce((z,v,j)=>z+v*s[j],0),q);return Math.min(x,q-x)<=B;});
      ck(!good,"no original witness");enumerated++;}}
    const residuals=new Set();let evaluated=0;
    for(let k=0;k<(m===6?64:128);k++){
      const r=Array.from({length:m},(_,i)=>m===6?(k>>i)&1:(next()>>>16)&1);
      const u=Array.from({length:n},(_,j)=>mod(A.reduce((z,row,i)=>z+row[j]*r[i],0),q));
      for(let bit=0;bit<2;bit++){
        const v=mod(b.reduce((z,bi,i)=>z+bi*r[i],0)+mu*bit,q);
        const z=mod(v-near.reduce((a,x,j)=>a+x*u[j],0),q);
        ck(z===mod(t*r[2]+mu*bit,q),"seam identity");
        ck(bit===0?(z===0||z===t):(z===mu||z===mu+t),"public bit recovery");
        residuals.add(z);evaluated++;
      }
    }
    ck(residuals.size===4,"all residuals observed");
    let fullKey=true;
    for(let bitidx=0;bitidx<256;bitidx++){
      const bit=(next()>>>20)&1,r=Array.from({length:m},()=>((next()>>>20)&1));
      const u=Array.from({length:n},(_,j)=>mod(A.reduce((z,row,i)=>z+row[j]*r[i],0),q));
      const v=mod(b.reduce((z,bi,i)=>z+bi*r[i],0)+mu*bit,q);
      const z=mod(v-near.reduce((a,x,j)=>a+x*u[j],0),q);
      const recovered=z===0||z===t?0:1;
      ck(recovered===bit,"complete signing-seed bit recovery");
      fullKey&&=recovered===bit;
    }
    out.push({q,n,m,A_rank:n,augmented_rank:n+1,nonzero_A_entries:n*m,distinct_nonzero_b:m,
      exhausted_candidate_secrets:enumerated,ciphertexts_evaluated:evaluated,
      recovered_all_256_key_bits:fullKey,original_relation:false,cryptographic_security:false});
  }
  const result={run:399,status:"PASS",checks,fixtures:out,
    scope:"chosen-false dense fullrank Regev frontier, public frame T=I+J",
    concrete_qpt_security:false,actual_native_signing:false};
  if(typeof console!=="undefined")console.log(JSON.stringify(result,null,2));
  return result;
})()
