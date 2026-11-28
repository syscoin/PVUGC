function R96() {
  const P=5,rounds=5;let assertions=0;
  const counts={privacy:0,maliciousPublicLeak:0,openings:0,hybridView:0};
  const eq=(v,m)=>{assertions++;if(!v)throw Error("assertion "+assertions+": "+m)};
  const mod=x=>(x%P+P)%P;
  const H=(...xs)=>{let z=2166136261>>>0,s=JSON.stringify(xs);
    for(let i=0;i<s.length;i++)z=Math.imul(z^s.charCodeAt(i),16777619)>>>0;return z;};
  const pk=[{A:0,B:0},{A:0,B:0},{A:2,B:1}],sk=[0,0,3];
  const Enc=(key,val,r)=>({u:mod(key.A*r),v:mod(key.B*r+val)});
  const Dec=(key,ct)=>mod(ct.v-key*ct.u);
  const interp=(s1,s2,s3)=>mod(3*s1-3*s2+s3);
  const pub=views=>H("manifest",views.map(v=>[v.label,v.ct,v.D]));
  const attach=(views,roots)=>{let J=pub(views);return {J,items:views.map((v,i)=>({
    ...v,ck:H("CK",roots[i],v.D,J,views.map(u=>u.label)),
    aux:H("AUX",roots[i],v.D,J,views.map(u=>u.label),i)}))}};
  const hist=Array.from({length:P},()=>new Map());
  for(let t=0;t<P;t++)for(let a=0;a<P;a++)for(let b=0;b<P;b++){
    let s1=mod(t+a+b),s2=mod(t+2*a+4*b);
    let key=s1+":"+s2;hist[t].set(key,(hist[t].get(key)||0)+1);
  }
  for(let t=0;t<P;t++)for(let x=0;x<P;x++)for(let y=0;y<P;y++){
    eq(hist[t].get(x+":"+y)===1,"perfect two-share joint privacy");counts.privacy++;
  }
  for(let k=0;k<rounds;k++)for(let t=0;t<P;t++)for(let a=0;a<P;a++)for(let b=0;b<P;b++){
    let shares=[1,2,3].map(x=>mod(t+a*x+b*x*x));
    let ct=shares.map((v,i)=>Enc(pk[i],v,(k+i+2*t)%P));
    eq(ct[0].v===shares[0]&&ct[1].v===shares[1],"malicious keys publicly leak two shares");
    counts.maliciousPublicLeak++;
    let p=shares.map((v,i)=>Dec(sk[i],ct[i]));
    eq(interp(...p)===t,"every full ORIGINAL leaf witness opens same T");counts.openings++;
    let relatedT=mod(t+1),relshares=[1,2,3].map(x=>mod(relatedT+2*x+x*x));
    let relct=relshares.map((v,i)=>Enc(pk[i],v,(k+i+3*t)%P));
    let views=[{label:"UTXO:k"+k+":target",ct,D:H("sigmask",t,k)},
               {label:"UTXO:k"+k+":related",ct:relct,D:H("sigmask",relatedT,k)}];
    let original=attach(views,[t,relatedT]);
    let altered=JSON.parse(JSON.stringify(views));altered[0].ct[2]=Enc(pk[2],0,(k+t)%P);
    if(JSON.stringify(altered[0].ct[2])===JSON.stringify(views[0].ct[2]))
      altered[0].ct[2].v=mod(altered[0].ct[2].v+1);
    let switched=attach(altered,[t,relatedT]);
    eq(switched.J!==original.J,"manifest binds challenge ciphertext");
    eq(switched.items.every((v,i)=>v.ck!==original.items[i].ck&&v.aux!==original.items[i].aux),
      "challenge bytes rebind every CK/Aux including related capsules");counts.hybridView++;
  }
  return {run:"R96-MANDATORY-HONEST-LWE-SOURCE-20261105",assertions,counts,
    fixture:"GF5 and zero-error linear encryption; insecure structural fixture, NOT QPT hardness"};
}
console.log(JSON.stringify(R96(),null,2));
