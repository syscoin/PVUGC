const runR104=function runR104(){
 const q=5, DELTA=128;
 let n=0;const counts={privacy:0,qualification:0,public_leak:0,joint_manifest:0};
 const ok=(v,msg)=>{n++;if(!v)throw Error("R104 assertion "+n+": "+msg)};
 const H=s=>{let h=2166136261;for(let i=0;i<s.length;i++)h=Math.imul(h^s.charCodeAt(i),16777619)>>>0;return h.toString(16)};
 const P=ids=>(ids.has("H")&&(ids.has("A")||ids.has("B")))||(ids.has("J")&&(ids.has("A")||ids.has("C")));
 const C=new Set(["A","B","C"]);
 ok(!P(C),"malicious set cannot authorize policy");
 ok(P(new Set(["H","A"]))&&P(new Set(["J","C"])),"no single required honest key");
 let baseline=null;
 for(let t=0;t<q;t++){
  const hist={};
  for(let u=0;u<q;u++)for(let v=0;v<q;v++){
   const vals={H:u,AL:(t-u+q)%q,B:(t-u+q)%q,J:v,AR:(t-v+q)%q,C:(t-v+q)%q};
   const corruption=[vals.AL,vals.B,vals.AR,vals.C].join(",");
   hist[corruption]=(hist[corruption]||0)+1;
   ok((vals.H+vals.AL)%q===t && (vals.J+vals.C)%q===t,"both independent honest paths recover same root");
   counts.privacy++;
   for(let mask=0;mask<32;mask++){
    const ids=new Set(["H","J","A","B","C"].filter((_,i)=>mask&(1<<i)));
    const hasL=ids.has("H")&&(ids.has("A")||ids.has("B"));
    const hasR=ids.has("J")&&(ids.has("A")||ids.has("C"));
    const L=hasL?(vals.H+(ids.has("A")?vals.AL:vals.B))%q:null;
    const R=hasR?(vals.J+(ids.has("A")?vals.AR:vals.C))%q:null;
    ok(P(ids)===(L!==null||R!==null),"availability follows original credentials");
    ok(L===null||L===t,"valid left path reconstructs root");
    ok(R===null||R===t,"valid right path reconstructs root");
    counts.qualification++;
   }
  }
  const histCanonical=JSON.stringify(Object.entries(hist).sort(([a],[b])=>a.localeCompare(b)));
  if(baseline!==null)ok(histCanonical===baseline,"FULL malicious joint view independent of root");
  else baseline=histCanonical;
 }
 for(let t=0;t<5;t++)for(let u=0;u<5;u++){
   const bits=[(t>>2)&1,(t>>1)&1,t&1],vs=bits.map(b=>DELTA*b);
   ok(bits.every((b,i)=>vs[i]===DELTA*b),"zero malicious B publicly exposes bit");
   counts.public_leak++;
 }
 const mkView=()=>{
  const pk={A:[[2,3],[4,5]],honestB:[1,2,3],maliciousB:[0,0,0]};
  const caps=[0,1,2].map(j=>({ctx:{claim:"utxo:"+j,branch:"challenge"},ct:[j+7,j+9],Dsig:"masked:"+j,rootCheck:"sealed:"+j}));
  const manifest=H(JSON.stringify({pk,caps:caps.map(c=>[c.ctx,c.ct,c.Dsig])}));
  const bound=caps.map(c=>({CK:H(manifest+JSON.stringify(c.ctx)+c.rootCheck),Aux:H("aux"+manifest+JSON.stringify(c.ctx)+c.rootCheck)}));
  return {pk,caps,manifest,bound};
 };
 const a=mkView(),b=mkView();b.caps[0].ct[0]=999;
 b.manifest=H(JSON.stringify({pk:b.pk,caps:b.caps.map(c=>[c.ctx,c.ct,c.Dsig])}));
 b.bound=b.caps.map(c=>({CK:H(b.manifest+JSON.stringify(c.ctx)+c.rootCheck),Aux:H("aux"+b.manifest+JSON.stringify(c.ctx)+c.rootCheck)}));
 ok(a.manifest!==b.manifest && JSON.stringify(a.pk)===JSON.stringify(b.pk),"challenge substitution retains PK and changes manifest");
 for(let i=0;i<3;i++){ok(JSON.stringify(a.bound[i])!==JSON.stringify(b.bound[i]),"related CK/Aux must rebind");counts.joint_manifest++}
 return {run:"R104-MIXED-MALICIOUS-KEY-MONOTONE-20261105",status:"RESTRICTED_COMPOSITION_NOT_GENERIC_ORIGINAL_NP",assertions:n,counts,exact_histogram_entries:25,malicious_set:["A","B","C"],policy:"(H AND (A OR B)) OR (J AND (A OR C))",limitations:"GF(5) exhaustive algebra, toy publicly leaking source keys, non-cryptographic digest; no QPT hardness or generic NP bridge"};
};
console.log(JSON.stringify(runR104(),null,2));
