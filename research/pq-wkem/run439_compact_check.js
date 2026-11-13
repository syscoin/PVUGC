/* Run439 exact S_4 colored-orbit independent JS checker; toy diagnostic, NOT PQ security. */
const run439 = function run439() {
  const d=4;
  const perms=[];
  const rec=(a,r)=>{if(!r.length){perms.push(a);return;}for(let i=0;i<r.length;i++)rec([...a,r[i]],[...r.slice(0,i),...r.slice(i+1)]);};
  rec([],Array.from({length:d},(_,i)=>i));
  const id=[0,1,2,3];
  const compose=(p,q)=>q.map(v=>p[v]);
  const inverse=p=>{const v=[];p.forEach((x,i)=>v[x]=i);return v;};
  const equality=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  let assertions=0;
  const chk=(yes,label)=>{assertions++;if(!yes)throw Error("assertion failed: "+label);};
  const build=(t1,t2,f,anchors=[0])=>{
    const t=compose(t2,t1),it=inverse(t),decoder=it.map(j=>f[j]);
    chk(equality(t.map(j=>decoder[j]),f),"source decoder");
    return {t1,t2,f,decoder,anchors};
  };
  const fixtures={
    ref:build(id,id,["A","A","B","B"]),
    alt:build([1,0,2,3],[0,2,1,3],["A","B","A","B"]),
    pin_mismatch:build(id,id,["B","A","A","B"]),
    histogram_mismatch:build(id,id,["A","A","A","B"]),
    unpinned_ref:build(id,id,["A","A","B","B"],[]),
    unpinned_alt:build([1,0,2,3],[0,2,1,3],["B","A","B","A"],[])
  };
  const factorial=n=>{let r=1;for(let i=2;i<=n;i++)r*=i;return r;};
  const invariants=src=>{
    const counts={};
    for(const c of src.f)counts[c]=(counts[c]||0)+1;
    const anchorColors=src.anchors.map(a=>src.f[a]), used={};
    for(const c of anchorColors)used[c]=(used[c]||0)+1;
    let aut=1;
    for(const c of Object.keys(counts))aut*=factorial(counts[c]-(used[c]||0));
    return {histogram:counts,anchor_colors:anchorColors,aut};
  };
  const transcript=(s,u0,u1,u2)=>{
    const g1=compose(u1,compose(s.t1,inverse(u0)));
    const g2=compose(u2,compose(s.t2,inverse(u1)));
    const inv2=inverse(u2);
    const labels=s.anchors.map(a=>u0[a]);
    const dpub=inv2.map(i=>s.decoder[i]);
    return {g1,g2,labels,dpub};
  };
  const distributions={};
  const stats={};
  for(const [name,src] of Object.entries(fixtures)){
    const hist=new Map();
    for(const u0 of perms)for(const u1 of perms)for(const u2 of perms){
      const key=JSON.stringify(transcript(src,u0,u1,u2));
      hist.set(key,(hist.get(key)||0)+1);
    }
    const inv=invariants(src);
    const multiplicities=[...new Set(hist.values())];
    chk(hist.size===13824/inv.aut,name+" support");
    chk(multiplicities.length===1&&multiplicities[0]===inv.aut,name+" uniform");
    let total=0;for(const c of hist.values())total+=c;
    chk(total===13824,name+" all frames");
    distributions[name]=hist;
    stats[name]={histogram:inv.histogram,anchor_colors:inv.anchor_colors,support:hist.size,multiplicity:inv.aut};
  }
  const equalMaps=(a,b)=>a.size===b.size&&[...a].every(([k,v])=>b.get(k)===v);
  const disjoint=(a,b)=>[...a.keys()].every(k=>!b.has(k));
  chk(equalMaps(distributions.ref,distributions.alt),"nontrivial same orbit");
  chk(disjoint(distributions.ref,distributions.pin_mismatch),"anchored color leakage");
  chk(disjoint(distributions.ref,distributions.histogram_mismatch),"histogram leakage");
  chk(equalMaps(distributions.unpinned_ref,distributions.unpinned_alt),"unpinned same orbit");
  // Transparent public semantic decoding negative control.
  let publicBypasses=0;
  for(const u0 of perms.slice(0,4))for(const u1 of perms.slice(0,4))for(const u2 of perms.slice(0,4)){
    const t=transcript(fixtures.ref,u0,u1,u2);
    const g=compose(t.g2,t.g1);
    const y0=g[u0[0]],y1=g[u0[1]];
    chk(y0!==y1,"different true-witness terminal states");
    chk(t.dpub[y0]==="A"&&t.dpub[y1]==="A","same semantic release class");
    const candidates=Array.from({length:d},(_,y)=>t.dpub[y]==="A"?"RUN439-DEMO-SIGNING-CAPABILITY":null);
    chk(candidates.some(v=>v==="RUN439-DEMO-SIGNING-CAPABILITY"),"witness-free output enumeration");
    publicBypasses++;
  }
  return {run:439,checks:assertions,finite_group:"S_4",frame_assignments_per_fixture:13824,
    fixtures:stats,same_distribution:["ref","alt"],disjoint_pairs:[["ref","pin_mismatch"],["ref","histogram_mismatch"]],
    unpinned_same_distribution:["unpinned_ref","unpinned_alt"],
    terminal_decoder_trials:publicBypasses,terminal_decoder_bypasses:publicBypasses,
    demo_only:true,post_quantum_or_witness_kem_security:false};
};
console.log(JSON.stringify(run439(),null,2));
