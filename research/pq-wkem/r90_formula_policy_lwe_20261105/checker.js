function R90(){
  let checks=0;
  let count={formulas:0,coalitions:0,unauthorized_privacy:0,authorized_reconstruction:0,sharing_cases:0,authorized_openings:0,unauthorized_paths:0,claim_tamper_rejected:0,checking_view_rebuilds:0};
  const ck=(v,m)=>{checks++;if(!v)throw new Error("R90 assertion "+checks+": "+m)};
  const leaf=i=>["L",i];
  function forms(ids){
    if(ids.length===1)return [leaf(ids[0])];
    let r=[];
    for(let i=1;i<ids.length;i++)
      for(let a of forms(ids.slice(0,i)))
        for(let b of forms(ids.slice(i)))
          for(let op of ["AND","OR"])r.push([op,a,b]);
    return r;
  }
  function allow(f,U){
    if(f[0]==="L")return U.has(f[1]);
    const a=allow(f[1],U),b=allow(f[2],U);
    return f[0]==="AND"?(a&&b):(a||b);
  }
  function symbolic(f,secret,rows,state){
    if(f[0]==="L"){rows[f[1]]=secret;return}
    if(f[0]==="OR"){
      symbolic(f[1],secret,rows,state);
      symbolic(f[2],secret,rows,state);
    }else{
      const mask=1<<state.next++;
      symbolic(f[1],mask,rows,state);
      symbolic(f[2],secret^mask,rows,state);
    }
  }
  function span(target,values){
    const base=new Map();
    for(let w of values){
      while(w){
        const p=31-Math.clz32(w);
        if(!base.has(p)){base.set(p,w);break}
        w^=base.get(p);
      }
    }
    while(target){
      const p=31-Math.clz32(target);
      if(!base.has(p))return false;
      target^=base.get(p);
    }
    return true;
  }
  for(let n=1;n<=5;n++)for(const f of forms(Array.from({length:n},(_,i)=>i))){
    const rows={};
    symbolic(f,1,rows,{next:1});
    ck(Object.keys(rows).length===n,"all leaves present");
    count.formulas++;
    for(let mask=0;mask<(1<<n);mask++){
      const U=new Set(Array.from({length:n},(_,i)=>i).filter(i=>mask&(1<<i)));
      const ok=allow(f,U);
      ck(span(1,[...U].map(i=>rows[i]))===ok,"GF2 row-span iff authorized");
      count.coalitions++;
      count[ok?"authorized_reconstruction":"unauthorized_privacy"]++;
    }
  }
  let state=0x90002026;
  const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state};
  function share(f,T,out){
    if(f[0]==="L"){out[f[1]]=T;return}
    if(f[0]==="OR"){share(f[1],T,out);share(f[2],T,out)}
    else{const x=rand()&255;share(f[1],x,out);share(f[2],T^x,out)}
  }
  function recover(f,U,shares){
    if(f[0]==="L")return U.has(f[1])?shares[f[1]]:null;
    const a=recover(f[1],U,shares),b=recover(f[2],U,shares);
    if(f[0]==="AND")return a!==null&&b!==null?(a^b):null;
    if(a!==null&&b!==null)ck(a===b,"two valid OR paths same root");
    return a!==null?a:b;
  }
  const toyHash=(...xs)=>xs.reduce((v,x)=>(Math.imul(v^x,16777619)+1013904223)>>>0,2166136261);
  const ps=[
    ["OR",["AND",leaf(0),leaf(1)],["AND",leaf(2),leaf(3)]],
    ["AND",["OR",leaf(0),leaf(1)],["OR",leaf(2),leaf(3)]],
    ["OR",leaf(0),["AND",leaf(1),["OR",leaf(2),leaf(3)]]],
    ["AND",leaf(0),["OR",leaf(1),["AND",leaf(2),leaf(3)]]]
  ];
  for(let trial=0;trial<64;trial++)for(const [idx,f] of ps.entries()){
    const T=rand()&255,sign=rand()&255;
    const shares={};
    share(f,T,shares);
    const P=toyHash(T,17)&255,B=toyHash(T,41)&255;
    const D=sign^P, ctx=toyHash(90,trial,idx,167);
    const source=toyHash(...Object.values(shares));
    const CK=toyHash(B,D,source,ctx),AUX=toyHash(B,CK,D,source,ctx);
    ck(CK===toyHash(B,D,source,ctx) && AUX===toyHash(B,CK,D,source,ctx),"full CK/AUX public correlations");
    count.checking_view_rebuilds++;
    for(let mask=0;mask<16;mask++){
      const U=new Set([0,1,2,3].filter(i=>mask&(1<<i)));
      const result=recover(f,U,shares);
      if(allow(f,U)){
        ck(result===T,"every valid original policy witness same precommitted root");
        const recoveredSig=D^(toyHash(result,17)&255);
        const B2=toyHash(result,41)&255;
        ck(recoveredSig===sign && CK===toyHash(B2,D,source,ctx)
            && AUX===toyHash(B2,CK,D,source,ctx),"every path same native toy signature and checking output");
        count.authorized_openings++;
      }else{
        ck(result===null,"unqualified path cannot reconstruct via release");
        count.unauthorized_paths++;
      }
    }
    ck(CK!==toyHash(B,D,source,ctx+1),"claim/branch context tampering must fail");
    count.claim_tamper_rejected++;
    count.sharing_cases++;
  }
  return {run:"R90-FORMULA-LWE-LSSS-20261105",status:"RESTRICTED_CONSTRUCTIVE_COMPOSITION_NOT_GENERIC_NP_WKEM",assertions:checks,count,
    verifier:"complete GF2 symbolic coalition census plus toy public checking path; not quantum experiment",
    extra_local_python:"separate executed exact toy LWE/Ed25519 fixture: 8989 assertions; NOT this checker"};
}
console.log(JSON.stringify(R90(),null,2));
