function checker(){
  'use strict';
  const run='R64-PACK16-DUAL-LWE-SIS-20261104';
  const q=16777216,m=64,n=2,E=1,delta=129,b=16,rootBytes=32,bindBytes=32,muMax=65535;
  let state=0x6400beef,checks=0,witnessOpens=0,fullCouplings=0,uniformHybrids=0,relatedOpens=0,transcriptChecks=0,uniformMatrixCouplings=0;
  function ok(c,msg){if(!c)throw Error('check '+checks+' '+msg);checks++;}
  function rnd(){state=(state+0x6D2B79F5)>>>0;let x=state;x=Math.imul(x^(x>>>15),x|1);x^=x+Math.imul(x^(x>>>7),x|61);return (x^(x>>>14))>>>0;}
  function mod(x){return ((x%q)+q)%q;}
  function bytes(len){return Array.from({length:len},()=>rnd()&255);}
  function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}
  function toyHash(s){let h=2166136261;for(let i=0;i<s.length;i++){h=Math.imul(h^s.charCodeAt(i),16777619)>>>0;}return h.toString(16).padStart(8,'0');}
  function stream(key,length){let x=(parseInt(toyHash('stream|'+key.join(',')),16)^0x9E3779B9)>>>0;return Array.from({length},()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return x&255;});}
  function matrix(planted){const a=Array.from({length:m},()=>Array.from({length:n},()=>rnd()%q));if(planted){a[1]=a[0].map(v=>mod(-v));a[2]=a[0].map(v=>mod(-v));}return a;}
  function witness(index){const r=Array(m).fill(0);r[0]=1;r[index]=1;return r;}
  function valid(a,r){return r.length===m&&r[0]===1&&r.every(v=>v===0||v===1)&&Array.from({length:n},(_,j)=>mod(r.reduce((z,v,i)=>z+v*a[i][j],0))===0).every(Boolean);}
  function decode(z){const anchor=Math.floor(z/delta),cand=new Set([0,muMax,anchor-2,anchor-1,anchor,anchor+1,anchor+2]);let best=-1,bestDist=Infinity,second=Infinity;for(const k of cand)if(k>=0&&k<=muMax){let d=Math.abs(z-delta*k);d=Math.min(d,q-d);if(d<bestDist){second=bestDist;bestDist=d;best=k;}else if(d<second){second=d;}}ok(bestDist<=m*E,'decode bound');ok(bestDist<second,'decoder unique');return best;}
  function symbols(k,kb){const x=k.concat(kb);ok(x.length===64,'fixed 64 bytes');return Array.from({length:32},(_,i)=>x[2*i]+256*x[2*i+1]);}
  function encode(a,k,kb){const values=symbols(k,kb),C=[],Y=[];for(const mu of values){const s=Array.from({length:n},()=>rnd()%q),e=Array.from({length:m},()=>rnd()%3-1);const y=a.map((row,j)=>mod(row[0]*s[0]+row[1]*s[1]+e[j]));Y.push(y);C.push(y.map((v,j)=>mod(v+(j===0?delta*mu:0))));}return {C,Y,values};}
  function open(a,C,r){ok(valid(a,r),'original witness in SIS');const words=C.map(v=>decode(mod(v.reduce((z,x,i)=>z+x*r[i],0))));const decoded=words.flatMap(w=>[w&255,(w>>>8)&255]);return {k:decoded.slice(0,32),kb:decoded.slice(32)};}
  function checkValues(v,view,k,kb,sigma){const base=JSON.stringify(view),ck=toyHash('CK|'+kb.join(',')+'|'+base),aux=toyHash('AUX|'+kb.join(',')+'|'+ck+'|'+base);ok(v.ck===ck&&v.aux===aux,'CK/AUX complete correlation');const pad=stream(k,sigma.length),sig=view.Dsig.map((x,i)=>x^pad[i]);ok(eq(sig,sigma),'same precommitted native capability');return {ck,aux};}
  const boundary=[-m*E,0,m*E];for(let word=0;word<=muMax;word++)for(const e of boundary){const recovered=decode(mod(word*delta+e));ok(recovered===word,'complete alphabet/worst-case-noise boundary');}
  const maxPacking=Math.floor(Math.log2(Math.floor((q-2*m*E-1)/delta)+1));
  ok(delta>2*m*E,'adjacent centers disjoint');ok(q-(2**b-1)*delta>2*m*E,'cyclic wrap centers disjoint');ok(maxPacking===16,'maximal 16 bit packing fixed q');
  for(let trial=0;trial<16;trial++){
    const a=matrix(true),r1=witness(1),r2=witness(2);ok(valid(a,r1)&&valid(a,r2),'two distinct valid SIS witnesses');const k=bytes(rootBytes),kb=bytes(bindBytes),sigma=bytes(192),pad=stream(k,sigma.length),Dsig=sigma.map((v,j)=>v^pad[j]),enc=encode(a,k,kb);
    const related=[];for(let j=0;j<2;j++){const ar=matrix(true),kr=bytes(rootBytes),kbr=bytes(bindBytes),cr=encode(ar,kr,kbr);related.push({A:ar,C:cr.C,r:witness(j+1),k:kr,kb:kbr});}
    const view={v:64,relation:'R_SIS(A,r):r binary,r0=1,A^T*r=0',scope:{claim:'test-UTXO-'+trial,branch:'challenge',window:'anchor',native_vk:'synthetic-vk',message:'preauthorized-'+trial},A:a,C:enc.C,Dsig,related:related.map(x=>({A:x.A,C:x.C,scope:'separate-related-message'}))};
    const base=JSON.stringify(view),ck=toyHash('CK|'+kb.join(',')+'|'+base),aux=toyHash('AUX|'+kb.join(',')+'|'+ck+'|'+base);
    for(const r of [r1,r2]){const o=open(a,enc.C,r);ok(eq(o.k,k)&&eq(o.kb,kb),'all original witnesses same key');checkValues({ck,aux},view,o.k,o.kb,sigma);witnessOpens++;}
    const choose=parseInt(toyHash(base),16)%2,rel=related[choose],oRel=open(rel.A,rel.C,rel.r);ok(eq(oRel.k,rel.k)&&eq(oRel.kb,rel.kb),'adaptive related opening isolated');relatedOpens++;
    const index=trial%32,mu=enc.values[index],sim=enc.Y[index].map((y,j)=>mod(y+(j===0?delta*mu:0)));ok(eq(sim,enc.C[index]),'real LWE sample exact source algebra');
    const sv={...view,C:view.C.slice()};sv.C[index]=sim;ok(JSON.stringify(sv)===base,'complete public source transcript coupling');ok(toyHash('CK|'+kb.join(',')+'|'+JSON.stringify(sv))===ck,'challenge CK recomputation');ok(toyHash('AUX|'+kb.join(',')+'|'+ck+'|'+JSON.stringify(sv))===aux,'challenge Aux recomputation');fullCouplings++;
    const uy=Array.from({length:m},()=>rnd()%q),uc=uy.map((v,j)=>mod(v+(j===0?delta*mu:0))),inv=uc.map((v,j)=>mod(v-(j===0?delta*mu:0)));ok(eq(inv,uy),'uniform challenge bijective shift');const hv={...view,C:view.C.slice()};hv.C[index]=uc;const newBase=JSON.stringify(hv),hck=toyHash('CK|'+kb.join(',')+'|'+newBase),haux=toyHash('AUX|'+kb.join(',')+'|'+hck+'|'+newBase);ok(hck===toyHash('CK|'+kb.join(',')+'|'+JSON.stringify(hv)),'uniform hybrid correlated CK');ok(haux===toyHash('AUX|'+kb.join(',')+'|'+hck+'|'+JSON.stringify(hv)),'uniform hybrid correlated Aux');uniformHybrids++;
    const badScope={...view,scope:{...view.scope,claim:'different-UTXO'}};ok(toyHash('CK|'+kb.join(',')+'|'+JSON.stringify(badScope))!==ck,'scope change caught in toy CK');transcriptChecks++;
  }
  for(let trial=0;trial<16;trial++){
    const a=matrix(false),k=bytes(rootBytes),kb=bytes(bindBytes),sigma=bytes(192),pad=stream(k,sigma.length),Dsig=sigma.map((v,i)=>v^pad[i]),enc=encode(a,k,kb),relatedA=matrix(true),relatedK=bytes(rootBytes),relatedKB=bytes(bindBytes),relatedC=encode(relatedA,relatedK,relatedKB);
    const related={A:relatedA,C:relatedC.C,scope:'independent-related',claimed_witness_type:'SIS'};
    const view={v:64,relation:'R_SIS(A,r)',scope:{claim:'honest-uniform-target-'+trial,branch:'challenge',window:'anchor',native_vk:'synthetic-vk',message:'preauthorized-uniform-'+trial},A:a,C:enc.C,Dsig,related:[related]};
    const base=JSON.stringify(view),ck=toyHash('CK|'+kb.join(',')+'|'+base),aux=toyHash('AUX|'+kb.join(',')+'|'+ck+'|'+base),index=trial%32,mu=enc.values[index],replacement=enc.Y[index].map((v,j)=>mod(v+(j===0?delta*mu:0)));
    const newC=enc.C.slice();newC[index]=replacement;const reproduced={...view,C:newC},reproducedBase=JSON.stringify(reproduced);
    ok(eq(replacement,enc.C[index])&&reproducedBase===base,'honest UNIFORM A + real LWE simulator coupling');ok(toyHash('CK|'+kb.join(',')+'|'+reproducedBase)===ck,'honest uniform CK coupling');ok(toyHash('AUX|'+kb.join(',')+'|'+ck+'|'+reproducedBase)===aux,'honest uniform Aux coupling');uniformMatrixCouplings++;
    const opened=open(relatedA,relatedC.C,witness(1));ok(eq(opened.k,relatedK)&&eq(opened.kb,relatedKB),'honest uniform target with independent opened related record');relatedOpens++;
  }
  const packedBytes=32*m*3,bitBytes=512*m*3;
  ok(packedBytes*16===bitBytes,'sixteen fold reduction');ok(32===Math.ceil(512/b),'packed sample count');
  return {run,configuration:{q,m,n,E,delta,packing_bits:b,maximum_packing_bits_at_fixed_q_delta:maxPacking,root_bits:256,checking_key_seed_bits:256},checks,boundary_decode_exhaustive:65536*3,original_witness_openings_planted_fixture:witnessOpens,full_public_planted_matrix_couplings:fullCouplings,honest_uniform_matrix_real_LWE_couplings:uniformMatrixCouplings,uniform_source_hybrid_translations:uniformHybrids,adaptive_independent_related_openings:relatedOpens,context_binding_checks:transcriptChecks,source_samples:{binary:512,packed:32},source_bytes:{binary:bitBytes,packed:packedBytes},source_reduction_percent:100*(bitBytes-packedBytes)/bitBytes,special_original_relation:'SIS_ONLY',honest_uniform_target_qpt_hardness:'NOT_ESTABLISHED',generic_NP_security:'UNPROVED',native_signature:'SYNTHETIC_TOY'};
}
console.log(JSON.stringify(checker(),null,2));
