'use strict';
// R103 exact GF(5) monotone-formula test. Toy only; no QPT hardness experiment.
function runR103(){
  const A=['and','A',['or','B',['and','C','D']]],B=['and','E','F'];
  const policies=[['nested',['or',A,B]],['repeated',['or',['and','A','B'],['and','A','C']]]];
  let checks=0,success=0;const counts={tapes:0,privacy:0,reconstruction:0,bindings:0};
  function ok(x,what){checks++;if(!x)throw Error('assertion '+checks+': '+what);}
  function labels(t){return typeof t==='string'?[t]:[...labels(t[1]),...labels(t[2])];}
  function eligible(t,U){if(typeof t==='string')return U.has(t);return t[0]==='and'?(eligible(t[1],U)&&eligible(t[2],U)):(eligible(t[1],U)||eligible(t[2],U));}
  function na(t){return typeof t==='string'?0:(t[0]==='and'?1:0)+na(t[1])+na(t[2]);}
  function dist(t,v,tape,st,path=''){
    if(typeof t==='string')return {[path+':'+t]:{owner:t,value:v}};
    let l,r;if(t[0]==='and'){l=tape[st.i++];r=(v-l+5)%5;}else{l=v;r=v;}
    return {...dist(t[1],l,tape,st,path+'L'),...dist(t[2],r,tape,st,path+'R')};
  }
  function rec(t,shares,U,path=''){
    if(typeof t==='string')return U.has(t)?shares[path+':'+t].value:null;
    const l=rec(t[1],shares,U,path+'L'),r=rec(t[2],shares,U,path+'R');
    if(t[0]==='and')return l!==null&&r!==null?(l+r)%5:null;
    if(l!==null&&r!==null)ok(l===r,'OR path consistent');
    return l===null?r:l;
  }
  for(const [name,t] of policies){
    const names=[...new Set(labels(t))].sort(),nr=na(t);ok(nr===(name==='nested'?3:2),'AND node count');
    const tapes=[];const push=(a)=>{if(a.length===nr){tapes.push(a);return;}for(let i=0;i<5;i++)push([...a,i]);};push([]);
    for(let mask=0;mask<(1<<names.length);mask++){
      const U=new Set(names.filter((_,i)=>(mask>>i)&1)),qual=eligible(t,U),hist=[];
      for(let s=0;s<5;s++){
        const h=new Map();
        for(const tape of tapes){
          const sh=dist(t,s,tape,{i:0}),visible=Object.entries(sh).filter(([k,v])=>U.has(v.owner)).sort().map(([k,v])=>[k,v.value]);
          const key=JSON.stringify(visible);h.set(key,(h.get(key)||0)+1);
          const reconstructed=rec(t,sh,U);
          ok(qual?reconstructed===s:reconstructed===null,'actual reconstruction iff qualifying');
          counts.reconstruction++;counts.tapes++;
        }
        hist.push(JSON.stringify([...h.entries()].sort((a,b)=>a[0].localeCompare(b[0]))));
      }
      for(let s=1;s<5;s++){
        ok(qual?hist[s]!==hist[0]:hist[s]===hist[0],'joint plaintext view privacy and qualified disjointness');
        if(!qual)counts.privacy++;
      }
    }
    success++;
  }
  // Only a toy dependency check: rebind joint checking/auxiliary keys after replacing target ciphertext.
  function mix(s){let z=0x811c9dc5;for(const c of s){z^=c.charCodeAt(0);z=Math.imul(z,0x01000193)>>>0;}return z.toString(16);}
  function view(cts,roots){const contexts=['claim:UTXO:1/branch:challenge/slot:0','claim:UTXO:1/branch:challenge/slot:1'];
    const ds=roots.map((r,j)=>mix('mask'+r+contexts[j]));
    const J=mix(JSON.stringify({contexts,cts,ds,source:'shared-A B_i',vk:'preauthorized'}));
    const CK=roots.map((r,j)=>mix('CK'+r+J+ds[j]+contexts[j]));
    const Aux=roots.map((r,j)=>mix('Aux'+r+CK[j]+J+contexts[j]));return {J,CK,Aux};
  }
  const old=view(['LWE-ciphertext-original','related-ct'],['T0','T1']);
  const changed=view(['LWE-ciphertext-challenge','related-ct'],['T0','T1']);
  ok(old.J!==changed.J,'manifest depends on exact challenge ciphertext');
  for(let j=0;j<2;j++){ok(old.CK[j]!==changed.CK[j],'CK dependency');ok(old.Aux[j]!==changed.Aux[j],'Aux dependency');counts.bindings+=2;}
  return {run:'R103-MONOTONE-FORMULA-LWE-SOURCE-20261105',status:'RESTRICTED_NONTHRESHOLD_RELEASE_NOT_GENERIC_NP',checks,counts,policies:success,
    caveat:'GF(5) privacy; toy hash dependency; not QPT security or arbitrary original NP extraction'};
}
console.log(JSON.stringify(runR103(),null,2));
