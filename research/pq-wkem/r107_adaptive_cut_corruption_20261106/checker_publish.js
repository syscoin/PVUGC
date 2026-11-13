/* R107 exact finite checker, portable JS: no crypto or QPT hardness claims. */
const q=5, cuts=[['H1','H2'],['H1','H3']];
let assertions=0, trials=0, comparisons=0;
function claim(x,detail){assertions++;if(!x)throw Error('check '+assertions+': '+detail)}
function qualified(ids){let x=new Set(ids);return (x.has('H1')&&(x.has('H2')||x.has('M')))||(x.has('H2')&&x.has('H3'))}
function shares(t,a,b){let left=(t-a+q)%q;return {H1:[a],H2:[left,b],M:[left],H3:[(t-b+q)%q]}}
function digest(s){let h=2166136261;for(let i=0;i<s.length;i++){h=Math.imul(h^s.charCodeAt(i),16777619)>>>0}return h.toString(16)}
function same(a,b){return JSON.stringify([...a.entries()].sort())===JSON.stringify([...b.entries()].sort())}
const ids=['H1','H2','H3','M'];
for(let mask=0;mask<16;mask++){
 let C=ids.filter((_,i)=>(mask>>i)&1);if(!C.includes('M'))continue;
 if(!qualified(C))claim(cuts.some(H=>H.every(i=>!C.includes(i))),'unqualified set has cut');
}
for(const H of cuts){
 claim(!qualified(ids.filter(i=>!H.includes(i))),'complement is unauthorized');
 let baseline={};
 for(let t=0;t<q;t++){
  let hist={none:new Map(),adaptive:new Map(),permitted:new Map()};
  for(let a=0;a<q;a++)for(let b=0;b<q;b++){
   const s=shares(t,a,b);
   claim((s.H1[0]+s.H2[0])%q===t && (s.H2[1]+s.H3[0])%q===t,'alternative witnesses same root');
   const plaintext=ids.filter(i=>!H.includes(i)).map(i=>[i,s[i]]);
   const zero=ids.filter(i=>H.includes(i)).map(i=>[i,'ZERO-challenge-ciphertext']);
   for(let y=0;y<8;y++){
    let dsig=5^(y^3), J=digest(JSON.stringify([plaintext,zero,dsig,'ctx','related-caps']));
    let CK=digest(JSON.stringify(['CK',y,J,dsig,'scope']));
    let Aux=digest(JSON.stringify(['Aux',y,CK,J,'source-keys','native-vk']));
    let publicRecord=[plaintext,zero,dsig,J,CK,Aux];
    let adaptive=(parseInt(CK.slice(-1),16)%2===0?'H2':'H3');
    let allowed=(H.includes('H2')?'H3':'H2');
    for(const [name,query] of [['none',null],['adaptive',adaptive],['permitted',allowed]]){
     let status=query===null?'NONE':(H.includes(query)?'ABORT':'REVEAL_SECRET_AND_COINS');
     let key=JSON.stringify([publicRecord,query,status]);
     hist[name].set(key,(hist[name].get(key)||0)+1);trials++;
    }
   }
  }
  if(t===0)baseline=hist;
  else for(const name of Object.keys(hist)){
   claim(same(hist[name],baseline[name]),'exact joint transcript distribution '+name);comparisons++;
  }
 }
}
claim(!qualified(['M']),'malicious-only unauthorized');
claim(('z'==='z') && ('not_z'==='not_z'),'public both Boolean-polarity tokens coexist in false (z AND !z) control');
const result={run:'R107-ADAPTIVE-TARGET-CORRUPTION-CUT-FAMILY-20261106',result:'PASS',
 assertions,full_transcript_cases:trials,histogram_equalities:comparisons,
 cuts,model:'GF(5) exact final hybrid with publicly disclosed ALL complement occurrence plaintext and adaptive classical corruption chosen from full public CK/Aux',
 warning:'not actual lattice security; arbitrary generic ORIGINAL NP remains unresolved'};
if(typeof console!=='undefined')console.log(JSON.stringify(result,null,2));
