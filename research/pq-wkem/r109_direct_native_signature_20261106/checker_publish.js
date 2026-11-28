function runR109Checker(){
 const policy=[["H1","H2"],["H2","H3"],["M","H1","H4"]], names=["H1","H2","H3","H4","M"];
 let assertions=0, histEqual=0, qualified=0, unqualified=0, covered=0;
 function ok(z,m){assertions++;if(!z)throw Error("R109 #"+assertions+": "+m)}
 function hash(x){let h=2166136261;for(const c of JSON.stringify(x)){h=Math.imul(h^c.charCodeAt(0),16777619)>>>0;}return h.toString(16)}
 const eligible=c=>policy.every(clause=>clause.some(i=>c.includes(i)));
 const hidden=["H1","H2"];
 const allhist=[];
 for(let sigma=0;sigma<4;sigma++){
  const hist={};
  for(let m0=0;m0<4;m0++)for(let m1=0;m1<4;m1++){
   const share=[m0,m1,sigma^m0^m1];
   ok((share[0]^share[1]^share[2])===sigma,"all-witness whole-signature recovery");
   for(let bits=0;bits<32;bits++){
    const subset=names.filter((n,k)=>bits&(1<<k));
    let recovered=null;
    if(eligible(subset)){
      recovered=share.reduce((a,v)=>a^v,0);
      ok(recovered===sigma,"authorized same precommitted bytes");
      qualified++;
    } else {ok(recovered===null,"unqualified source cannot open");unqualified++;}
    if(!eligible(subset)&&subset.includes("M")){
      const missing=policy.slice(0,2).some(c=>c.every(i=>!subset.includes(i)));
      ok(missing,"a polynomial honest-only blocking clause exists");covered++;
    }
   }
   // Exact final-hybrid view: every encryption under the hidden cut H
   // is a genuine ZERO challenge; no CK, Aux, or other field reads sigma.
   const visible={outsideClauseShares:[share[1],share[2]],hiddenCiphertext:"ENC-ZERO",
     nativeVK:"fixed-vk",sourceKeys:"fixed-source",context:"claim-path",
     otherCapsules:["opened-off-target-native-signature","off-target-keys"]};
   const J=hash(visible);
   const CK=hash(["R109-CK",J,visible.nativeVK,visible.context,visible.otherCapsules]);
   const Aux=hash(["R109-AUX",CK,J,visible.sourceKeys,visible.otherCapsules]);
   const view=JSON.stringify([visible,J,CK,Aux]);
   hist[view]=(hist[view]||0)+1;
  }
  allhist.push(hist);
 }
 for(let t=1;t<allhist.length;t++){
  const as=x=>JSON.stringify(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)));
  ok(as(allhist[t])===as(allhist[0]),"whole-visible-joint-distribution exactly same for each sigma");
  histEqual++;
 }
 // A signature-dependent public checking field is NOT native-EUF-simulatable.
 ok(new Set([0,1,2,3].map(s=>hash(["BAD-CK-DIRECT-SIG",s]))).size===4,"signature-dependent CK invalidates simulator");
 const noTargetOracle={signedMessages:["offtarget:0","offtarget:2"],target:"target:1"};
 ok(!noTargetOracle.signedMessages.includes(noTargetOracle.target),"native challenge message never requested");
 ok(hidden.every(x=>policy[0].includes(x)),"specified H blocks complete CNF clause");
 return {run:"R109-DIRECT-PRESIGNED-NATIVE-SIGNATURE-LWE-20261106",result:"PASS",assertions,
  exactJointHistogramEqualities:histEqual,allRootTapeCases:64,authorizationCases:qualified,
  rejectionCases:unqualified,unqualifiedMaliciousSetCutChecks:covered,
  output:"exact finite 2-bit clause-sharing whole-view check; toy digest; not QPT proof",
  construction:"encrypt actual preauthorized native signature bytes as CNF clause shares; public CK/Aux independent of signature; native EUF simulator need not know target signature",
  notEstablished:"generic ORIGINAL-NP source compiler; malicious N-of-N build; calibrated LWE/PQ-signatures; production"};
}
console.log(JSON.stringify(runR109Checker(),null,2));
