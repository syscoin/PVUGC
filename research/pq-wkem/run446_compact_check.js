const run446CompactCheck = function run446CompactCheck() {
  let assertions = 0;
  const check = (v, label) => {assertions++; if(!v) throw Error("Run446 compact: "+label);};
  const f = s => ((73*s + 29) & 255); // Toy permutation, EASY to invert; not a cryptographic OWF
  const originals = [3,7,11];
  const capsules = [17,70,123,176].map((s,i)=>({
    index:i, context:"UTXO-"+i+"/disprove", s, y:f(s), k:(37*i+41)&255
  }));
  const originalValid = (truth,w) => truth && originals.includes(w);
  const accept = (truth,tag,w,y) =>
    (tag===0 && originalValid(truth,w)) || (tag===1 && f(w)===y);
  const release = (truth,tag,w,c) =>
    accept(truth,tag,w,c.y) ? c.k : null;
  const results=[];
  for (const c of capsules) {
    let planted=0;
    for(let w=0;w<256;w++) {
      check(!originalValid(false,w),"false ORIGINAL source");
      check(!accept(false,0,w,c.y),"base false acceptance");
      check(accept(false,1,w,c.y)===(w===c.s),"grafted proof is unique");
      if(accept(false,1,w,c.y))planted++;
    }
    check(planted===1,"single grafted false proof");
    check(release(false,1,c.s,c)===c.k,"false gated program differs from zero");
    check(release(false,0,c.s,c)===null,"base false gate rejects");
    for(const w of originals) {
      check(accept(true,0,w,c.y),"valid original proof");
      check(release(true,0,w,c)===c.k,"same K for every valid witness");
    }
    const publicCheckKey=(43*c.k+17)&255; // Toy public correlation, not native crypto
    check(publicCheckKey===((43*release(false,1,c.s,c)+17)&255),"public checking-key relation");
    results.push({context:c.context, valid_original_on_false:0, planted_false_proofs:planted,
      valid_original_on_true:originals.length, same_capability_for_valid_originals:true,
      false_case_release_nonconstant:true});
  }
  for(let i=0;i<capsules.length;i++)for(let j=0;j<capsules.length;j++){
    if(i===j)continue;
    check(!accept(false,1,capsules[i].s,capsules[j].y),"cross-capsule proof replay");
  }
  return {run:446, assertions, finite_domain:256, capsules:results,
    toy_permutation_one_way:false,
    honest_setup_model:"classical", qpt_hardness_established:false,
    iO_implemented:false, actual_wkem:false,
    meaning:"Exact finite witness to proof-verifier extensional non-equivalence; no practical attack"};
};
console.log(JSON.stringify(run446CompactCheck(),null,2));
