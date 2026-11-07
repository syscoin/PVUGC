"use strict";
function main(){
  let assertions=0;
  const check=(c,s)=>{assertions++;if(!c)throw Error(s);};
  const N=256,perm=z=>(197*z+17)%N;
  const vals=Array.from({length:N},(_,z)=>perm(z));
  check(new Set(vals).size===N,"bijective toy map");
  const inv=new Map(vals.map((y,z)=>[y,z]));
  let ct=0,cf=0,same=0,leak=0;
  for(let b=0;b<2;b++)for(let y=0;y<N;y++){
    const key=(53*y+71)%N;
    const pkg={b,y,vk:(7*key+19)%257,field:b===1?key:null};
    check(pkg.vk===(7*key+19)%257,"faithful setup relation");
    check(pkg.field===(b===1?key:null),"approved-release field");
    const R=(w)=>b===1 && perm(w[0])===y && w[1]>=0 && w[1]<4;
    const open=w=>R(w)?pkg.field:null;
    if(b===1){
      ct++;
      for(let t=0;t<4;t++){
        check(R([inv.get(y),t]),"true witness");
        check(open([inv.get(y),t])===key,"same key");
        same++;
      }
      check(pkg.field===key,"public leak no witness");
      leak++;
    }else{
      cf++;
      for(let t=0;t<4;t++){
        check(!R([inv.get(y),t]),"false source");
        check(open([inv.get(y),t])===null,"false open rejected");
      }
      check(pkg.field===null,"false key omitted");
    }
  }
  check(ct===256 && cf===256 && same===1024 && leak===256,"census");
  return {run:496,assertions,contexts:512,true_contexts:ct,false_contexts:cf,
   valid_witness_same_key_releases:same,public_true_key_exposure_without_witness:leak,
   false_public_secret_omitted:cf,toy_map_bijection:true,
   limitations:"Toy affine permutation/public-key arithmetic only; NO QPT hardness, ZK implementation, PQ signing, mixer, or WKEM."};
}
if(typeof module!=="undefined" && require.main===module)
 process.stdout.write(JSON.stringify(main(),null,2)+"\n");
