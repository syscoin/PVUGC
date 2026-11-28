const run = ()=>{
let checks=0, alts=0, decoded=0;
const must=(x)=>{checks++;if(!x)throw Error("assertion "+checks)};
const q=65537,D=32768;
const hash=(s)=>(s*s)%17;
const bits=[1,0,1,1,0,0,1,0];
const secret=bits.map((_,i)=>[1+(i*5)%16,1+(i*9+3)%16]);
const pk=secret.map(pair=>pair.map(hash));
const sig=bits.map((b,i)=>secret[i][b]);
const verify=(candidate)=>candidate.length===bits.length && candidate.every((s,i)=>Number.isInteger(s)&&s>=1&&s<=16&&hash(s)===pk[i][bits[i]]);
must(verify(sig));
let st=0x13572468;
const rand=()=>{st=(Math.imul(st,1664525)+1013904223)>>>0;return st};
const enc=(bit)=>{
const a=rand()%q, e0=(rand()&1)?1:-1,e1=(rand()&1)?1:-1,e2=(rand()&1)?1:-1;
return [(a+D*bit+e0)%q,((q-a)+e1+q)%q,(e2+q)%q];
};
const decode=(c,z0,z1)=>{
const v=(c[0]+c[1]*z0+c[2]*z1)%q;
const distance=x=>Math.min((x%q+q)%q,(-x%q+q)%q);
return distance(v-D)<distance(v)?1:0;
};
for(let scope=0;scope<3;scope++){
const capsules=sig.map(s=>[4,3,2,1,0].map(k=>enc((s>>k)&1)));
for(const w of [[1,0],[1,1]]){
must(w[0]===1);
const opened=capsules.map((cs)=>cs.reduce((acc,c)=>{const b=decode(c,w[0],w[1]);decoded++;return (acc<<1)|b},0));
must(opened.every((s,i)=>s===sig[i]));
must(verify(opened));
}
}
for(let i=0;i<bits.length;i++){
for(let s=1;s<=16;s++){
const changed=s!==sig[i];
if(hash(s)===pk[i][bits[i]]&&changed){
const alt=sig.slice();alt[i]=s;
must(verify(alt)&&alt.some((x,j)=>x!==sig[j]));
must(hash(s)===hash(sig[i])); alts++;
}
}
}
must(alts>0);return {run_id:"R37-PRESIGNED-CAPABILITY-SUF-SPLIT",assertions:checks,decoding_checks:decoded,valid_original_witnesses:2,independent_scopes:3,accepted_alternative_signature_collisions:alts,signature_elements:sig.length,toy_hash:"square mod 17 (INSECURE)",endpoint:"not implemented",hard_true_extraction:"unproved"};
};
console.log(JSON.stringify(run(), null, 2));
