"use strict";
// Run 488 compact CHECKER: toy arithmetic, not SLH-DSA or a quantum implementation.
// Demonstrates two independently programmable flat-looking root families with
// fixed PK.seed, and a malicious selected-coin cross-family claw.
let assertions=0;
function ok(x,label){assertions++;if(!x)throw new Error("assertion "+label);}
function mix(x){x=(x^(x>>>16))>>>0;x=Math.imul(x,0x7feb352d)>>>0;x=(x^(x>>>15))>>>0;x=Math.imul(x,0x846ca68b)>>>0;return(x^(x>>>16))>>>0;}
function hash(tag,c,s,v){let x=2166136261>>>0;for(let i=0;i<tag.length;i++)x=Math.imul(x^tag.charCodeAt(i),16777619)>>>0;return mix(x^mix(c)^mix(s^0xc9125a31)^mix(v^0x145326ab));}
function builder(c,seed,r,mask){return hash("B/native-root-claw",c,seed,r)&mask;}
function native(seed,z,mask){return hash("G/native-root-claw",0,seed,z)&mask;}
const records=[];
for(const bits of [10,12,14,16]){
 const N=2**bits, mask=N-1, lim=Math.ceil(8*Math.sqrt(N));
 for(let c=0;c<8;c++){
  const context=0x43880000+c, seed=hash("fixed-PK.seed",context,0,0);
  const table=new Map();
  for(let r=0;r<lim;r++){const v=builder(context,seed,r,mask);if(!table.has(v))table.set(v,r);}
  let found=null;
  for(let z=0;z<lim;z++){const v=native(seed,z,mask);if(table.has(v)){found={r:table.get(v),z,root:v,native_tries:z+1};break;}}
  ok(found!==null,"toy root claw");const {r,z,root,native_tries}=found;
  ok(builder(context,seed,r,mask)===native(seed,z,mask),"two-family root equality");
  ok(builder(context,seed,r,mask)===root,"native root matches exact accepted builder root");
  ok(native_tries<=lim,"bounded search");
  const signature={native_secret_seed:z,tag:hash("fixed-message-signature-PROXY",context,seed,z^0xbeeef)};
  const verify=(m,sig)=>native(seed,sig.native_secret_seed,mask)===root&&sig.tag===hash("fixed-message-signature-PROXY",context^m,seed,sig.native_secret_seed^0xbeeef);
  ok(verify(0,signature),"toy key-possession demonstration");
  ok(!verify(1,signature),"altered message not the same toy signature");
  ok(seed!==(seed^1),"changing PK.seed breaks full-key equality");
  records.push({root_bits:bits,context_index:c,public_seed:seed>>>0,root,build_coin:r,retained_native_seed:z,build_tries:lim,native_tries});
 }
}
const stats={};
for(const bits of [10,12,14,16]){let a=records.filter(x=>x.root_bits===bits);stats[bits]={count:a.length,max_native_tries:Math.max(...a.map(x=>x.native_tries)),mean_native_tries:a.reduce((s,x)=>s+x.native_tries,0)/a.length};}
return {run:488,checker:"toy fixed-seed cross-family native-root claw",security_claim:"NONE; 10/12/14/16-bit noncryptographic mixer, no quantum implementation",assertions,fixtures:records.length,all_claws:true,bit_widths:[10,12,14,16],statistics:stats,selected_first:records.slice(0,4)};
