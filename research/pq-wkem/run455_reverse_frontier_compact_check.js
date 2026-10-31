// Run 455 compact independently executable finite proof check (Node >=18).
// Source model: reversible permutation PUBLIC; terminal only releases on public tag.
(function(){
 let checks=0;const ok=(v,m)=>{checks++;if(!v)throw Error(m)};
 let state=0x9e3779b9;
 const rnd=()=>{state^=state<<13;state^=state>>>17;state^=state<<5;return state>>>0};
 function gates(n){const out=[];for(let k=0;k<5*n;k++){
 const t=k%3,a=rnd()%n;let b=rnd()%(n-1);if(b>=a)b++;
 let c=0;if(t===2){const z=[];for(let j=0;j<n;j++)if(j!==a&&j!==b)z.push(j);c=z[rnd()%z.length]}
 out.push([t,a,b,c])}return out}
 function apply(x,g,back){const seq=back?[...g].reverse():g;
 for(const [t,a,b,c] of seq){let A=BigInt(a),B=BigInt(b),C=BigInt(c);
 if(t===0)x^=1n<<A;
 else if(t===1){if((x>>A)&1n)x^=1n<<B}
 else if(((x>>A)&1n)&&((x>>B)&1n))x^=1n<<C}
 return x}
 const cases=[];
 for(const n of [16,32,64,320]){
  const g=gates(n),tag=((1n<<BigInt(n-8))-1n)^0x23n,leaf='OPAQUE_BRANCH_LEAF_'+n;
  const rel=s=>(apply(s,g,false)>>8n)===tag?leaf:null;
  const enc=(x,w)=>x==='TRUE'&&w>=0&&w<16&&w%2===0?
    apply((tag<<8n)|BigInt(w),g,true):null;
  const seen=new Set();
  for(let w=0;w<16;w++){
   if(w%2){ok(enc('TRUE',w)===null,'invalid source');continue}
   const s=enc('TRUE',w);seen.add(s.toString());
   ok(rel(s)===leaf,'same leaf');ok(enc('FALSE',w)===null,'false source empty')}
  ok(seen.size===8,'eight distinct witness states');
  for(let j=0;j<30;j++){let z=(BigInt(rnd())<<BigInt(n-32<0?0:n-32)) & ((1n<<BigInt(n))-1n);
   ok(apply(apply(z,g,false),g,true)===z,'public inverse')}
  const target=(tag<<8n)|231n, forged=apply(target,g,true);
  ok(apply(forged,g,false)===target,'reverse targeting');
  ok(rel(forged)===leaf,'release with no false original witness');
  cases.push({bits:n,public_gates:g.length,distinct_honest_states:8,
   false_witnesses:0,accepted_false_frontier:true,
   acceptance_density:'2^-'+(n-8),generic_grover_query_exponent:(n-8)/2,
   structured_attack_terminal_calls:1});
 }
 return {run:455,assertions:checks,claim:'only public-permutation seam falsified; no PQ security',cases};
})()
