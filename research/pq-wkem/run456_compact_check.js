"use strict";
function run456Compact(){
  "use strict";
  let checks=0;
  function check(p,msg){checks++;if(!p)throw Error(msg);}
  function pub(s,c){
    let x=(s^c)>>>0;
    x=Math.imul(x^(x>>>16),0x7feb352d)>>>0;
    x=Math.imul(x^(x>>>15),0x846ca68b)>>>0;
    return (x^(x>>>16))>>>0;
  }
  const single=[];
  for(let bits=4;bits<=10;bits++){
    const n=2**bits,root=(37*bits+17)%n,c=0x13579bdf;
    const vk=pub(root,c);
    const marked=[];
    for(let s=0;s<n;s++)if(pub(s,c)===vk)marked.push(s);
    check(marked.length===1,"toy permutation uniqueness");
    check(marked[0]===root,"actual seed marked");
    check(pub(root,c)!==pub(root,c^0x77777777),"cross-context keys");
    single.push({bits,candidates:n,marked:marked.length,generic_quantum_query_scale:Math.sqrt(n)});
  }
  const coherent=[];
  for(let bits=4;bits<=8;bits++){
    const n=2**bits,root=(7*bits+3)%n,c=0x10203040,target=pub(root,c);
    const a=Array(n).fill(1/Math.sqrt(n));
    const theta=Math.asin(1/Math.sqrt(n));
    const record=[];
    for(let k=0;k<Math.min(12,Math.floor(1.3*Math.sqrt(n)));k++){
      const p=a[root]**2;
      check(Math.abs(p-Math.sin((2*k+1)*theta)**2)<1e-10,"coherent amplitude");
      if(k===0||k===1||k===2||k===4||k===8)record.push({iterations:k,success:Number(p.toFixed(12))});
      for(let s=0;s<n;s++)if(pub(s,c)===target)a[s]=-a[s];
      const avg=a.reduce((u,v)=>u+v,0)/n;
      for(let s=0;s<n;s++)a[s]=2*avg-a[s];
    }
    coherent.push({bits,marked:root,trace:record});
  }
  const multi=[];
  const seeds=[7,23,49,79,113,151,193,239],bits=9,n=2**bits,c=0x44556677;
  for(const t of [1,2,4,8]){
    const targets=new Set(seeds.slice(0,t).map(s=>pub(s,c)));
    check(targets.size===t,"unique target checking keys");
    const found=[];
    for(let s=0;s<n;s++)if(targets.has(pub(s,c)))found.push(s);
    check(found.length===t,"multi-target marked count");
    check(found.every(s=>seeds.slice(0,t).includes(s)),"multi-target identity");
    multi.push({targets:t,marked:t,generic_quantum_query_scale:Number(Math.sqrt(n/t).toFixed(12))});
  }
  return {run:456,diagnostic:"toy bijective public-key map, not cryptographic",assertions:checks,single_master:single,coherent_statevector:coherent,independent_targets:multi,claim:"public checking keys enable coherent candidate-seed search; tests do not prove PQ security"};
}
console.log(JSON.stringify(run456Compact(),null,2));
