function run484compact(){
  function H(s){let h=2166136261;for(let i=0;i<s.length;i++)h=Math.imul(h^s.charCodeAt(i),16777619);return h&65535;}
  function leaf(ctx,i,v){return H("L484|"+ctx+"|"+i+"|"+v);}
  function pair(a,b){return H("N484|"+a+"|"+b);}
  function merkle(ctx,w,s){let L=[leaf(ctx,0,w[0]),leaf(ctx,1,w[1]),leaf(ctx,2,w[2]),leaf(ctx,3,s)],P=[pair(L[0],L[1]),pair(L[2],L[3])],R=pair(P[0],P[1]);return{root:R,salt:s,open(i){return{i,value:w[i],sib:[L[i^1],P[(i>>1)^1]]}},P};}
  function check(ctx,R,o){let i=o.i,y=leaf(ctx,i,o.value);for(let j of o.sib){y=i&1?pair(j,y):pair(y,j);i>>=1;}return y===R;}
  function admit(ctx,R,a,b){let aa=a.open(0),au=a.open(1),bb=b.open(0),bu=b.open(1),bv=b.open(2);return[aa,au,bb,bu,bv].every(o=>check(ctx,R,o))&&au.value===1-aa.value&&bv.value===(bb.value&bu.value)&&bv.value===1;}
  let count=0, found=[];
  for(let j=0;j<4;j++){let ctx="Run484|claim="+j+"|branch=disprove|same_anchor",A=[0,1,1],B=[1,1,1],t=new Map(),a,b;
    for(let i=0;i<1024;i++){let r=merkle(ctx,A,i);if(!t.has(r.root))t.set(r.root,i);}
    for(let i=0;i<1024;i++){let r=merkle(ctx,B,i);if(t.has(r.root)){a=merkle(ctx,A,t.get(r.root));b=r;break;}}
    if(!a||!b)throw Error("claw not found "+j);
    function ok(x){count++;if(!x)throw Error("failed "+j+" "+count);}
    ok(a.root===b.root);ok(a.P[0]!==b.P[0]||a.P[1]!==b.P[1]);ok(admit(ctx,a.root,a,b));ok(!admit(ctx+"|other",a.root,a,b));
    ok(!(A[1]===1-A[0]&&A[2]===(A[0]&A[1])&&A[2]===1));ok(!(B[1]===1-B[0]&&B[2]===(B[0]&B[1])&&B[2]===1));
    found.push({claim:j,saltA:a.salt,saltB:b.salt,shared_root:a.root,hybrid_accepted:true});
  }
  return {run:484,status:"PASS",assertions:count,toy_digest_bits:16,cases:found,scope:"toy classical chosen-root collisions; conditional quantum query analysis only"};
}
console.log(JSON.stringify(run484compact(),null,2));
