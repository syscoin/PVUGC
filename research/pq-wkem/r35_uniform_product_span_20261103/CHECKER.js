function checker(){
 const rng=(()=>{let v=0x353535; return (n)=>{v=(Math.imul(1664525,v)+1013904223)>>>0;return v%n}})();
 let checks=0;const req=(v,msg)=>{checks++;if(!v)throw Error("Check "+checks+": "+msg)};
 const add=(a,b,q)=>{let o={...a};for(const [k,v] of Object.entries(b)){o[k]=(o[k]||0)+v}for(const k of Object.keys(o)){if(q)o[k]=((o[k]%q)+q)%q;if(!o[k])delete o[k]}return o};
 const mul=(a,b,q)=>{let o={};for(const [k,v] of Object.entries(a))for(const [h,w] of Object.entries(b)){const t=Number(k)|Number(h);o[t]=(o[t]||0)+v*w}for(const k of Object.keys(o)){if(q)o[k]=((o[k]%q)+q)%q;if(!o[k])delete o[k]}return o};
 const scale=(a,z,q)=>{let o={};for(const [k,v] of Object.entries(a)){let t=v*z;if(q)t=((t%q)+q)%q;if(t)o[k]=t}return o};
 const evalp=(a,z,q)=>{let x=Object.entries(a).reduce((s,[k,v])=>((Number(k)&z)===Number(k)?s+v:s),0);return q?((x%q)+q)%q:x};
 const fail=(ids,bad)=>{let f={0:1};for(let i=0;i<ids.length;i++){const j=Number(ids[i]),b=bad[i];f=mul(f,b==="1"?{[1<<j]:1}:{0:1,[1<<j]:-1})}return f};
 const specs=[["013","010"],["012","000"],["013","101"],["013","011"],["023","100"],["013","111"],["123","011"],["023","000"],["123","010"],["012","111"]];
 const f=specs.map(x=>fail(...x));
 for(let z=0;z<16;z++){req(f.some(p=>evalp(p,z)), "all FALSE");for(const p of f)req(evalp(p,z)===0||evalp(p,z)===1,"Boolean failure")};
 const pairs=[],g=[];for(let i=0;i<f.length;i++)for(let j=i;j<f.length;j++){pairs.push([i,j]);g.push(mul(f[i],f[j]))}
 req(g.length===55,"55 public product generators");
 const rank=(polys,q)=>{const a=polys.map(p=>Array.from({length:16},(_,i)=>((p[i]||0)%q+q)%q));let row=0;for(let j=0;j<16;j++){let ip=row;while(ip<a.length&&!a[ip][j])ip++;if(ip===a.length)continue;[a[ip],a[row]]=[a[row],a[ip]];let t=1;while(t*a[row][j]%q!==1)t++;a[row]=a[row].map(v=>v*t%q);for(let k=0;k<a.length;k++)if(k!==row&&a[k][j]){let s=a[k][j];a[k]=a[k].map((v,n)=>(v-s*a[row][n]%q+q)%q)}row++}return row};
 for(const q of [3,101,65537]){req(rank(f,q)===10,"rank f");req(rank(g,q)===13,"rank products");req(rank([...g,{0:1}],q)===13,"unit span")};
 const entries=[[0,0,1],[1,1,1],[2,2,1],[2,6,-1],[3,3,1],[4,4,1],[5,5,1],[5,9,-1],[6,6,1],[8,8,1],[9,9,1]];
 let cert={};const alpha={};for(const [i,j,v] of entries){let k=pairs.findIndex(([x,y])=>x===i&&y===j);req(k>=0,"certificate index");alpha[k]=v;cert=add(cert,scale(g[k],v))}req(JSON.stringify(cert)===JSON.stringify({0:1}),"integer certificate");
 const same=(a,b)=>{let ak=Object.keys(a),bk=Object.keys(b);return ak.length===bk.length&&ak.every(k=>a[k]===b[k])};
 let couplings=0;const q=101,Delta=50;
 for(let trial=0;trial<128;trial++){const a=pairs.map(()=>rng(q)),bit=rng(2);let orig={},sim={};for(let k=0;k<g.length;k++){orig=add(orig,scale(g[k],a[k],q),q);sim=add(sim,scale(g[k],a[k]+Delta*bit*(alpha[k]||0),q),q)}
 const noise={};for(let mon=0;mon<16;mon++)noise[mon]=rng(2)?1:-1;
 orig=add(add(orig,bit?{0:Delta}:{},q),noise,q);sim=add(sim,noise,q);req(same(orig,sim),"whole source capsule exact coupling");couplings++}
 const ft=fail("012","110"),trueg=mul(ft,ft);req(same(ft,trueg),"idempotence");const valid=Array.from({length:8},(_,i)=>i).filter(z=>evalp(ft,z)===0);req(valid.length===7,"7 valid witnesses");let correct=0;
 for(let scope=0;scope<2;scope++)for(let bitIndex=0;bitIndex<256;bitIndex++){const bit=rng(2),aa=rng(q);let e={};for(let mon=0;mon<8;mon++)e[mon]=rng(2)?1:-1;const C=add(add(scale(trueg,aa,q),bit?{0:Delta}:{},q),e,q);for(const z of valid){const v=evalp(C,z,q),expected=(Delta*bit+evalp(e,z,q))%q;req(v===expected,"valid same-key eval");const d0=Math.min(v,q-v),d1=Math.min(Math.abs(v-Delta),q-Math.abs(v-Delta));req(Number(d1<d0)===bit,"decode");correct++}}
 const count=Array(27).fill(0),id=(a,b,c)=>a*9+b*3+c,coords=(k)=>[Math.floor(k/9),Math.floor(k%9/3),k%3];
 for(let a=0;a<3;a++)for(let b=0;b<3;b++)for(let c=0;c<3;c++)for(let d=0;d<3;d++)count[id(a*c%3,b*d%3,(a*d+b*c)%3)]++;
 req(count.reduce((a,b)=>a+b,0)===81,"small field enumerates 81 mask samples");
 let current=Array(27).fill(0);current[0]=1;let results=[];
 for(let t=1;t<=7;t++){let next=Array(27).fill(0);for(let x=0;x<27;x++)for(let y=0;y<27;y++){const X=coords(x),Y=coords(y);next[id((X[0]+Y[0])%3,(X[1]+Y[1])%3,(X[2]+Y[2])%3)]+=current[x]*count[y]}current=next;
 const denom=81**t, tv=current.reduce((acc,v)=>acc+Math.abs(v/denom-1/27),0)/2;
 const bound=.5*Math.sqrt(27-1)*3**(-t);req(tv<=bound+1e-12,"universal mixing to W bound");results.push({t,tv,upper_bound:bound})}
 const M=16,r=13,t=30;const log2TV=-1+.5*Math.log2(101**r-1)-t*Math.log2(101);req(log2TV< -128,"R32 30-product all-instance uniformization bound");
 return {run:"R35-MINK-UNIFORM-PRODUCT-SPAN-20261103",assertions:checks,false_fixture:{n:4,clauses:10,public_product_generators:55,affine_rank:10,product_rank:13,exact_integer_unit_certificate_terms:11,full_capsule_exact_couplings:couplings},true_fixture:{genuine_original_witnesses:valid.length,same_capability_decodings:correct},small_field_exhaustive:results,illustrative:{q:101,M:16,rank_W:13,old_t:30,old_random_field_draws:600,new_random_field_draws:55,old_direct_pair_expansions:3000,new_direct_pair_expansions:55,old_to_new_direct_expansion_ratio:3000/55,old_to_uniform_log2_TV_bound:log2TV},status:"restricted FALSE exact; all-instance statistical equivalence for t sufficient; hard TRUE arbitrary recovered-key or forgery -> ORIGINAL witness unproved"}
}
console.log(JSON.stringify(checker(),null,2));
