function run400(){
let checks=0;const ok=(v,m)=>{checks++;if(!v)throw new Error(m)};
let seed=40020261010>>>0;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed};const bit=x=>{let p=0;while(x){p^=1;x&=x-1n}return p};
const bits=n=>{let v=0n;for(let j=0;j<n;j++)if(rand()&1)v|=1n<<BigInt(j);return v};
let report=[];
for(let [b,k] of [[8,3],[12,5],[64,24],[256,128]]){
let rows=[],rhs=[];for(let i=0;i<k;i++){rows.push((1n<<BigInt(i))|(bits(b-k)<<BigInt(k)));rhs.push(rand()&1)}
const valid=r=>rows.every((row,i)=>bit(row&r)===rhs[i]);
const sample=free=>{let r=free<<BigInt(k);for(let i=0;i<k;i++)if((bit(rows[i]&r)^rhs[i])===1)r|=1n<<BigInt(i);ok(valid(r),"source-free coset sample");return r};
const capability="sealed-ideal-K";
const release=r=>valid(r)?capability:null;
let samples=0;
for(let z=0;z<96;z++){let t=rand();let w="opaque-valid-ORIGINAL-witness:"+z;let r=sample(bits(b-k));let s={w,t,r};ok(release(s.r)===capability,"honest source release");let q=sample(bits(b-k));ok(release(q)===capability,"one-query source-free release");samples++}
let exact=0;
if(b<=12){let seen=new Set();for(let free=0;free<2**(b-k);free++){let r=sample(BigInt(free));ok(!seen.has(r.toString()),"unique coset");seen.add(r.toString())}for(let r=0;r<2**b;r++)ok(valid(BigInt(r))===seen.has(String(r)),"complete coset enumeration");exact=seen.size;ok(exact===2**(b-k),"fiber size")}
report.push({b,k,acceptance_fraction:`2^-${k}`,coset_size:`2^${b-k}`,exact_states:exact,honest_success:samples,source_free_success:samples});
}
return {run:400,status:"PASS",checks,fixtures:report,model:"public systematic affine projection and ideal sealed release",does_not_prove_one_wayness:true,does_not_implement_wkem:true};
}
console.log(JSON.stringify(run400(),null,2));
