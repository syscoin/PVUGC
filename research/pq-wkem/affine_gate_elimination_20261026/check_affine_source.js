// Exact GF(2) mixed affine+NAND SOURCE checker. Node/browser independent.
let tests=0;const assert=(ok,m)=>{if(!ok)throw Error(m);tests++};
const bit=(x)=>{let p=0;while(x){p^=1;x&=x-1}return p};
function kernel(rows,m){
 let a=rows.slice(), piv=[],k=0;
 for(let c=0;c<m;c++){
  let j=-1;for(let t=k;t<a.length;t++)if((a[t]>>>c)&1){j=t;break}
  if(j<0)continue; [a[k],a[j]]=[a[j],a[k]];
  for(let t=0;t<a.length;t++)if(t!==k&&((a[t]>>>c)&1))a[t]^=a[k];
  piv.push(c);k++;if(k===a.length)break;
 }
 const free=[];for(let c=0;c<m;c++)if(!piv.includes(c))free.push(c);
 const R=free.map(c=>{let v=1<<c;for(let i=0;i<piv.length;i++)if(bit(a[i]&v))v^=1<<piv[i];return v});
 for(let v of R)for(let row of rows)assert(bit(v&row)===0,'kernel');
 return {R,rank:piv.length};
}
function make(falseInstance,extra=0){
 const vars=['a','b','t','z','r'];const linear=[[['a','b'],'t',0],[['z','t'],'r',0]];
 let prev='a';for(let i=0;i<extra;i++){let name='extra'+i;vars.push(name);linear.push([[prev,'b'],name,i%2]);prev=name}
 const wi={};vars.forEach((v,i)=>wi[v]=[1+2*i,2+2*i]);
 const starts=1+2*vars.length,m=starts+4;
 const assignments=[[0,0,1],[0,1,1],[1,0,1],[1,1,0]],idx=[starts,starts+1,starts+2,starts+3],rows=[];
 for(let v of vars)rows.push(1^(1<<wi[v][0])^(1<<wi[v][1]));
 for(let [ins,out,eps] of linear){let row=1<<wi[out][1];for(let v of ins)row^=1<<wi[v][1];if(eps)row^=1;rows.push(row)}
 for(let [v,b] of [['r',0],...(falseInstance?[['a',0],['b',0]]:[])])rows.push((1<<wi[v][1])^b);
 rows.push(1^idx.reduce((v,x)=>v^(1<<x),0));
 for(let [pos,v] of ['a','b','z'].entries())for(let val=0;val<2;val++){
  let row=1<<wi[v][val];assignments.forEach((arr,i)=>{if(arr[pos]===val)row^=1<<idx[i]});rows.push(row)
 }
 const {R,rank}=kernel(rows,m);
 function project(E,X){return R.reduce((a,v,i)=>a|(bit((E^X)&v)<<i),0)}
 function hist(X){let h={};for(let [E,wt] of [[0,2],...idx.map(i=>[1<<i,1])]){let q=project(E,X);h[q]=(h[q]||0)+wt}return h}
 function vector(a,b){
  let values={a,b,t:a^b,z:1-(a&b),r:(a^b)^(1-(a&b))};
  let p=a;for(let i=0;i<extra;i++){p=p^b^(i%2);values['extra'+i]=p}
  let v=1;for(let name of vars)v^=1<<wi[name][values[name]];
  let j=assignments.findIndex(x=>x.join('')===[values.a,values.b,values.z].join(''));
  return {v:v^(1<<idx[j]),values}
 }
 return {m,R,rank,idx,rows,project,hist,vector};
}
for(let falseInstance of [false,true]){
 let s=make(falseInstance);assert(s.m===15,'mixed column count');
 assert(s.R.length===15-s.rank,'rank/nullity');
 const h0=s.hist(0),h1=s.hist(1);
 assert(Object.values(h0).reduce((a,b)=>a+b,0)===6,'law total');
 if(falseInstance){
  assert(JSON.stringify(h0)===JSON.stringify(h1),'full quotient false secrecy');
  for(let a=0;a<(1<<s.R.length);a++){
   let v=0;s.R.forEach((r,i)=>{if((a>>i)&1)v^=r});
   if(v&1){let selected=s.idx.reduce((u,i)=>u+((v>>i)&1),0);assert(selected===3,'odd pseudo triple')}
  }
 } else {
  assert(JSON.stringify(h0)!==JSON.stringify(h1),'truth channel');
  for(let [a,b] of [[0,1],[1,0],[1,1]]){
   let {v,values}=s.vector(a,b);assert(values.r===0,'true witness');
   for(let row of s.rows)assert(bit(row&v)===0,'original lift kernel');
   let alpha=-1;
   for(let k=0;k<(1<<s.R.length);k++){let u=0;s.R.forEach((r,i)=>{if((k>>i)&1)u^=r});if(u===v){alpha=k;break}}
   assert(alpha>=0,'public representation');
   let count=[0,0];
   for(let [E,wt] of [[0,2],...s.idx.map(i=>[1<<i,1])]){
    count[bit(E&v)]+=wt;
    for(let X of [0,1])assert(bit(alpha&s.project(E,X))===(X^bit(E&v)),'same X');
   }
   assert(count[0]===5&&count[1]===1,'BSC 1/6');
  }
 }
 for(let k of [1,3,5]){
  let ext=make(falseInstance,k);
  assert(ext.m===s.m+2*k,'affine coordinates');
  assert(ext.R.length===s.R.length,'affine quotient neutrality');
  if(falseInstance)assert(JSON.stringify(ext.hist(0))===JSON.stringify(ext.hist(1)),'extended false secrecy');
 }
}
return JSON.stringify({status:'PASS',assertions:tests,scope:'exact mixed affine/NAND quotient, three distinct true witnesses and false view, affine extension rank',noise:'P(0000)=2/6; P(each singleton)=1/6'});