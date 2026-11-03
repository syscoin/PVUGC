/* Exact offline-V8 executed checker; noncryptographic fixtures only. */
function checkR43(){
 let st=0x43a509,tests=0,opens=0,symbols=0;
 const ok=(v,msg)=>{tests++;if(!v)throw Error(msg)};
 const rnd=()=>{st^=st<<13;st^=st>>>17;st^=st<<5;return st>>>0};
 const ri=k=>rnd()%k,q=65537,n=2,m=12,p=256,kappa=16,B=1;
 const mod=(x,Q=q)=>((x%Q)+Q)%Q,centers=Array.from({length:p},(_,i)=>Math.floor(q*i/p));
 const dist=(a,b)=>Math.min(mod(a-b),mod(b-a));
 const gap=Math.min(...centers.slice(1).map((a,i)=>a-centers[i]),q-centers[p-1]);
 ok(gap>2*m*B,"unique symbol decoding gap");
 function gen(){let A=Array.from({length:n},()=>Array.from({length:m},()=>ri(q))),s=[ri(q),ri(q)],e=Array.from({length:m},()=>ri(3)-1),b=Array.from({length:m},(_,j)=>mod(A[0][j]*s[0]+A[1][j]*s[1]+e[j]));return {A,s,e,b}}
 function valid(pk,w){return pk.b.every((bj,j)=>Math.abs(w.e[j])<=B&&mod(pk.A[0][j]*w.s[0]+pk.A[1][j]*w.s[1]+w.e[j])===bj)}
 function enc(pk,mu){let r=Array.from({length:m},()=>ri(2));return {u:pk.A.map(row=>mod(row.reduce((a,v,j)=>a+v*r[j],0))),v:mod(pk.b.reduce((a,v,j)=>a+v*r[j],centers[mu]))}}
 function dec(c,w){let z=mod(c.v-c.u.reduce((a,v,j)=>a+v*w.s[j],0)),ind=-1,best=Infinity;for(let a=0;a<p;a++){let d=dist(z,centers[a]);if(d<best){best=d;ind=a}}return ind}
 function tag(o,k){let s=JSON.stringify(o)+"|"+k,h=2166136261>>>0;for(let a=0;a<s.length;a++)h=Math.imul(h^s.charCodeAt(a),16777619)>>>0;return h}
 const ctx={relation:"LWE_SURROGATE_NOT_ORIGINAL",claim:"C",utxo:"U",path:"fixed",anchors:"H"};
 const pubkeys=Array.from({length:3},gen),seeds=[ri(65536),ri(65536)];
 const pks=pubkeys.map(z=>({A:z.A,b:z.b}));
 const ct=pks.map(pk=>seeds.map(k=>Array.from({length:2},(_,block)=>
   Array.from({length:2},()=>enc(pk,(k>>>(8*block))&255)))));
 const pub={ctx,pks,ct,vk:"toy-vk",fixedMessage:"claim-C",D:"toy-DEM",CK:0};
 pub.CK=tag({...pub,CK:undefined},seeds[0]);
 for(let j=0;j<3;j++){let w={s:pubkeys[j].s,e:pubkeys[j].e};
  ok(valid(pks[j],w),"valid LWE witness");
  let recovered=[];for(let role=0;role<2;role++){let k=0;for(let block=0;block<2;block++){
   let x=ct[j][role][block].map(c=>dec(c,w));ok(x[0]===x[1],"fresh scope consistency");
   k|=(x[0]<<(8*block));symbols+=x.length;
  }recovered.push(k)}
  ok(recovered[0]===seeds[0]&&recovered[1]===seeds[1],"all branches same two seeds");
  ok(tag({...pub,CK:undefined},recovered[0])===pub.CK,"secret-correlated CK checked");
  opens++;
 }
 let pk={A:Array.from({length:2},()=>Array(m).fill(0)),b:Array(m).fill(0)};
 let w1={s:[1,1],e:Array(m).fill(0)},w2={s:[2,3],e:Array(m).fill(0)};
 ok(valid(pk,w1)&&valid(pk,w2),"two distinct restricted witnesses");
 for(let a=0;a<p;a++){let c=enc(pk,a);ok(dec(c,w1)===a&&dec(c,w2)===a,"all packed symbols, both witnesses");symbols+=2}
 let count=0,totalTV=0,maxShift=0;
 for(let A=0;A<81;A++)for(let b=0;b<81;b++){
  let aa=Array.from({length:4},(_,j)=>Math.floor(A/3**j)%3),bb=Array.from({length:4},(_,j)=>Math.floor(b/3**j)%3),hist=Array(9).fill(0);
  for(let mask=0;mask<16;mask++){let u=0,v=0;for(let j=0;j<4;j++)if((mask>>>j)&1){u=(u+aa[j])%3;v=(v+bb[j])%3}hist[3*u+v]++}
  const tv=h=>h.reduce((s,c)=>s+Math.abs(c/16-1/9),0)/2;
  let distance=tv(hist);totalTV+=distance;count++;
  for(let z=0;z<3;z++){let sh=Array(9).fill(0);for(let u=0;u<3;u++)for(let v=0;v<3;v++)sh[u*3+(v+z)%3]=hist[u*3+v];maxShift=Math.max(maxShift,Math.abs(tv(sh)-distance))}
 }
 const avgTV=totalTV/count,delta=.5*Math.sqrt(9/16);
 ok(count===6561&&avgTV<=delta+1e-10&&maxShift<1e-10,"average LHL and offset invariance");
 const example={q:65537,n:64,m:2048,B:1,p:8,kappa:256,J:3,old:1536,packed:516};
 ok(Math.floor(example.q/example.p)>2*example.m*example.B,"illustrative deterministic packing");
 ok(example.J*2*Math.ceil(example.kappa/Math.log2(example.p))===example.packed,"ciphertext counts");
 return {run:"R43-PACKED-JOINT-LWE",tests,opens,symbols,avgTV,delta,maxShift,
  toy:{q,n,m,B,p,kappa,scopes:2,oldPerBranch:64,packedPerBranch:8},example,
  status:"restricted LWE source algebra; no independent QPT security or ORIGINAL witness extraction"};
}
console.log(JSON.stringify(checkR43(),null,2));
