// Exact offline arithmetic checker for the NAND signed-short gap.
// JavaScript runtime: node check.js. No QPT or native-SLH hardness claim.
const q=257; let checks=0;
function ok(x,s){if(!x)throw Error(s);checks++}
function circuit(gates,inputs){
 const v=inputs+gates.length,m=1+2*v+4*gates.length, rows=[];
 const u=(i,b)=>1+2*i+b,t=(j,k)=>1+2*v+4*j+k;
 const row=xs=>rows.push(xs);
 for(let i=0;i<v;i++)row([[u(i,0),1],[u(i,1),1],[0,-1]]);
 gates.forEach(([a,b],j)=>{
   row([[t(j,0),1],[t(j,1),1],[t(j,2),1],[t(j,3),1],[0,-1]]);
   row([[t(j,2),1],[t(j,3),1],[u(a,1),-1]]);
   row([[t(j,1),1],[t(j,3),1],[u(b,1),-1]]);
   row([[t(j,0),1],[t(j,1),1],[t(j,2),1],[u(inputs+j,1),-1]]);
 });
 row([[u(v-1,1),1],[0,-1]]);
 return {v,m,rows,h:1+v+gates.length};
}
function wires(gs,bits){let a=bits.slice();for(let [x,y] of gs)a.push(1-a[x]*a[y]);return a}
function lift(gs,inputs,bits,force){
 let w=wires(gs,bits),v=w.length,m=1+2*v+4*gs.length,z=Array(m).fill(0);z[0]=1;
 if(w[v-1]===0&&!force)return null;
 if(w[v-1]===0)w[v-1]=1;
 w.forEach((b,i)=>z[1+2*i+b]=1);
 gs.forEach(([a,b],j)=>{
   let A=w[a],B=w[b],Y=w[inputs+j],T=[2-A-B-Y,B+Y-1,A+Y-1,1-Y];
   T.forEach((x,k)=>z[1+2*v+4*j+k]=x);
 });
 return z;
}
const trueG=[[0,1]],falseG=[[0,0],[0,1],[2,2]];
function padded(k){let g=falseG.map(x=>x.slice()),last=1+g.length-1;
 for(let i=0;i<k;i++){g.push([last,last]);last=1+g.length-1;g.push([last,last]);last=1+g.length-1}return g}
let cases=[["true",trueG,2],["false",falseG,1]];
for(let k=1;k<=5;k++)cases.push(["false_pad_"+k,padded(k),1]);
let summary=[];
for(const [name,gs,inputs] of cases){
 const {m,rows,h}=circuit(gs,inputs);
 ok(q>h+2,"q bound");
 for(let mask=0;mask<(1<<inputs);mask++){
   let bits=Array.from({length:inputs},(_,i)=>(mask>>i)&1);
   let z=lift(gs,inputs,bits,true),valid=wires(gs,bits).at(-1)===1;
   ok(z[0]===1,"anchor");
   ok(rows.every(row=>row.reduce((s,[i,a])=>s+a*z[i],0)%q===0),"all source rows");
   ok(z.reduce((s,a)=>s+Math.abs(a),0)===h+(valid?0:2),"exact L1 gap");
   if(!valid)ok(z.some(a=>a<0),"nonboolean fake");
 }
 let g=2*h+1,b=Math.floor(q/g),ell=Math.ceil(256/Math.log2(b));
 ok(b>=2&&Math.pow(b,ell)>=2**256,"radix capacity");
 let P=1-2*(h+3)/3**(h+2);
 summary.push({source:name,h,m,rows:rows.length,radix:b,columns:ell,
   fakePadRecoveryLowerBound:P**ell});
}
for(let h=2;h<=12;h++){
 let D=new Map([[0,1n]]);
 for(let i=0;i<h+2;i++){
  let N=new Map();
  for(const [s,c] of D)for(const e of [-1,0,1])N.set(s+e,(N.get(s+e)||0n)+c);
  D=N;
 }
 let good=[...D].filter(([s])=>Math.abs(s)<=h).reduce((a,[s,c])=>a+c,0n);
 ok(good===3n**BigInt(h+2)-2n*BigInt(h+3),"exact ternary tail");
}
const result={status:"PASS",assertions:checks,signedShortLemma:"proved in README",
 universalPublicFake:"constructed for every rejected NAND input",
 fullNativeKeyRecoverySecurity:false,source:summary};
if(typeof console!=="undefined")console.log(JSON.stringify(result));
result;
