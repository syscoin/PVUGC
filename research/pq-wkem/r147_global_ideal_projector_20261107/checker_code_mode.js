function checkR147(){
const q=101,D=3;
const m=[];for(let a=0;a<=D;a++)for(let b=0;b<=D-a;b++)m.push([a,b]);
m.sort((x,y)=>(x[0]+x[1])-(y[0]+y[1])||x[0]-y[0]);const N=m.length;
const pos=new Map(m.map(([a,b],i)=>[`${a},${b}`,i]));
let assertions=0;function ck(v,s){assertions++;if(!v)throw Error("check "+assertions+" "+s);}
function mm(x){return ((x%q)+q)%q;}function modpow(a,n){let z=1;for(;n;n=Math.floor(n/2),a=mm(a*a))if(n%2)z=mm(z*a);return z;}
function addPoly(f,g){const a={...f};for(const [k,v] of Object.entries(g))a[k]=(a[k]||0)+v;return a;}
function mulPoly(f,g){let h={};for(const [k,v] of Object.entries(f))for(const [t,w] of Object.entries(g)){const [a,b]=k.split(",").map(Number),[c,d]=t.split(",").map(Number);const u=`${a+c},${b+d}`;h[u]=(h[u]||0)+v*w;}return h;}
function col(f,a,b){let z=Array(N).fill(0);for(const [k,v] of Object.entries(f)){const [i,j]=k.split(",").map(Number);const p=pos.get(`${i+a},${j+b}`);if(p!==undefined)z[p]=mm(z[p]+v);}return z;}
function masks(fs){const out=[];for(const f of fs){const degree=Math.max(...Object.entries(f).filter(([,v])=>mm(v)!==0).map(([k])=>k.split(",").map(Number).reduce((a,b)=>a+b,0)));for(const [a,b]of m)if(a+b+degree<=D)out.push(col(f,a,b));}return out;}
function solve(A,B){const M=A.map((x,i)=>[...x.map(mm),mm(B[i])]),n=N;let row=0,piv=[];
for(let c=0;c<n&&row<M.length;c++){let k=row;while(k<M.length&&M[k][c]===0)k++;if(k===M.length)continue;[M[k],M[row]]=[M[row],M[k]];
let inv=modpow(M[row][c],q-2);M[row]=M[row].map(v=>mm(v*inv));
for(let i=0;i<M.length;i++){if(i===row||!M[i][c])continue;let t=M[i][c];M[i]=M[i].map((v,j)=>mm(v-t*M[row][j]));}
piv.push(c);row++;}
for(let i=row;i<M.length;i++)if(M[i][n])return null;
const x=Array(n).fill(0);for(let i=0;i<row;i++)x[piv[i]]=M[i][n];return x;}
function projector(C){const e0=Array(N).fill(0);e0[0]=1;return solve([...C,e0],[...Array(C.length).fill(0),1]);}
function evalP(p,a,b){return mm(p.reduce((z,v,i)=>z+v*(a**m[i][0])*(b**m[i][1]),0));}
function value(f,a,b){return mm(Object.entries(f).reduce((z,[k,v])=>{const[i,j]=k.split(",").map(Number);return z+v*a**i*b**j;},0));}
const Ba={"2,0":1,"1,0":-1},Bb={"0,2":1,"0,1":-1};const lit=[{"1,0":1},{"0,0":1,"1,0":-1},{"0,1":1},{"0,0":1,"0,1":-1}];
const clauses=[];for(let i=0;i<4;i++)clauses.push([i]);for(let i=0;i<4;i++)for(let j=i+1;j<4;j++)clauses.push([i,j]);
const fail=clauses.map(c=>c.reduce((acc,k)=>mulPoly(acc,addPoly({"0,0":1},Object.fromEntries(Object.entries(lit[k]).map(([l,v])=>[l,-v])))),{"0,0":1}));
let sat=0,unsat=0,falseExposed=0,example=null;
for(const count of [1,2,3]){
const combos=(start,chosen)=>{if(chosen.length===count){const fs=[Ba,Bb,...chosen.map(i=>fail[i])];const C=masks(fs),L=projector(C);let W=[];
for(let a=0;a<=1;a++)for(let b=0;b<=1;b++)if(fs.every(f=>value(f,a,b)===0))W.push([a,b]);
if(W.length){sat++;ck(L!==null,"all true instances have public projector");ck(L[0]===1,"public projector normalized");for(const col of C)ck(mm(col.reduce((z,v,i)=>z+v*L[i],0))===0,"public annihilator");for(let K of [0,1]){const r=C.map((_,j)=>mm(13+j*17+K*7+j*j*3));const P=m.map((_,i)=>mm((i===0?K:0)+C.reduce((z,col,j)=>z+col[i]*r[j],0)));ck(mm(P.reduce((z,v,i)=>z+L[i]*v,0))===K,"public key recovery");for(const[w0,w1] of W)ck(evalP(P,w0,w1)===K,"all witness same K");}
if(W.length>1&&!example)example={formula:chosen.map(i=>clauses[i]),witnesses:W,projector:L,masks:C.length};
}else{unsat++;if(L!==null)falseExposed++;}
return;}for(let i=start;i<clauses.length;i++)combos(i+1,[...chosen,i]);};combos(0,[]);
}
return {assertions,parameters:{q,D,monomials:N,clauses:clauses.length},counts:{sat,unsat,falseExposed},example,status:"REJECTED coefficient-exposed generic ORIGINAL SOURCE"};
}
console.log(JSON.stringify(checkR147(),null,2));
