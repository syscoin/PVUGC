const run = function run(){
 let checks=0;const chk=(a,m)=>{if(!a)throw Error(m);checks++};
 const dot=(a,b)=>{let z=a&b,p=0;while(z){p^=1;z&=z-1}return p};
 const norm=([a,b,c])=>{let d=Math.sqrt((a-c)*(a-c)+4*b*b);return (Math.abs(a+c+d)+Math.abs(a+c-d))/2};
 let cq=[];
 for(const t of [0,1,2,3])for(const c of [0,.6,1]){
  let s=Math.sqrt(1-c*c),rho=[[1,0,0],[c*c,c*s,s*s]],n=t+1,N=1<<n,D=0;
  for(let r=0;r<N;r++){let blocks=[[0,0,0],[0,0,0]],whole=[0,0,0];
   for(let k=0;k<N;k++){let v=k>>t,x=rho[v],h=dot(r,k);for(let j=0;j<3;j++){blocks[h][j]+=x[j]/N;whole[j]+=x[j]/N}}
   let ds=0;for(let h=0;h<2;h++)ds+=norm(blocks[h].map((x,j)=>x-whole[j]/2))/2;D+=ds/N;
  }
  let p=(1+s)/(2*(1<<t)),expected=p/2;
  chk(Math.abs(D-expected)<1e-11,"cq identity");chk(D<=.5*Math.sqrt(2*p)+1e-11,"LHL bound");
  cq.push({t,c,p_guess:Number(p.toFixed(9)),D:Number(D.toFixed(9))});
 }
 const rank=(rows,n)=>{let B={};for(let a of rows){a&=(1<<n)-1;while(a){let i=31-Math.clz32(a);if(B[i]!==undefined)a^=B[i];else{B[i]=a;break}}}return Object.keys(B).length};
 let ranks=[];
 for(let n=1;n<=3;n++)for(let q=n;q<=n+2;q++){
  let good=0,all=1<<(n*q);for(let z=0;z<all;z++){let rows=[];for(let j=0;j<q;j++)rows.push((z>>j*n)&((1<<n)-1));if(rank(rows,n)===n)good++}
  let theory=1;for(let j=0;j<n;j++)theory*=1-2**(j-q);
  chk(Math.abs(good/all-theory)<1e-12,"rank distribution");
  ranks.push({n,q,good,all});
 }
 return {run:473,assertions:checks,quantum_cq_cases:cq,exact_rank_cases:ranks,claims:"Finite density-matrix and rank-frequency checks only; NOT full QPT release security."}
};
console.log(JSON.stringify(run(),null,2));
