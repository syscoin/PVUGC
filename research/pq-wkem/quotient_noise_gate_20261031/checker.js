function runCheck(){
  const q=65537,g=4096,n=5,d=3,ell=7;
  const clauses=[[[1,2,3],[0,0,0]],[[1,2,4],[1,1,0]],[[0,1,4],[1,0,1]],[[0,1,2],[1,1,0]],[[0,2,3],[0,0,1]],[[0,1,3],[0,1,0]],[[0,1,4],[1,0,0]],[[1,2,4],[1,1,1]],[[0,2,4],[0,1,0]],[[1,2,4],[0,1,1]]];
  let checks=0,state=0x310c2026;
  const mod=x=>((x%q)+q)%q, rnd=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%q;};
  const ok=(x,why)=>{checks++;if(!x)throw Error(why+" #"+checks);};
  const dot=(a,b)=>mod(a.reduce((acc,x,i)=>acc+x*b[i],0));
  const inv=x=>{let y=1,z=mod(x),a=q-2;while(a){if(a&1)y=mod(y*z);z=mod(z*z);a=Math.floor(a/2);}return y;};
  const pop=x=>{let n=0;while(x){n+=x&1;x>>>=1;}return n;};
  const mon=Array.from({length:1<<n},(_,i)=>i).filter(x=>pop(x)<=d),T=mon.length;
  const mul=(a,b)=>{const r={};for(const [x,v] of Object.entries(a))for(const [y,w] of Object.entries(b)){const z=(Number(x)|Number(y));r[z]=mod((r[z]||0)+v*w);}return r;};
  const D=clauses.map(([ids,bits])=>{let p={0:1};ids.forEach((i,j)=>{p=mul(p,bits[j]?{[1<<i]:1}:{0:1,[1<<i]:q-1});});return mon.map(m=>p[m]||0);});
  const e=Array.from({length:T},(_,i)=>Number(i===0));
  function basis(rows){
    const piv=[],red=[],out=[];
    for(const row of rows){
      let v=row.map(mod);
      for(let a=0;a<piv.length;a++){const f=v[piv[a]];if(f)v=v.map((z,j)=>mod(z-f*red[a][j]));}
      const p=v.findIndex(x=>x!==0);if(p<0)continue;
      const mul=inv(v[p]);v=v.map(x=>mod(x*mul));
      let at=0;while(at<piv.length&&piv[at]<p)at++;
      piv.splice(at,0,p);red.splice(at,0,v);out.splice(at,0,row);
    }
    return out;
  }
  function solve(M,y){
    const k=M.length,N=M[0].length,A=M.map((row,i)=>[...row.map(mod),mod(y[i])]),piv=[];
    let j=0;
    for(let i=0;i<k;i++){
      while(j<N&&!A.some((row,h)=>h>=i&&row[j]!==0))j++;
      ok(j<N,"full row rank");
      let h=i;while(!A[h][j])h++;
      [A[i],A[h]]=[A[h],A[i]];
      const fac=inv(A[i][j]);A[i]=A[i].map(x=>mod(x*fac));
      for(let h=0;h<k;h++)if(h!==i&&A[h][j]){const f=A[h][j];A[h]=A[h].map((x,z)=>mod(x-f*A[i][z]));}
      piv.push(j);j++;
    }
    const v=Array(N).fill(0);piv.forEach((p,i)=>{v[p]=A[i][N];});
    ok(M.every((row,i)=>dot(row,v)===mod(y[i])),"linear solution");
    return v;
  }
  const valid=[];
  for(let W=0;W<(1<<n);W++){
    if(clauses.every(([ids,bits])=>ids.some((id,i)=>((W>>id)&1)!==bits[i])))valid.push(W);
  }
  ok(valid.length===0,"the ORIGINAL 3CNF must be FALSE");
  const Q=basis([e,...D]);
  ok(Q.length===11&&Q[0]===e,"uncertified FALSE source quotient dimension");
  const v0=solve(Q,[1,...Array(Q.length-1).fill(0)]);
  ok(dot(e,v0)===1&&D.every(row=>dot(row,v0)===0),"public nonwitness dual");
  let recovered=0;
  for(let z=0;z<512;z++){
    const bit=rnd()%2,u=Array.from({length:ell},rnd);
    const R=Array.from({length:ell},()=>Array.from({length:D.length},rnd));
    const B=R.map((row,a)=>Array.from({length:T},(_,t)=>mod(u[a]*e[t]+row.reduce((acc,v,j)=>acc+v*D[j][t],0))));
    const S=Array.from({length:D.length},rnd),s=Array.from({length:ell},rnd);
    const xi=Array.from({length:Q.length},()=>rnd()%5-2),etaStar=rnd()%5-2;
    const eta=Array.from({length:T},(_,t)=>mod(Q.reduce((acc,row,j)=>acc+row[t]*xi[j],0)));
    const c=Array.from({length:T},(_,t)=>mod(B.reduce((acc,row,a)=>acc+row[t]*s[a],0)+g*(bit*e[t]+D.reduce((acc,row,j)=>acc+row[t]*S[j],0))+eta[t]));
    const t=mod(dot(u,s)+etaStar), residual=mod(dot(v0,c)-t);
    ok(residual===mod(g*bit+xi[0]-etaStar),"full joint public dual identity");
    const dist=b=>Math.min(mod(residual-g*b),mod(g*b-residual));
    const guess=dist(0)<=dist(1)?0:1;
    ok(guess===bit,"unauthorized final master bit recovery");
    recovered++;
  }
  return {candidate:"quotient-aligned structured LWE source",status:"REJECTED; no generic PQ WKEM advance",q,g,degree:d,T,rank_D:Q.length-1,original_witness_count:valid.length,public_nonwitness_dual_support:v0.filter(x=>x!==0).length,full_joint_false_bits_recovered:recovered,assertions:checks,independent_qpt_security_proof:false,real_native_signatures:false};
}
console.log(JSON.stringify(runCheck()));
