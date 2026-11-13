const runR102Checker = function runR102Checker() {
  const m=1656, budget=2729, a=15n, b=16n, z=b**3n+2n*a*b*b+2n*a*a*b+2n*a**3n, syms=[-3,-2,-1,0,1,2,3];
  let assertions=0;
  function ck(x,why){assertions++;if(!x)throw Error("R102 assertion "+assertions+": "+why)}
  function cnt(n,k){
    let F=Array(k+1).fill(1n);
    for(let t=0;t<n;t++){
      const G=Array(k+1).fill(0n);
      for(let v=0;v<=k;v++)G[v]=F[v]+2n*((v>=1?F[v-1]:0n)+(v>=2?F[v-2]:0n)+(v>=3?F[v-3]:0n));
      F=G;
    }
    return F[k];
  }
  let toyChecks=0;
  for(const [n,k,aa,bb] of [[3,4,2n,3n],[4,6,3n,4n],[5,7,3n,4n]]){
    const common=aa**BigInt(k)*bb**BigInt(3*n-k);
    let actual=0n;
    function rec(i,s){
      if(i===n){
        if(s>k)return;
        const numerator=aa**BigInt(s)*bb**BigInt(3*n-s)*aa**BigInt(k-s);
        const denominator=bb**BigInt(k-s);
        ck(numerator===denominator*common,"uniform accepted mass");
        actual++;toyChecks++;return;
      }
      for(const v of syms)rec(i+1,s+Math.abs(v));
    }
    rec(0,0);
    ck(actual===cnt(n,k),"toy exact support matches DP");
  }
  const D=cnt(m,budget);
  const Z=z;
  ck(D>0n && D<7n**BigInt(m),"R101 support nontrivial");
  ck(z===25726n,"tilt partition function");
  const ratioNum=7n**BigInt(m)*a**BigInt(budget)*b**BigInt(3*m-budget),ratioDen=z**BigInt(m);
  ck(ratioNum>30n*ratioDen,"greater than 30x acceptance probability");
  const log2=(v)=>{const bits=v.toString(2);const n=Math.min(52,bits.length);return bits.length-n+Math.log2(Number("0b"+bits.slice(0,n)))};
  const logD=log2(D),p0=2**(logD-m*Math.log2(7)),pTilt=2**(logD+budget*Math.log2(Number(a))+(3*m-budget)*Math.log2(Number(b))-m*Math.log2(Number(z)));
  ck(Math.abs(p0-0.004601156368426588)/p0<1e-8,"independent exact support numerical check");
  ck(Math.abs(pTilt-0.1400996485986713)/pTilt<1e-8,"tilted exact rational numerical check");
  for(let digit=0;digit<4;digit++)for(const noise of [-8187,0,8187]){
    const q=65521,step=Math.floor(q/4),value=((digit*step+noise)%q+q)%q;
    const distance=t=>Math.min((value-t+q)%q,(t-value+q)%q);
    let best=-1,dist=q+1;
    for(let d=0;d<4;d++){const e=distance(d*step);if(e<dist){dist=e;best=d}}
    ck(best===digit,"R101 exact 2-bit decode envelope unchanged");
  }
  return {run:"R102-EXACT-TILTED-R101-COINS-20261105",scope:"restricted-LWE-leaf-only; generic-NP ORIGINAL compiler unresolved",assertions,toy_accepted_vectors_checked:toyChecks,parameters:{m,budget,a:Number(a),b:Number(b),integer_partition_Z:Number(z)},support_decimal_digits:D.toString().length,log2_support:Number(logD.toFixed(10)),baseline_acceptance:Number(p0.toPrecision(14)),tilted_acceptance:Number(pTilt.toPrecision(14)),expected_uniform_draws:Number((1/p0).toPrecision(12)),expected_tilted_draws:Number((1/pTilt).toPrecision(12)),proposal_reduction:Number((pTilt/p0).toPrecision(12)),security:"identical uniform distribution on R101 bounded-L1 coin support; no new cryptographic assumption; toy/exact algebra only; not QPT test"};
};
console.log(JSON.stringify(runR102Checker(), null, 2));
