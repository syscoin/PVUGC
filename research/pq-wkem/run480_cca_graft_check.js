"use strict";
const run480=function run480(){
  const pow=(a,e,m)=>{let z=1n;while(e>0n){if(e&1n)z=z*a%m;a=a*a%m;e>>=1n;}return z;};
  const gcd=(a,b)=>{while(b){const t=a%b;a=b;b=t;}return a;};
  const inverse=(a,m)=>{let [t,T,r,R]=[0n,1n,m,a];while(R){const q=r/R;[t,T]=[T,t-q*T];[r,R]=[R,r-q*R];}if(r!==1n)throw Error("no inverse");return (t%m+m)%m;};
  const pairs=[[101n,113n],[107n,127n],[131n,137n]];
  let assertions=0,trials=0,directRejected=0,relatedQueried=0,correctGuesses=0;
  const ok=x=>{assertions++;if(!x)throw Error("assertion "+assertions)};
  for(let z=0;z<pairs.length;z++){
    const [p,q]=pairs[z],n=p*q,n2=n*n,g=n+1n;
    const lam=(p-1n)/gcd(p-1n,q-1n)*(q-1n),mu=inverse(lam,n);
    const encrypt=(m,r)=>pow(g,m,n2)*pow(r,n,n2)%n2;
    const decrypt=c=>{const v=pow(c,lam,n2);ok((v-1n)%n===0n);return ((v-1n)/n*mu)%n};
    for(let ctx=0;ctx<4;ctx++)for(let i=0;i<48;i++){
      const bit=(z+ctx+i)&1;
      const secret=bit?7n:3n;
      const w=BigInt(1+((i*17+ctx*5+z*7)%31));
      const original=BigInt(ctx)*1024n+secret*32n;
      ok(original+w<n);
      let r=BigInt(2+(i*37+ctx*31+z*19)%300);
      while(gcd(r,n)!==1n)r++;
      const c=encrypt(original,r);
      ok(decrypt(c)===original);
      const c2=c*pow(g,w,n2)%n2;
      ok(c2!==c);
      ok(c2===encrypt(original+w,r));
      const direct=(x=>x===c?null:decrypt(x))(c);
      ok(direct===null);directRejected++;
      const altered=(x=>x===c?null:decrypt(x))(c2);
      ok(altered===original+w);relatedQueried++;
      ok(altered/1024n===BigInt(ctx));
      ok(altered%32n===w);
      const guess=(altered/32n)%32n===7n?1:0;
      ok(guess===bit);correctGuesses++;
      trials++;
    }
  }
  return {run:480,status:"PASS",kind:"tiny Paillier public-graft / ordinary IND-CCA2 thought-experiment; not a secure PKE or PQ WKEM",trials,assertions,direct_challenge_queries_rejected:directRejected,related_challenge_queries_allowed:relatedQueried,correct_challenge_guesses:correctGuesses,parameters:"three tiny Paillier n; four contexts; 48 trials/context",quantum_hardware:false,concrete_security:false};
};
process.stdout.write(JSON.stringify(run480(),null,2)+"\n");
