// Run 429 exact finite Simon quantum-interference oracle check. No quantum hardware.
// The SOURCE is the executed artifact. Standard Node.js, no dependencies.
'use strict';
let state=429429>>>0, assertions=0, oracles=0, measured=0, collisions=0;
function rand(n){state^=state<<13;state^=state>>>17;state^=state<<5;return (state>>>0)%n;}
function ck(b){assertions++;if(!b)throw Error('run429 assertion '+assertions);}
function dot(a,b){let v=a&b,p=0;while(v){p^=1;v&=v-1;}return p;}
for(let n=2;n<=6;n++){
  const N=1<<n;
  for(let t=0;t<7;t++){
    const s=1+rand(N-1), P=Array.from({length:N},(_,i)=>i);
    for(let i=N-1;i>0;i--){const j=rand(i+1);[P[i],P[j]]=[P[j],P[i]];}
    const F=Array.from({length:N},(_,z)=>{
      const a=P[z],b=P[z^s];return a<b?a*N+b:b*N+a;
    });
    const groups=new Map();
    for(let x=0;x<N;x++){
      let g=groups.get(F[x]);if(!g){g=[];groups.set(F[x],g);}g.push(x);
    }
    ck(groups.size===N/2);
    for(let x=0;x<N;x++)for(let z=x+1;z<N;z++){
      ck((F[x]===F[z])===((x^z)===s));collisions++;
    }
    let total=0, support=0;
    for(let y=0;y<N;y++){
      let numerator=0;
      for(const v of groups.values()){
        let amp=0;for(const x of v)amp+=dot(x,y)?-1:1;
        numerator+=amp*amp;
      }
      const predicted=dot(s,y)===0?2*N:0;
      ck(numerator===predicted);
      if(numerator) support++;
      total+=numerator;measured++;
    }
    ck(total===N*N&&support===N/2);oracles++;
  }
}
const output={run:429,checker:'finite coherent Fourier law, full Simon fibers',
  assertions,oracles,collision_pairs:collisions,measurement_probabilities:measured,
  scopes:['n=2..6; seven random permutations each','exact amplitudes, no rounding',
    'quantum coherent oracle model only; no public PPT protected program',
    'no all-witness SAME-K construction or QPT security proof'],
  complete_pq_wkem:false};
process.stdout.write(JSON.stringify(output,null,2)+'\n');
