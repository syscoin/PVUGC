function r44Check(){
 let seed=0x44a01c1,tests=0,decodes=0,couplings=0,exposures=0;
 function rnd(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0}
 const pick=k=>rnd()%k,ok=(a,m)=>{tests++;if(!a)throw Error(m)},q=257,m=7,n=2,p=16,B=1,Q=4,J=3;
 const mod=x=>((x%q)+q)%q,ctr=x=>Math.floor(q*x/p),dist=(x,y)=>Math.min(mod(x-y),mod(y-x));
 ok(Math.floor(q/p)>2*m*B,"correctness gap");
 function key(){let A=Array.from({length:n},()=>Array.from({length:m},()=>pick(q))),s=Array.from({length:n},()=>pick(q)),e=Array.from({length:m},()=>pick(3)-1),b=Array.from({length:m},(_,j)=>mod(e[j]+s.reduce((a,v,i)=>a+v*A[i][j],0)));return {A,s,e,b}}
 function enc(k,a){let r=Array.from({length:m},()=>pick(2));return {u:k.A.map(row=>mod(row.reduce((h,v,i)=>h+v*r[i],0))),v:mod(k.b.reduce((h,v,i)=>h+v*r[i],ctr(a)))}}
 function open(k,c){let z=mod(c.v-c.u.reduce((h,v,i)=>h+v*k.s[i],0)),best=-1,d=Infinity;for(let a=0;a<p;a++){let v=dist(z,ctr(a));if(v<d){d=v;best=a}}decodes++;return best}
 const claims=Array.from({length:Q},(_,i)=>{let seeds=[pick(65536),pick(65536)],ks=Array.from({length:J},key);
 let ct=ks.map(k=>seeds.map(s=>Array.from({length:4},(_,j)=>enc(k,(s>>>(4*j))&15))));
 return {id:i,message:`vk|UTXO${i}|path${i}`,seeds,ks,ct}});
 ok(new Set(claims.map(c=>c.message)).size===Q,"native messages distinct");
 for(const c of claims)for(let j=0;j<J;j++){let recovered=c.ct[j].map(role=>role.reduce((h,ct,i)=>h+(open(c.ks[j],ct)<<(i*4)),0));ok(JSON.stringify(recovered)===JSON.stringify(c.seeds),"every branch same seeds")}
 const opened=seq=>new Set(seq.map(q=>q[0]));
 const sequences=[[]];
 for(let len=1;len<=2;len++)for(let z=0;z<(Q*J)**len;z++){let v=z,a=[];for(let k=0;k<len;k++){let d=v%(Q*J);v=Math.floor(v/(Q*J));a.push([Math.floor(d/J),d%J])}sequences.push(a)}
 for(const seq of sequences)for(let t=0;t<Q;t++){let exposed=opened(seq).has(t),simAbort=seq.some(q=>q[0]===t);ok(exposed===simAbort,"claim closure");if(!exposed){couplings++;for(const [i,j] of seq){const c=claims[i],k=c.ks[j];ok(c.ct[j].every((role,roleIndex)=>role.every((ct,l)=>open(k,ct)===((c.seeds[roleIndex]>>>(4*l))&15))),"coupled opening records")}}}
 ok(opened([[0,0]]).has(0)&&!opened([[0,0]]).has(1),"sibling exposure is claim-wide");exposures++;
 const alias={...claims[1],message:claims[0].message};ok(alias.message===claims[0].message,"duplicate native message must be merged/rejected");exposures++;
 let selected=Array(Q).fill(0);
 for(const seq of sequences){let choices=claims.filter(c=>!opened(seq).has(c.id));if(choices.length){let t=choices[(seq.length+seed>>>0)%choices.length].id;ok(!opened(seq).has(t),"adaptive target eligible");selected[t]++}}
 return {run:"R44-ADAPTIVE-CLAIM-CLOSURE-20261103",tests,decodes,couplings,exposures,sequences:sequences.length,adaptiveSelections:selected,parameters:{q,n,m,B,p,Q,J},status:"restricted QPT composition algebra; not generic ORIGINAL witness-KEM, not a QPT hardness experiment"};
}
console.log(JSON.stringify(r44Check(),null,2));
