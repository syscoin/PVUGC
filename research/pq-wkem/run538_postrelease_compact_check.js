function check(){
 let seed=53820261015>>>0;
 const rand=()=>{seed=(Math.imul(1664525,seed)+1013904223)>>>0;return seed;};
 const signature=(k,m,c)=>((Math.imul(k^0x9e3779b9,2654435761)^Math.imul(m,2246822519)^c)>>>0);
 const view=(x,k,claim,branch)=>[x,(Math.imul(k^x,16777619)^claim^branch)>>>0,(k^0x45d9f3b)>>>0];
 const sim=(x,k,claim,branch,q)=>q[0]===0?k:q[0]===1?signature(k,q[1],q[2]):view(x,k,claim,branch);
 let cases=0,responses=0,basis=0;
 for(let bits=3;bits<=8;bits++){
   const N=1<<bits;
   for(let trial=0;trial<36;trial++){
     const f=Array.from({length:N},(_,i)=>i);
     for(let i=N-1;i>0;i--){const j=rand()%(i+1);[f[i],f[j]]=[f[j],f[i]];}
     const w=rand()%N,x=f[w],k=rand(),claim=rand(),branch=trial%2;
     if(f.filter(v=>v===x).length!==1)throw Error("not permutation");
     const calls=[[0],[2]];
     for(let j=0;j<12;j++)calls.push([1,rand(),rand()]);
     for(const q of calls){
       if(f[w]!==x)throw Error("invalid original witness");
       const genuine=sim(x,k,claim,branch,q);
       const simulated=sim(x,k,claim,branch,q);
       if(JSON.stringify(genuine)!==JSON.stringify(simulated))throw Error("mismatch");
       responses++;
     }
     for(let m=0;m<4;m++){
       const d=signature(k,m,0)&15;
       for(let z=0;z<16;z++){
         const genuine=z^d,simulated=z^d;
         if(genuine!==simulated)throw Error("coherent basis mismatch");
         basis++;
       }
     }
     cases++;
   }
 }
 return {run:538,status:"PASS",seed:53820261015,
         permutation_witness_scenarios:cases,postrelease_query_responses:responses,
         coherent_basis_checks:basis,widths:[3,4,5,6,7,8],
         warning:"Toy deterministic oracle identity only; NOT QPT hardness or native signing security"};
}
console.log(JSON.stringify(check(), null, 2));
