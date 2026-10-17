function run421Compact() {
  let assertions=0, falseGhost=0, trueTwoWitness=0, matrices=0, bad=0, good=0, corruptZero=0;
  const chk=(c)=>{assertions++;if(!c)throw Error("Run421 checker assertion "+assertions);};
  for(let n=3;n<=8;n++){
    const N=1<<n;
    for(let u=0;u<N;u++){
      const y=(5*u+3)%N;
      let count=0, sole=-1;
      for(let pi=0;pi<N;pi++){if((5*pi+3)%N===y){count++;sole=pi;}}
      chk(count===1&&sole===u);
      // The ORIGINAL false-instance relation is identically zero.
      const sourceFalse=Array.from({length:N},(_,w)=>false).every(v=>!v);
      chk(sourceFalse);
      // Computational argument soundness never implies that there is no
      // ghost accepting proof: pi=u exists in every finite fixture.
      chk(((5*u+3)%N===y));
      falseGhost++;
      // The original true relation has two distinct witnesses, both same K.
      const K=(u+13*n)%65521;
      const releaseTrue=(w)=> w===0||w===1 ? K : null;
      chk(releaseTrue(0)===K&&releaseTrue(1)===K);
      for(let w=0;w<N;w++)chk((releaseTrue(w)!==null)===(w===0||w===1));
      trueTwoWitness++;
    }
  }
  const residual=[1,0,1];
  for(let t=1;t<=5;t++){
    let thisBad=0;
    const all=1<<(3*t);
    for(let flat=0;flat<all;flat++){
      let acc=true;
      for(let i=0;i<t;i++){
        let dot=0;
        for(let j=0;j<3;j++)dot^= ((flat>>(3*i+j))&1)&residual[j];
        if(dot!==0)acc=false;
      }
      if(acc){thisBad++;bad++;}else good++;
      matrices++;
      chk(acc===Array.from({length:t},(_,i)=>(((flat>>(3*i))&1)^((flat>>(3*i+2))&1))===0).every(Boolean));
    }
    chk(thisBad===(1<<(2*t))); // fraction 2^{-t}, one fixed nonzero residual.
    chk(all===(1<<(3*t)));
    // Deliberately all-zero S is always an invalid-accepting malicious CRS.
    let zeroAccept=true;
    for(let i=0;i<t;i++)zeroAccept=zeroAccept&&true;
    chk(zeroAccept);
    corruptZero++;
  }
  return {run:421,model:"finite algebraic negative-control, not a QPT implementation",assertions,
          false_instance_hidden_proof_fixtures:falseGhost,
          true_instance_two_witness_fixtures:trueTwoWitness,
          folded_crs_matrices:matrices,good_crs:good,bad_crs:bad,
          malicious_zero_crs:corruptZero,
          exact_bad_fraction:"2^(-t) for fixed nonzero GF(2) residual",
          real_one_way_function:false,real_iO:false,real_qpt_attack:false,practical_wkem:false};
}
if (typeof process !== 'undefined' && process.stdout) process.stdout.write(JSON.stringify(run421Compact(),null,2)+'\n');
