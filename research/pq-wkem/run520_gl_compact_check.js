"use strict";
function parity(x){let b=0;while(x){b^=(x&1);x>>>=1;}return b;}
function run(){
let leakTests=0,leakPairs=0,padTests=0;let walsh=[];
for(let h=2;h<=8;h++){const n=1<<h;for(let known=0;known<=h;known++){
const mask=(1<<known)-1;let ok=0;
for(let k=0;k<n;k++)for(let r=0;r<n;r++){
const guess=((r&(~mask))===0)?parity(r&(k&mask)):0;
ok+=(guess===parity(r&k));leakTests++;
}
const expectedNumerator=(n*n)/2+n*n/(2**(h-known+1));
if(ok!==expectedNumerator)throw Error("leak h="+h+" known="+known+" "+ok+" != "+expectedNumerator);
leakPairs++;
}}
for(let h=1;h<=7;h++){const n=1<<h;for(let k=0;k<n;k++)for(let r=0;r<n;r++)for(let m=0;m<2;m++){
const c=m^parity(r&k);if((c^parity(r&k))!==m)throw Error("pad");padTests++;
}}
for(let h=3;h<=8;h++){const n=1<<h,k=(3*h+1)%n,j=(3*h+2)%n;let heavy=0;let nonzero=0;
for(let u=0;u<n;u++){let numerator=0;for(let r=0;r<n;r++){
const sk=1-2*parity(r&k),sj=1-2*parity(r&j),su=1-2*parity(r&u);
numerator+=(7*sk+sj)*su;
}
const want=u===k?7*n:u===j?n:0;if(numerator!==want)throw Error("Fourier");
if(numerator!==0)nonzero++;if(Math.abs(numerator)>=2*n)heavy++;
}
if(heavy!==1||nonzero!==2)throw Error("heavy");walsh.push({h,secret:k,decoy:j,nonzero,heavy_at_quarter:heavy,parseval:"25/32"});
}
return {run:520,status:"PASS",scope:"finite algebra only; no release or cryptographic security",leak_parameters:leakPairs,leak_key_mask_pairs:leakTests,honest_pad_cases:padTests,exact_walsh_spectra:walsh};
}
