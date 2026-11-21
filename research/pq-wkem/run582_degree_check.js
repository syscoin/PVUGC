/* Run 582, exact executed public Boolean-degree checker. Reproduce:
node -e 'console.log(JSON.stringify(require("./research/pq-wkem/run582_degree_check.js")()))'
Not a quantum or cryptographic security test. */
function main(){
 let assertions=0; const check=(ok)=>{if(!ok)throw Error("assertion "+assertions);assertions++};
 const pop=(v)=>{let c=0;while(v){v&=v-1;c++}return c};
 function mobius(c,n){let t=c,N=1<<n;for(let b=0;b<n;b++)for(let m=0;m<N;m++)if(m&(1<<b)){let v=((t>>m)&1)^((t>>(m^(1<<b)))&1);t=(t&~(1<<m))|(v<<m)}return t}
 function deg(c,n){let d=-1;for(let m=0;m<(1<<n);m++)if((c>>m)&1)d=Math.max(d,pop(m));return d}
 let polys=0,mins={};for(let n=1;n<=4;n++){let N=1<<n,table={};for(let c=1;c<(1<<N);c++){let d=deg(c,n),t=mobius(c,n),w=pop(t);check(w>=(1<<(n-d)));check(mobius(t,n)===c);table[d]=table[d]===undefined?w:Math.min(table[d],w);polys++}for(const [d,w] of Object.entries(table))check(w===(1<<(n-Number(d))));mins[n]=table;for(let h=0;h<N;h++)check(deg(mobius(1<<h,n),n)===n)}
 let matrices=0,affine=0;const n=3,N=1<<n, apply=(rows,x)=>rows.reduce((o,r,i)=>o|((pop(r&x)%2)<<i),0);
 const fixtures=[0b10100010,0b01010101,0b11110000,0b00001111,0b10000000,0b11111110];
 for(let a=0;a<N;a++)for(let b=0;b<N;b++)for(let c=0;c<N;c++){let rows=[a,b,c],image=new Set(Array.from({length:N},(_,i)=>apply(rows,i)));if(image.size!==N)continue;matrices++;
 for(let cf of fixtures){let d=deg(cf,n),tt=mobius(cf,n);for(let mask=0;mask<N;mask++){let newtt=0;for(let z=0;z<N;z++)newtt|=((tt>>(apply(rows,z)^mask))&1)<<z;check(deg(mobius(newtt,n),n)===d);check(pop(newtt)===pop(tt));affine++}}}
 check(matrices===168);
 return {run:582,assertions,polynomials:polys,minimum_weights:mins,affine_bijections:matrices,affine_cases:affine,quantum_executed:false,practical_wkem:false}
}
if(typeof module!=="undefined")module.exports=main;
