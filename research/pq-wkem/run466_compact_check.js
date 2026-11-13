function run466() {
  let assertions=0, controls=0, fixtures=0;
  function assert(x) { if (!x) throw Error("run466 failed"); assertions++; }
  function step(s,m) { return (5*s+1)%m; }
  for (const m of [4,8]) {
    const orbit=[]; let s=0;
    for(let t=0;t<m;t++){ orbit.push(s); s=step(s,m); }
    assert(s===0); assert(new Set(orbit).size===m);
    for(let mask=1;mask<(1<<m);mask++) {
      fixtures++;
      let hit=false;
      for (const state of orbit) {
        controls++;
        if ((mask & (1<<state)) !== 0) {hit=true; break;}
      }
      assert(hit);
    }
  }
  let states=new Set([0]);
  for(let i=0;i<12;i++) {
    const next=new Set();
    for(const v of states){ next.add(v*2); next.add(v*2+1); }
    states=next;
  }
  assert(states.size===4096);
  return {run:466,status:"PASS",assertions,nonempty_acceptance_fixtures:fixtures,
          total_candidate_evaluations:controls,
          binary_control_states:states.size,
          conclusion:"finite enumerability only; not cryptographic security"};
}
if (typeof console !== "undefined") console.log(JSON.stringify(run466(),null,2));
