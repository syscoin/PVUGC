#!/usr/bin/env python3
"""Run 692: exhaustive finite checks of a witness-liftable 3CNF encoding.
No cryptographic implementation, hardness test, or Syscoin verifier.
"""
import hashlib
import itertools
import json

OPS = ('AND', 'OR', 'XOR', 'NOT')

def apply(op, a, b):
    return {'AND': lambda: a & b, 'OR': lambda: a | b,
            'XOR': lambda: a ^ b, 'NOT': lambda: 1-a}[op]()

def clauses_for(op, a, b, z):
    A,B,Z=a+1,b+1,z+1  # signed DIMACS literals
    if op == 'AND':
        return [(-Z,A), (-Z,B), (Z,-A,-B)]
    if op == 'OR':
        return [(-A,Z), (-B,Z), (-Z,A,B)]
    if op == 'XOR':
        return [(A,B,-Z),(-A,-B,-Z),(A,-B,Z),(-A,B,Z)]
    return [(Z,A),(-Z,-A)]

def sat(clauses, bits):
    return all(any(bits[abs(lit)-1] == (lit > 0) for lit in clause)
               for clause in clauses)

def bound_sat(expected_context, supplied_context, clauses, bits):
    return expected_context == supplied_context and sat(clauses, bits)

def encode(gates):
    cls=[]
    for i,(op,a,b) in enumerate(gates):
        cls.extend(clauses_for(op,a,b,3+i))
    cls.append((3+len(gates),)) # output must equal 1 (DIMACS 1-indexed)
    return cls

def run():
    total=0; source_correct=0; invalid_rejected=0; witness_lifts=0
    for op1 in OPS:
        for a1 in range(3):
            for b1 in ([0] if op1=='NOT' else range(3)):
                gate1=(op1,a1,b1)
                for op2 in OPS:
                    for a2 in range(4):
                        for b2 in ([0] if op2=='NOT' else range(4)):
                            gates=(gate1,(op2,a2,b2)); cls=encode(gates)
                            total+=1
                            for inp in itertools.product((0,1),repeat=3):
                                out=list(inp)
                                for op,a,b in gates:
                                    out.append(apply(op,out[a],out[b]))
                                # The witness-lifting map computes intermediate wires.
                                assert sat(cls,out)==bool(out[-1]); witness_lifts+=1
                                for ext in itertools.product((0,1),repeat=2):
                                    candidate=tuple(inp)+ext
                                    if sat(cls,candidate):
                                        assert candidate==tuple(out) and out[-1]==1
                                        source_correct+=1
                                    else:
                                        invalid_rejected+=1
                                # Fixed relation binds context without changing semantics.
                                claim=('utxo-123','disprove','window-hash')
                                assert bound_sat(claim,claim,cls,out)==bool(out[-1])
                                assert not bound_sat(claim,('utxo-124','disprove','window-hash'),cls,out)
    result={'run':692,'toy_gate_circuits':total,
            'input_witness_lifts_checked':witness_lifts,
            'satisfying_complete_assignments':source_correct,
            'rejected_complete_assignments':invalid_rejected,
            'relation':'fixed 3CNF checker with claim-context binding',
            'claim':'finite witness-lift and soundness of Tseitin grammar only',
            'not_verified':['NP hardness of Syscoin challenge relation',
                             'WE security','local-mixing QPT security',
                             'malicious setup','native signature security']}
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':
    run()
