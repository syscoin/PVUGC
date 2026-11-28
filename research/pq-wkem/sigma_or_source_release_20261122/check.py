#!/usr/bin/env python3
"""Synthetic Sigma-OR source-to-planted-secret attempt. NOT WKEM/FE nor Bitcoin authentication.

Finite cyclic group for checking transcript equations, not a cryptographic assumption.
"""
import hashlib, json
P, Q = 607, 101
G = pow(2, (P-1)//Q, P)
assert pow(G,Q,P)==1 and G!=1

def inv(v):return pow(v,-1,P)
def pub(x):return pow(G,x,P)
def sim_a(y,e,z):return (pub(z)*inv(pow(y,e,P)))%P
def verify(y,a,e,z):return pub(z)==(a*pow(y,e,P))%P

def instance(r,w,seed):
    # In actual setup w is UNKNOWN; only y_w is public. Source w enters afterward.
    def rand(k):return int.from_bytes(hashlib.sha256(f'{seed}|{k}'.encode()).digest(),'big')%Q
    yr,yw=pub(r),pub(w)
    t_r=rand('t_r'); a_r=pub(t_r); e_r=rand('e_r'); z_r=(t_r+e_r*r)%Q
    e_w0=rand('e_w0'); z_w0=rand('z_w0'); a_w=sim_a(yw,e_w0,z_w0)
    assert verify(yr,a_r,e_r,z_r) and verify(yw,a_w,e_w0,z_w0)
    e_0=(e_r+e_w0)%Q
    # Recipient with source witness w discovers the exact simulator nonce t_w,
    # and reopens SOURCE arm at any challenge, leaving SECRET arm untouched.
    t_w=(z_w0-e_w0*w)%Q
    assert a_w==pub(t_w)
    e_w1=(e_w0+1)%Q; z_w1=(t_w+e_w1*w)%Q; e_1=(e_r+e_w1)%Q
    assert verify(yw,a_w,e_w1,z_w1) and verify(yr,a_r,e_r,z_r)
    assert e_1!=e_0
    extracted_w=((z_w1-z_w0)*pow((e_w1-e_w0)%Q,-1,Q))%Q
    assert extracted_w==w
    # Challenge change in secret arm instead requires an unavailable response.
    e_r1=(e_r+1)%Q
    z_r1_required=(t_r+e_r1*r)%Q
    # If published, this one additional SECRET response reveals r to everyone.
    extracted_r=((z_r1_required-z_r)*pow((e_r1-e_r)%Q,-1,Q))%Q
    assert extracted_r==r
    # sigma_i is a frozen native cancellation capability associated with r,
    # not generated here: publication of two secret-arm transcripts exposes r.
    return {'first_overall_challenge':e_0, 'second_overall_challenge':e_1,
            'source_reopening_extracts_source_witness':extracted_w==w,
            'secret_arm_remains_on_same_challenge':True,
            'publishing_second_secret_response_exposes_setup_secret':extracted_r==r,
            'source_public_statement_is_preselected_y_w':yw}

def main():
    rows=[]
    for k in range(32):
        r=int.from_bytes(hashlib.sha256(b'planted'+bytes([k])).digest(),'big')%Q
        w=int.from_bytes(hashlib.sha256(b'source'+bytes([k])).digest(),'big')%Q
        rows.append(instance(r,w,k))
    out={'scope':'algebraic Sigma-OR control only; NOT FE, not secure at toy parameters, no ORIGINAL source release',
         'p':P,'q':Q,'generator':G, 'fixtures':len(rows),
         'all_source_reopenings_extract_w_only':all(x['source_reopening_extracts_source_witness'] and x['secret_arm_remains_on_same_challenge'] for x in rows),
         'all_extra_secret_arm_responses_expose_r':all(x['publishing_second_secret_response_exposes_setup_secret'] for x in rows),
         'one_fixture':rows[0],
         'missing_original_gate':True,
         'not_security_test':True}
    print(json.dumps(out,sort_keys=True,indent=2))
if __name__=='__main__':main()
