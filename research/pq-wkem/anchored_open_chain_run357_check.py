#!/usr/bin/env python3
"""Run 357: exhaustive finite permutation-frame release-boundary checks.
This is an exact finite check, not a PQ or generic obfuscation security proof.
"""
import itertools
import collections
import json
from fractions import Fraction

ASSERTIONS = 0

def check(condition, label):
    global ASSERTIONS
    ASSERTIONS += 1
    if not condition:
        raise AssertionError(f"assertion {ASSERTIONS}: {label}")


def perms(n):
    return list(itertools.permutations(range(n)))


def compose(a, b):
    return tuple(a[b[j]] for j in range(len(a)))


def inv(a):
    r = [None] * len(a)
    for i, x in enumerate(a):
        r[x] = i
    return tuple(r)


def path_edges(g, frames):
    return tuple(compose(compose(frames[i + 1], g[i]), inv(frames[i]))
                 for i in range(len(g)))


def path_product(edges):
    ret = tuple(range(len(edges[0])))
    for edge in edges:
        ret = compose(edge, ret)
    return ret


def histogram(g, interior, output, source):
    hist = collections.Counter()
    for left in source:
        for mid in itertools.product(interior, repeat=len(g)-1):
            for right in output:
                frames = (left,) + mid + (right,)
                hist[path_edges(g, frames)] += 1
    return hist


def tv(a, b):
    sa, sb = sum(a.values()), sum(b.values())
    return sum(abs(Fraction(a.get(v,0),sa)-Fraction(b.get(v,0),sb))
               for v in a.keys() | b.keys()) / 2


def edge_uniform(hist, group, index):
    buckets = collections.Counter()
    for edges, freq in hist.items():
        buckets[edges[index]] += freq
    check(len(buckets) == len(group), f'full single-edge support {index}')
    for p in group:
        check(buckets[p] == sum(hist.values()) // len(group),
              f'perfect single-edge marginal {index}')

G = perms(4)
identity = tuple(range(4))
D = (0,0,1,1)
H = [p for p in G if all(D[p[i]] == D[i] for i in range(4))]
check(len(G) == 24 and len(H) == 4, 'group cardinalities')
check(all(D[p[i]]==D[i] for p in H for i in range(4)), 'decoder stabilizer')

# Two-edge, public source anchor, output frame randomized only within decoder stabilizer.
histograms = {}
for g in G:
    h = histogram((identity,g), G, H, (identity,))
    check(sum(h.values()) == 96 and len(h) == 96, '2-edge coset size and uniqueness')
    for edges, count in h.items():
        check(count == 1, 'unique frames for anchored source')
        product = path_product(edges)
        check(any(product == compose(p,g) for p in H), 'coset constraint')
        for x in range(4):
            check(D[product[x]] == D[g[x]], 'public decoded semantic function')
    edge_uniform(h,G,0)
    edge_uniform(h,G,1)
    histograms[g] = h

counts = collections.Counter()
for g0 in G:
    for g1 in G:
        expected = int(tuple(D[g0[x]] for x in range(4)) !=
                       tuple(D[g1[x]] for x in range(4)))
        distance = tv(histograms[g0],histograms[g1])
        check(distance == expected, 'exact zero-or-one coset TV law')
        counts[str(expected)] += 1
check(counts['0'] == 24*4 and counts['1'] == 24*20, 'equivalence class census')

g_shift = (2,3,0,1)  # (0 2)(1 3), even permutation
h_inside = (1,0,2,3) # within H, odd permutation
check(g_shift not in H and h_inside in H, 'fixture group classes')
check(tv(histograms[identity],histograms[g_shift]) == 1,
      'same-parity cross-partition transformation perfectly distinguished')
check(tv(histograms[identity],histograms[h_inside]) == 0,
      'different-parity decoder-equivalent transformation perfectly hidden')

# 3-edge path: additional interior frames do not change the leakage verdict.
three = {}
for g in (identity, g_shift, h_inside):
    hh = histogram((identity,identity,g), G, H, (identity,))
    check(sum(hh.values()) == 2304 and len(hh) == 2304,
          '3-edge coset support')
    for edges in hh:
        check(D[path_product(edges)[0]] == D[g[0]],
              '3-edge public output decoder')
    for i in range(3):
        edge_uniform(hh, G, i)
    three[g] = hh
check(tv(three[identity],three[g_shift]) == 1, '3-edge disjoint-support attack')
check(tv(three[identity],three[h_inside]) == 0, '3-edge identical-support control')

# If output frame is unconstrained and unreported, the *entire* edge tuple is uniform.
free = histogram((identity,identity), G, G, (identity,))
check(len(free) == 24**2 and set(free.values()) == {1},
      'free output, anchored source: full joint uniformity')
free_other = histogram((identity,g_shift), G, G, (identity,))
check(free == free_other, 'no leak when output frame wholly unanchored')

# If input encoding frame is also independent and secret, even a decoder-stabilized
# output frame does not distinguish semantic programs in the public edge tuple alone.
input_hidden = histogram((identity,identity), G, H, G)
input_hidden_other = histogram((identity,g_shift), G, H, G)
check(len(input_hidden) == 24**2 and set(input_hidden.values()) == {4},
      'hidden input frame gives uniform complete edge tuple')
check(input_hidden == input_hidden_other,
      'no public-edge leak if input frame is hidden')

# Fix both boundary frames. Each individual gate remains uniform, but the composite
# is publicly exactly the semantic program.
both_fixed_0 = histogram((identity,identity), G, (identity,), (identity,))
both_fixed_1 = histogram((identity,g_shift), G, (identity,), (identity,))
check(tv(both_fixed_0,both_fixed_1) == 1, 'both-known anchors: complete leak')
for edges in both_fixed_0:
    check(path_product(edges) == identity, 'both-fixed product identity')
for edges in both_fixed_1:
    check(path_product(edges) == g_shift, 'both-fixed product alternative')
for i in range(2):
    edge_uniform(both_fixed_0,G,i)
    edge_uniform(both_fixed_1,G,i)

# Same structural observation on S3, with a single known anchor or none.
GG = perms(3)
I3 = tuple(range(3))
g3 = (1,2,0)
rooted = histogram((I3,g3),GG,GG,(I3,))
free_rooted = histogram((I3,I3),GG,GG,(I3,))
check(rooted == free_rooted and len(rooted)==len(GG)**2,
      'S3 free output rooted path jointly uniform')

summary = {
    'run':357,
    'status':'PASS',
    'assertions':ASSERTIONS,
    'group_order':24,
    'decoder_stabilizer_order':4,
    'source_anchored_output_decoder_paths':{
       'edge_count_2':{'frame_samples_per_semantics':96,
                       'support_size':96,
                       'tv_equivalent_pairs':counts['0'],
                       'tv_disjoint_pairs':counts['1']},
       'edge_count_3':{'frame_samples_per_semantics':2304,
                       'support_size':2304,
                       'same_parity_different_decoder_tv':'1',
                       'decoder_equivalent_different_parity_tv':'0'},
    },
    'controls':{'free_output_joint_uniform_size':len(free),
                'hidden_input_joint_uniform_size':len(input_hidden),
                'both_fixed_boundaries_tv':'1'},
    'scope':'Exact finite group/coset and decoder-boundary identities; not WKEM or QPT hardness.'
}
print(json.dumps(summary,indent=2,sort_keys=True))
