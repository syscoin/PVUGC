#!/usr/bin/env python3
"""Exhaustive semantic quotient test, not FE/WE or source-authenticated evidence."""
import hashlib,json
for width in [4,8,12]:
    a=(1<<(width-1))|(1<<(width//2))|1
    counts=[0]*width
    for b in range(1<<width):
        if b==a:
            continue
        z=a^b
        category=z.bit_length()-1
        # The category captures the highest differing bit, a canonical first bit in MSB order.
        assert category in range(width)
        assert (a^b)&(~((1<<(category+1))-1))==0
        assert ((a^b)>>category)&1==1
        counts[category]+=1
    assert sum(counts)==(1<<width)-1
    assert sorted(counts)==[1<<i for i in range(width)]
    print(json.dumps({'width':width,'ancestor':a,'class_counts':counts,'total':sum(counts)},sort_keys=True))
