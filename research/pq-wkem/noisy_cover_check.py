import itertools, math, random, json
from fractions import Fraction

def parity_bias_exact(length, p):
    plus = Fraction(0,1)
    minus = Fraction(0,1)
    for bits in itertools.product((0,1), repeat=length):
        wt=sum(bits)
        prob=(p**wt)*((1-p)**(length-wt))
        if wt%2==0: plus += prob
        else: minus += prob
    return plus-minus

def exact_binary_control():
    p=Fraction(1,4)
    n=2
    honest=parity_bias_exact(n,p)
    false=parity_bias_exact(5*n,p)
    eta=1-2*p
    assert honest==eta**n
    assert false==eta**(5*n)
    assert false==honest**5
    return {
        "p": "1/4",
        "n": n,
        "eta": f"{eta.numerator}/{eta.denominator}",
        "honest_bias": f"{honest.numerator}/{honest.denominator}",
        "false_bias": f"{false.numerator}/{false.denominator}",
        "honest_bias_power_5": f"{(honest**5).numerator}/{(honest**5).denominator}",
        "honest_success": float((1+honest)/2),
        "false_success": float((1+false)/2),
        "enumerated_noise_vectors_honest": 2**n,
        "enumerated_noise_vectors_false": 2**(5*n),
    }

def rational_identity_checks():
    rng=random.Random(2026092201)
    checked=0
    for _ in range(1000):
        den=rng.randint(2,40)
        num=rng.randint(0,den)
        eta=Fraction(num,den)
        n=rng.randint(1,25)
        assert (eta**n)**5 == eta**(5*n)
        checked+=1
    return checked

def multi_operator_checks():
    rng=random.Random(2026092202)
    checked=0
    samples=[]
    for trial in range(500):
        n=rng.randint(1,12)
        N=rng.randint(1,8)
        etas=[]
        for _ in range(N):
            den=rng.randint(2,20)
            num=rng.randint(0,den)
            etas.append(Fraction(num,den))
        gh=Fraction(1,1)
        gf=Fraction(1,1)
        for e in etas:
            gh*=e**n
            gf*=e**(5*n)
        assert gf==gh**5
        checked+=1
        if trial<3:
            samples.append({
                "n":n,"operators":N,
                "honest_bias":f"{gh.numerator}/{gh.denominator}",
                "false_bias":f"{gf.numerator}/{gf.denominator}"
            })
    return checked,samples

def gaussian_success(t, cover_factor=1):
    return math.erf(t/math.sqrt(2*cover_factor))

def gaussian_controls():
    margins=[2.0,3.0,4.0,6.0,math.sqrt(128.0)]
    rows=[]
    for t in margins:
        ph=gaussian_success(t,1)
        pf=gaussian_success(t,5)
        rows.append({"t":t,"honest_success":ph,"false_cover_success":pf})
    return rows

def gaussian_monte_carlo():
    rng=random.Random(2026092203)
    n=64
    sigma=1.0
    t=3.0
    threshold=t*math.sqrt(n)*sigma
    trials=200000
    good_h=good_f=0
    for _ in range(trials):
        zh=rng.gauss(0.0, math.sqrt(n)*sigma)
        zf=rng.gauss(0.0, math.sqrt(5*n)*sigma)
        good_h += abs(zh)<threshold
        good_f += abs(zf)<threshold
    empirical_h=good_h/trials
    empirical_f=good_f/trials
    analytic_h=gaussian_success(t,1)
    analytic_f=gaussian_success(t,5)
    assert abs(empirical_h-analytic_h)<0.003
    assert abs(empirical_f-analytic_f)<0.003
    return {
        "n":n,"sigma":sigma,"t":t,"trials":trials,
        "analytic_honest":analytic_h,
        "empirical_honest":empirical_h,
        "analytic_false_cover":analytic_f,
        "empirical_false_cover":empirical_f,
    }

def explicit_cover_table_checks():
    rng=random.Random(2026092204)
    q=101
    n=7
    pi={0:1,1:0,2:3,3:4,4:2}
    checks=0
    for _ in range(500):
        ks=[rng.randrange(q) for _ in range(n)]
        K=sum(ks)%q
        pads=[[rng.randrange(q) for _ in range(5)] for _ in range(n)]
        noise=[[rng.randrange(-2,3) for _ in range(5)] for _ in range(n)]
        def tau(i,s):
            return s if i<n-1 else pi[s]
        Y=[[0]*5 for _ in range(n)]
        T=[[0]*5 for _ in range(n)]
        for i in range(n):
            ni=(i+1)%n
            for s in range(5):
                dst=tau(i,s)
                T[i][s]=(ks[i]+pads[i][s]-pads[ni][dst])%q
                Y[i][s]=(T[i][s]+noise[i][s])%q
        def orbit_sum(states, table):
            total=0
            for start in states:
                s=start
                for i in range(n):
                    total=(total+table[i][s])%q
                    s=tau(i,s)
            return total
        A2=orbit_sum([0,1],Y)
        A3=orbit_sum([2,3,4],Y)
        clean2=orbit_sum([0,1],T)
        clean3=orbit_sum([2,3,4],T)
        assert clean2==(2*K)%q
        assert clean3==(3*K)%q
        z2=sum(noise[i][s] for i in range(n) for s in [0,1])%q
        z3=sum(noise[i][s] for i in range(n) for s in [2,3,4])%q
        assert A2==(2*K+z2)%q
        assert A3==(3*K+z3)%q
        assert (A3-A2)%q==(K+z3-z2)%q
        checks+=1
    return {"q":q,"n":n,"trials":checks}

def polynomial_bias_table():
    return [{"a":a,"honest_exponent":a,"false_exponent":5*a} for a in range(1,9)]

out={
    "status":"PASS",
    "exact_binary":exact_binary_control(),
    "rational_identity_checks":rational_identity_checks(),
    "multi_operator":{},
    "gaussian_analytic":gaussian_controls(),
    "gaussian_monte_carlo":gaussian_monte_carlo(),
    "explicit_cover_table":explicit_cover_table_checks(),
    "inverse_polynomial_bias_exponents":polynomial_bias_table(),
}
count,samples=multi_operator_checks()
out["multi_operator"]={"checks":count,"sample_cases":samples}
print(json.dumps(out,indent=2,sort_keys=True))
