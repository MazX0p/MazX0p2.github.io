---
title: TwoTimesHack
date: 2021-12-01 23:32:00 +0300
categories: [Writeup, AtHackCTF]
tags: [AtHackCTF]     # TAG names should always be lowercase
---






 



### Description:

Crypto

### Difficulty:

`easy`

### Flag:

Flag: `AtHackCTF{F4ct0r_1t_cuBe_i7_R5A_S71ll_8r0k3n!!}`


### Solve

this challenge need to get the massage on the challenge description and xor it with the flag hex on python script, and xor the flag with the msg on the python script

then we will got a hex code after decode it we will got the flag with ZzZz!! thats equals to "^_^", so i wrote a script with sagemath to solve it with help of output.bin file as follow 

```

from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import gmpy2
import time
import random

def AMM(o, r, q):
    start = time.time()
    print('\n----------------------------------------------------------------------------------')
    print('Start to run Adleman-Manders-Miller Root Extraction Method')
    print('Try to find one {:#x}th root of {} modulo {}'.format(r, o, q))
    g = GF(q)
    o = g(o)
    p = g(random.randint(1, q))
    while p ^ ((q-1) // r) == 1:
        p = g(random.randint(1, q))
    print('[+] Find p:{}'.format(p))
    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s = s // r
    print('[+] Find s:{}, t:{}'.format(s, t))
    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alp = (k * s + 1) // r
    print('[+] Find alp:{}'.format(alp))
    print(p, r, t, s)
    a = p ^ (r**(t-1) * s)
    b = o ^ (r*alp - 1)
    c = p ^ s
    h = 1
    for i in range(1, t):
        d = b ^ (r^(t-1-i))
        if d == 1:
            j = 0
        else:
            print('[+] Calculating DLP...')
            j = - discrete_log(d, a)
            print('[+] Finish DLP...')
        b = b * (c^r)^j
        h = h * c^j
        c = c^r
    result = o^alp * h
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    print('Find one solution: {}'.format(result))
    return result

def findAllPRoot(p, e):
    print("Start to find all the Primitive {:#x}th root of 1 modulo {}.".format(e, p))
    start = time.time()
    proot = set()
    while len(proot) < e:
        proot.add(pow(random.randint(2, p-1), (p-1)//e, p))
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    return proot

def findAllSolutions(mp, proot, cp, p):
    print("Start to find all the {:#x}th root of {} modulo {}.".format(e_fixed, cp, p))
    start = time.time()
    all_mp = set()
    for root in proot:
        mp2 = mp * root % p
        assert(pow(mp2, e_fixed, p) == cp)
        all_mp.add(mp2)
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    return all_mp

c = bytes_to_long(open('output.bin', 'rb').read())
e = int(0x10001 * 3)
n = int(2878484237144058957039174874624090770599900489784647154744423901387428048184111906123929155824159)
p, q, r = map(int, [116912239795315244984923068717187, 158648706275555173588212318392723, 155191288826882271830043206382359])
assert p*q*r == n

phi = (p - 1)*(q - 1)*(r - 1)

# only p - 1 is divisble by 3
# print((p - 1) % 3, (q - 1) % 3, (r - 1) % 3)

_gcd, s, t = gmpy2.gcdext(e, phi)

c_fixed = int(pow(c, int(s % phi), n))
e_fixed = 3
cp = int(c_fixed % p)
cq = int(c_fixed % q)
cr = int(c_fixed % r)

mp = AMM(cp, e_fixed, p)
#mq = AMM(cq, e_fixed, q)
#mr = AMM(cr, e_fixed, r)

p_proot = findAllPRoot(p, e_fixed)
#q_proot = findAllPRoot(q, e_fixed)
#r_proot = findAllPRoot(r, e_fixed)

mps = findAllSolutions(mp, p_proot, cp, p)
#mqs = findAllSolutions(mq, q_proot, cq, q)
#mrs = findAllSolutions(mr, r_proot, cr, r)

dq = int(inverse_mod(e_fixed, q - 1))
dr = int(inverse_mod(e_fixed, r - 1))

mqq = pow(cq, dq, q)
mrr = pow(cr, dr, r)

for mpp in mps:
    #for mqq in mqs:
    #    for mrr in mrs:
    solution = CRT([int(mpp), int(mqq), int(mrr)], [p, q, r])
    print(long_to_bytes(solution))

```
### expline the code :

```
sagemath polynome x**3-c 
coppersmith can solve this since n is too small.
we can calculate the factors of n with alpetron

but the thing is p-1 is divisble by 3
so we need to calculate extended gcd
=> reduce the cipher
and we will work with e=3

=> calculating roots of p,q,r
after we reduce the ciphers cp,cq,cr (c%p and c%q c%r)
and solution of polynome

and we can calculate the chinese remainder theorem to find the message
```

### mathematical :

---------------------------------------------------------------------
The RSA private-key operation (used for decryption and signature generation) amounts to solving for x the equation y≡xe(modN), knowing y, the factorization of the public modulus N into k≥2 distinct primes N=r1…rk, public exponent e such that gcd(e,ri−1)≠1, and that 0≤x<N.

For an efficient implementation, we can solve this equation modulo each of the ri; then use the CRT to combine solutions between products of moduli for which we already have a solution, until reaching a solution modulo N. The common way, implicit in PKCS#1v2 since version 2.1, is:

precompute the following quantities di (the CRT exponents) and ti (the CRT inverses/coefficients), e.g. at key generation time, including the results in the private key:
for i∈{1,…,k}
di←e−1mod(ri−1), or equivalently di←dmod(ri−1)
m←r1
for i from 2 to k - ti←m−1modri - m←m⋅ri
when needing to use the private key and solve y≡xe(modN)
for i∈{1,…,k} [note: should be parallelized if possible]
xi←(ymodri)dimodri
x←x1, m←r1
for i from 2 to k [loop invariant: 0≤x<m, y≡xe(modm) ]
x←x+m⋅((xi−xmodri)⋅timodri)
m←m⋅ri
---------------------------------------------------------------------

and i Got the flag :D 

![image](https://user-images.githubusercontent.com/54814433/144742279-7e5091d7-f2a2-4686-877f-8319479f8276.png)


# revrences

https://crypto.stackexchange.com/questions/31109/rsa-encryption-and-decryption-with-multiple-prime-modulus-using-crt?noredirect=1&lq=1


