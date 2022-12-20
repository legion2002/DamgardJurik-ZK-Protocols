#!/usr/bin/env python3
from secrets import randbelow
from damgard_jurik.crypto import PublicKey, keygen
from gmpy2 import mpz
import math

public_key, private_key_ring = keygen(n_bits=512, s=1, threshold=3, n_shares=3)

def encrypt_zk(i:int, r: int):
    c = pow(public_key.n + 1, i, public_key.n_s_1) * pow(r, public_key.n_s, public_key.n_s_1) % public_key.n_s_1
    return c

# We will take input v, and then generate u according to u = E(0,v)
# In practical cases, prover would compute the v corresponding to a given u
def prover_generates_u(v: int):
    return encrypt_zk(0, v)

def prover_generates_a():
    r = mpz(randbelow(public_key.n - 1)) + 1
    a = encrypt_zk(0, r)
    return a, r
    

def verifier_generates_e():
    e = mpz(randbelow(public_key.n - 1)) + 1
    return e
    
def prover_generates_z(r:int, v:int, e: int):
    z = r * pow(v, e, public_key.n) % public_key.n
    return z
    
def verifier_verifies(u:int, a:int, z:int, e:int):
    # check that u, a and z are prime to n
    if( math.gcd(u, public_key.n) != 1):
        print("u is not prime to n")
        return False
    if( math.gcd(a, public_key.n) != 1):
        print("a is not prime to n")
        return False
    if( math.gcd(z, public_key.n) != 1):
        print("a is not prime to n")
        return False

    lhs = encrypt_zk(0,z)
    rhs =  a * pow(u, e, public_key.n_s_1) % public_key.n_s_1
    if(lhs == rhs):
        return True
    else:
        return False


def test_zk_system():
    v = int(input("Please enter value of v: "))
    u = prover_generates_u(v)
    print("Value of u is: ", u)
    a,r = prover_generates_a()
    print("Value of a is: ", a)
    print("Value of r is: ", r)

    e = verifier_generates_e()
    print("Value of e is: ", e)
    z = prover_generates_z(r, v, e)
    print("Value of z is: ", z)
    
    result = verifier_verifies(u, a, z, e)
    print("Verified to: ", result)


test_zk_system()
    





