#!/usr/bin/env python3
from secrets import randbelow
from damgard_jurik.crypto import PublicKey, keygen
from gmpy2 import mpz
import hashlib 
import math

public_key, private_key_ring = keygen(n_bits=512, s=1, threshold=3, n_shares=3)

def encrypt_zk(i:int, r: int):
    # Taken from library 
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
    
def verify_M(u:int, a:int, z:int, e:int):
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
        print("True for u: ", u)

        return True
    else:
        print("False for u: ", u)
        return False


def perform_M(v: int):
    
    u = prover_generates_u(v)
    a,r = prover_generates_a()
    e_hash =  hashlib.sha256(str(a).encode())
    e = int(e_hash.hexdigest(),16) % public_key.n
    z = prover_generates_z(r, v, e)
    return u, a, z, e, r

def generate_proof(v1 : int, v2: int):
    u2, a2, z2, e2, r2 = perform_M(v2)
    print("Value of r2 is: ", r2)
    print("Value of u2 is: ", u2)
    print("Value of a2 is: ", a2)
    print("Value of e2 is: ", e2)
    print("Value of z2 is: ", z2)
    u1 = prover_generates_u(v1)
    a1,r1 = prover_generates_a()
    s_hash =  hashlib.sha256(str(a1).encode())
    s = int(s_hash.hexdigest(),16) % public_key.n
    e1 = ( s - e2 ) % public_key.n
    z1 = prover_generates_z(r1, v1, e1)
    return s, u1, u2, a1, a2, r1, r2, e1, e2, z1, z2
    
def verify(s,u1, u2, e1, e2, z1, z2, a1, a2):
    if( s != (e1 + e2) % public_key.n):
        print("S is not equal to e1 + e2")
        return False

    checkhash = hashlib.sha256(str(a2).encode())
    checkNum = int(checkhash.hexdigest(),16) % public_key.n
    if(checkNum != e2):
        print("e2 not corresponding to committed value of a2")
        return False
    checkhash = hashlib.sha256(str(a1).encode())
    checkNum = int(checkhash.hexdigest(),16) % public_key.n
    if(checkNum != s):
        print("s not corresponding to commited value of a1")
        return False
    
    if(verify_M(u1, a1, z1, e1) and verify_M(u2, a2, z2, e2) ):
        return True
    else:
        return False



def test_zk_system():
    v1 = int(input("Please enter value of v1: "))
    v2 = int(input("Please enter value of v2: "))
    s, u1, u2, a1, a2, r1, r2, e1, e2 ,z1, z2 = generate_proof(v1,v2)

    print("Value of r1 is: ", r1)
    print("Value of u1 is: ", u1)
    print("Value of a1 is: ", a1)
    print("Value of e1 is: ", e1)
    print("Value of z1 is: ", z1)


    result = verify(s, u1, u2, e1, e2, z1, z2, a1, a2)
    print("ZK System Verified to: ", result)


test_zk_system()
