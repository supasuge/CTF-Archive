# Cert (Crypto)
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)
- Category: Cryptography
- Difficulty: Easy


Provided download `cert.py`:

```python
message = "Sign \"admin\" for flag. Cheers, "
m = 147375778215096992303698953296971440676323238260974337233541805023476001824
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581339496966919577443709945261868529023522932989623577005570770318555545829416559256628409790858255069196868638535981579544864087110789571665244161
e = 65537
signature = 20661001899082038314677406680643845704517079727331364133442054045393583514677972720637608461085964711216045721340073161354294542882374724777349428076118583374204393298507730977308343378120231535513191849991112740159641542630971203726024554641972313611321807388512576263009358133517944367899713953992857054626
assert(m == bytes_to_long(message.encode()))
print(long_to_bytes(m))
```

Remote connection:

```bash
nc chall.polygl0ts.ch 9024
Sign "admin" for flag. Cheers, 1d6c1823b1493029df1787795890f32f99bcb618ba0a57b7bcc10890c2c5a04326768125ef1cdb012e721c61d878acc826391b7cd4e20ea6f271e72eec5b048e97f151e808b1908533cb68824e93ad79837402acf1886ee1c81d1e89b4da0e23bcf0d6f1d7e1a066bb8f3257e4c8afcb2658c61e1b01edf0e15737f025c36da2
>
```

## Explanation

This challenge involves RSA signature's. We are given $N$, $e$, $m$, and $s$, the public key, public exponent, plaintext message expressed as an integer, and the signature of the message. To solve this challenge, we need to forge a signature for the message "admin". Within RSA signatures, the presence of a single known correct message-signature pair allows for recovery of the private key.
Remember that RSA signatures are computed as $s = m^d \mod N$.

This attack is asa follows:
1. Compute $gcd(m - s^e, N, N)$

- If the result is not 1, then we have found the two prime factors of $N$.

Once we have the two prime factors of $N$, we can compute the private exponent $d$ as $d = e^{-1} \mod \phi(N)$ then use this to forge a signature for any message $m$ as $s = m^d \mod N$.

## Solution Code + Output

```python
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from math import gcd
# Given parameters 
N = 128134160623834514804190012838497659744559662971015449992742073261127899204627514400519744946918210411041809618188694716954631963628028483173612071660003564406245581339496966919577443709945261868529023522932989623577005570770318555545829416559256628409790858255069196868638535981579544864087110789571665244161
e = 65537
m_known = 147375778215096992303698953296971440676323238260974337233541805023476001824
signature_known = 20661001899082038314677406680643845704517079727331364133442054045393583514677972720637608461085964711216045721340073161354294542882374724777349428076118583374204393298507730977308343378120231535513191849991112740159641542630971203726024554641972313611321807388512576263009358133517944367899713953992857054626
# Source: https://github.com/jvdsn/crypto-attacks
def attack_known_m(n, e, m, s):
    """
    Recovers the prime factors from a modulus using a known message and its faulty signature.
    n: the modulus
    e: the public exponent
    m: the message
    s: the faulty signature
        return: a tuple containing the prime factors, or None if the signature wasn't actually faulty.
    """
    g = gcd(m - pow(s, e, n), n)
    return None if g == 1 else (g, n // g)


target_message = "admin"
m_target = bytes_to_long(target_message.encode())
factors = attack_known_m(N, e, m_known, signature_known)

if factors:
    p, q = factors
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    forged_signature = pow(m_target, d, N)
else:
    forged_signature = None

conn = remote('chall.polygl0ts.ch', 9024)

initial_data = conn.recvuntil(b'> ')
print(initial_data.decode())


if forged_signature is not None:
    forged_sig_hex = hex(forged_signature)[2:].encode()
    conn.sendline(forged_sig_hex)
else:
    conn.sendline(b"Could not forge the signature")


response = conn.recvall(timeout=2)
print(response.decode())
conn.close()
```

### Output

```bash
[+] Opening connection to chall.polygl0ts.ch on port 9024: Done
Sign "admin" for flag. Cheers, 1d6c1823b1493029df1787795890f32f99bcb618ba0a57b7bcc10890c2c5a04326768125ef1cdb012e721c61d878acc826391b7cd4e20ea6f271e72eec5b048e97f151e808b1908533cb68824e93ad79837402acf1886ee1c81d1e89b4da0e23bcf0d6f1d7e1a066bb8f3257e4c8afcb2658c61e1b01edf0e15737f025c36da2
 > 
[+] Receiving all data: Done (36B)
[*] Closed connection to chall.polygl0ts.ch port 9024
EPFL{Fau17Y_5igNs_Ar3_al!_y0U_ne3D}
```

### Summary
This challenge involves using the known plaintext message $m$ and its known signature $s$ to find the prime factors of $N$ and then using this to forge a signature for the message `admin`. After sending this to the server, we receive the flag.
