# TamuCTF - Smelter (Crypto)
- **Author**: Evan Pardon | [supasuge](https://github.com/supasuge)
- **Category**: Crypto
- **Difficulty**: Medium/Hard
- **Points**: 400
- **Flag**: `gigem{h0p3fully_y0u_r3aliz3_that_e=3_is_bad_n0w}`
- **Date**: `03/29/25`

---
## Files
- `crypto.py`: Contains the RSA code for signing of messages, verification of signatures, and encryption.
- `utils.py`: Utility functions for cryptographic functionality/session management.
- `main.py`: Main flask functionality/endpoint handling.


### Challenge Overview

In this crypto challenge "smelter", we're given a Flask web application that manages user sessions through RSA-signed cookies. Our goal is simply forge a session cookie as the `admin` user.

For example:

```sh
{"user": "admin", "signature": "N2Z9bWHgn76tiKhU0h3iEO4DC..........................."}
```


### Vulnerable part of  code (`crypto.py`)

```python
e = 3 

# Signature verification code snippet:
def verify(message: bytes, signature: bytes) -> bool:
    h = sha256(message).digest()
    signature = bytes_to_long(signature)
    signature = pow(signature, e, n)
    signature = long_to_bytes(signature, 256)
    signed_h = decode(signature)
    return h == signed_h
```

This implementation directly performs RSA verification without rigorously validating PKCS#1 v1.5 padding. This critical oversight opens the door for Bleichenbacher's RSA signature forgery attack.

---

### Understanding the vulnerability - RSA signature verification & the Bleichenbacher attack

This challenge uses a low public exponent ($e=3$), combined with improper validation of PKCS#1 v1.5 padding during signature verification beyond simply copmparing hashes.

Normally, RSA signatures are verfied by:
1. Computing $m = \text{signature}^{e} \pmod n$
2. Then confirming $m$ adheres strictly to PKCS#1 v1.5 formatting, including ASN.1 encoding and padding.

The vulnerability arises when implementations fail to fully validate the padding format. This enables attackers to craft forged signatures that superficially pass verification by carefully structing the signature's cubed value to start with the expected padding structure, despite containing incorrect data elsewhere.

---

#### Why the Low Public Exponent Matters

With $e=3$, the attacker can easily compute cube roots of specially crafted messages. High exponents would make this impractical due to computational complexity which mitigate such attacks.

---

## Step-by-Step Solution

### Step 1: Analyzing Provided Source Code

The provided verification function (`crypto.py`) directly checks hashes without rigorously validating the entire PKCS#1 padding structure:

```python
def verify(message: bytes, signature: bytes) -> bool:
    h = sha256(message).digest()
    signature = pow(bytes_to_long(signature), e, n)
    signature = long_to_bytes(signature, 256)
    signed_h = decode(signature)
    return h == signed_h
```

Crucially, it **only validates that the final hash matches**, ignoring intermediate padding correctness.

### Step 2: Crafting the Forged Signature

We used the `SignatureForger` from [Bleichenbacher Signature Forger](https://github.com/hoeg/BleichenbacherSignatureForger) to exploit this specific scenario:

```python
forger = SignatureForger(
    keysize=key.size_in_bits(),
    hashAlg="SHA-256",
    public_exponent=e,
    ffcount=8,
    quiet=False,
)

forged_signature = forger.forge_signature_with_garbage_end("admin")
```

This method works by:

- Constructing a nearly valid PKCS#1 v1.5 padded message.
    
- Filling the remainder with "garbage" data.
    
- Computing the cube root of this message to produce a seemingly valid signature.
    

### Step 3: Local Verification (Sanity Check)

We confirmed locally:

```python
verified = pow(int.from_bytes(forged_signature, byteorder='big'), e, n)
verified_bytes = verified.to_bytes((verified.bit_length() + 7) // 8, 'big')
if sha256(message.encode()).digest() in verified_bytes:
    print("[+] Signature verification successful locally!")
```

This ensured our forged signature would bypass the flawed server-side validation.

### Step 4: Crafting and Using the Session Cookie

With our signature validated, we constructed a new session cookie for user `admin`:

```python
data = {
    "username": "admin",
    "signature": b64encode(forged_signature).decode()
}
session_cookie = b64encode(json.dumps(data).encode()).decode()
```

We then used this cookie to authenticate:

```python
cookies = {"smelter-session": session_cookie}
response = requests.get(url, cookies=cookies)
```

Full source code:

```python
#!/usr/bin/env python3

from hashlib import sha256
from Crypto.PublicKey import RSA
from base64 import b64encode
import json
import requests
from forgelib import SignatureForger
import re
PEM = """-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQB8HTNWyTtV+kkwv8RB9Qqn
ohrXg4y2X6SjKUCpVCZNBRE7iL7wlmTXaAUdXr7uSIQy0se/O8vunxqO8xZjYAq9
yJn9NcYbx8qSbAQUpUfmL4vTLhLeS4X8Ml4GtEEXCQTajg2lHEafeRvTr0G8UlXY
E9Bcy6LDEPmQ7zD/0kvfHEEExKA/cSDQMNsHJaDQOhlN01N6XQWBBvskt76L2Jz1
PTutUkEWnJG0MTR7HuGQV7+fjAYjxXZNXBXHq71LX9pvVATvs3F9btwIm950mgcs
eQ2+u+Ozud14jwydG7iK4aTAlKEcs5Wl4wuVcAlT87IZRzS6ieazeS53VMFeHX7z
AgED
-----END PUBLIC KEY-----"""

key = RSA.import_key(PEM)
n, e = key.n, key.e
print(f"[+] RSA Public key parameters: [+]")
print(f"[+] n {n}\te = {e} [+]\n")
# Use a message with odd hash last byte (confirmed working)
message = "admin"  # Try "admin\n" or " admin"

# Forge RSA signature using SignatureForger
forger = SignatureForger(
    keysize=key.size_in_bits(),
    hashAlg="SHA-256",
    public_exponent=e,
    ffcount=8,
    quiet=False,
)

forged_signature = forger.forge_signature_with_garbage_end(message)
print(f"[+] un-padded forged signature: {forged_signature} [+]")
# Verify forged signature locally
verified = pow(int.from_bytes(forged_signature, byteorder='big'), e, n)
verified_bytes = verified.to_bytes((verified.bit_length() + 7) // 8, 'big')

if sha256(message.encode()).digest() in verified_bytes:
    print("[+] Signature verification successful locally! [+]")
else:
    print("[-] Signature verification failed locally! [-]")
    exit(1)

# Create session cookie
data = {
    "username": message.strip(),  # Strip newline if server expects 'admin'
    "signature": b64encode(forged_signature).decode()
}
session_cookie = b64encode(json.dumps(data).encode()).decode()
print("[+] Forged session cookie:", session_cookie, " [+]")

# Make request to get flag
url = "https://smelter.tamuctf.com/"
cookies = {"smelter-session": session_cookie}

response = requests.get(url, cookies=cookies, allow_redirects=True, timeout=5)
pattern = r'gigem\{.*\}'
flag = re.search(pattern, response.text)
if flag:
    flag = flag.group(0)
    #flag = flag.group(1)
print(f"[+] Flag found: {flag} [+]")
```


---

###### Resources and Research
Resource used to help solve the challenge:
- [Bleichenbacher's Signature Forgery](https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/) – Original research article and example by Filippo Valsorda.
- [IETF Mailing Archive Discussion](https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html) – Discussing the specific vulnerability scenario and signature forgery.
- [RSA Bleichenbacher Signature](https://github.com/maximmasiutin/rsa-bleichenbacher-signature/blob/master/SignatureForgerLib.py)

