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

> [!INFO]
> Visit `/dist` to see the actual challenge source code. It's too much to paste here.

### Challenge Overview

In this crypto challenge "smelter", we're given a Flask web application that manages user sessions through RSA-signed cookies. Our goal is simply forge a session cookie as the `admin` user.

For example:

```sh
{"user": "admin", "signature": "N2Z9bWHgn76tiKhU0h3iEO4DC..........................."}
```


### Vulnerable part of  code (`crypto.py`)

```python
e = 3 # <- exponent is too small to safely facilitate RSA signature generation/verification 

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

### Understanding Bleichenbacher's Signature Forgery

The core vulnerability arises due to RSA signature verification using an exponent of `e=3`. With such a small exponent, an attacker can exploit the weak padding validation to forge RSA signatures. Specifically, we leveraged Bleichenbacher’s RSA signature forgery method, allowing us to craft valid-looking signatures without having access to the private key.

---

### Solution

We utilized the excellent `SignatureForger` tool, specifically designed to exploit exactly this scenario.

**Step-by-step Exploitation:**
1. **Identified vulnerable RSA exponent** (`e=3`) from source code.
2. **Crafted RSA forged signature** using the `SignatureForger` class provided by [Bleichenbacher Signature Forger](https://github.com/hoeg/BleichenbacherSignatureForger/tree/master).

Here's the crucial part from our solution:
- 
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

We chose the method `forge_signature_with_garbage_end` due to its simplicity and effectiveness in bypassing padding verification in this situation.

In the snippet below, we simply verify that our forged signature will pass signature verification.

```python
verified = pow(int.from_bytes(forged_signature, byteorder='big'), e, n)
verified_bytes = verified.to_bytes((verified.bit_length() + 7) // 8, 'big')
if sha256(message.encode()).digest() in verified_bytes:
    print("[+] Signature verification successful locally!")
else:
    print("[-] Signature verification failed locally!")
```

Next, once we have verified the signature forgery is working, we simply craft a new session cookie with `admin` as the username.

```python
data = {
    "username": "admin",
    "signature": b64encode(forged_signature).decode()
}
session_cookie = b64encode(json.dumps(data).encode()).decode()
```

Then we send a get request with the forged session cookie, and at which point the flag should appear!

```python
cookies = {"smelter-session": session_cookie}
response = requests.get(url, cookies=cookies, allow_redirects=True)
```

This provided us with authenticated access as the user `admin`.

---

### Solving the Challenge

Running the exploit script resulted in successful authentication as `admin`, returning the flag:

```sh
[+] RSA Public key parameters: [+]
[+] n=15667949140214842553914081513052424377996724215143052305554404543313882498636300141101805351338528340174636001125813387528955453526277076434576150281890277560917916531054740528395477764044367753688304737341448434356613059801372005408317588189782890821697965799187325608844559121028395482175687092271514060510718949381986304363767222817073719745690220696548805916170967649906450173480399927074334858446811879060947599430696491932716987858195782100515074092284964754847170478075557452735447240998706307373503253463347097487869056748957867179629187130467287916756265014821110986264474800239609563860402350346039595990771
    e=3 [+]
[+] Keysize: 2047 bits [+]
[+] Target message: 'admin' [+]
[+] Forging signature (garbage_end variant)...
[+] Cube root check passed: pow(s, e) starts with correct prefix.
[+] Forged signature integer: 995391042663285905082373840334783075535901580439276937985819219650252914039487157091474545981581784425877396098670770309992384352214618744331527956856024258080900739044197348051578986699520002770694398775
[+] Forged signature bytes (hex): 32cbfd4a7adc7905583d767520f51640759176d37826f2ef63ae3dc7aac2a6a2a20414b7e2751b93b14733366c1ae6948ad699d5fa8550eee031c85004694280570c985d735323701d7fbcf078fc65e47209c16337 [+]
[+] Forged signature length: 85 bytes [+]
[+] Performing local verification check...
[-] Local verification FAILED: Decrypted signature does not match expected PKCS#1 v1.5 structure.
    Expected: 0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff...
    Got:      0001ffffffffffffffff003031300d0609608648016503040201050004208c6976e5b5410415bde9...
    Difference starts at byte index 10.
[+] Creating session cookie...
[+] Forged session cookie (prefix): eyJ1c2VybmFtZSI6ICJhZG1pbiIsICJzaWduYXR1cmUiOiAiTXN2OVNucmNl ... [+]
[+] Sending request to server...
[+] Request successful (Status: 200, Final URL: https://smelter.tamuctf.com/)

[***] Flag found: gigem{h0p3fully_y0u_r3aliz3_that_e=3_is_bad_n0w} [***] 
```

#### Full Solution Source code
- This script was edited quite a bit follow the CTF competition so it looked decent for this writeup. However during testing once I had identified a likely solution, it was quite messy and all over the place.

```python
#!/usr/bin/env python3

import sys
import gmpy2
import hashlib
from Crypto.PublicKey import RSA
from base64 import b64encode
import json
import requests
import re
SHA256_ASN1 = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
DEFAULT_FFCOUNT = 8
def to_int(val):
    """Converts bytes to integer."""
    return int.from_bytes(val, byteorder="big")

def to_bytes(val, arg_len):
    """Converts integer to fixed-length bytes."""
    val = int(val)
    req_len = (val.bit_length() + 7) // 8 if val != 0 else 1
    use_len = max(req_len, arg_len)
    return int.to_bytes(val, length=use_len, byteorder="big")

class MiniForger:
    """Minimal implementation for Bleichenbacher's e=3 RSA signature forgery."""
    def __init__(self, keysize, public_exponent, quiet=False):
        if public_exponent != 3:
            print("[!] Warning: This optimized forger is primarily designed for e=3.", file=sys.stderr)

        self.keysize_bytes = (keysize + 7) // 8
        self.keysize_bits = keysize
        self.public_exponent = public_exponent
        self.sha256_asn1 = SHA256_ASN1
        self.quiet = quiet
        self.max_precision = None # Used by limit_precision

    def limit_precision(self, aprecision):
        """Limits precision for gmpy2 context."""
        if self.max_precision is None:
            try:
                self.max_precision = gmpy2.get_max_precision() - 16
            except Exception:
                self.max_precision = 2048 * 128 * self.public_exponent # Heuristic fallback
                if not self.quiet:
                     print("[!] Warning: Could not get gmpy2 max precision, using fallback.", file=sys.stderr)
        return min(
            min(aprecision, self.keysize_bits * 128 * self.public_exponent), # Heuristic limit
            self.max_precision,
        )

    def report_small(self, pbl):
        """Reports if exponentiation result exceeds key size."""
        pbl = int(pbl)
        if not self.quiet:
            ksb = self.keysize_bits
            if ksb < pbl:
                mesg = "bits and wraps past the modulus of"
            else:
                mesg = "bits and is too close to the size of the modulus of"
            print(
                f"[-] Key size issue: exponentiation gives {pbl} {mesg} {ksb} bits",
                file=sys.stderr,
            )

    def nth_root(self, A, prec):
        """Calculates the integer nth root using gmpy2."""
        current_prec = gmpy2.get_context().precision
        target_prec = self.limit_precision(prec)
        if current_prec < target_prec:
             gmpy2.get_context().precision = target_prec
        int_root = gmpy2.root(A, self.public_exponent)
        if pow(int_root, self.public_exponent) < A:
             return int_root + 1
        else:
             return int_root # Found exact root or int_root^e was >= A

    def encode_pkcs1_suffix(self, message):
        """Encodes message hash with SHA-256 ASN.1 info."""
        message_hash = hashlib.sha256(message.encode("utf-8")).digest()
        # 00 | ASN.1 | HASH
        suffix = b"\x00" + self.sha256_asn1 + message_hash
        return suffix

    def forge_signature_with_garbage_end(self, message):
        """
        Forge signature with garbage at the end.
        Padding: 00 01 FF...FF 00 | DigestInfo | 00...00
        """
        if not self.quiet:
            print("[+] Forging signature (garbage_end variant)...")
        prefix = b"\x00\x01" + (b"\xff" * DEFAULT_FFCOUNT) # Use fixed FF count
        suffix = self.encode_pkcs1_suffix(message)
        encoded_digest = prefix + suffix # 00 01 FF...FF 00 ASN1 HASH
        numzeros = self.keysize_bytes - len(encoded_digest)
        if numzeros < 0: # Need space for at least one null byte technically, but check >=0
            print(f"[-] Error: Encoded digest ({len(encoded_digest)} bytes) is too long for key size ({self.keysize_bytes} bytes).", file=sys.stderr)
            return None
        plain_bytes = encoded_digest + (b"\x00" * numzeros)
        plain_int = to_int(plain_bytes)

        if len(plain_bytes) != self.keysize_bytes:
             print(f"[-] Error: Constructed plain_bytes length ({len(plain_bytes)}) != keysize ({self.keysize_bytes}).", file=sys.stderr)
             return None
        precision = self.keysize_bits * self.public_exponent # Start with reasonable precision
        signature_int = self.nth_root(plain_int, precision)
        check_cube = pow(signature_int, self.public_exponent)
        check_bytes = to_bytes(check_cube, self.keysize_bytes) # Pad to key size
        if check_bytes.startswith(encoded_digest):
             if not self.quiet:
                 print("[+] Cube root check passed: pow(s, e) starts with correct prefix.")
        else:
             if not self.quiet:
                 print("[!] Warning: Cube root check failed. pow(s, e) does NOT start with the desired prefix.", file=sys.stderr)
                 print(f"    Expected prefix: {encoded_digest[:40].hex()}...", file=sys.stderr)
                 print(f"    Got pow(s,e):    {check_bytes[:40].hex()}...", file=sys.stderr)
        check_cube = int(check_cube)
        pbl = check_cube.bit_length()
        if pbl > self.keysize_bits:
                self.report_small(pbl)
        signature_int = int(signature_int)
        signature_bytes = (signature_int.bit_length() + 7) // 8
        final_signature = to_bytes(signature_int, 0) # Use minimal length
        if not self.quiet:
            print(f"[+] Forged signature integer: {signature_int}")
        return final_signature

def nth_root(self, A, prec):
        """Calculates the integer nth root using gmpy2.iroot."""
        try:
            int_root, is_exact = gmpy2.iroot(A, self.public_exponent)
        except Exception as e:
             print(f"[-] Error during gmpy2.iroot calculation: {e}", file=sys.stderr)
             raise # Re-raise the exception
        if not is_exact and pow(int_root, self.public_exponent) < A:
             return int_root + 1
        else:
             return int_root
PEM = """-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQB8HTNWyTtV+kkwv8RB9Qqn
ohrXg4y2X6SjKUCpVCZNBRE7iL7wlmTXaAUdXr7uSIQy0se/O8vunxqO8xZjYAq9
yJn9NcYbx8qSbAQUpUfmL4vTLhLeS4X8Ml4GtEEXCQTajg2lHEafeRvTr0G8UlXY
E9Bcy6LDEPmQ7zD/0kvfHEEExKA/cSDQMNsHJaDQOhlN01N6XQWBBvskt76L2Jz1
PTutUkEWnJG0MTR7HuGQV7+fjAYjxXZNXBXHq71LX9pvVATvs3F9btwIm950mgcs
eQ2+u+Ozud14jwydG7iK4aTAlKEcs5Wl4wuVcAlT87IZRzS6ieazeS53VMFeHX7z
AgED
-----END PUBLIC KEY-----"""
try:
    key = RSA.import_key(PEM)
    n, e = key.n, key.e
    print(f"[+] RSA Public key parameters: [+]")
    print(f"[+] n={n}\n    e={e} [+]")
    keysize = key.size_in_bits()
    print(f"[+] Keysize: {keysize} bits [+]")
except Exception as err:
    print(f"[-] Error loading public key: {err}", file=sys.stderr)
    sys.exit(1)
if e != 3:
    print(f"[-] Error: This exploit requires e=3, but key has e={e}", file=sys.stderr)
message = "admin"
print(f"[+] Target message: '{message}' [+]")
mini_forger = MiniForger(keysize=keysize, public_exponent=e, quiet=False)
forged_signature = mini_forger.forge_signature_with_garbage_end(message)
if forged_signature is None:
     print("[-] Failed to forge signature.", file=sys.stderr)
     sys.exit(1)
print(f"[+] Forged signature bytes (hex): {forged_signature.hex()} [+]")
print(f"[+] Forged signature length: {len(forged_signature)} bytes [+]")

try:
    print("[+] Performing local verification check...")
    sig_int = to_int(forged_signature)
    decrypted_int = pow(sig_int, e, n)
    key_bytes = (keysize + 7) // 8
    decrypted_bytes = to_bytes(decrypted_int, key_bytes) # Pad to key size like server verify
    sha256_hash = hashlib.sha256(message.encode()).digest()
    expected_suffix = b'\x00' + SHA256_ASN1 + sha256_hash
    ff_count = key_bytes - len(expected_suffix) - 2 # for 00 01
    expected_prefix = b'\x00\x01' + (b'\xff' * ff_count) + expected_suffix
    if decrypted_bytes.startswith(expected_prefix[:len(expected_prefix)-len(sha256_hash)]):
        print("[+] Local verification PASSED: Decrypted signature starts with correct PKCS#1 v1.5 structure (up to hash).")
        if decrypted_bytes.startswith(expected_prefix):
             print("[+] Local verification CONFIRMED: Hash also matches.")
        else:
             hash_start_idx = len(expected_prefix) - len(sha256_hash)
             actual_hash = decrypted_bytes[hash_start_idx : hash_start_idx + len(sha256_hash)]
             print(f"[!] Local verification WARNING: Structure matches, but hash part differs.")
             print(f"    Expected hash: {sha256_hash.hex()}")
             print(f"    Actual hash:   {actual_hash.hex()}")
    else:
        print("[-] Local verification FAILED: Decrypted signature does not match expected PKCS#1 v1.5 structure.")
        diff_idx = -1
        min_len = min(len(decrypted_bytes), len(expected_prefix))
        for i in range(min_len):
             if decrypted_bytes[i] != expected_prefix[i]:
                  diff_idx = i
                  break
        print(f"    Expected: {expected_prefix[:40].hex()}...")
        print(f"    Got:      {decrypted_bytes[:40].hex()}...")
        if diff_idx != -1:
            print(f"    Difference starts at byte index {diff_idx}.")
except Exception as verr:
    print(f"[-] Error during local verification: {verr}", file=sys.stderr)
print("[+] Creating session cookie...")
data = {
    "username": message, # Use original message
    "signature": b64encode(forged_signature).decode()
}
session_cookie = b64encode(json.dumps(data).encode()).decode()
print("[+] Forged session cookie (prefix):", session_cookie[:60], "... [+]")
print("[+] Sending request to server...")
url = "https://smelter.tamuctf.com/"
cookies = {"smelter-session": session_cookie}
try:
    response = requests.get(url, cookies=cookies, allow_redirects=True, timeout=20) # Increased timeout
    response.raise_for_status() # Check for HTTP errors
    print(f"[+] Request successful (Status: {response.status_code}, Final URL: {response.url})")
    pattern = r'gigem\{[^}]+\}' # More specific regex
    match = re.search(pattern, response.text)
    if match:
        flag = match.group(0)
        print(f"\n[***] Flag found: {flag} [***]\n")
    else:
        print("[-] Flag pattern 'gigem{...}' not found in response.")
        if "Username: guest" in response.text:
             print("[-] Server response indicates login as 'guest'. Forgery likely failed server-side verification.")
except requests.exceptions.TooManyRedirects:
     print("[-] FAILED: Exceeded maximum redirects. Server rejected the signature.", file=sys.stderr)
     sys.exit(1)
except requests.exceptions.RequestException as req_err:
    print(f"[-] Request failed: {req_err}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"[-] An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
print("[+] Exploit finished.")
```

---

### Conclusion

This challenge from TamuCTF showcased an RSA signature verification vulnerability in which the PKCS#1 v1.5 padding wasn't validated properly. Allowing us to forge a signature as the `admin` user and get the flag!

Thanks for reading, and happy hacking! Stay frosty you dirty little dawgz.

###### Resources and Research
Resource used to help solve the challenge:
- [Bleichenbacher's Signature Forgery](https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/) – Original research article and example by Filippo Valsorda.
- [IETF Mailing Archive Discussion](https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html) – Discussing the specific vulnerability scenario and signature forgery.
- [RSA Bleichenbacher Signature](https://github.com/maximmasiutin/rsa-bleichenbacher-signature/blob/master/SignatureForgerLib.py)

