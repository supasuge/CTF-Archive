import requests
import time
import string
from urllib.parse import quote

# 1) Use a session for fewer TCP handshakes
session = requests.Session()

# 2) Possibly reduce charset if you know the flag's format
chars = string.printable

url = lambda msg: f"http://localhost:5000/encrypt?message={msg}"

def get_enc(plaintext):
    response = session.get(url(quote(plaintext)))
    return response.text  # hex-encoded ciphertext

def generate(prefix):
    """Generate list of prefix+candidate for every candidate in chars."""
    return [prefix + c for c in chars]

def main():
    known = 'a' * 16  # This is your discovered prefix so far
    start = time.time()
    print(f"[+] Starting attack at: {start}")

    # For demonstration, let's assume we want 5 blocks of the unknown (like your example).
    # Typically you'd continue until you get the entire flag.
    for block_idx in range(5):
        for i in range(16):
            # Build the big single-try input:
            prefix = known[-15:]  # Last 15 chars of discovered text
            candidates = generate(prefix)
            # By joining all candidates, you get len(chars)*16 bytes
            # plus the padding for alignment:
            padded_input = ''.join(candidates) + 'a' * (15 - i)

            # Single request for all candidate guesses
            ciphertext_hex = get_enc(padded_input)

            # Split hex-encoded ciphertext into 16-byte (32 hex chars) blocks
            blocks = [ciphertext_hex[i : i+32] for i in range(0, len(ciphertext_hex), 32)]

            # The 'target' is the (len(chars) + block_idx)-th block
            # Because the first len(chars) blocks correspond to each candidate, 
            # the next block is the real encryption of prefix + next unknown byte
            target_block = blocks[len(chars) + block_idx]

            # Find which candidate block matches the target block
            # i.e., which candidate's ciphertext block is identical
            # to the real block
            for idx, blk in enumerate(blocks[:len(chars)]):
                if blk == target_block:
                    known += chars[idx]
                    print(f"[+] Known so far: {known}")
                    break

    end = time.time()
    print(f"[+] Attack finished at: {end}")
    print(f"[+] Attack took: {end - start} seconds")
    print(f"[+] Final discovered text: {known}")

if __name__ == "__main__":
    main()
