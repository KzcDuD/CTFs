from pwn import *

r = remote("mercury.picoctf.net", 11188)
r.recvline()
r.recvline()
flag_enc = bytes.fromhex(r.recvline().decode())
fl =len(flag_enc)

def enc(m):
    r.sendlineafter(b'What data would you like to encrypt? ',m)
    r.recvline()
    return bytes.fromhex(r.recvline().decode())

enc('a'*(50000-fl))
keyxor = enc(b'a'*fl)

def xor(p,k):
    return bytes(a^b for a,b in zip(p,k))

key = xor(keyxor,b'a'*fl)
flag = xor(flag_enc,key)
print(flag.decode())
    
