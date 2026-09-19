**道典型的花指令混淆 + 简单异或加密的逆向入门题**

>平台：MeoCTF
>方向：逆向（花指令）
>知识点：花指令修复、IDA Patch
>难度：入门

# 一、信息获取

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image01.png)

使用exeinfoPE识别，该程序为 Linux 64位 ELF 文件，无壳，编译环境为 Ubuntu GCC

# 二、分析
使用IDA打开

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image02.png)

## 1.观察main函数
check 函数通过 ptrace 进行反调试检测
if语句判断了zero是否为0，保护随后的10 / main::zero、10 % main::zero计算，防御除零异常
（未获得直接线索，但排除了反调试与异常机制的干扰）

## 2.观察数据流
寻找cin，发现输入的数据被传给了v8，而solve对v8进行了处理
![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image03.png)


尝试对solve进行反编译，发现失败了：
4048E9: positive sp value has been found ->在地址 4048E9 处：发现了正的栈指针（SP）值

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image04.png)


回到汇编查看，在4048E9附近可以看到jz与jnz使程序运行时跳过了 call near ptr Label+1
因此将此 call 指令 NOP 掉，欺骗 IDA 的栈指针分析，使其能够正常进行 F5 反编译。

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image05.png)


应用后再次打开对solve进行反汇编得到：

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image06.png)

分析 solve 函数
发现flag的长度为32，其经过 encode 函数后，每一位与enc数组进行比较

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image07.png)

encode如图，函数将返回flag与key的异或结果，并且key自增

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image08.png)

找到enc与key的值

# 三、解密
```python
enc = [0x4F, 0x1A, 0x59, 0x1F, 0x5B, 0x1D,
       0x5D, 0x6F, 0x7B, 0x47, 0x7E, 0x44, 
       0x6A, 0x07, 0x59, 0x67, 0x0E, 0x52, 
       0x08, 0x63, 0x5C, 0x1A, 0x52, 0x1F,
       0x20, 0x7B, 0x21, 0x77, 0x70, 0x25,
       0x74, 0x2B, 0x44]
key = 0x23
flag = ""
for i in range(len(enc)):
    flag +=chr(enc[i]^key)
    key+=1
flag = flag.strip() #除字符串 flag 开头和结尾的空白字符
print("moectf{" + flag + "}")
input()
```

尝试后发现结果不对
返回，对key与enc使用交叉引用定位

![alt text](/Reverse/[MeoCTF2025]flower_WP/image/image09.png)

发现main引用并修改了key的值

```python
key = 0x23 ^ 0x0A #正确值
```

重新解密即可得到flag

# 四、总结
逆向解密脚本跑出乱码 时，不一定是算法问题，往往是因为漏掉了隐藏的初始化逻辑，回到汇编层面跟踪数据流是最高效的解法
