一个魔改的TEA加密题，我写的wp比较繁琐，对小白比较友好

> **平台**：NSSCTF  
> **方向**：逆向  
> **知识点**：（魔改）TEA、大小端序  
> **难度**：入门

## 一、信息获取

![image01](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image01.png)

无壳、64位程序

## 二、分析

### 1.整体分析

![image02](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image02.png)

使用 IDA 打开，main 函数中 `scanf("%50s", &Buf1)` (**sub_140001064(“%50s”)**)接收用户输入。随后经过 4 次 `sub_1400010B4` (加密函数)调用。最后 `memcmp(&Buf1, Buf2, 0x22u)` 比较 **34** 字节，相同则输出 Congratulations!。结合 `Buf2` 和 `n32107` 的初值，判定 Buf2 为密文，用户输入经加密后应与其匹配。

### 2.加密函数分析

目前看不懂传参内容，先打开加密函数查看

![image03](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image03.png)

发现特征：**>>5、<<4(16*)、32轮迭代**，判断为 TEA 加密

![image04](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image04.png)

我把变量名修改了一下，看起来更直观，如图可得：

### 3.返回分析（说明一下为什么分四次加密）

![image05](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image05.png)

![image06](/Reverse/[HGAME%202023%20week1]a_cup_of_tea_WP/image/image06.png)

```c
v3 = memcmp(&Buf1, Buf2, 0x22u);
```

TEA总共处理了**32**个字节，但对比的时候对比了**34**个字节，还差两个字节。  
看地址偏移发现`Buf2`与`n32107`的地址是连在一起的，因此差的两个字节为`n32107`里的内容,解密的时候需要加上这两个字节（p_Buf1[1]是用来存储这2字节的，同时也防止的栈溢出）

## 三、EXP

解密

```cpp
#include <iostream>
#include <cstring>
using namespace std;
unsigned int k[4] = { 0x12345678, 0x23456789, 0x34567890, 0x45678901 };

void tea(unsigned int* v) {
    unsigned int v0 = v[0];//Syntactic Sugar
    unsigned int v1 = v[1];
    unsigned int sum = -(1412567261 * 32);
    for (int i = 0;i < 32;i++) {
        v1 -= (sum + v0) ^ (k[2] + 16 * v0) ^ (k[3] + (v0 >> 5));
        v0 -= (sum + v1) ^ (k[0] + 16 * v1) ^ (k[1] + (v1 >> 5));
        sum += 1412567261;//原先为减，反过来为加
    }//将加密反过来进行解密
    v[0] = v0;
    v[1] = v1;

}
int main() {
    unsigned int buf[9] = {//密文
    778273437,    // 0x2E63D99D
    -1051836401,  // 0xC13F454F
    -1690714183,  // 0x9B47E2B9
    1512016660,   // 0x5A1C64B4
    1636330974,   // 0x618A0F5E
    1701168847,   // 0x65642E8F
    -1626976412,  // 0x9F05B6A4
    594166774,     // 0x236B0E76
    32107 //n32107
    };
    for (int i = 0;i < 8;i += 2) {
        tea(&buf[i]);
    }
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 4; j++) {
            char c = (buf[i] >> (j * 8)) & 0xFF;//从后向前把每个字节取出，从后先前输出为正（小端序问题）
            if (c >= 32 && c <= 126) { // 只打印可打印字符，过滤掉乱码
                cout << c;
            }
        }
    }
    return 0;
}
```

输出解密结果时要当心小端序的坑。编译器 把 4 个字母强塞进了一个整数里，这就导致排在最前面的字母（低地址）反而变成了整数十六进制的最后两位（低字节）。我在写脚本时，把这个大整数一点点‘拆开’，让字母回到了它们原本的位置上。

## 四、总结

魔改TEA  
要注意小端序问题
