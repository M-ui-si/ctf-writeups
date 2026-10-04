# [MoeCTF 2025]A cup of tea_WP

**一个简单的TEA加密的wp**

> **平台**：MoeCTF  
> **方向**：re  
> **知识点**：TEA  
> **难度**：入门

## 一、信息获取

![image01](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image01.png)

64位、无壳

![image02](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image02.png)

需要输入flag

## 二、分析

![image03](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image03.png)

用 IDA 打开找到字符串 `You are wrong!!`,交叉引用找到引用此字符串的函数

![image04](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image04.png)

查看反汇编代码，发现其将 `buf_1` 与 `v6` 进行了比较，需要两者内容相同。

![image05](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image05.png)

![image06](/Reverse/[MoeCTF%202025]A%20cup%20of%20tea_WP/image/image06.png)

分析加密算法发现是 TEA 加密（仅将delta魔改）
所以：
v5->key
v6->密文
buf->明文（flag）

## 三、EXP

```c
#include <iostream>
using namespace std;

unsigned int k[4] = { 289739801,427884820,1363251608,269567252 };

unsigned int buf[11] = {
    2026214571,
    578894681,
    1193947460,
    -229306230,
    73202484,
    961145356,
    -881456792,
    358205817,
    -554069347,
    119347883,
    0,
};


void tea_decrypt(uint32_t& v4, uint32_t& v5, uint32_t* k) {
    uint32_t sum = 1131796 * 32;
    uint32_t delta = 1131796;

    for (int i = 0; i < 32; i++) {
        v5 -= (k[3] + (v4 >> 5)) ^ (sum + v4) ^ (k[2] + 16 * v4);
        v4 -= (k[1] + (v5 >> 5)) ^ (sum + v5) ^ (k[0] + 16 * v5);
        sum -= delta;
    }

}

int main() {
    char plaintext[41] = { 0 };
    uint32_t* p = reinterpret_cast<uint32_t*>(plaintext);//强制类型转换

    for (int i = 0;i < 5;i++) {
        uint32_t v12 = buf[2 * i];
        uint32_t v13 = buf[2 * i + 1];
        tea_decrypt(v12, v13, k);
        p[2 * i] = v12;
        p[2 * i + 1] = v13;
    }

    cout << plaintext << endl;
    return 0;
}
```

对其进行解密即可得出flag

## 四、总结
