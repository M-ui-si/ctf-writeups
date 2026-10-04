# [MoeCTF 2025]ezwindow_WP

**一个简短窗口程序的wp记录**

> **平台**：MoeCTF  
> **方向**：逆向  
> **知识点**：窗口程序分析，异或解密  
> **难度**：入门

## 一、信息获取

![image01](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image01.png)

![image02](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image02.png)

运行程序发现有三个可以交互的窗口，其中最后一个窗口是要求输入flag并验证的，因此flag应该藏在这里

## 二、分析

![image03](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image03.png)

分析反汇编代码  
在13行 `v11.lpfnWndProc = sub_140001210`这里将 sub_140001210 注册为窗口过程函数。这意味着所有窗口消息（如键盘输入、按钮点击）以及程序的核心逻辑都交由这个 sub_140001210 函数接管。

点开向下查看

![image04](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image04.png)

这里发现三个**事件触发点**，刚好分别对应程序的**帮助、文件、交互**按钮

点开`DialogFunc`(这个函数会接管用户点击交互时的输入，因此里面会藏着flag验证逻辑)

![image05](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image05.png)

分析函数内部  
由`GetDlgItemTextW`可得输入的flag被存入了String，下方的do while 则是将String的长度存入n32

![image06](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image06.png)

最后判断了一下n32（flag长度）是否等于16，只有长度为16的时候才可正常退出，因此正确的flag长度为16

![image07](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image07.png)

看加密算法  
第一个if语句在flag长度大于等于32的时候进入，因此永远不会进入下方代码段

![image08](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image08.png)

第二个if语句里的内容就是本题的加密 算法  
加密：对flag进行了简单的异或

下方的do while则是通过指针对输入的flag和`aGeoiLqbj`里面的内容（**密文**）进行了对比，对比结果保存在v17里面（完全匹配v17必定为0）

![image09](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image09.png)

我直接查看密文内容发现没有显示完全，被折叠了  
可以先`U`键取消字符串定义，再转为字节数组并把Array size设置大一点

![image10](/Reverse/[MoeCTF%202025]ezwindow_WP/image/image10.png)

## 三、EXP

```python
cipher = [
    0x47, 0x45, 0x4F, 0x49, 0x5E, 
    0x4C, 0x51, 0x62, 0x6A, 0x5C, 
    0x1E, 0x75, 0x4C, 0x7F, 0x44, 0x57
]

flag = ''.join(chr(b^0x2A) for b in cipher)
print(flag)
```

## 四、总结

解题关键是要找到flag输入窗口的控制函数
