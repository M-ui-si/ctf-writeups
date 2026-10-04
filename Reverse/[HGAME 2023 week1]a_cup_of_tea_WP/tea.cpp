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
