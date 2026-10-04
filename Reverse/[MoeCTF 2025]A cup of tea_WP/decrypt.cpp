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
