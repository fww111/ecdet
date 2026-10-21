/* 评测语料：内存类漏洞样例（基准真值由函数名清单生成） */
#include <string.h>
#include <stdint.h>

#define MAX_NAME 8

/* 漏洞函数：strcpy 无界拷贝 */
void buf_copy_bad(void)
{
    char name[MAX_NAME];
    strcpy(name, "0123456789ABCDEF");
}

/* 干净函数：限长拷贝 */
void buf_copy_ok(void)
{
    char name[MAX_NAME];
    strncpy(name, "short", sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
}

/* 干净函数：常量越界已规避 */
int array_ok(int idx)
{
    int table[4] = {0, 1, 2, 3};
    if (idx < 0 || idx > 3) {
        return -1;
    }
    return table[idx];
}
