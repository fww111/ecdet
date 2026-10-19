
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define UNUSED_MACRO 42
#define DOUBLE_IT(x) ((x) * 2)
#define BAD_MUL(a, b) (a * b)

static uint8_t g_counter = 0;
uint32_t g_only_local = 5;

int helper_add(int a, int b) { return a + b; }

int recurse_fact(int n) {
    if (n <= 1) return 1;
    return n * recurse_fact(n - 1);
}

int multi_return(int x) {
    if (x > 0) return 1;
    return 0;
}

void use_goto(void) {
    int i = 0;
loop:
    i++;
    if (i < 10) goto loop;
}

void switch_bad(int v) {
    switch (v) {
    case 1:
        break;
    }
}

void buffer_bug(void) {
    char name[8];
    strcpy(name, "0123456789ABCDEF");
    int arr[4] = {0};
    arr[6] = 1;
    uint8_t small = 300;
    gets(name);
    printf(name);
    scanf("%s", name);
    int r = rand();
    (void)r;
}

void logic_side_effect(int a, int b) {
    int c = 0;
    if ((a > 0) && (c++ > 1)) {
        c = 1;
    }
    int d = (b > 0) || helper_add(a, b);
    (void)d;
}

void for_bad(void) {
    int i;
    int s = 0;
    for (i = 0; i < 10; i++) {
        s += i;
        i = i + 2;
    }
    (void)s;
}

void implicit_call(void) {
    undeclared_function_xyz(1, 2);
}

void _ReservedName(void) {
}
