char *strcpy(char *destination, const char *source);

int case_a(void)
{
    int values[4] = {0, 1, 2, 3};
    return values[4];
}

int case_b(void)
{
    int values[4] = {0, 1, 2, 3};
    return values[3];
}

void case_c(void)
{
    char target[4];
    strcpy(target, "1234567");
}

void case_d(void)
{
    char target[8];
    strcpy(target, "abc");
}
