/* Controlled positive: a known null pointer reaches the dereference. */
int dereference_bad(void)
{
    int *value = 0;
    return *value;
}
