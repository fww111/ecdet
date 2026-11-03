/* Controlled negative: both branches are defined before dereference. */
int dereference_good(int *value)
{
    if (value == 0) {
        return 0;
    }
    return *value;
}
