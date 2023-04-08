#include <stdio.h>
#include <unistd.h>

// nm test | grep foo
int foo(int a, int b) 
{
    sleep(1);
    return a + b;
}
int main()
{
    int i = 0;

    while(1)
    {
        foo(i++, i);
        sleep(1);
    }
    return 0;
}
