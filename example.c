#include <stdio.h>

int main(){
    int i;
    char origname[20];
    char destname[20];
    for (i = 0; i < 20; i++) {
        sprintf(origname, "test%d", i);
        sprintf(destname, "test%d.lockbit", i);
        rename(origname, destname);
    }
    return 0;
}

