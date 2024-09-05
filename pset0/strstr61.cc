#include <cstring>
#include <cassert>
#include <cstdio>

char* mystrstr(const char* s1, const char* s2) {
    if (*s2 == '\0') {
        return (char*)s1;
    }
    for (const char* cursor = s1; *cursor != '\0'; cursor++) {
        unsigned long i = 0;
        while (true) {
            const char* subcursor = cursor + i;
            if (*(subcursor) == '\0') {
                return (char*)cursor;
            }
            if (*(s2 + i) != *(subcursor)) {
                break;
            }
            i++;
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    assert(argc == 3);
    printf("strstr(\"%s\", \"%s\")   = %p\n",
           argv[1], argv[2], strstr(argv[1], argv[2]));
    printf("mystrstr(\"%s\", \"%s\") = %p\n",
           argv[1], argv[2], mystrstr(argv[1], argv[2]));
    assert(strstr(argv[1], argv[2]) == mystrstr(argv[1], argv[2]));
}