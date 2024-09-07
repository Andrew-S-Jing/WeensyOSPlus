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
            if (*(s2 + i) == '\0') {
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

char* arraystrstr(const char* s1, const char* s2) {
    if (*s2 == '\0') {
        return (char*)s1;
    }
    for (unsigned int i = 0; s1[i] != '\0'; i++) {
        unsigned int j = 0;
        while (true) {
            if (s2[j] == '\0') {
                return &((char*)s1)[i];
            } else if (s1[i + j] != s2[j]) {
                break;
            }
            j++;
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    assert(argc == 3);
    printf("strstr(\"%s\", \"%s\")      = %p\n",
           argv[1], argv[2], strstr(argv[1], argv[2]));
    printf("arraystrstr(\"%s\", \"%s\") = %p\n",
           argv[1], argv[2], arraystrstr(argv[1], argv[2]));
    printf("mystrstr(\"%s\", \"%s\")    = %p\n",
           argv[1], argv[2], mystrstr(argv[1], argv[2]));
    assert(strstr(argv[1], argv[2]) == mystrstr(argv[1], argv[2]));
    return 0;
}