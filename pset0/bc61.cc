#include <cstdlib>
#include <cstdio>

int main(void) {
    int counter = 0;
    while (fgetc(stdin) != EOF) {
        counter++;
    }
    fprintf(stdout, "%d\n", counter);;
    return 0;
}