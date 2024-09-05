#include <cstdio>
#include <cstdlib>
#include <cctype>

int main(void) {
    int lines = 0, words = 0, chars = 0;
    bool is_word = false;
    for (char cursor = fgetc(stdin); cursor != EOF; cursor = fgetc(stdin)) {
        if (!isspace(cursor)) {
            if (!is_word) {
                words++;
                is_word = true;
            }
        } else {
            if (cursor == '\n') {
                lines++;
            }
            is_word = false;
        }
        chars++;
    }
    fprintf(stdout, "%d, %d, %d\n", lines, words, chars);
    return 0;
}