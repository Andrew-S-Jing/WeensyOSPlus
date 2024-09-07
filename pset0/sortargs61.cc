#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <vector>
#include <iostream>

int main(int argc, char* argv[]) {

    // 2.
    // using std::string, std::vector, std::cout
    std::vector<std::string> elts(argc - 1);
    for (int i = 1; i < argc; i++) {
        std::string temp = argv[i];
        elts[i - 1] = temp;
    }
    std::sort(elts.begin(), elts.end());
    for (auto i : elts) {
        std::cout << i << '\n';
    }
    std::cout << '\n';

    // 1.
    // using just arrays
    // loops for the 2nd to (n-1)th elements in argv
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], argv[i + 1]) > 0) {
            char* temp = argv[i + 1];
            int j = 0;
            while (strcmp(argv[i - j], temp) > 0 && j < i) {
                argv[(i + 1) - j] = argv[i - j];
                j++;
            }
            argv[(i - j) + 1] = temp;
        }
    }
    // print sorted list
    for (int i = 1; i < argc; i++) {
        printf("%s\n", argv[i]);
    }

    return 0;
}