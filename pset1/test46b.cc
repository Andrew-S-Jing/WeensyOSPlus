#include "m61.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
// Check detection of boundary write errors at lower fence-post of allocation.

int main() {
    int* ptr = (int*) m61_malloc(sizeof(int) * 10);
    fprintf(stderr, "Will free %p\n", ptr);
    ptr[-1] = 0;
    m61_free(ptr);
    m61_print_statistics();
}

//! Will free ??{0x\w+}=ptr??
//! MEMORY BUG???: detected wild write during free of pointer ??ptr??
//! ???
//!!ABORT
