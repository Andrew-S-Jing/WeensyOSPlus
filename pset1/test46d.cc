#include "m61.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <random>
// Check detection of boundary write errors at non-adjacent bytes at lower fence-post of allocation.

int main() {
    int* ptr = (int*) m61_malloc(sizeof(int) * 10);
    fprintf(stderr, "Will free %p\n", ptr);
    
    // Zero a random int block in [ begin - alignof(std::max_align_t), begin )
    // See Citation "Rand" for getting a random number
    std::random_device rd; // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator
    std::uniform_int_distribution<> distr(2, alignof(std::max_align_t) / sizeof(int)); // define the range
    ptr[-distr(gen)] = 0;

    m61_free(ptr);
    m61_print_statistics();
}

//! Will free ??{0x\w+}=ptr??
//! MEMORY BUG???: detected wild write during free of pointer ??ptr??
//! ???
//!!ABORT
