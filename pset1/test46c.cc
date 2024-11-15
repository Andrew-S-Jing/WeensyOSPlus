#include "m61.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <random>
// Check detection of boundary write errors at non-adjacent bytes at upper fence-post of allocation.
// Extension of test46: detects writes a bit further away than immediately adjacent fence-post writes (at upper border)
//      Randomly tests one byte only to avoid adding as many tests as bytes to test


int main() {
    int nints = 189;
    int mintalign = alignof(std::max_align_t) / sizeof(int);
    int ncanaryints = mintalign - (nints % mintalign) + 1;
    int* ptr = (int*) m61_malloc(sizeof(int) * nints);
    fprintf(stderr, "Will free %p\n", ptr);
    
    // Zero a random int block in [ end + 1, end + CSIZE + 1 )
    // See Citation "Rand" for getting a random number
    std::random_device rd; // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator
    std::uniform_int_distribution<> distr(1, ncanaryints - 1); // define the range
    ptr[nints + distr(gen)] = 0;

    m61_free(ptr);
    m61_print_statistics();
}

//! Will free ??{0x\w+}=ptr??
//! MEMORY BUG???: detected wild write during free of pointer ??ptr??
//! ???
//!!ABORT
