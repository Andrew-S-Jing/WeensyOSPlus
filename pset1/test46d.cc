#include "m61.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <random>
// Check detection of boundary write errors at non-adjacent bytes at lower fence-post of allocation.
// Extension of test46: detects writes a bit further away than immediately adjacent fence-post writes (at lower border)
//      Randomly tests one byte only to avoid adding as many tests as bytes to test


int main() {
    int nbytes = 10;
    char* ptr = (char*) m61_malloc(nbytes);
    fprintf(stderr, "Will free %p\n", ptr);
    
    // Zero a random byte in [ begin - CSIZE, begin )
    // See Citation "Rand" for getting a random number
    std::random_device rd; // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator
    std::uniform_int_distribution<> distr(2, 4); // define the range
    ptr[-distr(gen)] = 0;

    m61_free(ptr);
    m61_print_statistics();
}

//! Will free ??{0x\w+}=ptr??
//! MEMORY BUG???: detected wild write during free of pointer ??ptr??
//! ???
//!!ABORT
