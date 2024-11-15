#include "m61.hh"
// Check that m61_free doesn't attempt coalescing outside of heap
// Extension of test27: ensure std::maps iterators do not try to iterate below
//   map.begin() or above map.end()
// BORD_BLOCKS setting in m61.cc must be 1 for this test to work
//     This would be adjusted for by this test, but BORD_BLOCKS should be kept
//       static, so manual adjustment will have to do

int main() {
    size_t buffer_max_alloc = 8 << 20;
    buffer_max_alloc -= 3 * alignof(std::max_align_t);
    void* ptr = m61_malloc(buffer_max_alloc);
    m61_free(ptr);

    m61_print_statistics();
}

//! alloc count: active          0   total          1   fail          0
//! alloc size:  active          0   total    8388560   fail          0