#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
// Additional includes
#include <cmath>
#include <iostream>
#include <map>
#include <set>


// Setting for # of blocks of alignof(std::max_align_t) of fence-post border regions on either side of an m61_malloc
// See Citation "Border" for idea to include buffer-borders around each m61_malloc
static const size_t BORD_BLOCKS = 1;

// Specs for the border regions (not overflow protected, but BORD_BLOCKS should be kept low anyways)
static const size_t BORD_SZ = BORD_BLOCKS * alignof(std::max_align_t);
static const char BORD_CHAR = 'b';


struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;


m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr,    // Place the buffer at a random address
        this->size,              // Buffer should be 8 MiB big
        PROT_WRITE,              // We want to read and write the buffer
        MAP_ANON | MAP_PRIVATE, -1, 0);
                                 // We want memory freshly allocated by the OS
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}




// Static global to track mem stats and overhead
static m61_statistics stats = {0, 0, 0, 0, 0, 0, (uintptr_t)default_buffer.buffer, (uintptr_t)default_buffer.buffer};
// Elt in actives is {pre_border_ptr, {allotment, extra}}
static std::map<uintptr_t, std::pair<size_t, size_t>> actives;
// Elt in inactives is {pre_border_ptr, allotment}
static std::map<uintptr_t, size_t> inactives = {{(uintptr_t)default_buffer.buffer, default_buffer.size}};
static std::set<void*> frees;


/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings

    // m61_malloc(0) returns the nullptr. Counts as a successful, inactive allocation.
    if (sz == 0) {
        stats.ntotal++;
        return nullptr;
    }

    // Enforce alignof(std::max_align_t) as the quantum of malloc sizes
    const size_t quantum = alignof(std::max_align_t);
    size_t allotment = sz;
    size_t misalign = sz % quantum;
    size_t extra = 0;
    if (misalign != 0) {
        extra = quantum - misalign;
    }

    // Handle cases of overflow (handled before finding allocation space for efficiency)
    if (allotment > SIZE_MAX - (extra + 2 * BORD_SZ)) {
        // Update stats with failed allocation
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // Align allotment size to alignof(std::max_align_t)
    allotment += extra;    
    // Add two border zones of size BORD_SZ to allotment size
    allotment += 2 * BORD_SZ;

    
    // Check for space in tail of buffer or inactives list (find_free_space())
    void* pre_border_ptr = nullptr;
    // If space at an inactive chunk of memory, claim `allotment` bytes
    // See Citation "Valfind" for method to value-search in a std::map
    for (auto iter = inactives.begin(); iter != inactives.end(); iter++) {
        if (allotment <= iter->second) {
            pre_border_ptr = (void*)iter->first;
            if (allotment != iter->second) {
                inactives.insert({((uintptr_t)pre_border_ptr + allotment), iter->second - allotment});
            }
            inactives.erase(iter);
            break;
        }
    }

    // Handle cases of no space found in inactives
    if (pre_border_ptr == nullptr) {
        // Update stats with failed allocation
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }


    // Add overhead to actives map
    actives.insert({(uintptr_t)pre_border_ptr, {allotment, extra}});

    // Update set of frees
    frees.erase(pre_border_ptr);
    
    // After successful allocation, update stats
    stats.nactive++;
    stats.active_size += sz;
    stats.ntotal++;
    stats.total_size += sz;
    if ((uintptr_t)pre_border_ptr < stats.heap_min) {
        stats.heap_min = (uintptr_t)pre_border_ptr;
    }
    if ((uintptr_t)pre_border_ptr + allotment - 1 > stats.heap_max) {
        stats.heap_max = (uintptr_t)pre_border_ptr + allotment - 1;
    }

    // Set memory in border regions to BORD_CHAR
    memset(pre_border_ptr, BORD_CHAR, BORD_SZ);
    memset((void*)((uintptr_t)pre_border_ptr + allotment - (extra + BORD_SZ)), BORD_CHAR, extra + BORD_SZ);


    // Return ptr adjusted for border size
    void* ptr = (void*)((uintptr_t)pre_border_ptr + BORD_SZ);
    return ptr;
}


/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void* ptr, const char* file, int line) {
    // Do nothing upon m61_free(nullptr)
    if (ptr == nullptr) {
        return;
    }


    // The pointer stored in actives is BORD_SZ below the called ptr
    void* pre_border_ptr = (void*)((uintptr_t)ptr - BORD_SZ);

    // Find pre_border_ptr in actives
    auto elt_to_free = actives.find((uintptr_t)pre_border_ptr);


    // Error Detection
    // Double Free
    if (frees.find(pre_border_ptr) != frees.end()) {
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", double free\n";
        abort();
    }
    // Non-Heap Free
    if (pre_border_ptr < default_buffer.buffer || pre_border_ptr >= default_buffer.buffer + default_buffer.size) {
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", not in heap\n";
        abort();
    }
    // Wild Free
    if (elt_to_free == actives.end()) {
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", not allocated\n";
        abort();
    }


    // Pull information into locals
    size_t allotment = elt_to_free->second.first;
    size_t extra = elt_to_free->second.second;


    // Error Detection (Cont.)
    // Fence-Post Write (Border Write)
    if (BORD_SZ != 0) {
        // Check fence-post writes on lower border
        char* lower_border_begin = (char*)pre_border_ptr;
        for (size_t i = 0; i < BORD_SZ; i++) {
            if (lower_border_begin[i] != BORD_CHAR) {
                // It's possible to specify the Lower Border error, but this would fail CS61 tests
                std::cerr << "MEMORY BUG: " << file << ':' << line << ": detected wild write during free of pointer " << ptr << '\n';
                abort();
            }
        }
        // Check fence-post writes on upper border
        char* upper_border_end = (char*)((uintptr_t)pre_border_ptr + allotment - 1);
        for (size_t i = 0; i < BORD_SZ + extra; i++) {
            if (upper_border_end[-i] != BORD_CHAR) {
                // It's possible to specify the Upper Border error, but this would fail CS61 tests
                std::cerr << "MEMORY BUG: " << file << ':' << line << ": detected wild write during free of pointer " << ptr << '\n';
                abort();
            }
        }
    }
    

    // Free from actives
    actives.erase((uintptr_t)pre_border_ptr);
    // Free into inactives
    inactives.insert({(uintptr_t)pre_border_ptr, allotment});
    // Add to set of frees
    frees.insert(pre_border_ptr);

    // Update memory statistics
    stats.nactive--;
    stats.active_size -= allotment - (extra + 2 * BORD_SZ);


    // Coalesce up
    auto iter = inactives.find((uintptr_t)pre_border_ptr);
    auto next = iter;
    next++;
    if (iter != inactives.end() && next != inactives.end() && iter->first + iter->second == next->first) {
        iter->second += next->second;
        inactives.erase(next);
    }
    // Coalesce down
    auto prev = iter;
    prev--;
    if (iter != inactives.begin() && prev != inactives.begin() && prev->first + prev->second == iter->first) {
        prev->second += iter->second;
        inactives.erase(iter);
    }
}


/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    // Detect overflow in count * sz
    bool overflow = sz != 0 && count > SIZE_MAX / sz;
    if (overflow) {
        stats.nfail++;
        return nullptr;
    }

    void* ptr = m61_malloc(count * sz, file, line);
    if (ptr) {
        memset(ptr, 0, count * sz);
    }
    return ptr;
}


/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
    return stats;
}


/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
    m61_statistics local_stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           local_stats.nactive, local_stats.ntotal, local_stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           local_stats.active_size, local_stats.total_size, local_stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
}
