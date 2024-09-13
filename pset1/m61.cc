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
// Elt in actives is {ptr, {allotment, extra}}
static std::map<uintptr_t, std::pair<size_t, size_t>> actives;
// Elt in inactives is {ptr, allotment}
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
    // Align allotment size to alignof(std::max_align_t)
    if (misalign != 0) {
        extra = quantum - misalign;
        allotment += extra;
    }

    // Handle cases of overflow
    if (sz > SIZE_MAX - extra) {
        // Update stats with failed allocation
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }
    
    // Check for space in tail of buffer or inactives list (find_free_space())
    void* ptr = nullptr;
    // If space at an inactive chunk of memory, claim `allotment` bytes
    // Consulted google on the step-search through the values of inactives (See Citation 1)
    for (auto iter = inactives.begin(); iter != inactives.end(); iter++) {
        if (allotment <= iter->second) {
            ptr = (void*)iter->first;
            if (allotment != iter->second) {
                inactives.insert({((uintptr_t)ptr + allotment), iter->second - allotment});
            }
            inactives.erase(iter);
            break;
        }
    }

    // Handle cases of not enough space or overflow
    if (ptr == nullptr) {
        // Not enough space left in default buffer for allocation
        // Update stats with failed allocation
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // Add overhead to actives map
    actives.insert({(uintptr_t)ptr, {allotment, extra}});

    // Update set of frees
    frees.erase(ptr);
    
    // After successful allocation, update stats
    stats.nactive++;
    stats.active_size += sz;
    stats.ntotal++;
    stats.total_size += sz;
    if ((uintptr_t)ptr < stats.heap_min) {
        stats.heap_min = (uintptr_t)ptr;
    }
    if ((uintptr_t)ptr + allotment - 1 > stats.heap_max) {
        stats.heap_max = (uintptr_t)ptr + allotment - 1;
    }

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

    // Find ptr in actives
    auto elt_to_free = actives.find((uintptr_t)ptr);

    // Error Detection
    if (frees.find(ptr) != frees.end()) {
        //Double Free
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", double free\n";
        abort();
    } else if (ptr < default_buffer.buffer || ptr >= default_buffer.buffer + default_buffer.size) {
        // Non-Heap Free
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", not in heap\n";
        abort();
    } else if (elt_to_free == actives.end()) {
        // Wild Free
        std::cerr << "MEMORY BUG: " << file << ':' << line << ": invalid free of pointer " << ptr << ", not allocated\n";
        abort();
    }

    // Free (from actives) and pull information into locals
    size_t allotment = elt_to_free->second.first;
    size_t extra = elt_to_free->second.second;
    actives.erase((uintptr_t)ptr);

    // Free (into inactives)
    inactives.insert({(uintptr_t)ptr, allotment});

    // Add to set of frees
    frees.insert(ptr);

    // Update memory statistics
    stats.nactive--;
    stats.active_size -= allotment - extra;

    // Coalesce up
    auto iter = inactives.find((uintptr_t)ptr);
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
    // Your code here (not needed for first tests).
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
    // Your code here.
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
