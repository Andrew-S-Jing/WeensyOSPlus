#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
// Additional includes
#include <iostream>
#include <set>


// Setting for # of blocks of alignof(std::max_align_t) of fence-post border
//   regions on either side of an m61_malloc
// See Citation "Border" for idea of buffer-borders around each m61_malloc
static const size_t BORD_BLOCKS = 1;

// Specs for the border regions
// Not overflow protected, but BORD_BLOCKS should be kept low anyways
static const size_t BORD_SZ = BORD_BLOCKS * alignof(std::max_align_t);
static const char BORD_CHAR = 61;


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




// Constant of system alignment
static const size_t quantum = alignof(std::max_align_t);

// Global, external metadata objects
// stats
//     Memory statistics tracker
static m61_statistics stats = {
    0,                                  // # active allocations
    0,                                  // # bytes in active allocations
    0,                                  // # total allocations
    0,                                  // # bytes in total allocations
    0,                                  // # failed allocation attempts
    0,                                  // # bytes in failed alloc attempts
    (uintptr_t)default_buffer.buffer,   // smallest allocated addr
    (uintptr_t)default_buffer.buffer    // largest allocated addr
};

// actives
//     std::map of all currently active allocations
//     Elt in actives is {ptr, metadata}
//     See type actives_t and substruct meta in "m61.hh"
static actives_t actives;

// inactives
//     std::map of all currently inactive allocations
//     Elt in inactives is {ptr, allotment}
//     See type inactives_t in "m61.hh"
//     Allotment defined below by `sz_to_allot()`
static inactives_t inactives = {
    {
        (uintptr_t)default_buffer.buffer + BORD_SZ,     // lowest allocable addr
        default_buffer.size                             // total buffer allot
    }
};

// frees
//     Set of previously freed pointers - set of currently allocated pointers
static std::set<void*> frees;



/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {

    // `m61_malloc(0)` returns the nullptr
    //     Counts as a successful, inactive allocation
    if (sz == 0) {
        stats.ntotal++;
        return nullptr;
    }

    // Adjust `sz` to `allotment`, fail on overflow
    //     Handled before finding allocation space for efficiency
    size_t allotment = sz_to_allot(sz);
    if (allotment == 0) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    
    // Check for enough free space in inactives
    void* ptr = m61_find_free_space(allotment);

    // Fail on no space found by `m61_find_free_space()`
    if (ptr == nullptr) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }

    // Reinsert leftover memory from inactive chunk into inactives
    {
        inactives_t::iterator iter = inactives.find((uintptr_t)ptr);
        if (allotment != iter->second) {
            uintptr_t remainder_ptr = (uintptr_t)ptr + allotment;
            size_t remainder_allotment = iter->second - allotment;
            inactives.insert({remainder_ptr, remainder_allotment});
        }
        inactives.erase(iter);
    }

    // Add allocation and metadata to `actives`, set border canaries
    m61_activate_mem(ptr, sz, allotment, file, line);
    actives_t::iterator active_iter = actives.find((uintptr_t)ptr);


    // Update `frees`
    frees.erase(ptr);

    // After successful allocation, update `stats`
    stats.nactive++;
    stats.active_size += sz;
    stats.ntotal++;
    stats.total_size += sz;
    if (active_iter->second.lower_border_first < stats.heap_min) {
        stats.heap_min = active_iter->second.lower_border_first;
    }
    if (active_iter->second.upper_border_last > stats.heap_max) {
        stats.heap_max = active_iter->second.upper_border_last;
    }


    // Return `ptr`
    return ptr;
}


/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void* ptr, const char* file, int line) {

    // Do nothing upon `m61_free(nullptr)`
    if (ptr == nullptr) {
        return;
    }
    
    // Call `abort()` if any bugs are detected
    m61_free_bug_detect(ptr, file, line);

    // Find `ptr` in actives, pull data into locals
    actives_t::iterator elt_to_free = actives.find((uintptr_t)ptr);
    size_t sz = elt_to_free->second.size;
    size_t allotment = sz_to_allot(sz);

    // Free from `actives`
    actives.erase((uintptr_t)ptr);
    // Free into `inactives`
    inactives.insert({(uintptr_t)ptr, allotment});
    // Add to `frees`
    frees.insert(ptr);

    // Update `stats`
    stats.nactive--;
    stats.active_size -= sz;

    // Coalesce inactive chunks
    m61_coalesce(ptr);
}


/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {

    // Detect overflow in `count * sz`
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


/// m61_activate_mem(ptr, sz, allotment, file, line)
///     Adds the allocation described by the arguments, as well as the
///       corresponding metadata to `actives`.
///     Also establishes the canary borders above and below the allocation

void m61_activate_mem(void* ptr, size_t sz, size_t allotment,
                      const char* file, int line) {

    // Define border boundaries with respect to `BORD_SZ`
    uintptr_t lower_border_first = (uintptr_t)ptr - BORD_SZ;
    uintptr_t upper_border_last = lower_border_first + allotment - 1;

    // Add allocated pointer and its metadata to actives
    meta metadata = {
        sz,                     // metadata.size
        lower_border_first,     // metadata.lower_border_first
        upper_border_last,      // metadata.upper_border_last
        file,                   // metadata.file
        line                    // metadata.line
    };
    actives.insert({(uintptr_t)ptr, metadata});

    // Set memory in border regions to `BORD_CHAR`
    size_t lower_border_sz = BORD_SZ;
    size_t upper_border_sz = allotment - (sz + BORD_SZ);
    uintptr_t upper_border_first = upper_border_last + 1 - upper_border_sz;
    memset((void*)lower_border_first, BORD_CHAR, lower_border_sz);
    memset((void*)upper_border_first, BORD_CHAR, upper_border_sz);
}


/// m61_find_free_space(allotment)
///     Return a pointer to at least `allotment` bytes of inactive memory.
///     Returns `nullptr` if no such space is found.
///     `allotment == 0` is not allowed.
///     See Citation "Valfind" for method to value-search in a std::map

void* m61_find_free_space(size_t allotment) {
    void* ptr = nullptr;
    for (inactives_t::iterator iter = inactives.begin();
         iter != inactives.end();
         iter++) {
            if (allotment <= iter->second) {
                ptr = (void*)iter->first;
                break;
            }
    }
    return ptr;
}


/// m61_free_bug_detect(ptr, file, line)
///     If any memory bugs during the process of `m61_free()`, calls `abort()`.

void m61_free_bug_detect(void* ptr, const char* file, int line) {

    // Pull the entry in `actives` for this free attempt
    actives_t::iterator elt_to_free = actives.find((uintptr_t)ptr);

    // Bug Detection
    // Double Free
    if (frees.find(ptr) != frees.end()) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", double free\n";
        abort();
    }
    // Non-Heap Free
    if ((void*)((uintptr_t)ptr - BORD_SZ) < default_buffer.buffer
        || ptr >= default_buffer.buffer + default_buffer.size) {
            std::cerr << "MEMORY BUG: " << file << ':' << line
                << ": invalid free of pointer " << ptr << ", not in heap\n";
            abort();
    }
    // Wild Free
    if (elt_to_free == actives.end()) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", not allocated\n";
        actives_t::iterator prev_active = actives.upper_bound((uintptr_t)ptr);
        if (prev_active != actives.begin()) {
            prev_active--;
            if (prev_active != actives.begin()) {
                uintptr_t prev_ptr = prev_active->first;
                meta prev_metadata = prev_active->second;
                // Wild Free inside allocated chunk
                if (prev_ptr <= (uintptr_t)ptr
                    && (uintptr_t)ptr < prev_ptr + prev_metadata.size) {
                        std::cerr << "  " << prev_metadata.file << ':'
                            << prev_metadata.line << ": " << ptr << " is "
                            << (uintptr_t)ptr - prev_ptr << " bytes inside a "
                            << prev_metadata.size
                            << " byte region allocated here" << '\n';
                }
            }
        }
        abort();
    }

    // Pull information into locals
    uintptr_t lower_border_first = elt_to_free->second.lower_border_first;
    uintptr_t upper_border_last = elt_to_free->second.upper_border_last;
    size_t sz = elt_to_free->second.size;
    size_t allotment = sz_to_allot(sz);

    // Bug Detection (Cont.)
    // Fence-Post Write (Border Write)
    if (BORD_SZ != 0) {
        // Check fence-post writes on lower border
        size_t lower_border_sz = BORD_SZ;
        for (size_t i = 0; i < lower_border_sz; i++) {
            if (((char*)lower_border_first)[i] != BORD_CHAR) {
                std::cerr << "MEMORY BUG: " << file << ':' << line
                    << ": detected wild write during free of pointer " << ptr
                    << '\n'
                    << "Wild write occured on the allocation's lower border\n";
                abort();
            }
        }
        // Check fence-post writes on upper border
        size_t upper_border_sz = allotment - (sz + BORD_SZ);
        for (size_t i = 0; i < upper_border_sz; i++) {
            if (((char*)upper_border_last)[-i] != BORD_CHAR) {
                std::cerr << "MEMORY BUG: " << file << ':' << line
                    << ": detected wild write during free of pointer " << ptr
                    << '\n'
                    << "Wild write occured on the allocation's upper border\n";
                abort();
            }
        }
    }
}


/// m61_coalesce(ptr)
///     Coalesces the `inactives` element with key `(uintptr_t)ptr` with its
///       immediate upwards neighbor and immediate downwards neighbor

void m61_coalesce(void* ptr) {
    // Coalesce up
    inactives_t::iterator iter = inactives.find((uintptr_t)ptr);
    inactives_t::iterator next = iter;
    if (next != inactives.end()) {
        next++;
        if (iter != inactives.end() && next != inactives.end()
            && iter->first + iter->second == next->first) {
                iter->second += next->second;
                inactives.erase(next);
        }
    }

    // Coalesce down
    inactives_t::iterator prev = iter;
    if (prev != inactives.begin()) {
        prev--;
        if (iter != inactives.begin()
            && prev != inactives.begin()
            && prev->first + prev->second == iter->first) {
                prev->second += iter->second;
                inactives.erase(iter);
        }
    }
}


/// sz_to_allot(sz)
///     Helper to safely translate from size to allotment
///     Allotment is the size of an m61_malloc, but also accounting for the
///       fence-post canary borders and alignment adjustments
///     Returns an adjusted allotment, will return `0` if overflow is detected

size_t sz_to_allot(size_t sz) {
    
    // Prepare for allotment adjustments
    size_t allotment = sz;
    size_t misalign = sz % quantum;
    size_t extra = 0;
    if (misalign != 0) {
        extra = quantum - misalign;
    }

    // Detect overflow
    if (allotment > SIZE_MAX - (extra + 2 * BORD_SZ)) {
        return 0;
    }

    // Align allotment size to `alignof(std::max_align_t)`
    allotment += extra;    
    // Add two border zones of size BORD_SZ to allotment size
    allotment += 2 * BORD_SZ;

    // Return adjusted value
    return allotment;
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
           local_stats.nactive,
           local_stats.ntotal,
           local_stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           local_stats.active_size,
           local_stats.total_size,
           local_stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Check actives for leaks (actives is not empty)
    if (!actives.empty()) {
        for (actives_t::iterator iter = actives.begin();
             iter != actives.end();
             iter++) {
                void* ptr = (void*)iter->first;
                meta metadata = iter->second;
                std::cout << "LEAK CHECK: "
                    << metadata.file << ':' << metadata.line
                    << ": allocated object " << ptr
                    << " with size " << metadata.size << '\n';
        }
    }
}
