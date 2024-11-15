#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
// Additional includes (also included <map> in "m61.hh")
#include <iostream>
#include <set>

// Size of `header` struct
static const size_t HSIZE = sizeof(header);

// Canary value
static const char CANARY = 61;
static const char CANARIES[4] = {61, 61, 61, 61};
static const size_t CSIZE = 4;

// Extended, quasi-booleans for more protection against wild writes
static const unsigned ACTIVE =  61616161;
static const unsigned INACTIVE = 0x61616161;
static const unsigned FREED = 06161616161;


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
    // Initialize buffer to be one, big inactive chunk of memory
    header initial_head = {
        .canary1 = 0,
        .status = INACTIVE,
        .size = default_buffer.size - HSIZE,
        .allotment = default_buffer.size - HSIZE,
        .prev_header = 0,
        .file = 0,
        .line = 0,
        .canary2 = 0
    };
    memcpy(initial_head.canary1, CANARIES, CSIZE);
    memcpy(initial_head.canary2, CANARIES, CSIZE);
    *((header*) default_buffer.buffer) = initial_head;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}




// header::next
//    Returns a pointer to the next header or `nullptr` if last entry

header* header::next() {
    char* next = (char*) (this + 1) + this->allotment;
    char* bufend = default_buffer.buffer + default_buffer.size;
    return next >= bufend ? nullptr : (header*) next;
}


// header::this
//    Returns the address of the allocated memory described by `this`

uintptr_t header::mem() {
    return (uintptr_t) (this + 1);
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
    (uintptr_t) default_buffer.buffer + HSIZE,      // smallest heap addr
    (uintptr_t) default_buffer.buffer + HSIZE       // largest heap addr
};



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
    header* head = m61_find_free_space(allotment);
    uintptr_t head_addr = (uintptr_t) head;

    // Fail on no space found by `m61_find_free_space()`
    if (head == nullptr) {
        stats.nfail++;
        stats.fail_size += sz;
        return nullptr;
    }
    assert(head->mem() % quantum == 0);

    // Reinsert leftover memory from inactive chunk into inactives
    {
        if (head->allotment - allotment < HSIZE + quantum) {
            allotment = head->allotment;
        } else {
            header* remainder = (header*) (head_addr + allotment) + 1;
            *remainder = {
                .canary1 = 0,
                .status = INACTIVE,
                .size = 0,
                .allotment = head->allotment - allotment - HSIZE,
                .prev_header = head,
                .file = file,
                .line = line,
                .canary2 = 0
            };
            memcpy(remainder->canary1, CANARIES, CSIZE);
            memcpy(remainder->canary2, CANARIES, CSIZE);
            header* next = remainder->next();
            if (next) next->prev_header = remainder;
        }
    }

    // Add allocation and metadata to `actives`, set border canaries
    *head = {
        .canary1 = 0,
        .status = ACTIVE,
        .size = sz,
        .allotment = allotment,
        .prev_header = head->prev_header,
        .file = file,
        .line = line,
        .canary2 = 0
    };
    memcpy(head->canary1, CANARIES, CSIZE);
    memcpy(head->canary2, CANARIES, CSIZE);
    memset((void*) (head->mem() + sz), CANARY, allotment - sz);

    // After successful allocation, update `stats`
    stats.nactive++;
    stats.active_size += sz;
    stats.ntotal++;
    stats.total_size += sz;
    if (head->mem() < stats.heap_min) {
        stats.heap_min = head_addr;
    }
    uintptr_t current_last = head->mem() + allotment - 1;
    if (current_last > stats.heap_max) {
        stats.heap_max = current_last;
    }
    assert(stats.heap_min <= stats.heap_max);


    // Return pointer to newly allocated mem
    assert(head->mem() != 0);
    return (void*) head->mem();
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
    
    // Call `abort()` on bug detected, get iterator for elt with key `ptr`
    header* head_to_free = m61_free_bug_detect(ptr, file, line);

    // Pull data into locals
    size_t sz = head_to_free->size;
    size_t allotment = head_to_free->allotment;
    assert(allotment != 0);
    assert(head_to_free->mem() % quantum == 0);

    // Free
    head_to_free->status = FREED;

    // Update `stats`
    stats.nactive--;
    stats.active_size -= sz;

    // Coalesce inactive chunks
    m61_coalesce(head_to_free);
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


/// m61_find_free_space(allotment)
///     Returns a `header*` to >=`allotment` bytes of inactive payload capacity.
///     Returns `nullptr` if no such space is found.
///     `allotment == 0` is not allowed.
///     See Citation "Valfind" for method to value-search in a std::map

header* m61_find_free_space(size_t allotment) {
    header* ptr = nullptr;
    for (header* cursor = (header*) default_buffer.buffer;
             cursor;
             cursor = cursor->next()) {
        if ((cursor->status == INACTIVE || cursor->status == FREED)
                && allotment <= cursor->allotment) {
            ptr = cursor;
            break;
        }
    }
    return ptr;
}


/// m61_free_bug_detect(ptr, file, line)
///     If any memory bugs during the process of `m61_free()`, calls `abort()`.
///     Returns the iterator to the element to be freed by m61_free() to avoid
///       double-searching through the actives map.

header* m61_free_bug_detect(void* ptr, const char* file, int line) {

    // Bug Detection
    // Non-Heap Free
    if ((uintptr_t) ptr < stats.heap_min || (uintptr_t) ptr >= stats.heap_max) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", not in heap\n";
        abort();
    }

    // Pull the entry in `actives` for this free attempt
    header* head_to_free = (header*) ptr - 1;

    // Bug Detection (Cont.)
    // Unaligned Free
    if (head_to_free->mem() % quantum != 0) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", unaliged address\n";
        abort();
    }
    // Double Free
    if (head_to_free->status == FREED) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", double free\n";
        abort();
    }
    // Wild Free
    if ((head_to_free->next() != nullptr
             && head_to_free->next()->prev_header != head_to_free)
        || (head_to_free->prev_header != 0
            && ((header*) head_to_free->prev_header)->next() != head_to_free)) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": invalid free of pointer " << ptr << ", not allocated\n";
        if (head_to_free->prev_header != 0) {
            header* prev_active = (header*) head_to_free->prev_header;
            uintptr_t prev_addr = (uintptr_t) (prev_active + 1);
            // Wild Free inside allocated chunk
            if (prev_addr <= head_to_free->mem()
                    && head_to_free->mem() < prev_addr + prev_active->size) {
                std::cerr << "  " << prev_active->file << ':'
                    << prev_active->line << ": " << ptr << " is "
                    << head_to_free->mem() - prev_addr << " bytes inside a "
                    << prev_active->size
                    << " byte region allocated here" << '\n';
            }
        }
        abort();
    }

    assert(head_to_free->allotment != 0);
    assert(head_to_free->mem() % quantum == 0);

    // Bug Detection (Cont.)
    // Fence-Post Write (Border Write)
    // Check fence-post writes on lower border
    if (memcmp(head_to_free->canary2, CANARIES, CSIZE) != 0) {
        std::cerr << "MEMORY BUG: " << file << ':' << line
            << ": detected wild write during free of pointer " << ptr
            << '\n'
            << "Wild write occured on the allocation's lower border\n";
        abort();
    }
    // Check fence-post writes on upper border
    header* next_header = head_to_free->next();
    if (next_header != nullptr) {
        bool wild = false;
        for (size_t i = head_to_free->size; i < head_to_free->allotment; ++i) {
            if (((char*) head_to_free->mem())[i] != CANARY) {
                wild = true;
                break;
            }
        }
        if (wild || memcmp(next_header->canary1, CANARIES, CSIZE) != 0) {
            std::cerr << "MEMORY BUG: " << file << ':' << line
                << ": detected wild write during free of pointer " << ptr
                << '\n'
                << "Wild write occured on the allocation's upper border\n";
            abort();
        }
    }

    // Return the element to be freed
    return head_to_free;
}


/// m61_coalesce(addr)
///     Coalesces the `inactives` element with key `ptr` (as uintptr_t) with its
///       immediate upwards neighbor and immediate downwards neighbor

void m61_coalesce(header* current) {

    // Coalesce up
    header* next = current->next();
    if (next && (next->status == INACTIVE || next->status == FREED)) {
        header* next_next = next->next();
        current->allotment += next->allotment + HSIZE;
        memset(next, 0, HSIZE);
        if (next_next) next_next->prev_header = current;
    }

    // Coalesce down
    header* prev = (header*) current->prev_header;
    if (prev && (prev->status == INACTIVE || prev->status == FREED)) {
        prev->allotment += HSIZE + current->allotment;
        memset(current, 0, HSIZE);
        next = prev->next();
        if (next) next->prev_header = prev;
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
    size_t fragmentation = 0;
    if (misalign != 0) {
        fragmentation = quantum - misalign;
    }

    // Detect overflow
    if (allotment > SIZE_MAX - fragmentation) {
        return 0;
    }

    // Align allotment size to `alignof(std::max_align_t)`
    allotment += fragmentation;

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
    for (header* cursor = (header*) default_buffer.buffer;
             cursor != nullptr;
             cursor = cursor->next()) {
        if (cursor->status == ACTIVE) {
            std::cout << "LEAK CHECK: "
                << cursor->file << ':' << cursor->line
                << ": allocated object " << (void*) (cursor + 1)
                << " with size " << cursor->size << '\n';
        }
    }
}
