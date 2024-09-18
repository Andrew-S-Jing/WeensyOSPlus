#ifndef M61_HH
#define M61_HH 1
#include <cassert>
#include <cstdlib>
#include <cinttypes>
#include <cstdio>
#include <new>
#include <random>
// Additional includes
#include <map>


/// ADDED HEADER DEFINITIONS:

/// struct meta
///     Structure of the metatdata carried by actives
struct meta {
    size_t size;
    uintptr_t lower_border_first;
    uintptr_t upper_border_last;
    const char* file;
    int line;
};

/// type actives_t
///     Type of the actives map
typedef std::map<uintptr_t, meta> actives_t;

/// type inactives_t
///     Type of the inactives map
typedef std::map<uintptr_t, size_t> inactives_t;

/// m61_activate_mem(addr, sz, allotment, file, line)
///     Adds the allocation described by the arguments, as well as the
///       corresponding metadata to `actives`.
///     Also establishes the canary borders above and below the allocation
void m61_activate_mem(uintptr_t addr, size_t sz, size_t allotment,
                      const char* file, int line);

/// m61_find_free_space(allotment)
///     Return a pointer to at least `allotment` bytes of inactive memory.
///     Returns `nullptr` if no such space is found.
///     See Citation "Valfind" for method to value-search in a std::map
void* m61_find_free_space(size_t allotment);

/// m61_free_bug_detect(ptr, file, line)
///     If any memory bugs during the process of `m61_free()`, calls `abort()`.
///     Returns the iterator to the element to be freed by m61_free() to avoid
///       double-searching through the actives map.
actives_t::iterator m61_free_bug_detect(void* ptr, const char* file, int line);

/// m61_coalesce(addr)
///     Coalesces the `inactives` element with key `(uintptr_t)ptr` with its
///       immediate upwards neighbor and immediate downwards neighbor
void m61_coalesce(uintptr_t addr);

/// sz_to_allot(sz)
///     Helper to safely translate from size to allotment
///     Allotment is the size of an m61_malloc, but also accounting for the
///       fence-post canary borders and alignment adjustments
///     Returns an adjusted allotment, will return `0` if overflow is detected
size_t sz_to_allot(size_t sz);



/// DISPO HEADER DEFINITIONS:

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
void* m61_malloc(size_t sz, const char* file = __builtin_FILE(), int line = __builtin_LINE());

/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`.
void m61_free(void* ptr, const char* file = __builtin_FILE(), int line = __builtin_LINE());

/// m61_calloc(count, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `count` elements of `sz` bytes each. The memory
///    is initialized to zero.
void* m61_calloc(size_t count, size_t sz, const char* file = __builtin_FILE(), int line = __builtin_LINE());


/// m61_statistics
///    Structure tracking memory statistics.
struct m61_statistics {
    unsigned long long nactive;         // # active allocations
    unsigned long long active_size;     // # bytes in active allocations
    unsigned long long ntotal;          // # total allocations
    unsigned long long total_size;      // # bytes in total allocations
    unsigned long long nfail;           // # failed allocation attempts
    unsigned long long fail_size;       // # bytes in failed alloc attempts
    uintptr_t heap_min;                 // smallest allocated addr
    uintptr_t heap_max;                 // largest allocated addr
};

/// m61_get_statistics()
///    Return the current memory statistics.
m61_statistics m61_get_statistics();

/// m61_print_statistics()
///    Print the current memory statistics.
void m61_print_statistics();

/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.
void m61_print_leak_report();


/// This magic class lets standard C++ containers use your allocator
/// instead of the system allocator.
template <typename T>
class m61_allocator {
public:
    using value_type = T;
    m61_allocator() noexcept = default;
    m61_allocator(const m61_allocator<T>&) noexcept = default;
    template <typename U> m61_allocator(m61_allocator<U>&) noexcept {}

    T* allocate(size_t n) {
        return reinterpret_cast<T*>(m61_malloc(n * sizeof(T), "?", 0));
    }
    void deallocate(T* ptr, size_t) {
        m61_free(ptr, "?", 0);
    }
};
template <typename T, typename U>
inline constexpr bool operator==(const m61_allocator<T>&, const m61_allocator<U>&) {
    return true;
}

/// Returns a random integer between `min` and `max`, using randomness from
/// `randomness`.
template <typename Engine, typename T>
inline T uniform_int(T min, T max, Engine& randomness) {
    return std::uniform_int_distribution<T>{min, max}(randomness);
}

#endif
