#ifndef WEENSYOS_K_FDITER_HH
#define WEENSYOS_K_FDITER_HH
#include "kernel.hh"
#include <atomic>



// kalloc_fdtable
//    Allocate and return a new, empty fdtable.

weensy_fdtable* kalloc_fdtable() {
    weensy_fdtable* fdt = reinterpret_cast<weensy_fdtable*>(kalloc(PAGESIZE));
    if (fdt) {
        memset(&fdt->entries[0], 0, sizeof(weensy_fdtable));
    }
    return fdt;
}


// file_find_pa(ft, filename), file_find_kptr(ft, filename)
//    Returns the pa or kptr associated with `filename` in filetable `ft`.
//    If not found, returns `0` or `nullptr`.

uintptr_t file_find_pa(weensy_filetable* ft, filename_t filename) {

    // Entry errors
    assert(ft == reinterpret_cast<weensy_filetable*>(FILETABLE_ADDR),
               "file_find_pa invalid ft");
    assert(memcmp(&filename, &FILENAME_NONE, sizeof(filename_t)) != 0,
               "file_find_pa no filename provided");
    
    for (auto entry : ft->entries) {
        if (memcmp(&filename, &entry.filename, sizeof(filename_t)) == 0) {
            return reinterpret_cast<uintptr_t>(entry.filestart);
        }
    }

    return 0;
}
void* file_find_kptr(weensy_filetable* ft, filename_t filename) {
    // Entry errors
    assert(ft == reinterpret_cast<weensy_filetable*>(FILETABLE_ADDR),
               "file_find_kptr invalid ft");
    assert(memcmp(&filename, &FILENAME_NONE, sizeof(filename_t)) != 0,
               "file_find_kptr no filename provided");

    return pa2kptr(file_find_pa(ft, filename));
}

int file_try_map(weensy_filetable* ft, uintptr_t pa, filename_t filename) {

    // Entry errors
    assert(ft == reinterpret_cast<weensy_filetable*>(FILETABLE_ADDR),
               "file_try_map invalid ft");
    assert(memcmp(&filename, &FILENAME_NONE, sizeof(filename_t)) != 0,
               "file_try_map no filename provided");
    assert(allocatable_physical_address(pa), "file_try_map invalid pa");

    // Find available file entry, confirm uniqueness of file filename and addr
    fileentry_t* nextvacant = nullptr;
    bool is_unique_pa = true, is_unique_name = true;
    for (fileentry_t* cursor = ft->entries;
             reinterpret_cast<weensy_filetable*>(cursor) < ft + 1;
             ++cursor) {
        if (memcmp(cursor, &FILEENTRY_NONE, sizeof(fileentry_t)) == 0) {
            if (!nextvacant) nextvacant = cursor;
        } else {
            if (pa == cursor->filestart) is_unique_pa = false;
            if (memcmp(&filename, &cursor->filename, sizeof(filename_t)) == 0) {
                is_unique_name = false;
            }
        }
    }

    // Fail
    if (!is_unique_pa || !is_unique_name || !nextvacant) return -1;

    // Map
    fileentry_t fe = {.filename = filename, .filestart = pa};
    std::atomic_thread_fence((std::memory_order_release));
    *nextvacant = fe;
    std::atomic_thread_fence((std::memory_order_release));
    memset(reinterpret_cast<void*>(pa), 0, PAGESIZE);

    return 0;
}
int file_try_map(weensy_filetable* ft, void* kptr, filename_t filename) {
    return file_try_map(ft, kptr2pa(kptr), filename);
}

filename_t file_name(const char* str) {

    // Entry
    assert(*str, "file_name str must not be empty");
    assert(strlen(str) <= sizeof(filename_t), "file_name str too long");

    filename_t filename;
    memset(&filename, 0, sizeof(filename_t));
    memcpy(&filename, str, strlen(str));
    
    return filename;
}


// fd_find_pa(fdt, fd), file_find_kptr(fdt, fd)
//    Returns the pa or kptr associated with `fd` in fdtable `fdt`.
//    If not found, returns `0` or `nullptr`.

uintptr_t fd_find_pa(weensy_fdtable* fdt, int fd) {
    // Entry errors
    assert(fdt, "fd_find_pa no fdt provided");
    if (fd < 0 && fd >= NFDENTRIES) return 0;
    
    return fdt->entries[fd];
}
void* fd_find_kptr(weensy_fdtable* fdt, int fd) {
    // Entry errors
    assert(fdt, "fd_find_kptr no fdt provided");
    if (fd < 0 && fd >= NFDENTRIES) return 0;

    return pa2kptr(fd_find_pa(fdt, fd));
}


// fd_set_pa(fdt, pa), fd_set_kptr(fdt, kptr)
//    Returns the FD that was set or `-1` if none.
int fd_set_pa(weensy_fdtable* fdt, uintptr_t pa) {
    // Entry errors
    assert(fdt, "fd_set_pa no fdt provided");
    assert(pa && !(pa & PAGEOFFMASK), "fd_set_pa bad pa");

    for (int i = 0;
             reinterpret_cast<weensy_fdtable*>(&fdt->entries[i]) < fdt + 1;
             ++i) {
        if (fdt->entries[i] == 0) {
            fdt->entries[i] = pa;
            return i;
        }
    }
    
    return -1;
}
int fd_set_kptr(weensy_fdtable* fdt, void* kptr) {
    // Entry errors
    assert(fdt, "fd_set_kptr no fdt provided");
    assert(kptr, "fd_set_kptr bad kptr");

    return fd_set_pa(fdt, kptr2pa(kptr));
}


// fd_delete(fdt, fd)
//    Delete the fdentry for `fd` in `fdt`.
//    Returns `0` on success and `-1` on failure.

int fd_delete(weensy_fdtable* fdt, int fd) {
    // Entry errors
    assert(fdt, "fd_delete no fdt provided");
    assert(fd >= 0 && fd < NFDENTRIES,
        "fd_delete bad fd");

    if (fdt->entries[fd] == 0) return -1;
    fdt->entries[fd] = 0;
    return 0;
}

#endif
