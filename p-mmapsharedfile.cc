#include "u-lib.hh"
#ifndef ALLOC_SLOWDOWN
#define ALLOC_SLOWDOWN 18
#endif

extern uint8_t end[];

volatile uint8_t* heap_top;
volatile uint8_t* stack_bottom;

// Remember which pages we wrote data into
volatile uint8_t pagemark[4096] = {0};

void process_main() {
    for (size_t i = 0; i != sizeof(pagemark); ++i) {
        assert(pagemark[i] == 0);
    }

    while (true) {
        int x = rand(0, ALLOC_SLOWDOWN);
        if (x == 0) {
            // fork, then either exit or start allocating
            pid_t p = sys_fork();
            assert(p < PID_MAX);
            int choice = rand(0, 2);
            if (choice == 0 && p > 0) {
                sys_exit();
            } else if (choice != 2 ? p > 0 : p == 0) {
                break;
            }
        } else {
            sys_yield();
        }
    }

    int speed = rand(1, 16);
    pid_t self = sys_getpid();

    uint8_t* heap_bottom = (uint8_t*) round_up((uintptr_t) end, PAGESIZE);
    heap_top = heap_bottom;
    stack_bottom = (uint8_t*) round_down((uintptr_t) rdrsp() - 1, PAGESIZE);
    unsigned nalloc = 0;

    // Allocate heap pages until out of address space,
    // forking along the way.
    while (heap_top != stack_bottom) {
        int x = rand(0, 6 * ALLOC_SLOWDOWN);
        if (x >= 8 * speed) {
            // do not check consistency of shared mem
            sys_yield();
            continue;
        }

        x = rand(0, 7 + min(nalloc / 4, 10U));
        if (x < 2) {
            pid_t p = sys_fork();
            assert(p < PID_MAX);
            if (p == 0) {
                pid_t new_self = sys_getpid();
                assert(new_self != self);
                self = new_self;
                speed = rand(1, 16);
            }
        } else if (x < 3) {
            sys_exit();
        } else {
            int fd = sys_open("user file");
            assert(fd >= 0);
            void* r1 = sys_mmap(nullptr,
                                PAGESIZE,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_SHARED,
                                fd,
                                0);
            int r2 = sys_close(fd);
            assert(r2 == 0);
            if (r1 != MAP_FAILED) {
                // do not check that the page starts out all zero
                // check we can write to new page
                *heap_top = speed;
                // check we can write to console
                console[CPOS(24, 79)] = speed;
                // do not record data written
                // update `heap_top`
                heap_top += PAGESIZE;
                nalloc = (heap_top - heap_bottom) / PAGESIZE;
                // clear "Out of physical memory" msg
                if (console[CPOS(24, 0)]) {
                    console_printf(CPOS(24, 0), 0, "\n");
                }
            } else if (nalloc < 4) {
                sys_exit();
            } else {
                nalloc -= 4;
            }
        }
    }

    // After running out of memory
    while (true) {
        if (rand(0, 2 * ALLOC_SLOWDOWN - 1) == 0) {
            sys_exit();
        } else {
            sys_yield();
        }
    }
}
