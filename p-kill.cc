#include "u-lib.hh"
#ifndef ALLOC_SLOWDOWN
#define ALLOC_SLOWDOWN 100
#endif

extern uint8_t end[];

volatile uint8_t* heap_top;
volatile uint8_t* stack_bottom;

void process_main() {
    bool child = false;
    int forks_pending = 15;
    while (!child && forks_pending != 0) {
        int r = sys_fork();
        if (r > 0) --forks_pending;
        child = r == 0;
    }
    if (!child) sys_exit();

    pid_t p = sys_getpid();
    srand(p);

    uint8_t* heap_bottom = (uint8_t*) round_up((uintptr_t) end, PAGESIZE);
    heap_top = heap_bottom;
    stack_bottom = (uint8_t*) round_down((uintptr_t) rdrsp() - 1, PAGESIZE);

    while (heap_top != stack_bottom) {
        int x = rand(0, ALLOC_SLOWDOWN - 1);
        if (x < p) {
            if (sys_page_alloc((void*) heap_top) < 0) {
                break;
            }
            // check that the page starts out all zero
            for (unsigned long* l = (unsigned long*) heap_top;
                 l != (unsigned long*) (heap_top + PAGESIZE);
                 ++l) {
                assert(*l == 0);
            }
            // check we can write to new page
            *heap_top = p;
            // check we can write to console
            console[CPOS(24, 79)] = p;
            // update `heap_top`
            heap_top += PAGESIZE;
        } else if (x < p + 1 && heap_bottom < heap_top) {
            // ensure we can write to any previously-allocated page
            uintptr_t addr = rand((uintptr_t) heap_bottom,
                                  (uintptr_t) heap_top - 1);
            *((char*) addr) = p;
        } else {
            int kernel_kill = sys_kill(0);
            int wild_kill = sys_kill(INT_MAX);
            assert(kernel_kill == -1 && wild_kill == -1);
            // Kill!!
            int victim = rand(2, PID_MAX - 1);
            if (victim != p) sys_kill(victim);
        }
        sys_yield();
    }

    // After running out of memory, do nothing forever
    while (true) {
        sys_yield();
    }
}
