#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[PID_MAX];           // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state - see `kernel.hh`
physpageinfo physpages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
[[noreturn]] void syscall_exit();
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel_start(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // (re-)initialize kernel page table
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int perm = PTE_P | PTE_W | PTE_U;
        if (addr == 0) {
            // nullptr is inaccessible even to the kernel
            perm = 0;
        } else if (addr < PROC_START_ADDR && addr != CONSOLE_ADDR) {
            // kernel memory (except CGA console) is inaccessible to user
            perm ^= PTE_U;
        }
        // install identity mapping
        int r = vmiter(kernel_pagetable, addr).try_map(addr, perm);
        assert(r == 0); // mappings during kernel_start MUST NOT fail
                        // (Note that later mappings might fail!!)
    }

    // set up process descriptors
    for (pid_t i = 0; i < PID_MAX; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) {
        command = WEENSYOS_FIRST_PROCESS;
    }
    if (!program_image(command).empty()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // switch to first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel physical memory allocator. Allocates at least `sz` contiguous bytes
//    and returns a pointer to the allocated memory, or `nullptr` on failure.
//    The returned pointer’s address is a valid physical address, but since the
//    WeensyOS kernel uses an identity mapping for virtual memory, it is also a
//    valid virtual address that the kernel can access or modify.
//
//    The allocator selects from physical pages that can be allocated for
//    process use (so not reserved pages or kernel data), and from physical
//    pages that are currently unused (`physpages[N].refcount == 0`).
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The returned memory is initially filled with 0xCC, which corresponds to
//    the `int3` instruction. Executing that instruction will cause a `PANIC:
//    Unhandled exception 3!` This may help you debug.

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) return nullptr;

    static int pageno = 0;
    int page_increment = 1;
    // In the handout code, `kalloc` returns the first free page.
    // Alternate search strategies can be faster and/or expose bugs elsewhere.
    // This initialization returns a random free page:
    //     int pageno = rand(0, NPAGES - 1);
    // This initialization remembers the most-recently-allocated page and
    // starts the search from there:
    //     static int pageno = 0;
    // In Step 3, you must change the allocation to use non-sequential pages.
    // The easiest way to do this is to set page_increment to 3, but you can
    // also set `pageno` randomly.

    for (int tries = 0; tries != NPAGES; ++tries) {
        uintptr_t pa = pageno * PAGESIZE;
        if (allocatable_physical_address(pa)
            && physpages[pageno].refcount == 0) {
            ++physpages[pageno].refcount;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
        pageno = (pageno + page_increment) % NPAGES;
    }

    return nullptr;
}


// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    if (!kptr) return;
    uintptr_t pa = reinterpret_cast<uintptr_t>(kptr);
    assert((pa & PAGEOFFBITS) == 0);
    int pageno = pa / PAGESIZE;
    assert(physpages[pageno].used());
    physpages[pageno].refcount--;
}


// kfree_pagetable(pt)
//    Frees all virt addrs referred to in the pagetable at `pt`, then
//    frees all level 1-3 pagetable pages in the pagetable, then
//    frees the top-level (root) pagetable page at `pt`.
//    Does nothing if the pagetable does not exist (`pt` == `nullptr`).

void kfree_pagetable(x86_64_pagetable* pt) {
    if (!pt) return;
    for (vmiter it(pt, 0); !it.done(); it.next())
        if (it.user()) kfree(it.kptr());
    for (ptiter it(pt); !it.done(); it.next()) kfree(it.kptr());
    kfree(pt);
}


// kcleanup(pid)
//    Frees and cleans all data (except shared pages) associated with the
//    process with PID `pid`. Does not schedule the next process.
//    Useful as a "kill-this-process" cleanup function during `syscall_fork()`
//    and during a `SYSCALL_EXIT` exception in `syscall()`.

void kcleanup(pid_t pid) {
    kfree_pagetable(ptable[pid].pagetable);
    ptable[pid].pagetable = nullptr;
    memset(&ptable[pid].regs, 0, sizeof(regstate));
    ptable[pid].state = P_FREE;
}


// kpage_alloc(pid, va)
//    Allocates a currently free page in phys mem and maps that address to `va`
//    in the pagetable for process `pid`. Gives permissions in allocated page.
//
//    Returns:
//      Success: returns  `0`
//      Errors:  returns `-1` on failed mem page allocation
//               returns `-2` on failed pagetable page allocation

int kpage_alloc(pid_t pid, uintptr_t va) {
    // Allocate page
    void* kptr = kalloc(PAGESIZE);
    if (!kptr) return -1;
    // Map and user-permit the newly allocated page
    int r = vmiter(ptable[pid].pagetable, va)
        .try_map(kptr, PTE_P | PTE_W | PTE_U);
    if (r != 0) return -2;
    return 0;
}


// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//
//    **Assumes there is enough mem to initialize the process**

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // initialize process page table
    ptable[pid].pagetable = kalloc_pagetable();
    assert(ptable[pid].pagetable);
    // Map kernel mem to user pagetable
    for (uint64_t addr = 0; addr < PROC_START_ADDR; addr += PAGESIZE) {
        vmiter k_pte = vmiter(kernel_pagetable, addr);
        int r = vmiter(ptable[pid].pagetable, addr)
            .try_map(k_pte.pa(), k_pte.perm());
        assert(r == 0);
    }

    // obtain reference to program image
    // (The program image models the process executable.)
    program_image pgm(program_name);

    // allocate and map process memory as specified in program image
    // copy instructions and data from program image into process memory
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {

        // Broad-scoped vars to help during copying process
        const char* cursor = seg.data();
        bool is_first_page = true;
        int remaining = seg.data_size();

        // `a` is the process virtual address for the next code/data page
        for (uintptr_t a = round_down(seg.va(), PAGESIZE);
                 a < seg.va() + seg.size();
                 a += PAGESIZE) {
            
            // Allocate and map
            int r = kpage_alloc(pid, a);
            assert (r == 0);

            // Copy code/data
            vmiter pte = vmiter(ptable[pid].pagetable, a);
            memset(pte.kptr(), 0, PAGESIZE);
            // `size` (below) is the # of bytes to be copied on this page and
            //   is equal to either `PAGESIZE` or a smaller value, when fewer
            //   than `PAGESIZE` bytes are to-be-copied in `seg.data()` or
            //   the first `offset` bytes of 1st-page are before `seg.va()`
            int size = min(remaining, (int) PAGESIZE);
            if (is_first_page) {
                uintptr_t offset = seg.va() - a;
                size -= offset;
                memcpy((void*) (pte.pa() + offset), cursor, size);
                is_first_page = false;
            }
            else memcpy(pte.kptr(), cursor, size);

            // Iterate vars
            cursor += PAGESIZE;
            remaining -= size;
        }
    }

    // mark entry point
    ptable[pid].regs.reg_rip = pgm.entry();

    // Compute process virtual address for stack page
    uintptr_t va_last = MEMSIZE_VIRTUAL - 1;
    uintptr_t stack_addr = (va_last) - (va_last & PAGEOFFMASK);
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;
    // allocate and map stack segment
    int r = kpage_alloc(pid, stack_addr);
    assert(r == 0);

    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PTE_W
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PTE_P
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PTE_U)) {
            proc_panic(current, "Kernel page fault on %p (%s %s, rip=%p)!\n",
                       addr, operation, problem, regs->reg_rip);
        }
        error_printf(CPOS(24, 0), COLOR_ERROR,
                     "PAGE FAULT on %p (pid %d, %s %s, rip=%p)!\n",
                     addr, current->pid, operation, problem, regs->reg_rip);
        log_print_backtrace(current);
        current->state = P_FAULTED;
        break;
    }

    default:
        proc_panic(current, "Unhandled exception %d (rip=%p)!\n",
                   regs->reg_intno, regs->reg_rip);

    }


    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// These functions are defined farther below
int syscall_page_alloc(uintptr_t addr);
pid_t syscall_fork();


// syscall(regs)
//    Handle a system call initiated by a `syscall` instruction.
//    The process’s register values at system call time are accessible in
//    `regs`.
//
//    If this function returns with value `V`, then the user process will
//    resume with `V` stored in `%rax` (so the system call effectively
//    returns `V`). Alternately, the kernel can exit this function by
//    calling `schedule()`, perhaps after storing the eventual system call
//    return value in `current->regs.reg_rax`.
//
//    It is only valid to return from this function if
//    `current->state == P_RUNNABLE`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state.
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        user_panic(current);
        break; // will not be reached

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        kcleanup(current->pid);
        schedule();             // does not return

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Handles the SYSCALL_PAGE_ALLOC system call. Implements the specification
//    for `sys_page_alloc` in `u-lib.hh`.
//
//    Returns:
//      Success: returns  `0`
//      Errors:  returns `-1` on failed mem page allocation
//               returns `-2` on failed pagetable page allocation
//               returns `-3` on permission denied to kernel virt memspace
//               returns `-4` on misaligned addr

int syscall_page_alloc(uintptr_t addr) {

    // Fail on misaligned or kernel memspace virt addr
    bool misaligned, inaccessible;
    inaccessible = addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL;
    misaligned = (addr & PAGEOFFMASK) != 0;
    if (inaccessible) return -3;
    if (misaligned) return -4;

    // Map allocated page to user pagetable
    int r = kpage_alloc(current->pid, addr);
    if (r != 0) return r;
    void* kptr = vmiter(current->pagetable, addr).kptr();
    assert(kptr);
    memset(kptr, 0, PAGESIZE);

    return 0;
}


// syscall_fork
//    Forks current process into parent and child.
//    Copies all of parent's mem into child's mem, but any writeable mem is
//    mapped to a different phys addr in the child pagetable, for process iso.
//    On failed fork, the partially created child will be cleaned up.
//
//    Returns:
//      Success: `pid` to parent process, where `pid` is the child's PID
//                 `0` to child process
//      Error:    `-1` on failed mem page allocation for child
//                `-2` on failed pagetable page allocation for child
//                `-3` on failed PID/process slot allocation

pid_t syscall_fork() {

    // Find next free PID
    pid_t pid = 0;
    for (pid_t procno = 1; procno < PID_MAX; ++procno) {
        if (ptable[procno].state == P_FREE) {
            pid = procno;
            break;
        }
    }
    // Fail on `-3` when there are no free PIDs
    if (pid == 0) return -3;

    // Create child
    ptable[pid].pagetable = kalloc_pagetable();
    if (!ptable[pid].pagetable) return -2;
    ptable[pid].regs = current->regs;
    ptable[pid].state = P_RUNNABLE;

    // Copy kernel mem mappings into new pagetable
    for (vmiter it = vmiter(current->pagetable, 0); !it.done(); it.next()) {
        vmiter pte = vmiter(ptable[pid].pagetable, it.va());
        if (it.va() < PROC_START_ADDR || (it.user() && !it.writable())) {
            // Map kernel and read-only mem to same phys addr
            int r = pte.try_map(it.pa(), it.perm());
            if (r != 0) {
                kcleanup(pid);
                return -2;
            }
            if (it.user()) physpages[it.pa() / PAGESIZE].refcount++;
        } else if (it.user() && it.writable()) {
            // Map writeable mem to newly alloc'd phys addr
            void* pa = kalloc(PAGESIZE);
            if (!pa) {
                kcleanup(pid);
                return -1;
            }
            int r = pte.try_map(pa, it.perm());
            if (r != 0) {
                kfree(pa);
                kcleanup(pid);
                return -2;
            }
            memcpy(pa, it.kptr(), PAGESIZE);
        }
    }

    ptable[pid].regs.reg_rax = 0;
    return pid;
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % PID_MAX;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
        }
    }
}


// run(p)
//    Run process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current registers.
    check_process_registers(p);

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % PID_MAX;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < PID_MAX; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % PID_MAX;
        }
    }

    console_memviewer(p);
    if (!p) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}
