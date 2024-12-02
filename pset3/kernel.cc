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



// Kernel uses a *STRICT* overcommit policy for copy-on-write
//    Currently no disk compatibility, so policy must be strict to avoid
//    arbitrarily picking a process and killing it for memory.
// ncommittable
//    Once-usable function to initialize `NCOMMITTABLE`

ssize_t ncommittable() {
    static bool used = false;
    assert(!used);
    ssize_t count = 0;
    for (uintptr_t pa = 0; pa < MEMSIZE_VIRTUAL; pa += PAGESIZE) {
        if (allocatable_physical_address(pa)) ++count;
    }
    used = true;
    return count;
}
static const ssize_t NCOMMITTABLE = ncommittable();
static ssize_t ncommitted = 0;


// multflag(flags, desired_flags)
//    Returns true iff all flags set in `desired_flags` are all set in `flags`

bool multflag(int flags, int desired_flags) {
    return (flags & desired_flags) == desired_flags;
}


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

    // zero the universal newpage
    memset(pa2kptr(NEWPAGE_ADDR), 0, PAGESIZE);
    
    // check that `physpageinfo::refcount` type can handle max refs to newpage
    physpageinfo max;
    --max.refcount;
    assert(max.refcount >= PID_MAX * (MEMSIZE_VIRTUAL / PAGESIZE));

    // (re-)initialize kernel page table (kernel pages are shared)
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int perm = PTE_PWU;
        if (addr == 0) {
            // nullptr is inaccessible even to the kernel
            perm = 0;
        } else if (addr < PROC_START_ADDR && addr != CONSOLE_ADDR) {
            // kernel memory (except CGA console) is inaccessible to user
            perm &= ~PTE_U;
        }
        // install identity mapping
        int r = vmiter(kernel_pagetable, addr).try_map(addr, perm);
        assert(r == 0); // mappings during kernel_start MUST NOT fail
                        // (Note that later mappings might fail!!)
    }

    // set up process descriptors
    for (pid_t i = 0; i < PID_MAX; ++i) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) command = WEENSYOS_FIRST_PROCESS;
    if (!program_image(command).empty()) process_setup(1, command);
    else {
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
    if (sz > PAGESIZE || ncommitted >= NCOMMITTABLE) return nullptr;

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
            ++ncommitted;
            void* kptr = pa2kptr(pa);
            memset(kptr, 0xCC, PAGESIZE);
            return kptr;
        }
        pageno = (pageno + page_increment) % NPAGES;
    }

    return nullptr;
}


// kfree(kptr, is_private)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr`, does nothing.
//    Decommits as needed, always decommits page for private (`is_private`).

void kfree(void* kptr, bool is_private) {
    if (!kptr) return;
    uintptr_t pa = kptr2pa(kptr);
    assert(!(pa & PAGEOFFBITS));
    int pageno = pa / PAGESIZE;
    assert(physpages[pageno].used());
    --physpages[pageno].refcount;

    // Decommit if page is completely freed or is private
    bool is_completely_freed = pa != CONSOLE_ADDR
                            && pa != NEWPAGE_ADDR
                            && physpages[pageno].refcount == 0;
    if (is_private || is_completely_freed) {
        --ncommitted;
    }
    assert(ncommitted >= 0);
}


// kfree_pagetable(pt)
//    Frees all virt addrs referred to in the pagetable at `pt`, then
//    frees all level 1-3 pagetable pages in the pagetable, then
//    frees the top-level (root) pagetable page at `pt`.
//    Does nothing if the pagetable does not exist (`pt` == `nullptr`).

void kfree_pagetable(x86_64_pagetable* pt) {
    if (!pt) return;

    // Free virt pages
    for (vmiter it(pt, 0); !it.done(); it.next()) {
        if (it.user()) kfree(it.kptr(), it.priv());
    }

    // Free level 1-3 pagetable pages
    for (ptiter it(pt); !it.done(); it.next()) {
        kfree(it.kptr(), false);
    }

    // Free level 4 pagetable page
    kfree(pt, false);
}


// kcleanup(pid)
//    Frees and cleans all data (except shared pages) associated with the
//    process with PID `pid`. Does not schedule the next process.
//    Useful as a "kill-this-process" cleanup function during `syscall_fork()`
//    and during a `SYSCALL_EXIT` exception in `syscall()`.

void kcleanup(pid_t pid) {
    assert(pid > 0 && pid < PID_MAX && ptable[pid].state != P_FREE);
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

int kpage_alloc(pid_t pid, uintptr_t va, int perm) {
    // Allocate page
    void* kptr = kalloc(PAGESIZE);
    if (!kptr) return -1;
    // Map and user-permit the newly allocated page
    if (vmiter(ptable[pid].pagetable, va).try_map(kptr, perm) != 0) {
        kfree(kptr, false);
        return -2;
    }
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
    for (uintptr_t addr = 0; addr < PROC_START_ADDR; addr += PAGESIZE) {
        vmiter k_pte(kernel_pagetable, addr);
        int r = vmiter(ptable[pid].pagetable, addr)
            .try_map(k_pte.pa(), k_pte.perm());
        assert(r == 0);
    }
    ++physpages[CONSOLE_ADDR / PAGESIZE].refcount;

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
            
            // Allocate and map (writable segments are private)
            int perm = seg.writable() ? PTE_PWU_PRIV : PTE_PU;
            int r = kpage_alloc(pid, a, perm);
            assert (r == 0);

            // Copy code/data
            vmiter pte(ptable[pid].pagetable, a);
            memset(pte.kptr(), 0, PAGESIZE);
            // `size` (below) is the # of bytes to be copied on this page and
            //   is equal to either `PAGESIZE` or a smaller value, when fewer
            //   than `PAGESIZE` bytes are to-be-copied in `seg.data()` or
            //   the first `offset` bytes of 1st-page are before `seg.va()`
            int size = min(remaining, (int) PAGESIZE);
            if (is_first_page) {
                uintptr_t offset = seg.va() - a;
                size -= offset;
                memcpy(pa2kptr(pte.pa() + offset), cursor, size);
                is_first_page = false;
            } else {
                memcpy(pte.kptr(), cursor, size);
            }

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
    // allocate and map stack segment (stack is private)
    int r = kpage_alloc(pid, stack_addr, PTE_PWU_PRIV);
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
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) memshow();

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

        // Write permission faults
        if (multflag(regs->reg_errcode, PTE_PWU)) {
            uintptr_t va = addr - (addr & PAGEOFFMASK);
            vmiter pte(current->pagetable, va);
            assert(pte.pa());

            // Handle copy-on-write faults, fresh page will also be private
            if (pte.cow()) {
                assert(pte.writable() != pte.cow());

                // Do not free the ref page completely (`kalloc` will wipe mem),
                // but also never assign write access to the newpage
                if (pte.pa() != NEWPAGE_ADDR
                        && physpages[pte.pa() / PAGESIZE].refcount == 1) {
                    pte.map(pte.kptr(), PTE_PWU_PRIV);
                    break;
                }

                // Strict overcommit policy
                assert(ncommitted <= NCOMMITTABLE);
                void* kptr = pte.kptr();
                kfree(kptr, true);
                void* cowpage = kalloc(PAGESIZE);
                assert(cowpage);
                pte.map(cowpage, PTE_PWU_PRIV);
                memcpy(cowpage, kptr, PAGESIZE);
                break;
            }
        }


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
    if (current->state == P_RUNNABLE) run(current);
    else schedule();
}


// These functions are defined farther below
int syscall_mmap(uintptr_t addr);
int syscall_mmap(uintptr_t addr, size_t length, int prot, int flags,
                 int fd, off_t offset);
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

    case SYSCALL_MMAP:
        return syscall_mmap(current->regs.reg_rdi,
                            current->regs.reg_rsi,
                            current->regs.reg_rdx,
                            current->regs.reg_r8,
                            current->regs.reg_r9,
                            current->regs.reg_r10);

    case SYSCALL_PAGE_ALLOC:
        return syscall_mmap(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        kcleanup(current->pid);
        schedule();             // does not return

    case SYSCALL_KILL:
        if (current->regs.reg_rdi < 1
                || current->regs.reg_rdi >= PID_MAX
                || ptable[current->regs.reg_rdi].state == P_FREE) {
            return -1;
        }
        kcleanup(current->regs.reg_rdi);
        if (ptable[current->pid].state == P_RUNNABLE) return 0;
        schedule();             // does not return

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);

    }

    panic("Should not get here!\n");
}


// lvlx_index(addr, x)
//    Returns the the level `x` index of physical address `addr`.
//    Per WeensyOS's design, there are only levels `1` through `4`.

int lvlx_index(uintptr_t addr, int x) {
    assert(x >= 1 && x <= NPTLEVELS);
    unsigned lvlx_bits = x * PAGEINDEXBITS + PAGEOFFBITS;
    uintptr_t lvlx_total_mask = (1UL << lvlx_bits) - 1;
    uintptr_t lvlx_mask = lvlx_total_mask & ~PAGEOFFMASK;
    uintptr_t unshifted_index = addr & lvlx_mask;
    int index = unshifted_index >> x * PAGEINDEXBITS;
    assert(index >= 0 && !(index >> PAGEINDEXBITS));
    return index;
}


// pte_next_down(pte)
//    Dereferences a valid, present pagetable entry.
//    Returns the phys addr of either a mem page or pagetable page, so
//    the return typing is `void*` to make this ambiguity more apparent.

void* pte_next_down(x86_64_pageentry_t pte) {
    assert(pte & PTE_P);
    unsigned total_bits = NPTLEVELS * PAGEINDEXBITS + PAGEOFFBITS;
    assert(total_bits >= PAGEOFFBITS && total_bits <= 64);
    uintptr_t total_mask = (1UL << total_bits) - 1;
    uintptr_t no_flags_mask = total_mask & ~PAGEOFFMASK;
    uintptr_t addr = pte & no_flags_mask;
    assert(!(addr & PAGEOFFMASK) && addr <= total_mask);
    return pa2kptr(addr);
}


// syscall_mmap(addr)
//    Handles the `SYSCALL_PAGE_ALLOC` system call.
//    Implements the specification for `sys_page_alloc` in `u-lib.hh`.
//
//    Returns:
//      Success: returns  `0`
//      Errors:  returns `-1` on failed mem page allocation
//               returns `-2` on failed pagetable page allocation
//               returns `-3` on permission denied to kernel virt memspace
//               returns `-4` on misaligned addr

int syscall_mmap(uintptr_t addr) {

    // Fail on misaligned or kernel memspace virt addr
    bool misaligned, inaccessible;
    inaccessible = addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL;
    misaligned = addr & PAGEOFFMASK;
    if (inaccessible) return -3;
    if (misaligned) return -4;

    // Map newpage to user pagetable if enough pages committable for
    // both the new mem page and any new pagetable page(s)
    if (ncommitted >= NCOMMITTABLE) return -1;

    // Calculate the lowest level pagetable page that has the PTE for `addr`
    int level_present = NPTLEVELS;                  // Top level always present
    x86_64_pagetable* ptp = current->pagetable;
    while (level_present != 1) {
        x86_64_pageentry_t pte = ptp->entry[lvlx_index(addr, level_present)];

        // Next pagetable page is present (in a lower level)
        if (pte & PTE_P) {
            --level_present;
            ptp = (x86_64_pagetable*) pte_next_down(pte);

        // No lower pagetable page
        } else {
            break;
        }
    }

    // Confirm enough committable for both mem pages and pagetable pages
    int nptp_needed = level_present - 1;
    if (ncommitted + nptp_needed > NCOMMITTABLE) return -2;

    // Map newpage, commit a future cloned newpage, should never fail
    vmiter(current->pagetable, addr).map(NEWPAGE_ADDR, PTE_PU_PRIV);
    ++physpages[NEWPAGE_ADDR / PAGESIZE].refcount;
    ++ncommitted;

    return 0;
}


// syscall_mmap(addr, length, prot, flags, fd, offset)
//    Handles the `SYSCALL_MMAP` system call......
//    If `addr == nullptr`, current implementation allocates a page at
//    the top of the user heap.
//    `prot` can be `PROT_NONE`, `PROT_READ`, or `PROT_WRITE`.
//    `PROT_WRITE` implies read/write permissions. `PROT_EXEC` not implemented.
//    If files are implemented, `prot` must be checked against
//    the underlying file permissions.
//    Must have one or the other of `MAP_PRIVATE` and `MAP_SHARED`.
//    `MAP_PRIVATE` marks pages (if `PROT_WRITE`) for copy-on-write.
//    `MAP_SHARED` shares pages (if `PROT_WRITE`) to not be process-isolated.
//    **CURRENTLY ONLY USES `addr`, REST OF ARGS TO BE IMPLEMENTED**

int syscall_mmap(uintptr_t addr, size_t length, int prot, int flags,
                 int fd, off_t offset) {

    assert(fd == -1);           // File mapping not implemented

    (void) length, (void) flags, (void) fd, (void) offset;

    // Check flags for `MAP_PRIVATE` xor `MAP_SHARED`
    if ((bool) (flags & MAP_PRIVATE) == (bool) (flags & MAP_SHARED)) {
        return -1234;           // Must be one or the other
    }

    // `addr == nullptr`, so must decide the virt addr to map onto
    if (!addr) {
        // Find a free range of virt addrs that can fit `PAGESIZE` bytes
        for (uintptr_t cursor = PROC_START_ADDR;
                 cursor < MEMSIZE_VIRTUAL;
                 cursor += PAGESIZE) {
            if (!vmiter(current->pagetable, cursor).present()) {
                addr = cursor;
                break;
            }
        }
        if (!addr) return -42069;        // Not enough virt mem?!?!
    }

    // Fail on misaligned or kernel memspace virt addr
    bool misaligned, inaccessible;
    inaccessible = addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL;
    misaligned = addr & PAGEOFFMASK;
    if (inaccessible) return -3;
    if (misaligned) return -4;

    // Map newpage to user pagetable if enough pages committable for
    // both the new mem page and any new pagetable page(s)
    if (ncommitted >= NCOMMITTABLE) return -1;

    // Calculate the lowest level pagetable page that has the PTE for `addr`
    int level_present = NPTLEVELS;                  // Top level always present
    x86_64_pagetable* ptp = current->pagetable;
    while (level_present != 1) {
        x86_64_pageentry_t pte = ptp->entry[lvlx_index(addr, level_present)];

        // Next pagetable page is present (in a lower level)
        if (pte & PTE_P) {
            --level_present;
            ptp = (x86_64_pagetable*) pte_next_down(pte);

        // No lower pagetable page
        } else {
            break;
        }
    }

    // Confirm enough committable for both mem pages and pagetable pages
    int nptp_needed = level_present - 1;
    if (ncommitted + nptp_needed > NCOMMITTABLE) return -2;

    // Decide permissions, default to `MAP_PRIVATE` if needed
    // `PROT_EXEC` not yet implemented
    int perm;
    if (prot == PROT_NONE) return 0;        // No new mapping (success)
    else {
        perm = PTE_PU;
        if (prot & PROT_WRITE) perm |= flags & MAP_PRIVATE ? PTE_PRIV : PTE_W;
    }

    // Map an anonymous page, should never fail
    if (flags & MAP_ANON) {
        bool use_newpage = !(flags & MAP_SHARED) || !(prot & PROT_WRITE);
        uintptr_t pa = 0;

        // Set up private page (newpage), commit copy-on-write page if needed
        if (use_newpage) {
            pa = NEWPAGE_ADDR;
            ++physpages[NEWPAGE_ADDR / PAGESIZE].refcount;
            if (prot & PROT_WRITE) ++ncommitted;

        // Set up writable page (newly allocated and zeroed page)
        } else {
            void* kptr = kalloc(PAGESIZE);
            memset(kptr, 0, PAGESIZE);
            pa = kptr2pa(kptr);
        }

        // Map
        assert(pa);
        vmiter(current->pagetable, addr).map(pa, perm);
    
    // Files not implemented (must be `MAP_ANON`)
    } else {
        assert(false);
    }

    return 0;
}


// syscall_fork
//    Forks current process into parent and child.
//    Copies all of parent's mem into child's mem, but any writable mem is
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

    // Copy parent's mem mappings into new child's pagetable
    for (vmiter it(current->pagetable, 0); !it.done(); it.next()) {

        // Child's PTE
        vmiter pte(ptable[pid].pagetable, it.va());

        // Map kernel, read-only, and explicitly shared writable mem
        if (it.va() < PROC_START_ADDR || (it.user() && !it.priv())) {
            if (pte.try_map(it.pa(), it.perm()) != 0) {
                kcleanup(pid);
                return -2;
            }
            if (it.user()) ++physpages[it.pa() / PAGESIZE].refcount;

        // Map private writable mem (mark for copy-on-write)
        } else if (it.user() && it.priv()) {

            // Strict overcommit policy
            if (ncommitted >= NCOMMITTABLE) {
                kcleanup(pid);
                return -1;
            }

            // Map copy-on-write mem to child, commit a future cloned page
            if (pte.try_map(it.pa(), PTE_PU_PRIV) != 0) {
                kcleanup(pid);
                return -2;
            }
            ++physpages[it.pa() / PAGESIZE].refcount;
            ++ncommitted;
            
            // Check that `pte.try_map` did not overcommit
            if (ncommitted > NCOMMITTABLE) {
                kcleanup(pid);
                return -2;
            }

            // Parent permissions must also be copy-on-write
            if (it.writable()) it.map(it.pa(), PTE_PU_PRIV);
        }
    }

    // Return `0` to child proc
    ptable[pid].regs.reg_rax = 0;
    // Return `pid` to parent proc
    return pid;
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % PID_MAX;
        if (ptable[pid].state == P_RUNNABLE) run(&ptable[pid]);

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) memshow();
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
    while (true);
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
