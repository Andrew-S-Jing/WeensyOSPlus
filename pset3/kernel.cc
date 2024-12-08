#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "k-fditer.hh"
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
    for (uintptr_t pa = 0; pa < MEMSIZE_PHYSICAL; pa += PAGESIZE) {
        if (allocatable_physical_address(pa)) ++count;
    }
    used = true;
    return count;
}
#define ncommit_t ssize_t
#define NCOMMIT_MAX SSIZE_MAX
const ncommit_t NCOMMITTABLE = ncommittable();
ncommit_t ncommitted = 0;


// FILETABLE
//    The `weensy_filetable*` casting of the kernel filetable.

#define FILETABLE (reinterpret_cast<weensy_filetable*>(FILETABLE_ADDR))


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

    // check that `ncommit_t` can handle all phys mem pages
    assert(NCOMMIT_MAX >= NPAGES);

    // zero the universal newpage
    memset(pa2kptr(NEWPAGE_ADDR), 0, PAGESIZE);
    // zero the filetable
    memset(pa2kptr(FILETABLE_ADDR), 0, PAGESIZE);
    
    // check that `physpageinfo::refcount` type can handle max refs to newpage
    physpageinfo max;
    --max.refcount;
    assert(max.refcount >= PID_MAX * (MEMSIZE_VIRTUAL / PAGESIZE));

    // (re-)initialize kernel pagetable (kernel pages are shared)
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        uint64_t perm = PTE_PWU;

        // nullptr is inaccessible even to the kernel
        if (addr == 0) {
            perm = 0;

        // kernel memory (except CGA console) is inaccessible to user
        } else if (addr < PROC_START_ADDR && addr != CONSOLE_ADDR) {
            perm &= ~PTE_U;
        }

        // non-kernel memory should not be executable
        if (reserved_physical_address(addr)
                || allocatable_physical_address(addr)
                || addr == NEWPAGE_ADDR
                || addr == FILETABLE_ADDR) {
            perm |= PTE_XD;
        }
        // install identity mapping
        int r = vmiter(kernel_pagetable, addr).try_map(addr, perm);
        assert(r == 0); // mappings during kernel_start MUST NOT fail
                        // (Note that later mappings might fail!!)
    }

    // Create files
    {
        // Make list of filenames
        const char* filenames[] {
            "user file",
            "controller file",
            "kernel file",
            "system file",
            "GNU C++ code file",
            "internet protocols file",
            "virtual hardware file",
            "emulators file",
            "new file"
        };

        // Map files
        weensy_filetable* ft = reinterpret_cast<weensy_filetable*>(FILETABLE_ADDR);
        for (auto name : filenames) {
            void* f = kalloc(PAGESIZE);
            assert(f);
            int r = file_try_map(ft, f, file_name(name));
            assert(!r);
        }
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
//    `is_private` should only be set if page is user accessible and private.

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


void kfree_fdtable(weensy_fdtable* fdt) {
    if (!fdt) return;

    for (auto file : fdt->entries) {
        if (file) --physpages[file / PAGESIZE].refcount;
    }
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
    kfree(ptable[pid].fdtable, false);
    ptable[pid].fdtable = nullptr;
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

int kpage_alloc(pid_t pid, uintptr_t va, uint64_t perm) {
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

    // initialize process fdtable
    ptable[pid].fdtable = kalloc_fdtable();
    assert (ptable[pid].fdtable);

    // initialize process pagetable
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
            
            // Allocate and map
            // Writable segments are private
            uint64_t perm = seg.writable() ? PTE_PWU_PRIV : PTE_PU;
            // Allow executable to execute
            if (seg.executable()) perm &= ~PTE_XD;
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
    int r = kpage_alloc(pid, stack_addr, PTE_PWU_PRIV | PTE_XD);
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
        if (!(regs->reg_errcode & PFERR_EXEC)
                && multflag(regs->reg_errcode, PFERR_PWU)) {
            uintptr_t va = addr - (addr & PAGEOFFMASK);
            vmiter pte(current->pagetable, va);
            assert(pte.pa());

            // Handle copy-on-write faults, fresh page will also be private
            if (pte.priv()) {
                assert(pte.writable() != pte.priv());

                uint64_t perm = PTE_PWU_PRIV;
                if (!pte.executable()) perm |= PTE_XD;

                // Do not free the ref page completely (`kalloc` will wipe mem),
                // but also never assign write access to the newpage
                if (pte.pa() != NEWPAGE_ADDR
                        && physpages[pte.pa() / PAGESIZE].refcount == 1) {
                    pte.map(pte.kptr(), perm);
                    break;
                }

                // Strict overcommit policy
                assert(ncommitted <= NCOMMITTABLE);
                void* kptr = pte.kptr();
                kfree(kptr, true);
                void* cowpage = kalloc(PAGESIZE);
                assert(cowpage);
                pte.map(cowpage, perm);
                memcpy(cowpage, kptr, PAGESIZE);
                break;
            }
        }


        const char* operation;
        if (regs->reg_errcode & PFERR_EXEC) operation = "execute";
        else if (regs->reg_errcode & PFERR_WRITE) operation = "write";
        else operation = "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
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
int syscall_open(const char* pathname_vptr);
int syscall_close(int fd);
void* syscall_mmap(uintptr_t addr, size_t length, int prot, int flags,
                   int fd, off_t offset);
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

    case SYSCALL_OPEN:
        return syscall_open(reinterpret_cast<const char*>(current->regs.reg_rdi));

    case SYSCALL_CLOSE:
        return syscall_close(current->regs.reg_rdi);

    case SYSCALL_MMAP:
        return kptr2pa(syscall_mmap(current->regs.reg_rdi,
                                    current->regs.reg_rsi,
                                    current->regs.reg_rdx,
                                    current->regs.reg_r8,
                                    current->regs.reg_r9,
                                    current->regs.reg_r10));

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

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


// ptp_lvl_index(addr, lvl)
//    Returns the the level `lvl` index of physical address `addr`.
//    Per WeensyOS's design, there are only levels `1` through `4`.

int ptp_lvl_index(uintptr_t addr, int lvl) {
    assert(lvl >= 1 && lvl <= NPTLEVELS);
    uintptr_t index_plus = addr >> ((lvl - 1) * PAGEINDEXBITS + PAGEOFFBITS);
    int index = index_plus & PAGEINDEXMASK;
    assert(index >= 0 && !(index >> PAGEINDEXBITS));
    return index;
}


// pte_next_down(pte)
//    Dereferences a valid, present pagetable entry.
//    Returns the phys addr of either a mem page or pagetable page, so
//    the return typing is `void*` to make this ambiguity more apparent.

void* pte_next_down(x86_64_pageentry_t pte) {
    assert(pte & PTE_P);
    uintptr_t addr = pte & PTE_PAMASK;
    assert(!(addr & PAGEOFFMASK) && addr <= PTE_PAMASK);
    return pa2kptr(addr);
}


// syscall_mmap(addr, length, prot, flags, fd, offset)
//    Handles the `SYSCALL_MMAP` and `SYSCALL_PAGE_ALLOC` system calls.
//
//    Arguments:
//      `addr`:     The memory mapping will be from exactly `addr`, as if
//                  `MAP_FIXED` were set in the Linux implementation.
//                  Must be page aligned. If `nullptr`, the mapping will be
//                  from the lowest, available and large enough contiguous
//                  chunk of user virt mem space (usually top-of-heap).
//      `length`:   Request `length` bytes of contiguous virt mem.
//                  Must be a multiple of `PAGESIZE` (i.e. request
//                  `length / PAGESIZE` pages). Requests of `length == 0`
//                  may or may not fail, depending on permissions.
//      `prot`:     `prot` is a bitwise or of `PROT_NONE`, `PROT_READ`,
//                  `PROT_WRITE`, and `PROT_EXEC`, which determine if the
//                  mapped memory has read, write, and/or execute permissions.
//                  `PROT_READ` is implied by `PROT_WRITE` and `PROT_EXEC`.
//      `flags`:    `flags` is exactly one of `MAP_PRIVATE` and `MAP_SHARED`,
//                  onto which `MAP_ANON` must be or'd, since files are
//                  not yet implemented. `MAP_PRIVATE` isolates the mapped
//                  memory from other processes, whereas `MAP_SHARED` does not
//                  preclude other processes from having permissions.
//                  `MAP_ANON` means the mapped memory is initialized to zero.
//                  Shared anonymous mappings are only shareable via `sys_fork`.
//      `fd`:       Dictates what file (associated with `fd`) the mapping will
//                  be backed by. If `MAP_SHARED` is set, there will be no
//                  process isolation for the mapped chunk of virt mem space,
//                  and any process can access any file. Fails is `fd` was not
//                  previously returned by a call to `sys_open`. Ignored if
//                  `MAP_ANON` is set.
//      `offset`:   Ignored (multi-page files are not yet implemented).
//
//    Returns:
//      Success:    Returns the virt addr to which the requested memory
//                  is mapped. This is either `addr`, if `addr`, or
//                  some virt addr that the kernel decides if `!addr`.
//                  The return will be `nullptr` if `prot == PROT_NONE`.
//      Failure:    Returns `MAP_FAILED`, which is `((void*) -1)`. In the
//                  future, there may be an error code implemented to provide
//                  processes details about the failure.
//
//    **FILES TO BE IMPLEMENTED**

void* syscall_mmap(uintptr_t addr, size_t length, int prot, int flags,
                   int fd, off_t offset) {

    (void) offset;

    // Entry errors
    // Mapping only implemented for whole pages
    if (length & PAGEOFFMASK) return MAP_FAILED;
    // Files are currently all exactly one page long
    if (length > PAGESIZE && !(flags & MAP_ANON)) return MAP_FAILED;
    // Check flags for `MAP_PRIVATE` xor `MAP_SHARED`
    if ((bool) (flags & MAP_PRIVATE) == (bool) (flags & MAP_SHARED)) {
        return MAP_FAILED;
    }

    uintptr_t end;

    // `addr` is provided
    if (addr) {
        // Fail on misaligned or kernel memspace virt addr
        bool inaccessible, misaligned;
        inaccessible = addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL;
        if (inaccessible) return MAP_FAILED;
        misaligned = addr & PAGEOFFMASK;
        if (misaligned) return MAP_FAILED;

        // Test for valid range in virt mem space
        end = addr + length;
        bool overflow, end_inaccessible;
        overflow = end < addr;
        if (overflow) return MAP_FAILED;
        end_inaccessible = end < PROC_START_ADDR || end >= MEMSIZE_VIRTUAL;
        if (end_inaccessible) return MAP_FAILED;

        // No overwriting previous pagetable mappings
        for (vmiter pte(current->pagetable, addr);
                 pte.va() < end;
                 pte += PAGESIZE) {
            if (pte.present()) return MAP_FAILED;
        }

    // `addr == nullptr`, so must decide the virt addr to map onto
    } else {
        // Find a free range of virt addrs that can fit `PAGESIZE` bytes
        uintptr_t free_start = 0;
        size_t free_length = 0;
        for (uintptr_t cursor = PROC_START_ADDR;
                 cursor < MEMSIZE_VIRTUAL;
                 cursor += PAGESIZE) {

            // Increment
            if (vmiter(current->pagetable, cursor).present()) {
                free_start = free_length = 0;
            } else {
                if (free_start == 0) free_start = cursor;
                free_length += PAGESIZE;
            }

            // Test for large enough virt addr chunk
            if (length <= free_length) {
                assert(free_start);
                addr = free_start;
                break;
            }
        }
        if (!addr) return MAP_FAILED;        // Not enough virt mem
        end = addr + length;
        bool overflow = end < addr;
        if (overflow) return MAP_FAILED;
    }

    // Map newpage to user pagetable if enough pages committable for
    // both the new mem page and any new pagetable page(s)
    if (ncommitted >= NCOMMITTABLE) return MAP_FAILED;

    // Calculate number of committed pages needed to map `addr` in current table
    // ** CURRENTLY DOES NOT ANTICIPATE PS-FLAGGED PTES **
    // ** CURRENTLY OVERCOUNTS # of L2 and L3 PAGES NEEDED **
    //      ** NOT INCORRECT, JUST USES MEM INEFFICIENTLY ON LARGE MMAPs **
    x86_64_pagetable* pt = current->pagetable;
    ssize_t npagesneeded = 0;
    // For each page of the mapping, a page must be committed if the mapping
    // is a (1) writable anonymous mapping or (2) private file-backed mapping.
    bool mempageneeded = ((flags & MAP_ANON) && (prot & PROT_WRITE))
                         || (!(flags & MAP_ANON) && (flags & MAP_PRIVATE));
    for (uintptr_t cursor = addr; cursor < end; cursor += PAGESIZE) {

        // Calculate lowest level of PTP that has the PTE for `cursor`
        x86_64_pagetable* ptp = pt;
        int level_present = NPTLEVELS;     // Top level always present
        while (level_present != 1) {
            x86_64_pageentry_t pte =
                ptp->entry[ptp_lvl_index(cursor, level_present)];

            // Next pagetable page is present (in a lower level)
            if (pte & PTE_P) {
                --level_present;
                ptp = reinterpret_cast<x86_64_pagetable*>(pte_next_down(pte));

            // No lower pagetable page
            } else {
                break;
            }
        }

        // # of pages needed is `level_present - 1 + 1` for `level_present - 1`
        // PTPs needed and either `1` or `0` mem pages needed.
        npagesneeded += level_present - 1 + (mempageneeded ? 1 : 0);
    }

    // Confirm enough committable for both mem pages and pagetable pages
    if (ncommitted + npagesneeded > NCOMMITTABLE) return MAP_FAILED;

    // Decide permissions, default to `MAP_PRIVATE` if needed
    // `PROT_EXEC` not yet implemented
    uint64_t perm;
    if (prot == PROT_NONE) return nullptr;        // No new mapping
    else {
        perm = PTE_PU;
        if (prot & PROT_WRITE) perm |= flags & MAP_PRIVATE ? PTE_PRIV : PTE_W;
        if (!(prot & PROT_EXEC)) perm |= PTE_XD;
    }

    // Map anonymous pages, should never fail
    if (flags & MAP_ANON) {
        bool use_newpage = (flags & MAP_PRIVATE) || !(prot & PROT_WRITE);

        for (uintptr_t cursor = addr;
                 cursor < end;
                 cursor += PAGESIZE) {
            void* map_kptr = nullptr;

            // Set up private page (newpage), commit COW page if needed
            if (use_newpage) {
                map_kptr = pa2kptr(NEWPAGE_ADDR);
                ++physpages[NEWPAGE_ADDR / PAGESIZE].refcount;
                if (prot & PROT_WRITE) ++ncommitted;

            // Set up shared writable page (newly allocated and zeroed page)
            } else {
                map_kptr = kalloc(PAGESIZE);
                memset(map_kptr, 0, PAGESIZE);
            }

            // Map
            assert(map_kptr);
            vmiter(current->pagetable, cursor).map(map_kptr, perm);
        }

    // Map a file
    } else {
        void* file = fd_find_kptr(current->fdtable, fd);
        // `fd` not mapped for process
        if (!file) return MAP_FAILED;

        void* map_kptr;

        // Private read-only files are immediately copied to prevent clobbering
        if (!(prot & PROT_WRITE) && (flags & MAP_PRIVATE)) {
            map_kptr = kalloc(PAGESIZE);
            if (!map_kptr) return MAP_FAILED;
            memcpy(map_kptr, file, PAGESIZE);

        // All other mappings use the underlying file's phys mem
        } else {
            map_kptr = file;
            ++physpages[kptr2pa(file) / PAGESIZE].refcount;
            // Commit a copy-on-write page for private writable pages
            if ((prot & PROT_WRITE) && (flags & MAP_PRIVATE)) ++ncommitted;
        }

        vmiter(current->pagetable, addr).map(map_kptr, perm);
    }

    return pa2kptr(addr);
}


// syscall_page_alloc(addr)
//    Implements specs for `sys_page_alloc` in "u-lib.hh".

int syscall_page_alloc(uintptr_t addr) {

    // Free a single page if needed
    if (!addr) return -1;
    if (!(addr & PAGEOFFMASK)) {
        vmiter pte(current->pagetable, addr);
        if (pte.user()) kfree(pte.kptr(), pte.priv());
    }

    // `sys_page_alloc` does not specify `addr == nullptr` behavior
    void* r = syscall_mmap(addr,
                           PAGESIZE,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANON,
                           -1,
                           0);
    return r == MAP_FAILED ? -1 : 0;
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

    // Copy fdtable
    ptable[pid].fdtable = kalloc_fdtable();
    if (!ptable[pid].fdtable) {
        kcleanup(pid);
        return -2;
    }
    memcpy(ptable[pid].fdtable, current->fdtable, sizeof(weensy_fdtable));
    for (auto file : ptable[pid].fdtable->entries) {
        if (file) ++physpages[file / PAGESIZE].refcount;
    }

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

            uint64_t perm = PTE_PU_PRIV;
            if (!pte.executable()) perm |= PTE_XD;

            // Map copy-on-write mem to child, commit a future cloned page
            if (pte.try_map(it.pa(), perm) != 0) {
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
            if (it.writable()) it.map(it.pa(), perm);
        }
    }

    // Return `0` to child proc
    ptable[pid].regs.reg_rax = 0;
    // Return `pid` to parent proc
    return pid;
}


// syscall_open(pathname_vptr)
//    Returns an FD that is newly mapped to the process's fdtable.
//    Returns `-1` on failure.

int syscall_open(const char* pathname_vptr) {

    // Entry
    uintptr_t pathname_va = kptr2pa(pathname_vptr);
    if (pathname_va < PROC_START_ADDR || pathname_va >= MEMSIZE_VIRTUAL) {
        return -1;
    }

    // Locals
    char pathname[sizeof(filename_t) + 1] = {'\0'};
    bool is_pathname_done = false;
    unsigned pathname_length = 0;

    // Construct `pathname` out of all characters in the string,
    // allowing for strings that straddle page borders. This design
    // further ensures scalability if pathnames can be larger in the future.
    for (vmiter pte(current->pagetable, pathname_va);
             !is_pathname_done;
             pte.find(pathname_va + pathname_length)) {

        // Set this iteration's locals
        assert(pte.va() == pathname_va || !(pte.va() & PAGEOFFMASK));
        const char* cursor = reinterpret_cast<const char*>(pte.kptr());
        const char* page_end = cursor + PAGESIZE - (pte.va() & PAGEOFFMASK);

        // String goes into unmapped virt mem
        if (!cursor) return -1;

        // Build `pathname`
        for (; cursor != page_end; ++cursor, ++pathname_length) {
            if (pathname_length > sizeof(filename_t)) return -1;
            if (*cursor == '\0') {
                is_pathname_done = true;
                break;
            }
            pathname[pathname_length] = *cursor;
        }

        // No empty pathnames
        if (is_pathname_done && pathname_length == 0) return -1;
    }

    filename_t filename = file_name(pathname);

    uintptr_t pa = file_find_pa(FILETABLE, filename);
    // File not found
    if (!pa) return -1;

    int fd = fd_set_pa(current->fdtable, pa);
    // On success, `fd` now refers to the file at `pa`
    if (fd >= 0) ++physpages[pa / PAGESIZE].refcount;
    return fd;
}


// syscall_close(fd)
//    Returns `0` on success and `-1` on failure (e.g. `fd` not already open).

int syscall_close(int fd) {
    if (fd < 0 || fd >= NFDENTRIES) return -1;
    uintptr_t file = fd_delete(current->fdtable, fd);
    if (file == 0) return -1;
    --physpages[file / PAGESIZE].refcount;
    return 0;
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
//    `exception_return` to restore its pagetable and registers.

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
