CS 61 Problem Set 3
===================

**Fill out both this file and `AUTHORS.md` before submitting.** We grade
anonymously, so put all personally identifying information, including
collaborators, in `AUTHORS.md`.

Grading notes (if any)
----------------------



Extra credit attempted (if any)
-------------------------------
Copy-on-write: strict overcommit policy. (Denoted in the memviewer as `W`)
Universal newpage (anonymous mapping): `syscall_page_alloc` commits a
    copy-on-write, zeroed page (currently at address `0x1000`) to the user,
    rather than calling `kalloc` every time. (Denoted in the memviewer as `0`)
`sys_kill`: Processes can kill another process with `sys_kill` (or itself).
    Added tests:
        `p-kill.cc`: A group of processes have a battle royale! Last one
        standing gets exclusive rights over memory allocation!
        `p-nothing.cc`: A process starts and dies.
`sys_mmap`: Allows processes to map memory to their virtual memory space. Now
this mapping can either be anonymous or backed by a limited set of named files.
See (lengthy) details in the specs for `syscall_mmap` in `kernel.cc`.
    Added tests:
        `p-mmap.cc`: Tests WeensyOS in the same way as `p-exit.cc`, except
        the `sys_mmap` syscall is used instead of `sys_page_alloc`.
        `p-mmapshared.cc`: Same as `p-mmap.cc`, except it requests shared
        pages, so it does not check that previously written mem is still same.
        `p-mmaprandom.cc`: Same as `p-mmapshared.cc`, except that the `addr`,
        `prot`, and `flags` args of `sys_mmap` are toggled at random.
        `p-mmaplength.cc`: Same as `p-mmap.cc`, except it requests large
        chunks of memory at a time with `sys_mmap`.
`sys_open` and `sys_close`: WeensyOS now supports files, albeit a small set of
hardcoded, named files created during `kernel_start`, mostly because of the
constraints of a small phys mem space. Files are catalogued in the "filetable",
which is an page-length array (at 0x2000) of pathnames and phys addrs associated
with each file. Each process has an "fdtable" allocated on setup/fork, which
is a page-length array of phys addrs associated with the `fd`th entry.
    Added tests:
        `p-mmapsharedfile.cc`: Same as `p-mmapshared.cc`, except the underlying
        mem is backed by the file "user file".
        `p-mmapfile.cc`: Same as `p-mmapsharedfile.cc`, except the mappings of
        "user file" are all private. Also tests the edge case where the pathname
        provided to `sys_open` straddles a page boundary.
