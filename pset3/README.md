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
