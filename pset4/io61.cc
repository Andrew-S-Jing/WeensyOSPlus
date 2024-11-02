#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <climits>

// io61.cc


// cache
//    General purpose cache struct

static const ssize_t BUFMAX = 8192;             // Buffer size (bytes)
static const ssize_t OFFBUFMASK = BUFMAX - 1;   // Mask for `n % BUFMAX`
struct cache {
    off_t start = 0;                            // Cache's starting offset
    off_t end = 0;                              // Cache's one-past-end offset
    unsigned char buf[BUFMAX];                  // Buffer object
};


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct alignas(64) io61_file {
    int fd = -1;                    // file descriptor
    int mode;                       // open mode (O_RDONLY or O_WRONLY)
    off_t size = -1;                // file size
    off_t cursor = 0;               // file cursor (not kernel file pointer)
    bool seekable = false;          // file seekability

    unsigned char* map = nullptr;   // memory map pointer
    cache c;                        // single-slot cache
};


// io61_fdopen(fd, mode)
//    Returns a new io61_file for file descriptor `fd`. `mode` is either
//    O_RDONLY for a read-only file or O_WRONLY for a write-only file.
//    You need not support read/write files.

io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    io61_file* f = new io61_file;
    f->fd = fd;
    f->mode = mode;
    f->size = io61_filesize(f);
    f->seekable = lseek(f->fd, 0, SEEK_CUR) != -1;
    // f->map
    if (f->mode == O_RDONLY && f->size >= 0) {
        void* r = mmap(nullptr, f->size, PROT_READ, MAP_PRIVATE, f->fd, 0);
        if (r != MAP_FAILED) f->map = (unsigned char*) r;
    }
    return f;
}


// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    int r = 0;
    if (f->map) r = munmap(f->map, f->size);
    delete f;
    return r;
}


// fill(f)
//    Internal function. Fills cache associated with `f`, aligned to `BUFMAX`.
//    Returns number of bytes filled on success and `-1` on failure.

ssize_t fill(io61_file* f) {

    // Locals
    f->c.start = f->cursor - (f->cursor & OFFBUFMASK);
    assert (f->c.start >= 0 && (f->c.start < f->size || f->size < 0));
    ssize_t nfilled = 0;

    // Seek if needed
    if (f->seekable && f->c.start != f->c.end)
        lseek(f->fd, f->c.start, SEEK_SET);

    // Main loop
    while (nfilled != BUFMAX) {
        ssize_t r = read(f->fd, f->c.buf + nfilled, BUFMAX - nfilled);
        if (r == 0) break;                      // EOF
        else if (r > 0) nfilled += r;
        else if (errno != EINTR && errno != EAGAIN) return -1;
    }

    // Update cache
    f->c.end = f->c.start + nfilled;
    return nfilled;
}


// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.

int io61_readc(io61_file* f) {

    // Read mapped file
    if (f->map) {
        assert(f->cursor >= 0 && f->cursor <= f->size && f->size >= 0);
        if (f->mode == O_WRONLY) return -1;
        if (f->cursor == f->size) {
            errno = 0;
            return -1;                          // EOF
        }
        return f->map[f->cursor++];
    }

    // Read unmapped file
    if (f->cursor < f->c.start || f->cursor >= f->c.end) {
        ssize_t r = fill(f);
        if (r < 1) {
            if (r == 0) errno = 0;              // EOF
            return -1;
        }
    }
    return f->c.buf[f->cursor++ - f->c.start];
}


// io61_read(f, buf, sz)
//    Reads up to `sz` bytes from `f` into `buf`. Returns the number of
//    bytes read on success. Returns 0 if end-of-file is encountered before
//    any bytes are read, and -1 if an error is encountered before any
//    bytes are read.
//
//    Note that the return value might be positive, but less than `sz`,
//    if end-of-file or error is encountered before all `sz` bytes are read.
//    This is called a “short read.”

ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {

    // Read mapped files
    if (f->map) {
        assert(f->cursor >= 0 && f->cursor <= f->size && f->size >= 0);
        if (f->cursor == f->size) return 0;     // EOF
        if ((size_t) (f->size - f->cursor) < sz) sz = f->size - f->cursor;
        memcpy(buf, f->map + f->cursor, sz);
        f->cursor += sz;
        return sz;
    }

    // Entry errors
    if (f->mode == O_WRONLY || f->fd < 0) return -1;
    assert(f->cursor >= 0
               && f->c.start <= f->c.end
               && f->c.end - f->c.start <= BUFMAX);

    // Catch size 0 and EOF reads early
    if (sz == 0 || f->cursor == f->size) return 0;

    // Locals
    if (f->size >= 0 && (size_t) (f->size - f->cursor) < sz)
        sz = f->size - f->cursor;
    ssize_t npending = sz;

    // Main loop
    while (npending != 0) {

        // Reading outside cache, update cache and buffer (aligned to `BUFMAX`)
        if (f->cursor < f->c.start || f->cursor >= f->c.end){
            ssize_t r = fill(f);
            if (r == 0) break;                  // EOF
            else if (r == -1) return -1;
        }

        // Calculate number of bytes to copy from current buffer
        ssize_t nreadable = f->c.end - f->cursor;
        ssize_t nread = npending > nreadable ? nreadable : npending;

        // Copy from buffer, update cache
        memcpy(buf, f->c.buf + (f->cursor - f->c.start), nread);
        npending -= nread;
        f->cursor += nread;
        buf += nread;
    }
    
    return sz - npending;
}


// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file* f, int c) {

    // Entry errors
    if (f->mode == O_RDONLY || f->fd < 0) return -1;
    assert(f->cursor >= 0);

    // Writing outside buffer, update cache and buffer (not aligned to `BUFMAX`)
    if (f->cursor < f->c.start
            || f->cursor > f->c.end
            || f->cursor >= f->c.start + BUFMAX) {
        io61_flush(f);
        f->c.start = f->cursor;
        if (f->seekable && f->c.start != f->c.end)          // Seek if needed
            lseek(f->fd, f->c.start, SEEK_SET);
        f->c.end = f->c.start;
    }

    // Write to and update cache
    f->c.buf[f->cursor++ - f->c.start] = c;
    if (f->cursor > f->c.end) f->c.end = f->cursor;
    return 0;
}


// io61_write(f, buf, sz)
//    Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
//    Can write fewer than `sz` characters when there is an error, such as
//    a drive running out of space. In this case io61_write returns the
//    number of characters written, or -1 if no characters were written
//    before the error occurred.

ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    
    // Entry errors
    if (f->mode == O_RDONLY || f->fd < 0) return -1;
    assert(f->cursor >= 0
               && f->c.start <= f->c.end
               && f->c.end - f->c.start <= BUFMAX);

    // Catch size 0 writes early
    if (sz == 0) return 0;

    // Locals
    ssize_t npending = sz;

    // Main loop
    while (npending != 0) {

        // Writing outside cache, update cache/buffer (not aligned to `BUFMAX`)
        if (f->cursor != f->c.end || f->cursor >= f->c.start + BUFMAX) {
            io61_flush(f);
            f->c.start = f->cursor;
            if (f->seekable && f->c.start != f->c.end)      // Seek if needed
                lseek(f->fd, f->c.start, SEEK_SET);
            f->c.end = f->c.start;
        }

        // Calculate number of bytes to copy to current buffer
        ssize_t nwritable = f->c.start + BUFMAX - f->cursor;
        ssize_t nwrite = npending > nwritable ? nwritable : npending;

        // Copy to buffer, update cache
        memcpy(f->c.buf + (f->cursor - f->c.start), buf, nwrite);
        npending -= nwrite;
        f->cursor += nwrite;
        if (f->cursor > f->c.end) f->c.end = f->cursor;
        buf += nwrite;
    }
    
    return sz - npending;
}


// io61_flush(f)
//    If `f` was opened write-only, `io61_flush(f)` forces a write of any
//    cached data written to `f`. Returns 0 on success; returns -1 if an error
//    is encountered before all cached data was written.
//
//    If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
//    drop any data cached for reading.

int io61_flush(io61_file* f) {

    // Entry errors
    if (f->fd < 0) return -1;

    // Catch read-only files and clean caches early
    if (f->mode == O_RDONLY || f->c.start == f->c.end) return 0;

    // Locals
    ssize_t sz = f->c.end - f->c.start;
    assert (sz >= 0 && sz <= BUFMAX);
    ssize_t nflushed = 0;

    // Main loop (assumes infinite disk space)
    while (nflushed != sz) {
        ssize_t r = write(f->fd, f->c.buf + nflushed, sz - nflushed);
        if (r > 0) nflushed += r;
    }

    // Reset cache
    f->c.start = f->c.end;
    return 0;
}


// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t off) {

    // Entry errors
    if (!f->seekable
            || f->fd < 0
            || off < 0
            || (f->map && off > f->size))
        return -1;

    // Seek
    f->cursor = off;
    return 0;
}


// You shouldn't need to change these functions.

// io61_open_check(filename, mode)
//    Opens the file corresponding to `filename` and returns its io61_file.
//    If `!filename`, returns either the standard input or the
//    standard output, depending on `mode`. Exits with an error message if
//    `filename != nullptr` and the named file cannot be opened.

io61_file* io61_open_check(const char* filename, int mode) {
    int fd;
    if (filename) {
        fd = open(filename, mode, 0666);
    } else if ((mode & O_ACCMODE) == O_RDONLY) {
        fd = STDIN_FILENO;
    } else {
        fd = STDOUT_FILENO;
    }
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}


// io61_fileno(f)
//    Returns the file descriptor associated with `f`.

int io61_fileno(io61_file* f) {
    return f->fd;
}


// io61_filesize(f)
//    Returns the size of `f` in bytes. Returns -1 if `f` does not have a
//    well-defined size (for instance, if it is a pipe).

off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}
