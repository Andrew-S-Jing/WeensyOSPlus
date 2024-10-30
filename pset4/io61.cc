#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <climits>
#include <map>
#include <iostream>

// io61.cc
//    Debug info:
//
//    For test c1, run this in shell
//      gdb --args cat61 -o outputs/out.txt inputs/text32k.txt
//
//    For test c8, put this into ".gdbinit":
//      r <(cat inputs/text32k.txt) >> cat > outputs/out.txt
//    then run:
//      gdb cat61
//
//    For test cn3, put this into ".gdbinit":
//      r < inputs/text32k.txt > outputs/c14.txt
//    then run:
//      gdb wreverse61


// cachedata
//    General purpose cachedata struct

static const ssize_t BUFMAX = 4096;                 // Buffer size (bytes)
static const ssize_t OFFBUFMASK = BUFMAX - 1;       // Mask for `n % BUFMAX`
struct alignas(64) cachedata {
    int fd;                             // Cache's associated FD
    bool clean;                         // Buffer's clean/dirty status
    off_t start;                        // Buffer's starting offset
    off_t end;                          // Buffer's one-past-end offset
    off_t last;                         // Offset of last read/write for `fd`
    unsigned char* buf;                 // Buffer object

    cachedata(int);                     // Constructor
    ~cachedata();                       // Destructor
};
cachedata::cachedata(int fd_) {
    fd = fd_;
    clean = true;
    start = -1;
    end = -1;
    last = 0;
    buf = new unsigned char[BUFMAX];
}
cachedata::~cachedata() {
    delete[] buf;
}


// TODO: One per FILE!!! single-slot cache
// TODO: Read section! Read chapter! Read man pages for read/write!
// TODO: Figure out why writing is delayed from the corresponding read in c11 (strace)
// TODO: Handle errno


// caches
//    Pre-fetching buffers, defined this way for scalability

static std::map<int, cachedata*> caches;
static cachedata scache = cachedata(-1);      // Shared/seekable cache


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct alignas(32) io61_file {
    int fd = -1;        // file descriptor
    int mode;           // open mode (O_RDONLY or O_WRONLY)
    off_t size = -1;    // file size
    off_t cursor = 0;   // io61's file cursor (different from system's cursor)
    bool seekable = false;
                        // file seekability
};


// cacheget(f)
//    Finds the cache associated with file `f`
//    Returns iterator of the `caches` element with key `fd` if unseekable
//    or `scache` if seekable

cachedata* cacheget(io61_file* f) {
    return f->seekable ? &scache : caches[f->fd];
}


// cacheflush(cache)
//    Flushes `cache`. Returns `0` on success and `-1` on error.

int cacheflush(cachedata* cache) {
    if (cache->clean) return 0;
    ssize_t sz = cache->end - cache->start;
    ssize_t npending = sz;
    while (npending != 0) {
        ssize_t r = write(cache->fd, cache->buf + (sz - npending), npending);
        if (r == -1) {
            return -1;
            if (npending == sz) return -1;
            break;
        }
        npending -= r;
    }
    cache->start = -1;
    cache->end = -1;
    cache->clean = true;
    return 0;
}


// syspointer_fix(cache)
//    Restores file pointer associated with FD `cache->fd` to last user call.

void syspointer_fix(cachedata* cache) {
    if (cache->clean && cache == &scache && cache->last != cache->end)
        assert(lseek(cache->fd, cache->last, SEEK_SET) == cache->last);
}


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
    f->seekable = lseek(f->fd, 0, SEEK_CUR) != -1 && f->size != -1;
    if (!f->seekable) caches.insert({f->fd, new cachedata(f->fd)});
    return f;
}


// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    int r = close(f->fd);
    if (!f->seekable) delete caches.extract(f->fd).mapped();
    delete f;
    return r;
}


// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.

int io61_readc(io61_file* f) {
    unsigned char c;
    return io61_read(f, &c, 1) == 1 ? c : EOF;
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
    
    // Entry errors
    if (f->mode == O_WRONLY || f->fd < 0) return -1;
    assert(f->cursor >= 0);

    // Catch size 0 and EOF reads early
    if (sz == 0 || f->cursor == f->size) return 0;

    // Locals
    cachedata* cache = cacheget(f);
    assert(cache->start <= cache->end && cache->end - cache->start <= BUFMAX);
    if (f->size >= 0 && (size_t) (f->size - f->cursor) < sz) sz = f->size - f->cursor;
    ssize_t npending = sz;

    // Reading uncached file, must update buffer
    if (f->fd != cache->fd) {
        cacheflush(cache);
        assert(f->seekable);
        if (cache->fd != -1) syspointer_fix(cache);
        cache->fd = f->fd;
        cache->start = -1;
        cache->end = -1;
    }

    // Main loop
    while (npending != 0) {

        // Reading outside buffer, must update buffer (aligned to `BUFMAX`)
        if (f->cursor < cache->start || f->cursor >= cache->end || cache->start == -1) {
            cacheflush(cache);
            cache->start = f->cursor - (f->cursor & OFFBUFMASK);
            cache->last = cache->start;
            assert (cache->start >= 0 && (cache->start <= f->size || f->size < 0));
            syspointer_fix(cache);
            ssize_t r = read(f->fd, cache->buf, BUFMAX);
            assert(r != -1);
            if (r == 0) {
                errno = 0;
                break;      // EOF
            }
            cache->end = cache->start + r;
        }

        // Calculate number of bytes to read from current buffer
        ssize_t nreadable = cache->end - f->cursor;
        ssize_t nread = npending > nreadable ? nreadable : npending;

        // Read from buffer, update metadata
        memcpy(buf, cache->buf + (f->cursor - cache->start), nread);
        npending -= nread;
        f->cursor += nread;
        cache->last = f->cursor;
        buf += nread;
    }
    
    return sz - npending;
}


// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file* f, int c) {
    unsigned char c_ = c;
    return -(io61_write(f, &c_, 1) != 1);
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
    assert(f->cursor >= 0);

    // Catch size writes early
    if (sz == 0) return 0;

    // Locals
    cachedata* cache = cacheget(f);
    assert(cache->start <= cache->end && cache->end - cache->start <= BUFMAX);
    ssize_t npending = sz;

    // Writing uncached file, must update buffer
    if (f->fd != cache->fd) {
        cacheflush(cache);
        assert(f->seekable);
        if (cache->fd != -1) syspointer_fix(cache);
        cache->fd = f->fd;
        cache->start = -1;
        cache->end = -1;
    }

    // Main loop
    while (npending != 0) {

        // Writing outside buffer, must update buffer (not aligned to `BUFMAX`)
        if (f->cursor < cache->start || f->cursor - cache->start >= BUFMAX || cache->start == -1) {
            cacheflush(cache);
            cache->start = f->cursor;
            cache->last = cache->start;
            syspointer_fix(cache);
            cache->end = cache->start;
        }

        // Calculate number of bytes to write to current buffer
        ssize_t nwritable = BUFMAX - (f->cursor - cache->start);
        ssize_t nwrite = npending > nwritable ? nwritable : npending;

        // Write to buffer, update metadata
        memcpy(cache->buf + (f->cursor - cache->start), buf, nwrite);
        cache->clean = false;
        npending -= nwrite;
        f->cursor += nwrite;
        if (f->cursor > cache->end) cache->end = f->cursor;
        cache->last = f->cursor;
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
    if (f->mode == O_RDONLY) return 0;
    cachedata* cache = cacheget(f);
    if (cache->fd != f->fd) return 0;
    return cacheflush(cache);
}


// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t off) {
    off_t r = lseek(f->fd, (off_t) off, SEEK_SET);
    // Ignore the returned offset unless it’s an error.
    if (r == -1) {
        return -1;
    } else {
        return 0;
    }
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
