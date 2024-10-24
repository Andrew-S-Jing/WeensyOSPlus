#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <climits>
#include <cerrno>

// io61.cc
//    Debug info:
//      gdb --args cat61 -o outputs/out.txt inputs/text32k.txt


// buffer
//    General purpose buffer struct

static const size_t BUFMAX = 4096;
struct buffer {
    unsigned char buf[BUFMAX];
    ssize_t size = 0;
    ssize_t cursor = 0;
    int fd = -1;
};


// read_buf
//    Pre-fetching buffers

static const size_t NBUFS = 1;
static buffer read_bufs[NBUFS];
static buffer* read_buf = read_bufs;


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct io61_file {
    int fd = -1;     // file descriptor
    int mode;        // open mode (O_RDONLY or O_WRONLY)
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
    return f;
}


// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    int r = close(f->fd);
    delete f;
    return r;
}


// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.

int io61_readc(io61_file* f) {
    unsigned char c;
    return io61_read(f, &c, 1) <= 0 ? -1 : (int) c;
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
    assert(read_buf->cursor <= read_buf->size);
    if (f->mode == O_WRONLY) return -1;
    if (sz == 0) return 0;
    if (f->fd != read_buf->fd || read_buf->cursor == read_buf->size) {
        ssize_t r = read(f->fd, (void*) read_buf, BUFMAX);
        if (r <= 0) return r;
        if (f->fd != read_buf->fd)
            lseek(read_buf->fd, read_buf->cursor - read_buf->size, SEEK_CUR);
        read_buf->size = (size_t) r;
        read_buf->cursor = 0;
        read_buf->fd = f->fd;
    }
    size_t nreadable = read_buf->size - read_buf->cursor;
    size_t nread = sz > nreadable ? nreadable : sz;
    memcpy(buf, read_buf->buf + read_buf->cursor, nread);
    read_buf->cursor += nread;
    ssize_t nremaining = io61_read(f, buf + nread, sz - nread);
    return nremaining == -1 ? -1 : nread + nremaining;
}


// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file* f, int c) {
    unsigned char ch = c;
    ssize_t nw = write(f->fd, &ch, 1);
    if (nw == 1) {
        return 0;
    } else {
        return -1;
    }
}


// io61_write(f, buf, sz)
//    Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
//    Can write fewer than `sz` characters when there is an error, such as
//    a drive running out of space. In this case io61_write returns the
//    number of characters written, or -1 if no characters were written
//    before the error occurred.

ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    return write(f->fd, buf, sz);
}


// io61_flush(f)
//    If `f` was opened write-only, `io61_flush(f)` forces a write of any
//    cached data written to `f`. Returns 0 on success; returns -1 if an error
//    is encountered before all cached data was written.
//
//    If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
//    drop any data cached for reading.

int io61_flush(io61_file* f) {
    (void) f;
    return 0;
}


// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t off) {
    if (f->fd == read_buf->fd && f->mode == O_RDONLY) {
        read_buf->cursor = 0;
        read_buf->size = 0;
    }
    off_t r = lseek(f->fd, off, SEEK_SET);
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
