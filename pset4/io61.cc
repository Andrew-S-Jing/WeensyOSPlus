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

static const size_t BUFMAX = 4096;      // Buffer size (bytes)
struct buffer {
    unsigned char buf[BUFMAX];          // Buffer object
    off_t start = 0;                    // Buffer's starting offset
    off_t end = 0;                      // Buffer's one-past-end offset
    off_t last_read = 0;                // Offset of last `io61_read` for `fd`
    int fd = -1;                        // Buffer's associated FD
};


// read_buf
//    Pre-fetching buffers, defined this way for scalability

static const size_t NBUFS = 1;
static buffer read_bufs[NBUFS];
static buffer* read_buf = read_bufs;


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct io61_file {
    int fd = -1;        // file descriptor
    int mode;           // open mode (O_RDONLY or O_WRONLY)
    off_t size = -1;    // file size
    off_t cursor = 0;   // io61's file cursor (different from system's cursor)
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
//
//    Handles this single-byte read as a special case of `io61_read`

int io61_readc(io61_file* f) {
    unsigned char c;
    ssize_t r = io61_read(f, &c, 1);
    if (r == 0) errno = 0;
    return r <= 0 ? -1 : (int) c;
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
//
//    Uses one prefetching buffer for reads. Forward reads execute normally,
//    While backward reads first read any partial forward reads, then update
//    the buffer to end on the last byte of the read.

ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {

    // Check entry errors
    if (f->mode == O_WRONLY) return -1;
    assert(f->cursor >= 0);

    // Base case
    if (sz == 0) return 0;
    off_t nforward = 0;

    // If reading outside of current buffer (or different file), update buffer
    if (f->fd != read_buf->fd
            || f->cursor < read_buf->start || f->cursor >= read_buf->end) {

        off_t newbufstart = f->cursor;

        // If reading different file
        if (f->fd != read_buf->fd) {
            if (f->cursor == f->size) return 0;
            lseek(read_buf->fd, read_buf->last_read, SEEK_SET);

        // If reading after current buffer (not directly after)
        } else if (f->cursor > read_buf->end) {
            if (lseek(f->fd, f->cursor, SEEK_SET) == -1) return -1;

        // If reading before current buffer
        } else if (f->cursor < read_buf->start) {
            // First perform any partial forward reads
            if (f->cursor + (off_t) sz > read_buf->start) {
                off_t ndefer = read_buf->start - f->cursor;
                off_t savecursor = f->cursor;
                f->cursor = read_buf->start;
                nforward = io61_read(f, buf + ndefer, sz - ndefer);
                if (nforward == -1) return -1;
                f->cursor = savecursor;
                sz = ndefer;
            }
            // Set new buffer start offset
            newbufstart = read_buf->start + sz - BUFMAX;
            newbufstart = newbufstart > 0 ? newbufstart : 0;
            newbufstart = newbufstart > f->cursor ? f->cursor : newbufstart;
            if (lseek(f->fd, newbufstart, SEEK_SET) == -1) return -1;
        }

        // Attempt read, set buffer information
        ssize_t r = read(f->fd, (void*) read_buf->buf, BUFMAX);
        read_buf->start = newbufstart;
        read_buf->end = read_buf->start + r;
        read_buf->fd = f->fd;
        if (r <= 0) return r;
    }

    // Calculate number of bytes to read from current buffer
    size_t nreadable = read_buf->end - f->cursor;
    size_t nread = sz > nreadable ? nreadable : sz;

    // Read from current buffer
    memcpy(buf, read_buf->buf + (f->cursor - read_buf->start), nread);
    f->cursor += nread;
    read_buf->last_read = f->cursor;

    // Execute the remaining read request
    ssize_t nremaining = io61_read(f, buf + nread, sz - nread);
    return nremaining == -1 ? -1 : nread + nremaining + nforward;
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
//
//    UD for negative offsets and offsets past EOF

int io61_seek(io61_file* f, off_t off) {

    // Seeks for current buffer's associated FD, avoids syscalls
    if (f->size != -1 && f->fd == read_buf->fd && f->mode == O_RDONLY) {
        if (off >= 0 && off <= f->size) {
            f->cursor = off;
            return 0;
        }
        return -1;
    }

    // Seeks for FDs not in current buffer
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
