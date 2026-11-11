/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PROC_READ_H
#define RVVM_USER_PROC_READ_H
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Proc classifiers need bounded stack storage, including in killable shared
 * address spaces. Callers hold their descriptor guard while this FD exists. */
struct user_proc_reader {
    int fd;
    int error;
    size_t cursor, available;
    bool positional;
    uint64_t offset;
    char bytes[1024];
};

static inline bool user_proc_open(struct user_proc_reader* reader, const char* path)
{
    *reader = (struct user_proc_reader){.fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0)};
    return reader->fd >= 0;
}

static inline bool user_proc_byte(struct user_proc_reader* reader, char* byte)
{
    if (reader->cursor == reader->available) {
        long count;
        do {
            count = reader->positional
                ? syscall(SYS_pread64, reader->fd, reader->bytes, sizeof(reader->bytes), reader->offset)
                : syscall(SYS_read, reader->fd, reader->bytes, sizeof(reader->bytes));
        }
        while (count < 0 && errno == EINTR);
        if (count <= 0) {
            if (count < 0) reader->error = errno;
            return false;
        }
        reader->offset += count;
        reader->cursor = 0;
        reader->available = count;
    }
    *byte = reader->bytes[reader->cursor++];
    return true;
}

static inline bool user_proc_line(struct user_proc_reader* reader, char* line, size_t capacity)
{
    size_t length = 0;
    bool read = false;
    for (;;) {
        char byte;
        if (!user_proc_byte(reader, &byte)) break;
        read = true;
        if (byte == '\n') break;
        if (length + 1 < capacity) line[length++] = byte;
    }
    /* Consume overlong lines completely so their tail cannot become a new
     * record. The classifiers using this helper need only short fields. */
    if (capacity) line[length] = 0;
    return read;
}

static inline void user_proc_close(struct user_proc_reader* reader)
{
    syscall(SYS_close, reader->fd);
}

static inline bool user_proc_integer(const char* line, const char* field, int32_t* result)
{
    size_t length = strlen(field);
    if (strncmp(line, field, length)) return false;
    const char* digit = line + length;
    while (*digit == ' ' || *digit == '\t') ++digit;
    bool negative = *digit == '-';
    if (negative) ++digit;
    if (*digit < '0' || *digit > '9') return false;
    uint32_t value = 0, limit = INT32_MAX + (uint32_t)negative;
    while (*digit >= '0' && *digit <= '9') {
        unsigned next = *digit++ - '0';
        if (value > (limit - next) / 10) return false;
        value = value * 10 + next;
    }
    *result = negative ? -(int64_t)value : value;
    return true;
}
#endif
