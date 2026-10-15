/* SPDX-License-Identifier: GPL-3.0-or-later */
/* rvvm_user's allocator. It replaces libc's malloc family through libc's
 * public replacement interface (glibc's "Replacing malloc"; musl supports
 * the same), so the allocator locks a fork must hold are RVVM's own: a raw
 * fork takes them before its clone, libc's fork() through pthread_atfork.
 *
 * Requests up to 16 KiB come from 64 KiB slabs of one size class each, with
 * a short per-thread cache in front of every class. Larger requests get a
 * mapping of their own; freed ones up to 1 MiB, 16 MiB in all, are kept for
 * reuse. Slabs and the header block of a large mapping are
 * 64 KiB aligned, so free() finds a header from the pointer alone. Address
 * space grows with use only: unlike per-thread arenas, nothing is reserved
 * ahead, which matters under a finite RLIMIT_AS.
 *
 * Internal paths never call malloc, calloc or free by name: compilers may
 * fold malloc+memset into calloc, which here would recurse. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/futex.h>
#include "rvvm_user_malloc.h"

#define SLAB_SIZE    ((size_t)65536)
#define SLAB_MASK    (SLAB_SIZE - 1)
#define SLAB_START   64     // offset of the first object
#define SMALL_MAX    16384
#define CLASSES      36
#define CHUNK_SLABS  16     // slabs mapped at a time
#define POOL_MAX     32     // empty slabs kept mapped
#define REUSE_BLOCK  ((size_t)1 << 20)  // largest freed mapping kept for reuse
#define REUSE_TOTAL  ((size_t)16 << 20) // all freed mappings kept
#define SLAB_MAGIC   0x52534c42U
#define LARGE_MAGIC  0x524c5247U
#define MIN_ALIGN    16

/* Builds use -fvisibility=hidden. A dynamic link must export the family:
 * libc.so allocates through these symbols too. */
#define USER_MALLOC_API __attribute__((visibility("default")))

struct slab {
    uint32_t magic, cls;
    uint32_t size, capacity, used, carved;
    void* free;
    struct slab *next, *prev;
    bool listed;
};
_Static_assert(sizeof(struct slab) <= SLAB_START, "slab header size");

struct large {
    uint32_t magic;
    uintptr_t base;
    size_t length;
    struct large* next; // while kept for reuse
};

struct class_state {
    uint32_t lock;
    struct slab* partial;
} __attribute__((aligned(64)));

struct cache_bin {
    void* head;
    uint32_t count;
};

static struct class_state classes[CLASSES];
static uint32_t pool_lock;
static struct slab* pool;
static size_t pool_count;
/* Freed large mappings, reused instead of unmapping: each munmap of a
 * multi-threaded process costs a TLB shootdown, each new mapping its page
 * faults. Guest thread churn frees several such blocks per thread. */
static uint32_t reuse_lock;
static struct large* reuse;
static size_t reuse_total;

enum { CACHE_OFF, CACHE_ON, CACHE_REGISTERING, CACHE_EXITED };
static __thread struct cache_bin cache[CLASSES];
static __thread uint8_t cache_state;
static pthread_key_t cache_key;
static bool cache_key_ready;

static void alloc_relax(void)
{
#if defined(__x86_64__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ volatile("yield");
#endif
}

/* 0 free, 1 held, 2 held with waiters. */
static void alloc_lock(uint32_t* lock)
{
    uint32_t prev = 0;
    if (__atomic_compare_exchange_n(lock, &prev, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    for (unsigned spin = 0; spin < 64 && prev != 2; ++spin) {
        alloc_relax();
        prev = 0;
        if (__atomic_compare_exchange_n(lock, &prev, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    }
    int saved = errno;
    while (__atomic_exchange_n(lock, 2, __ATOMIC_ACQUIRE))
        syscall(SYS_futex, lock, FUTEX_WAIT_PRIVATE, 2, NULL, NULL, 0);
    errno = saved;
}

static void alloc_unlock(uint32_t* lock)
{
    if (__atomic_exchange_n(lock, 0, __ATOMIC_RELEASE) == 2) {
        int saved = errno;
        syscall(SYS_futex, lock, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        errno = saved;
    }
}

static size_t alloc_page(void)
{
    static size_t page;
    size_t value = __atomic_load_n(&page, __ATOMIC_RELAXED);
    if (!value) {
        value = (size_t)sysconf(_SC_PAGESIZE);
        __atomic_store_n(&page, value, __ATOMIC_RELAXED);
    }
    return value;
}

static void alloc_unmap(void* address, size_t length)
{
    int saved = errno;
    munmap(address, length);
    errno = saved;
}

/* 16..128 by 16, then four classes per doubling up to 16 KiB. */
static unsigned size_class(size_t size)
{
    if (size <= 128) return size ? (unsigned)((size - 1) >> 4) : 0;
    unsigned bits = 63 - __builtin_clzll(size - 1);
    size_t base = (size_t)1 << bits, step = base >> 2;
    return 8 + (bits - 7) * 4 + (unsigned)((size - base + step - 1) / step) - 1;
}

static size_t class_size(unsigned cls)
{
    if (cls < 8) return (size_t)(cls + 1) << 4;
    size_t base = (size_t)128 << ((cls - 8) >> 2);
    return base + (base >> 2) * (((cls - 8) & 3) + 1);
}

/* About 8 KiB per class and thread. */
static uint32_t cache_limit(size_t size)
{
    size_t count = 8192 / size;
    return count < 1 ? 1 : count > 32 ? 32 : (uint32_t)count;
}

static void* header_of(const void* pointer)
{
    uintptr_t address = (uintptr_t)pointer;
    /* Objects never start a slab; aligned large blocks keep their header
     * one slab below the pointer. */
    return (void*)((address & SLAB_MASK) ? address & ~SLAB_MASK : address - SLAB_SIZE);
}

static void* slab_object(struct slab* slab, void* pointer)
{
    char* data = (char*)slab + SLAB_START;
    return data + (size_t)((char*)pointer - data) / slab->size * slab->size;
}

static void list_push(struct class_state* state, struct slab* slab)
{
    slab->prev = NULL;
    slab->next = state->partial;
    if (slab->next) slab->next->prev = slab;
    state->partial = slab;
    slab->listed = true;
}

static void list_remove(struct class_state* state, struct slab* slab)
{
    if (slab->prev) slab->prev->next = slab->next;
    else state->partial = slab->next;
    if (slab->next) slab->next->prev = slab->prev;
    slab->next = slab->prev = NULL;
    slab->listed = false;
}

/* Called with a class lock held. */
static struct slab* slab_get(void)
{
    alloc_lock(&pool_lock);
    struct slab* slab = pool;
    if (slab) {
        pool = slab->next;
        pool_count--;
    }
    alloc_unlock(&pool_lock);
    if (slab) return slab;
    size_t length = (CHUNK_SLABS + 1) * SLAB_SIZE;
    char* raw = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return NULL;
    char* start = (char*)(((uintptr_t)raw + SLAB_MASK) & ~SLAB_MASK);
    char* end = start + CHUNK_SLABS * SLAB_SIZE;
    if (start > raw) alloc_unmap(raw, start - raw);
    if (raw + length > end) alloc_unmap(end, raw + length - end);
    alloc_lock(&pool_lock);
    for (size_t i = 1; i < CHUNK_SLABS; ++i) {
        struct slab* spare = (void*)(start + i * SLAB_SIZE);
        spare->next = pool;
        pool = spare;
        pool_count++;
    }
    alloc_unlock(&pool_lock);
    return (void*)start;
}

static void slab_release(struct slab* slab)
{
    slab->magic = 0;
    alloc_lock(&pool_lock);
    bool keep = pool_count < POOL_MAX;
    if (keep) {
        slab->next = pool;
        pool = slab;
        pool_count++;
    }
    alloc_unlock(&pool_lock);
    if (!keep) alloc_unmap(slab, SLAB_SIZE);
}

static void* class_take(unsigned cls)
{
    struct class_state* state = &classes[cls];
    struct slab* slab = state->partial;
    if (!slab) {
        slab = slab_get();
        if (!slab) return NULL;
        size_t size = class_size(cls);
        *slab = (struct slab){
            .magic = SLAB_MAGIC, .cls = cls, .size = (uint32_t)size,
            .capacity = (uint32_t)((SLAB_SIZE - SLAB_START) / size),
        };
        list_push(state, slab);
    }
    void* object = slab->free;
    if (object) slab->free = *(void**)object;
    else object = (char*)slab + SLAB_START + (size_t)slab->carved++ * slab->size;
    if (++slab->used == slab->capacity) list_remove(state, slab);
    return object;
}

static void class_put(struct slab* slab, void* object)
{
    struct class_state* state = &classes[slab->cls];
    *(void**)object = slab->free;
    slab->free = object;
    if (!slab->listed) list_push(state, slab);
    /* Keep a class's last partial slab: alternating use would remap it. */
    if (!--slab->used && (slab->next || slab->prev)) {
        list_remove(state, slab);
        slab_release(slab);
    }
}

static bool cache_ready(void)
{
    if (cache_state == CACHE_ON) return true;
    if (cache_state != CACHE_OFF || !__atomic_load_n(&cache_key_ready, __ATOMIC_ACQUIRE)) return false;
    /* Allocations made by pthread_setspecific itself bypass the cache. */
    cache_state = CACHE_REGISTERING;
    bool registered = !pthread_setspecific(cache_key, cache);
    cache_state = registered ? CACHE_ON : CACHE_OFF;
    return registered;
}

static void* small_alloc(size_t size)
{
    unsigned cls = size_class(size);
    void* object;
    if (cache_ready()) {
        struct cache_bin* bin = &cache[cls];
        object = bin->head;
        if (object) {
            bin->head = *(void**)object;
            bin->count--;
            return object;
        }
        uint32_t refill = (cache_limit(class_size(cls)) + 1) / 2;
        alloc_lock(&classes[cls].lock);
        object = class_take(cls);
        for (uint32_t i = 1; object && i < refill; ++i) {
            void* extra = class_take(cls);
            if (!extra) break;
            *(void**)extra = bin->head;
            bin->head = extra;
            bin->count++;
        }
        alloc_unlock(&classes[cls].lock);
    } else {
        alloc_lock(&classes[cls].lock);
        object = class_take(cls);
        alloc_unlock(&classes[cls].lock);
    }
    if (!object) errno = ENOMEM;
    return object;
}

static void small_free(struct slab* slab, void* pointer)
{
    void* object = slab_object(slab, pointer);
    unsigned cls = slab->cls;
    if (cache_ready()) {
        struct cache_bin* bin = &cache[cls];
        uint32_t limit = cache_limit(slab->size);
        if (bin->count < limit) {
            *(void**)object = bin->head;
            bin->head = object;
            bin->count++;
            return;
        }
        alloc_lock(&classes[cls].lock);
        class_put(slab, object);
        for (uint32_t i = limit / 2; i && bin->head; --i) {
            void* cached = bin->head;
            bin->head = *(void**)cached;
            bin->count--;
            class_put(header_of(cached), cached);
        }
        alloc_unlock(&classes[cls].lock);
        return;
    }
    alloc_lock(&classes[cls].lock);
    class_put(slab, object);
    alloc_unlock(&classes[cls].lock);
}

static void cache_flush(void* unused)
{
    (void)unused;
    /* Late frees during thread exit go straight to the classes. */
    cache_state = CACHE_EXITED;
    for (unsigned cls = 0; cls < CLASSES; ++cls) {
        struct cache_bin* bin = &cache[cls];
        if (!bin->head) continue;
        alloc_lock(&classes[cls].lock);
        while (bin->head) {
            void* cached = bin->head;
            bin->head = *(void**)cached;
            class_put(header_of(cached), cached);
        }
        bin->count = 0;
        alloc_unlock(&classes[cls].lock);
    }
}

/* A kept mapping that fits span without wasting more than a quarter. */
static struct large* reuse_take(size_t span)
{
    if (span > REUSE_BLOCK) return NULL;
    alloc_lock(&reuse_lock);
    struct large** link = &reuse;
    while (*link && ((*link)->length < span || (*link)->length - span > span / 4)) link = &(*link)->next;
    struct large* block = *link;
    if (block) {
        *link = block->next;
        reuse_total -= block->length;
    }
    alloc_unlock(&reuse_lock);
    return block;
}

static void large_release(struct large* block)
{
    block->magic = 0;
    if (block->length <= REUSE_BLOCK) {
        alloc_lock(&reuse_lock);
        bool keep = reuse_total + block->length <= REUSE_TOTAL;
        if (keep) {
            block->next = reuse;
            reuse = block;
            reuse_total += block->length;
        }
        alloc_unlock(&reuse_lock);
        if (keep) return;
    }
    alloc_unmap((void*)block->base, block->length);
}

/* The pointer is offset from a 64 KiB aligned base: by max(align, 64) below
 * 64 KiB alignment, else by 64 KiB with the pointer itself aligned. A reused
 * mapping is not zeroed: *reused tells calloc. */
static void* large_alloc_ex(size_t size, size_t align, bool* reused)
{
    size_t page = alloc_page();
    size_t offset = align < SLAB_SIZE ? (align > 64 ? align : 64) : SLAB_SIZE;
    size_t slack = align < SLAB_SIZE ? SLAB_SIZE : align;
    if (size > PTRDIFF_MAX - offset - slack - page) {
        errno = ENOMEM;
        return NULL;
    }
    size_t span = (offset + size + page - 1) & ~(page - 1);
    /* Kept mappings are 64 KiB aligned, which suits all smaller alignments. */
    struct large* kept = align < SLAB_SIZE ? reuse_take(span) : NULL;
    if (kept) {
        kept->magic = LARGE_MAGIC;
        *reused = true;
        return (void*)(kept->base + offset);
    }
    *reused = false;
    size_t length = span + slack;
    char* raw = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return NULL;
    uintptr_t base = align < SLAB_SIZE ? ((uintptr_t)raw + SLAB_MASK) & ~SLAB_MASK
        : (((uintptr_t)raw + SLAB_SIZE + align - 1) & ~(align - 1)) - SLAB_SIZE;
    if (base > (uintptr_t)raw) alloc_unmap(raw, base - (uintptr_t)raw);
    if ((uintptr_t)raw + length > base + span) alloc_unmap((void*)(base + span), (uintptr_t)raw + length - base - span);
    *(struct large*)base = (struct large){LARGE_MAGIC, base, span, NULL};
    return (void*)(base + offset);
}

static void* large_alloc(size_t size, size_t align)
{
    bool reused;
    return large_alloc_ex(size, align, &reused);
}

static void* large_realloc(struct large* block, void* pointer, size_t size)
{
    size_t page = alloc_page();
    size_t offset = (uintptr_t)pointer - block->base;
    if (size > PTRDIFF_MAX - offset - SLAB_SIZE - page) {
        errno = ENOMEM;
        return NULL;
    }
    size_t span = (offset + size + page - 1) & ~(page - 1);
    if (span <= block->length) {
        if (span < block->length) alloc_unmap((void*)(block->base + span), block->length - span);
        block->length = span;
        return pointer;
    }
    int saved = errno;
    if (mremap((void*)block->base, block->length, span, 0) != MAP_FAILED) {
        block->length = span;
        return pointer;
    }
    errno = saved;
    /* Move with the kernel, not memcpy, to a 64 KiB aligned reservation. */
    char* raw = mmap(NULL, span + SLAB_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (raw == MAP_FAILED) return NULL;
    uintptr_t base = ((uintptr_t)raw + SLAB_MASK) & ~SLAB_MASK;
    if (mremap((void*)block->base, block->length, span, MREMAP_MAYMOVE | MREMAP_FIXED, (void*)base) == MAP_FAILED) {
        alloc_unmap(raw, span + SLAB_SIZE);
        return NULL;
    }
    if (base > (uintptr_t)raw) alloc_unmap(raw, base - (uintptr_t)raw);
    if ((uintptr_t)raw + SLAB_SIZE > base) alloc_unmap((void*)(base + span), (uintptr_t)raw + SLAB_SIZE - base);
    block = (struct large*)base;
    block->base = base;
    block->length = span;
    return (void*)(base + offset);
}

static void* alloc_any(size_t size)
{
    return size <= SMALL_MAX ? small_alloc(size) : large_alloc(size, MIN_ALIGN);
}

static void* alloc_aligned(size_t align, size_t size)
{
    if (align <= MIN_ALIGN) return alloc_any(size);
    if (align <= 4096 && size <= SMALL_MAX - (align - MIN_ALIGN)) {
        char* object = small_alloc(size + align - MIN_ALIGN);
        return object ? (void*)(((uintptr_t)object + align - 1) & ~(align - 1)) : NULL;
    }
    return large_alloc(size, align);
}

static void invalid_pointer(void)
{
    static const char message[] = "rvvm_user: free(): invalid pointer\n";
    (void)!write(STDERR_FILENO, message, sizeof(message) - 1);
    abort();
}

static size_t usable_size(void* pointer)
{
    struct slab* slab = header_of(pointer);
    if (slab->magic == SLAB_MAGIC) return (char*)slab_object(slab, pointer) + slab->size - (char*)pointer;
    struct large* block = (struct large*)slab;
    if (block->magic != LARGE_MAGIC) invalid_pointer();
    return block->base + block->length - (uintptr_t)pointer;
}

USER_MALLOC_API void* malloc(size_t size)
{
    return alloc_any(size);
}

USER_MALLOC_API void free(void* pointer)
{
    if (!pointer) return;
    struct slab* slab = header_of(pointer);
    if (slab->magic == SLAB_MAGIC) {
        small_free(slab, pointer);
        return;
    }
    struct large* block = (struct large*)slab;
    if (block->magic != LARGE_MAGIC) invalid_pointer();
    large_release(block);
}

USER_MALLOC_API void* calloc(size_t count, size_t size)
{
    size_t total;
    if (__builtin_mul_overflow(count, size, &total)) {
        errno = ENOMEM;
        return NULL;
    }
    void* object;
    if (total > SMALL_MAX) {
        bool reused;
        object = large_alloc_ex(total, MIN_ALIGN, &reused);
        if (object && reused) memset(object, 0, total); // a new mapping is zeroed
        return object;
    }
    object = small_alloc(total);
    if (object) memset(object, 0, total);
    return object;
}

USER_MALLOC_API void* realloc(void* pointer, size_t size)
{
    if (!pointer) return alloc_any(size);
    if (!size) {
        free(pointer); // as glibc: free and return NULL
        return NULL;
    }
    struct slab* slab = header_of(pointer);
    size_t usable = usable_size(pointer);
    if (slab->magic == LARGE_MAGIC && size > SMALL_MAX) {
        return large_realloc((struct large*)slab, pointer, size);
    }
    /* Keep a small block unless it would waste more than half. */
    if (slab->magic == SLAB_MAGIC && size <= usable && size > usable / 2) return pointer;
    void* moved = alloc_any(size);
    if (!moved) return NULL;
    memcpy(moved, pointer, usable < size ? usable : size);
    free(pointer);
    return moved;
}

void* memalign(size_t align, size_t size);
USER_MALLOC_API void* memalign(size_t align, size_t size)
{
    if (align > SIZE_MAX / 2 + 1) {
        errno = EINVAL;
        return NULL;
    }
    /* As glibc: round other alignments up to a power of two. */
    if (align & (align - 1)) align = (size_t)1 << (64 - __builtin_clzll(align));
    return alloc_aligned(align, size);
}

USER_MALLOC_API void* aligned_alloc(size_t align, size_t size)
{
    if (!align || (align & (align - 1))) {
        errno = EINVAL;
        return NULL;
    }
    return alloc_aligned(align, size);
}

USER_MALLOC_API int posix_memalign(void** result, size_t align, size_t size)
{
    if (!align || (align & (align - 1)) || align % sizeof(void*)) return EINVAL;
    int saved = errno;
    void* object = alloc_aligned(align, size);
    errno = saved;
    if (!object) return ENOMEM;
    *result = object;
    return 0;
}

void* valloc(size_t size);
USER_MALLOC_API void* valloc(size_t size)
{
    return alloc_aligned(alloc_page(), size);
}

void* pvalloc(size_t size);
USER_MALLOC_API void* pvalloc(size_t size)
{
    size_t page = alloc_page();
    if (size > SIZE_MAX - page) {
        errno = ENOMEM;
        return NULL;
    }
    return alloc_aligned(page, size ? (size + page - 1) & ~(page - 1) : page);
}

size_t malloc_usable_size(void* pointer);
USER_MALLOC_API size_t malloc_usable_size(void* pointer)
{
    return pointer ? usable_size(pointer) : 0;
}

void user_malloc_fork_lock(void)
{
    /* Class locks come before the pool lock everywhere else too. */
    for (unsigned cls = 0; cls < CLASSES; ++cls) alloc_lock(&classes[cls].lock);
    alloc_lock(&pool_lock);
    alloc_lock(&reuse_lock);
}

void user_malloc_fork_unlock(void)
{
    alloc_unlock(&reuse_lock);
    alloc_unlock(&pool_lock);
    for (unsigned cls = CLASSES; cls--;) alloc_unlock(&classes[cls].lock);
}

/* Only the forking thread survives, and it held every lock. Other threads'
 * caches stay allocated in the child: their objects are never reused. */
void user_malloc_fork_child(void)
{
    reuse_lock = 0;
    pool_lock = 0;
    for (unsigned cls = 0; cls < CLASSES; ++cls) classes[cls].lock = 0;
}

__attribute__((constructor)) static void user_malloc_init(void)
{
    if (!pthread_key_create(&cache_key, cache_flush))
        __atomic_store_n(&cache_key_ready, true, __ATOMIC_RELEASE);
    pthread_atfork(user_malloc_fork_lock, user_malloc_fork_unlock, user_malloc_fork_child);
}
