/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "user_ptrace_events.h"
#include "util/spinlock.h"
#include "util/user_fd_guard.h"
#include "util/user_proc_read.h"
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct event_node {
    struct event_node* next;
    struct user_ptrace_event value;
};
struct stop_node {
    struct stop_node* next;
    struct user_ptrace_stop value;
};
struct events_context {
    spinlock_t lock, normalization;
    struct event_node *nodes, **last;
    struct stop_node* stoplist;
    uint32_t queued, tracked, changed, sleeping;
    void* (*allocate)(void*, size_t, void*);
    void* opaque;
};
static struct events_context initial_context = {
    .lock = SPINLOCK_INIT, .normalization = SPINLOCK_INIT,
    .last = &initial_context.nodes,
};
static _Thread_local struct events_context* selected_context;
static struct events_context* context(void)
{
    return selected_context ? selected_context : &initial_context;
}
#define events_lock (context()->lock)
#define normalization_lock (context()->normalization)
#define events (context()->nodes)
#define tail (context()->last)
#define stops (context()->stoplist)
#define queued_count (context()->queued)
#define tracked_count (context()->tracked)
#define generation (context()->changed)
#define sleepers (context()->sleeping)

void* user_ptrace_events_context_new(void)
{
    struct events_context* next = calloc(1, sizeof(*next));
    if (next) {
        spin_init(&next->lock);
        spin_init(&next->normalization);
        next->last = &next->nodes;
    }
    return next;
}

void* user_ptrace_events_context_current(void) { return selected_context; }
void user_ptrace_events_context_select(void* selected) { selected_context = selected; }

void user_ptrace_events_context_allocator(void* selected,
                                         void* (*allocate)(void*, size_t, void*), void* opaque)
{
    struct events_context* owned = selected;
    owned->allocate = allocate;
    owned->opaque = opaque;
}

static void* event_allocate(size_t size)
{
    return context()->allocate ? context()->allocate(context()->opaque, size, NULL) : malloc(size);
}

static void event_release(void* pointer)
{
    if (context()->allocate) context()->allocate(context()->opaque, 0, pointer);
    else free(pointer);
}

void user_ptrace_events_context_free(void* opaque)
{
    struct events_context* owned = opaque;
    if (!owned) return;
    if (owned->allocate) { free(owned); return; }
    while (owned->nodes) {
        struct event_node* node = owned->nodes;
        owned->nodes = node->next;
        free(node);
    }
    while (owned->stoplist) {
        struct stop_node* node = owned->stoplist;
        owned->stoplist = node->next;
        free(node);
    }
    free(owned);
}

bool user_ptrace_events_tracing(void)
{
    return atomic_load_uint32_relax(&tracked_count) != 0;
}

uint32_t user_ptrace_events_generation(void)
{
    return atomic_load_uint32(&generation);
}

uint32_t* user_ptrace_events_sleep_begin(void)
{
    atomic_add_uint32(&sleepers, 1);
    return &generation;
}

void user_ptrace_events_sleep_end(void)
{
    atomic_sub_uint32(&sleepers, 1);
}

static void changed(void)
{
    atomic_add_uint32(&generation, 1);
    if (atomic_load_uint32(&sleepers))
        syscall(SYS_futex, &generation, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
}

void user_ptrace_events_normalize_lock(void)
{
    spin_lock(&normalization_lock);
}

void user_ptrace_events_normalize_unlock(void)
{
    spin_unlock(&normalization_lock);
}

void user_ptrace_events_identify(struct user_ptrace_event* event)
{
    struct user_ptrace_stop stop;
    if (user_ptrace_events_get(event->pid, &stop)) {
        if (!event->owner_tid) event->owner_tid = stop.owner_tid;
        event->pidfd_dev = stop.event.pidfd_dev;
        event->pidfd_ino = stop.event.pidfd_ino;
    }
    if (!event->owner_tid) {
        char path[64], line[256];
        snprintf(path, sizeof(path), "/proc/%d/status", event->pid);
        user_fd_lock();
        struct user_proc_reader status;
        if (user_proc_open(&status, path)) {
            while (user_proc_line(&status, line, sizeof(line))) {
                int32_t tid;
                if (user_proc_integer(line, "TracerPid:", &tid)) {
                    event->owner_tid = tid;
                    break;
                }
            }
            user_proc_close(&status);
        }
        user_fd_unlock();
    }
#ifdef SYS_pidfd_open
    if (!event->pidfd_ino) {
        user_fd_lock();
        int fd = syscall(SYS_pidfd_open, event->pid, 0);
        /* New kernels can identify individual nonleader threads too. */
        if (fd < 0) fd = syscall(SYS_pidfd_open, event->pid, O_EXCL);
        if (fd >= 0) {
            struct stat st;
            if (!fstat(fd, &st)) {
                event->pidfd_dev = st.st_dev;
                event->pidfd_ino = st.st_ino;
            }
            close(fd);
        }
        user_fd_unlock();
    }
#endif
}

bool user_ptrace_events_pending(void)
{
    return atomic_load_uint32_relax(&queued_count) != 0;
}

bool user_ptrace_events_push(const struct user_ptrace_event* value)
{
    struct event_node* node = event_allocate(sizeof(*node));
    if (!node) return false;
    *node = (struct event_node){.value = *value};
    spin_lock(&events_lock);
    *tail = node;
    tail = &node->next;
    atomic_add_uint32(&queued_count, 1);
    spin_unlock(&events_lock);
    changed();
    return true;
}

static bool selected(const struct user_ptrace_event* event, pid_t pid, pid_t pgid)
{
    return pid > 0 ? event->pid == pid : (!pgid || event->pgid == pgid);
}

bool user_ptrace_events_release(pid_t pid)
{
    bool found = false;
    spin_lock(&events_lock);
    for (struct event_node* node = events; node; node = node->next) {
        if (node->value.pid == pid) {
            node->value.deferred = false;
            found = true;
            break;
        }
    }
    spin_unlock(&events_lock);
    if (found) changed();
    return found;
}

bool user_ptrace_events_pop_deferred(pid_t pid, struct user_ptrace_event* result)
{
    spin_lock(&events_lock);
    struct event_node** link = &events;
    while (*link) {
        struct event_node* node = *link;
        if (node->value.pid == pid && node->value.deferred) {
            *result = node->value;
            *link = node->next;
            if (!*link) tail = link;
            event_release(node);
            atomic_sub_uint32(&queued_count, 1);
            spin_unlock(&events_lock);
            return true;
        }
        link = &node->next;
    }
    spin_unlock(&events_lock);
    return false;
}

static bool take(pid_t pid, pid_t pgid, const struct stat* pidfd, int options, bool waitid,
                 struct user_ptrace_event* result)
{
    pid_t owner = options & __WNOTHREAD ? syscall(SYS_gettid) : 0;
    spin_lock(&events_lock);
    struct event_node** link = &events;
    while (*link) {
        struct event_node* node = *link;
        int status = node->value.status;
        bool eligible = WIFSTOPPED(status)
            ? (waitid ? (options & WSTOPPED) != 0
                      : node->value.traced || (options & WUNTRACED))
            : WIFCONTINUED(status) ? (options & WCONTINUED) != 0
            : !waitid || (options & WEXITED);
        bool identity = pidfd ? node->value.pidfd_ino == pidfd->st_ino
            && node->value.pidfd_dev == pidfd->st_dev : selected(&node->value, pid, pgid);
        if (!node->value.deferred && identity && eligible
            && (!owner || node->value.owner_tid == owner)) {
            *result = node->value;
            if (!waitid || !(options & WNOWAIT)) {
                *link = node->next;
                if (!*link) tail = link;
                event_release(node);
                atomic_sub_uint32(&queued_count, 1);
            }
            spin_unlock(&events_lock);
            return true;
        }
        link = &node->next;
    }
    spin_unlock(&events_lock);
    return false;
}

bool user_ptrace_events_wait4(pid_t selector, pid_t caller_pgid, int options,
                             struct user_ptrace_event* result)
{
    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL))
        return false;
    /* Negate in a wider type: wait4 accepts INT_MIN as a selector. */
    int64_t group = selector < -1 ? -(int64_t)selector : 0;
    if (group > INT32_MAX) return false;
    return take(selector > 0 ? selector : 0,
                selector == 0 ? caller_pgid : (pid_t)group, NULL, options, false, result);
}

bool user_ptrace_events_waitid(idtype_t type, id_t id, pid_t caller_pgid, int options,
                              struct user_ptrace_event* result)
{
    if (options & ~(WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT
                    | __WNOTHREAD | __WCLONE | __WALL)) return false;
    if (!(options & (WSTOPPED | WEXITED | WCONTINUED))) return false;
    if (type == P_PID) return id && id <= INT32_MAX && take(id, 0, NULL, options, true, result);
    if (type == P_PGID) return id <= INT32_MAX
        && take(0, id ? (pid_t)id : caller_pgid, NULL, options, true, result);
    if (type == (idtype_t)3 && id <= INT32_MAX) { /* Linux P_PIDFD */
        /* Pin the descriptor while validating its type and matching identity.
         * fdinfo Pid becomes -1 after native reap; the inode remains stable. */
        user_fd_lock();
        int fd = fcntl((int)id, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) { user_fd_unlock(); return false; }
        char path[64], line[256];
        snprintf(path, sizeof(path), "/proc/thread-self/fdinfo/%d", fd);
        struct user_proc_reader info;
        bool valid = false;
        if (user_proc_open(&info, path)) {
            while (user_proc_line(&info, line, sizeof(line))) {
                int32_t pid;
                if (user_proc_integer(line, "Pid:", &pid)) { valid = true; break; }
            }
            user_proc_close(&info);
        }
        struct stat st;
        valid = valid && !fstat(fd, &st);
        bool found = valid && take(0, 0, &st, options, true, result);
        close(fd);
        user_fd_unlock();
        return found;
    }
    return type == P_ALL && take(0, 0, NULL, options, true, result);
}

bool user_ptrace_events_get(pid_t pid, struct user_ptrace_stop* result)
{
    bool found = false;
    spin_lock(&events_lock);
    for (struct stop_node* node = stops; node; node = node->next) {
        if (node->value.pid == pid) {
            *result = node->value;
            found = true;
            break;
        }
    }
    spin_unlock(&events_lock);
    return found;
}

bool user_ptrace_events_set(const struct user_ptrace_stop* value)
{
    spin_lock(&events_lock);
    for (struct stop_node* node = stops; node; node = node->next) {
        if (node->value.pid == value->pid) {
            node->value = *value;
            spin_unlock(&events_lock);
            return true;
        }
    }
    struct stop_node* node = event_allocate(sizeof(*node));
    if (node) {
        *node = (struct stop_node){.next = stops, .value = *value};
        stops = node;
        atomic_add_uint32(&tracked_count, 1);
    }
    spin_unlock(&events_lock);
    return node != NULL;
}

bool user_ptrace_events_inherit(pid_t parent, pid_t child)
{
    struct user_ptrace_stop inherited = {.pid = child};
    spin_lock(&events_lock);
    for (struct stop_node* node = stops; node; node = node->next) {
        if (node->value.pid == parent) {
            inherited.options = node->value.options;
            inherited.resume_request = node->value.resume_request;
            inherited.owner_tid = node->value.owner_tid;
            break;
        }
    }
    for (struct stop_node* node = stops; node; node = node->next) {
        if (node->value.pid == child) {
            node->value.options = inherited.options;
            node->value.resume_request = inherited.resume_request;
            node->value.owner_tid = inherited.owner_tid;
            spin_unlock(&events_lock);
            return true;
        }
    }
    struct stop_node* node = event_allocate(sizeof(*node));
    if (node) {
        *node = (struct stop_node){.next = stops, .value = inherited};
        stops = node;
        atomic_add_uint32(&tracked_count, 1);
    }
    spin_unlock(&events_lock);
    return node != NULL;
}

void user_ptrace_events_remove(pid_t pid)
{
    spin_lock(&events_lock);
    struct stop_node** stop = &stops;
    while (*stop) {
        struct stop_node* node = *stop;
        if (node->value.pid == pid) {
            *stop = node->next;
            event_release(node);
            atomic_sub_uint32(&tracked_count, 1);
            break;
        }
        stop = &node->next;
    }
    struct event_node** event = &events;
    while (*event) {
        struct event_node* node = *event;
        if (node->value.pid == pid) {
            *event = node->next;
            event_release(node);
            atomic_sub_uint32(&queued_count, 1);
        } else event = &node->next;
    }
    tail = event;
    spin_unlock(&events_lock);
}

void user_ptrace_events_fork_reset(void)
{
    /* Another thread may have owned the copied lock at fork. */
    spin_init(&events_lock);
    spin_init(&normalization_lock);
    atomic_store_uint32(&queued_count, 0);
    atomic_store_uint32(&tracked_count, 0);
    atomic_store_uint32(&generation, 0);
    atomic_store_uint32(&sleepers, 0);
    /* A raw fork may also inherit libc allocator locks. These private copies
     * are unreachable in the child; avoid touching malloc until normal startup. */
    events = NULL;
    stops = NULL;
    tail = &events;
}
#endif
