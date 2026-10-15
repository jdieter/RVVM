/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "user_ptrace_replay.h"
#include "util/spinlock.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct replay {
    struct replay* next;
    pid_t pid;
    bool sent;
    struct user_ptrace_replay_entry entry;
};
struct replay_records {
    spinlock_t lock;
    struct replay *nodes, **last;
    uint64_t token;
    void* (*allocate)(void*, size_t, void*);
    void* opaque;
};
static struct replay_records initial_records = {
    .lock = SPINLOCK_INIT, .last = &initial_records.nodes, .token = 1,
};
static _Thread_local struct replay_records* selected_records;
static struct replay_records* records(void)
{
    return selected_records ? selected_records : &initial_records;
}
#define replay_lock (records()->lock)
#define replays (records()->nodes)
#define replay_tail (records()->last)
#define next_token (records()->token)

void* user_ptrace_replay_records_new(void* (*allocate)(void*, size_t, void*), void* opaque)
{
    struct replay_records* next = calloc(1, sizeof(*next));
    if (next) {
        spin_init(&next->lock);
        next->last = &next->nodes;
        next->token = 1;
        next->allocate = allocate;
        next->opaque = opaque;
    }
    return next;
}

void user_ptrace_replay_records_free(void* pointer)
{
    struct replay_records* owned = pointer;
    if (!owned) return;
    if (!owned->allocate) while (owned->nodes) {
        struct replay* node = owned->nodes;
        owned->nodes = node->next;
        free(node);
    }
    free(owned);
}

void* user_ptrace_replay_temporary(size_t size)
{
    return records()->allocate ? records()->allocate(records()->opaque, size, NULL) : malloc(size);
}

void user_ptrace_replay_temporary_free(void* pointer)
{
    if (records()->allocate) records()->allocate(records()->opaque, 0, pointer);
    else free(pointer);
}
static __thread struct user_ptrace_replay_entry* mailbox;
static __thread size_t mailbox_count;
static __thread void* (*mailbox_allocator)(void*, size_t, void*);
static __thread void* mailbox_allocator_opaque;

void user_ptrace_replay_context_save(struct user_ptrace_replay_context* context)
{
    *context = (struct user_ptrace_replay_context){
        mailbox, mailbox_count, mailbox_allocator, mailbox_allocator_opaque, selected_records,
    };
}

void user_ptrace_replay_context_load(const struct user_ptrace_replay_context* context)
{
    mailbox = context->mailbox;
    mailbox_count = context->count;
    mailbox_allocator = context->allocate;
    mailbox_allocator_opaque = context->opaque;
    selected_records = context->records;
}

void user_ptrace_replay_context_release(struct user_ptrace_replay_context* context)
{
    if (context->mailbox) {
        if (context->allocate) context->allocate(context->opaque, 0, context->mailbox);
        else munmap(context->mailbox, context->count * sizeof(*context->mailbox));
    }
    context->mailbox = NULL;
    context->count = 0;
}

static int send_replay(struct replay* node, pid_t tgid)
{
    siginfo_t tagged = {.si_signo = node->entry.info.si_signo, .si_code = SI_QUEUE};
    tagged.si_pid = node->entry.sender;
    tagged.si_uid = geteuid();
    tagged.si_value.sival_ptr = (void*)(uintptr_t)node->entry.token;
    if (syscall(SYS_rt_tgsigqueueinfo, tgid, node->pid, tagged.si_signo, &tagged)) return -errno;
    node->sent = true;
    return 0;
}

static int store_replay(pid_t pid, pid_t tgid, const siginfo_t* info, bool send)
{
    struct replay* node = user_ptrace_replay_temporary(sizeof(*node));
    if (!node) return -ENOMEM;
    memset(node, 0, sizeof(*node));
    node->pid = pid;
    node->entry.info = *info;
    node->entry.sender = getpid();
    spin_lock(&replay_lock);
    int ret = next_token ? 0 : -EOVERFLOW;
    if (!ret) node->entry.token = next_token++;
    if (!ret && send) ret = send_replay(node, tgid);
    if (!ret) {
        *replay_tail = node;
        replay_tail = &node->next;
    }
    spin_unlock(&replay_lock);
    if (ret) user_ptrace_replay_temporary_free(node);
    return ret;
}

int user_ptrace_replay_queue(pid_t pid, pid_t tgid, const siginfo_t* info)
{
    return store_replay(pid, tgid, info, true);
}

int user_ptrace_replay_store_unsent(pid_t pid, const siginfo_t* info)
{
    return store_replay(pid, 0, info, false);
}

size_t user_ptrace_replay_count(pid_t pid)
{
    size_t count = 0;
    spin_lock(&replay_lock);
    for (struct replay* node = replays; node; node = node->next) count += node->pid == pid;
    spin_unlock(&replay_lock);
    return count;
}

bool user_ptrace_replay_pending(pid_t pid)
{
    return user_ptrace_replay_count(pid) != 0;
}

int user_ptrace_replay_export(pid_t pid, struct user_ptrace_replay_entry* entries, size_t capacity)
{
    size_t count = 0;
    spin_lock(&replay_lock);
    for (struct replay* node = replays; node; node = node->next) {
        if (node->pid != pid) continue;
        if (count < capacity) entries[count] = node->entry;
        count++;
    }
    spin_unlock(&replay_lock);
    return count > capacity ? -ENOSPC : count > INT_MAX ? -EOVERFLOW : (int)count;
}

static bool matches(const struct replay* node, pid_t pid, const siginfo_t* tagged)
{
    return tagged->si_code == SI_QUEUE && tagged->si_pid == node->entry.sender
        && (uintptr_t)tagged->si_value.sival_ptr == node->entry.token && node->pid == pid
        && node->entry.info.si_signo == tagged->si_signo;
}

bool user_ptrace_replay_hold(pid_t pid, const siginfo_t* tagged)
{
    bool found = false;
    spin_lock(&replay_lock);
    for (struct replay* node = replays; node; node = node->next) {
        if (!matches(node, pid, tagged)) continue;
        node->sent = false;
        found = true;
        break;
    }
    spin_unlock(&replay_lock);
    return found;
}

int user_ptrace_replay_resend(pid_t pid, pid_t tgid)
{
    int ret = 0;
    spin_lock(&replay_lock);
    for (struct replay* node = replays; node && !ret; node = node->next)
        if (node->pid == pid && !node->sent) ret = send_replay(node, tgid);
    spin_unlock(&replay_lock);
    return ret;
}

bool user_ptrace_replay_take(pid_t pid, const siginfo_t* tagged, siginfo_t* original)
{
    if (tagged->si_code != SI_QUEUE || tagged->si_pid != getpid()) return false;
    bool found = false;
    spin_lock(&replay_lock);
    struct replay** link = &replays;
    while (*link) {
        struct replay* node = *link;
        if (matches(node, pid, tagged)) {
            *original = node->entry.info;
            *link = node->next;
            if (!*link) replay_tail = link;
            user_ptrace_replay_temporary_free(node);
            found = true;
            break;
        }
        link = &node->next;
    }
    spin_unlock(&replay_lock);
    return found;
}

struct user_ptrace_replay_entry* user_ptrace_replay_allocate(size_t count)
{
    size_t active = 0;
    for (size_t i = 0; i < mailbox_count; i++) active += mailbox[i].token != 0;
    if (count > SIZE_MAX / sizeof(*mailbox) - active) { errno = ENOMEM; return NULL; }
    size_t length = active + count;
    if (!length) return NULL;
    struct user_ptrace_replay_entry* next = mailbox_allocator
        ? mailbox_allocator(mailbox_allocator_opaque, length * sizeof(*next), NULL)
        : mmap(NULL, length * sizeof(*next), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!next || next == MAP_FAILED) { errno = ENOMEM; return NULL; }
    /* mmap is zero-filled; a trusted-runtime allocator need not be. */
    if (mailbox_allocator) memset(next, 0, length * sizeof(*next));
    size_t index = 0;
    for (size_t i = 0; i < mailbox_count; i++)
        if (mailbox[i].token) next[index++] = mailbox[i];
    struct user_ptrace_replay_context old;
    user_ptrace_replay_context_save(&old);
    user_ptrace_replay_context_release(&old);
    mailbox = next;
    mailbox_count = length;
    return next + active;
}

bool user_ptrace_replay_restore(siginfo_t* info)
{
    if (info->si_code != SI_QUEUE) return false;
    uint64_t token = (uintptr_t)info->si_value.sival_ptr;
    if (!token) return false;
    for (size_t i = 0; i < mailbox_count; i++) {
        struct user_ptrace_replay_entry* entry = &mailbox[i];
        if (entry->token != token || entry->sender != info->si_pid
            || entry->info.si_signo != info->si_signo) continue;
        entry->token = 0;
        *info = entry->info;
        return true;
    }
    return false;
}

void user_ptrace_replay_remove(pid_t pid)
{
    spin_lock(&replay_lock);
    struct replay** link = &replays;
    while (*link) {
        struct replay* node = *link;
        if (!pid || node->pid == pid) {
            *link = node->next;
            if (!*link) replay_tail = link;
            user_ptrace_replay_temporary_free(node);
        }
        else link = &node->next;
    }
    spin_unlock(&replay_lock);
}

void user_ptrace_replay_thread_destroy(void)
{
    struct user_ptrace_replay_context old;
    user_ptrace_replay_context_save(&old);
    user_ptrace_replay_context_release(&old);
    mailbox = NULL;
    mailbox_count = 0;
}

void user_ptrace_replay_fork_reset(void)
{
    spin_init(&replay_lock);
    replays = NULL;
    replay_tail = &replays;
    user_ptrace_replay_thread_destroy();
}
#endif
