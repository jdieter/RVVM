/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "core/user_ptrace/user_ptrace_replay.h"

static void store(pid_t pid, int value)
{
    siginfo_t info = {.si_signo = SIGRTMIN, .si_code = SI_QUEUE};
    info.si_value.sival_int = value;
    assert(!user_ptrace_replay_store_unsent(pid, &info));
}

static void take(pid_t pid, struct user_ptrace_replay_entry* entry)
{
    siginfo_t tagged = {.si_signo = entry->info.si_signo, .si_code = SI_QUEUE,
                        .si_pid = entry->sender}, original;
    tagged.si_value.sival_ptr = (void*)(uintptr_t)entry->token;
    assert(user_ptrace_replay_take(pid, &tagged, &original));
    assert(original.si_value.sival_int == entry->info.si_value.sival_int);
}

static void* allocate(void* opaque, size_t size, void* release)
{
    int* retained = opaque;
    if (release) { free(release); --*retained; return NULL; }
    void* next = malloc(size);
    assert(next);
    memset(next, 0xa5, size);
    ++*retained;
    return next;
}

int main(void)
{
    pid_t pid = getpid();
    const size_t count = 40000;
    struct user_ptrace_replay_entry* entries = calloc(count, sizeof(*entries));
    assert(entries);
    for (size_t i = 0; i < count; ++i) store(pid, i);
    assert(user_ptrace_replay_export(pid, entries, count) == (int)count);
    for (size_t i = 0; i < count; ++i) assert(entries[i].info.si_value.sival_int == (int)i);
    take(pid, &entries[count - 1]); // Removing the tail must permit another append.
    store(pid, count);
    take(pid, &entries[0]);
    assert(user_ptrace_replay_count(pid) == count - 1);
    store(pid + 1, 99);
    user_ptrace_replay_remove(pid + 1); // Remove a tail belonging to another pid.
    store(pid + 1, 100);
    assert(user_ptrace_replay_export(pid + 1, entries, count) == 1);
    take(pid + 1, entries);
    user_ptrace_replay_remove(pid);
    store(pid, 1);
    assert(user_ptrace_replay_export(pid, entries, count) == 1);
    take(pid, entries); // Empty the queue by take, then append again.
    store(pid, 2);
    user_ptrace_replay_remove(0);
    store(pid, 3);
    user_ptrace_replay_remove(0);
    user_ptrace_replay_fork_reset();
    store(pid, 4);
    assert(user_ptrace_replay_export(pid, entries, count) == 1);
    assert(entries[0].info.si_value.sival_int == 4);
    user_ptrace_replay_remove(0);
    free(entries);
    store(pid, 91);
    struct user_ptrace_replay_context original, isolated = {0};
    user_ptrace_replay_context_save(&original);
    int owned = 0;
    isolated.records = user_ptrace_replay_records_new(allocate, &owned);
    assert(isolated.records);
    user_ptrace_replay_context_load(&isolated);
    assert(!user_ptrace_replay_count(pid));
    store(pid, 92);
    struct user_ptrace_replay_entry one;
    assert(user_ptrace_replay_export(pid, &one, 1) == 1 && one.info.si_value.sival_int == 92);
    take(pid, &one);
    assert(!owned);
    user_ptrace_replay_context_load(&original);
    assert(user_ptrace_replay_export(pid, &one, 1) == 1 && one.info.si_value.sival_int == 91);
    user_ptrace_replay_remove(0);
    user_ptrace_replay_records_free(isolated.records);
    struct user_ptrace_replay_entry* parent = user_ptrace_replay_allocate(1);
    assert(parent); parent->token = 42;
    struct user_ptrace_replay_context saved, borrowed;
    user_ptrace_replay_context_save(&saved);
    int retained = 0;
    borrowed = (struct user_ptrace_replay_context){.allocate = allocate, .opaque = &retained};
    user_ptrace_replay_context_load(&borrowed);
    struct user_ptrace_replay_entry* child = user_ptrace_replay_allocate(2);
    assert(child && !child[0].token && !child[1].token);
    child[0].token = 17;
    assert(user_ptrace_replay_allocate(1));
    user_ptrace_replay_context_save(&borrowed);
    assert(borrowed.mailbox[0].token == 17 && retained == 1);
    user_ptrace_replay_context_load(&saved);
    assert(parent->token == 42);
    user_ptrace_replay_context_release(&borrowed);
    assert(!retained);
    user_ptrace_replay_thread_destroy();
    puts("PASS replay backlog ordering, tail removal and queue reset");
}
