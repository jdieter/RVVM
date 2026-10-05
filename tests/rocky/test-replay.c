/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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
    puts("PASS replay backlog ordering, tail removal and queue reset");
}
