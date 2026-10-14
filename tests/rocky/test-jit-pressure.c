/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "util/feature_test.h"
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include "core/rvvm.c"

/* Exercise policy and reclamation without executing a guest CPU. */
void riscv_jit_flush_cache(rvvm_hart_t* hart)
{
    if (hart->jit_enabled) rvjit_flush_cache(&hart->jit);
}

static uint64_t mapped;
static pthread_mutex_t transition = PTHREAD_MUTEX_INITIALIZER;
static __thread bool in_transition;
static void enter(void)
{
    assert(!in_transition);
    assert(!pthread_mutex_lock(&transition));
    in_transition = true;
}
static void leave(void)
{
    assert(in_transition);
    in_transition = false;
    assert(!pthread_mutex_unlock(&transition));
}
static uint64_t probe(void) { assert(in_transition); return mapped; }
static uint32_t go, admitted;
static void* grow(void* opaque)
{
    rvvm_hart_t* hart = opaque;
    while (!atomic_load_uint32(&go)) sched_yield();
    if (user_jit_growth_begin(hart, 100)) {
        assert(in_transition && !spin_try_lock(&global_lock));
        atomic_add_uint64(&hart->jit.user_metadata_size, 100);
        atomic_add_uint32(&admitted, 1);
        user_jit_growth_end(hart);
    }
    return NULL;
}

int main(void)
{
    rvvm_machine_t machine = {0};
    rvvm_hart_t a = {.machine = &machine, .rv64 = true};
    rvvm_hart_t b = {.machine = &machine, .rv64 = true};
    machine.user_memory_probe = probe;
    machine.user_jit_enter = enter;
    machine.user_jit_leave = leave;
    vector_init(machine.harts);
    vector_push_back(machine.harts, &a);
    vector_push_back(machine.harts, &b);
    rvvm_set_opt(&machine, RVVM_OPT_JIT, true);
    rvvm_set_opt(&machine, RVVM_OPT_JIT_CACHE, 1U << 20);
    user_jit_prepare(&a);
    user_jit_prepare(&b);
    assert(a.jit_enabled && b.jit_enabled);
    uint64_t used = user_jit_used(&machine);
    struct rlimit policy = {used * 2 + 200, RLIM_INFINITY};
    assert(user_jit_room(&machine, &policy, 0, 100));
    assert(!user_jit_room(&machine, &policy, 0, 101));

    struct rlimit original, finite;
    assert(!getrlimit(RLIMIT_AS, &original));
    finite = original;
    finite.rlim_cur = 1U << 30;
    assert(!setrlimit(RLIMIT_AS, &finite));
    mapped = finite.rlim_cur / 10 * 9;
    rvvm_user_jit_pressure(&a);
    assert(machine.user_jit_pressure && (a.user_cache_flush & 2) && (b.user_cache_flush & 2));
    rvvm_user_jit_reclaim(&a);
    rvvm_user_jit_reclaim(&b);
    assert(!a.jit_enabled && !b.jit_enabled && !user_jit_used(&machine));
    mapped = finite.rlim_cur / 4 * 3;
    rvvm_user_jit_pressure(&a);
    assert(machine.user_jit_pressure); // Hysteresis prevents immediate regrowth.
    mapped = finite.rlim_cur / 5 * 3;
    rvvm_user_jit_pressure(&a);
    assert(!machine.user_jit_pressure && (a.user_cache_flush & 4));
    rvvm_user_jit_reclaim(&a);
    rvvm_user_jit_reclaim(&b);
    assert(a.jit_enabled && b.jit_enabled && user_jit_used(&machine));
    assert(a.jit.user_growth_begin && b.jit.user_growth_begin);
    uint64_t a_size = a.jit.user_metadata_size, b_size = b.jit.user_metadata_size;
    atomic_add_uint64(&b.jit.user_metadata_size, finite.rlim_cur / 2 - user_jit_used(&machine) - 100);
    pthread_t first, second;
    assert(!pthread_create(&first, NULL, grow, &a));
    assert(!pthread_create(&second, NULL, grow, &b));
    atomic_store_uint32(&go, 1);
    assert(!pthread_join(first, NULL) && !pthread_join(second, NULL));
    assert(admitted == 1 && user_jit_used(&machine) == finite.rlim_cur / 2);
    a.jit.user_metadata_size = a_size;
    b.jit.user_metadata_size = b_size;
    assert(!setrlimit(RLIMIT_AS, &original));
    rvjit_ctx_free(&a.jit);
    rvjit_ctx_free(&b.jit);
    vector_free(machine.harts);
    puts("PASS shared JIT budget, pressure eviction and hysteretic recovery");
    return 0;
}
