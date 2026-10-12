/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_SERVICE_H
#define RVVM_USER_SERVICE_H

/* Guest __WALL waiters may race the native service waiter. Published records
 * remain readable until process exit; joining clears the PID before reuse. */
struct user_service {
    struct user_service* next;
    uint32_t pid, reaped;
    int status;
};
static struct user_service* user_services;

static struct user_service* user_service_find(pid_t pid)
{
    if (pid <= 0) return NULL;
    struct user_service* service = __atomic_load_n(&user_services, __ATOMIC_ACQUIRE);
    for (; service; service = service->next)
        if (atomic_load_uint32(&service->pid) == (uint32_t)pid) return service;
    return NULL;
}

static void user_service_publish(struct user_service* service, pid_t pid)
{
    service->pid = pid;
    struct user_service* head = __atomic_load_n(&user_services, __ATOMIC_ACQUIRE);
    do { service->next = head; }
    while (!__atomic_compare_exchange_n(&user_services, &head, service, false,
                                        __ATOMIC_RELEASE, __ATOMIC_ACQUIRE));
}

static void user_service_guest(pid_t pid)
{
    struct user_service* service = user_service_find(pid);
    if (service) atomic_store_uint32(&service->pid, 0);
}

static bool user_service_wait(pid_t pid, int status, bool consumed)
{
    struct user_service* service = user_service_find(pid);
    if (!service) return false;
    if (consumed) {
        service->status = status;
        atomic_store_uint32(&service->reaped, 1);
    }
    return true;
}

#endif
