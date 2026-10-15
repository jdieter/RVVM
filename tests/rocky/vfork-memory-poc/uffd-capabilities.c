#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void)
{
    int fd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror("userfaultfd(kernel-fault capable)"); return 1; }
    struct uffdio_api api = {.api = UFFD_API,
        .features = UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_EVENT_FORK};
    if (ioctl(fd, UFFDIO_API, &api)) { perror("UFFDIO_API"); return 1; }
    printf("api=%llu features=0x%llx ioctls=0x%llx missing_shmem=%d event_fork=%d wp_shmem_hugetlbfs=%d\n",
        (unsigned long long)api.api, (unsigned long long)api.features,
        (unsigned long long)api.ioctls, !!(api.features & UFFD_FEATURE_MISSING_SHMEM),
        !!(api.features & UFFD_FEATURE_EVENT_FORK),
        !!(api.features & UFFD_FEATURE_WP_HUGETLBFS_SHMEM));
    close(fd);
    return 0;
}
