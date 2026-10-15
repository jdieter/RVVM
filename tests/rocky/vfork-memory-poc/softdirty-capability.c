#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    volatile unsigned char *p = mmap(NULL, page, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 2;
    *p = 1;
    int map = open("/proc/self/pagemap", O_RDONLY), clear = open("/proc/self/clear_refs", O_WRONLY);
    uint64_t before, clean, dirty;
    off_t at = ((uintptr_t)p / page) * sizeof(before);
    if (map < 0 || clear < 0 || pread(map, &before, sizeof(before), at) != sizeof(before)
        || pwrite(clear, "4", 1, 0) != 1 || pread(map, &clean, sizeof(clean), at) != sizeof(clean)) return 2;
    *p = 2;
    if (pread(map, &dirty, sizeof(dirty), at) != sizeof(dirty)) return 2;
    printf("before=%016llx clean=%016llx written=%016llx supported=%d\n",
           (unsigned long long)before, (unsigned long long)clean, (unsigned long long)dirty,
           !(clean & (UINT64_C(1) << 55)) && !!(dirty & (UINT64_C(1) << 55)));
    return !(dirty & (UINT64_C(1) << 55));
}
