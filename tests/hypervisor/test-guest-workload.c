/* Run in the inner Linux to exercise SMP, FPU context and package-built code. */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_uint_fast64_t counter;
static volatile double scale[] = { 1.5, 2.5 };

static void* worker(void* index)
{
    double factor = (uintptr_t)index + 1;
    double sum = 0;
    for (unsigned i = 0; i < 100000; ++i) {
        sum += scale[0] * scale[1] * factor;
        atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);
    }
    assert(sum == 375000 * factor);
    return NULL;
}

int main(int argc, char** argv)
{
    pthread_t threads[4];
    for (uintptr_t i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, worker, (void*)i));
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(atomic_load(&counter) == 400000);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        execl("/bin/true", "true", (char*)NULL);
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int fd = open(argc == 2 ? argv[1] : "/root/kvm-workload-storage", O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0 && !ftruncate(fd, 4096));
    char* data = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(data != MAP_FAILED);
    const char marker[] = "INNER_SMP_FPU_ATOMIC_STORAGE_PASS\n";
    memcpy(data, marker, sizeof(marker));
    assert(!msync(data, 4096, MS_SYNC) && !munmap(data, 4096));
    char readback[sizeof(marker)];
    assert(pread(fd, readback, sizeof(readback), 0) == (ssize_t)sizeof(readback));
    assert(!memcmp(readback, marker, sizeof(marker)) && !close(fd));
    puts("PASS four-thread FPU/atomics, fork/exec and persisted mapped storage");
}
