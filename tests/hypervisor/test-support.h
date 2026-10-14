#include <util/utils.h>

static void enable_h(void)
{
    static char* args[] = { "hypervisor-test", "-nogui" };
    rvvm_set_args(2, args);
}
