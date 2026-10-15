/* SPDX-License-Identifier: MPL-2.0 */
/* The RISC-V 64-bit interpreter for userland harts. Each guest memory access
 * is a recorded host fault site, so a guest fault resumes at the faulting
 * instruction. The full-system interpreter keeps plain accesses. */

#ifdef RVVM_USER_TEST
#undef RISCV32
#define RISCV64 1
#define RISCV_USERLAND 1

#include "riscv_interpreter.h" // IWYU pragma: keep
#endif
