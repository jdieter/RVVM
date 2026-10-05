/* SPDX-License-Identifier: MPL-2.0 */
#ifndef RVVM_SOFTFLOAT_PLATFORM_H
#define RVVM_SOFTFLOAT_PLATFORM_H
#include "compiler.h"
// Reuse RVVM's byte order and THREAD_LOCAL definition so concurrent harts
// keep independent SoftFloat rounding and exception state.
#ifdef HOST_LITTLE_ENDIAN
#define LITTLEENDIAN 1
#endif
// Use native integer arithmetic and inline helpers within the wrapper's single
// translation unit; GCC/Clang intrinsics accelerate normalization and products.
#define SOFTFLOAT_FAST_INT64 1
#define SOFTFLOAT_FAST_DIV32TO16 1
#define SOFTFLOAT_FAST_DIV64TO32 1
#define INLINE_LEVEL 5
#define INLINE static inline
#if defined(__GNUC__) || defined(__clang__)
#define SOFTFLOAT_BUILTIN_CLZ 1
#if defined(__SIZEOF_INT128__)
#define SOFTFLOAT_INTRINSIC_INT128 1
#endif
#include "opts-GCC.h"
#endif
#endif
