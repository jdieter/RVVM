/* SPDX-License-Identifier: MPL-2.0 */
#ifndef RVVM_SOFTFLOAT_PLATFORM_H
#define RVVM_SOFTFLOAT_PLATFORM_H
#include "compiler.h"
#ifdef HOST_LITTLE_ENDIAN
#define LITTLEENDIAN 1
#endif
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
