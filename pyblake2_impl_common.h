#ifndef _MSC_VER
# include <stdint.h>
#else
 typedef unsigned __int8  uint8_t;
 typedef unsigned __int32 uint32_t;
 typedef unsigned __int64 uint64_t;
# ifndef inline
#  define inline __forceinline
# endif
#endif

/* pure SSE2 implementation is very slow, so only use the more optimized SSSE3+
 * https://github.com/dchest/pyblake2/issues/11 */
#if defined(__SSSE3__) || defined(__SSE4_1__) || defined(__AVX__) || defined(__XOP__)
# define USE_OPTIMIZED_IMPL
#endif
