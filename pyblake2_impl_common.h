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

/* Optimization choice support */
#if defined(BLAKE2_COMPRESS_XOP)
# define HAVE_XOP
# define USE_OPTIMIZED_IMPL
#elif defined(BLAKE2_COMPRESS_AVX)
# define HAVE_AVX
# define USE_OPTIMIZED_IMPL
#elif defined(BLAKE2_COMPRESS_SSSE3)
# define HAVE_SSSE3
# define USE_OPTIMIZED_IMPL
#elif defined(BLAKE2_COMPRESS_SSE2)
# define HAVE_SSE2
# define USE_OPTIMIZED_IMPL
#elif defined(BLAKE2_COMPRESS_AUTO)

/* Auto-detect optimization based on CFLAGS (from upstream) */
# if defined(__SSE2__) || defined(__x86_64__) || defined(__amd64__)
#  define HAVE_SSE2
# endif
# if defined(__SSSE3__)
#  define HAVE_SSSE3
# endif
# if defined(__SSE4_1__)
#  define HAVE_SSE41
# endif
# if defined(__AVX__)
#  define HAVE_AVX
# endif
# if defined(__XOP__)
#  define HAVE_XOP
# endif

/* pure SSE2 implementation is very slow, so only use the more optimized SSSE3+
 * https://github.com/dchest/pyblake2/issues/11 */
# if defined(__SSSE3__) || defined(__SSE4_1__) || defined(__AVX__) || defined(__XOP__)
#  define USE_OPTIMIZED_IMPL
# endif

#endif
